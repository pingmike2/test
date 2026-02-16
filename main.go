package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// -------------------- Config --------------------
type Config struct {
	FilePath    string
	UUID        string
	ArgoPort    string
	UploadURL   string
	BotToken    string
	ChatID      string
	Name        string
	DisableArgo bool
	// Nezha
	NezhaServer string
	NezhaPort   string
	NezhaKey    string
	// 其他端口
	S5Port       string
	HY2Port      string
	TUICPort     string
	AnyTLSPort   string
	RealityPort  string
	AnyReality   string
	CFIP         string
	CFPort       string
}

var cfg Config
var sbxProcess *exec.Cmd
var nezhaProcess *exec.Cmd
var botProcess *exec.Cmd
var webProcess *exec.Cmd

var allEnvVars = []string{
	"PORT", "FILE_PATH", "UUID", "NEZHA_SERVER", "NEZHA_PORT",
	"NEZHA_KEY", "ARGO_PORT", "ARGO_DOMAIN", "ARGO_AUTH",
	"S5_PORT", "HY2_PORT", "TUIC_PORT", "ANYTLS_PORT",
	"REALITY_PORT", "ANYREALITY_PORT", "CFIP", "CFPORT",
	"UPLOAD_URL", "CHAT_ID", "BOT_TOKEN", "NAME", "DISABLE_ARGO",
}

// -------------------- Init Config --------------------
func initConfig() {
	cfg = Config{
		FilePath:    getEnv("FILE_PATH", "./world"),
		UUID:        getEnv("UUID", "fe7431cb-ab1b-4205-a14c-d056f821b383"),
		ArgoPort:    os.Getenv("ARGO_PORT"),
		UploadURL:   os.Getenv("UPLOAD_URL"),
		BotToken:    os.Getenv("BOT_TOKEN"),
		ChatID:      os.Getenv("CHAT_ID"),
		Name:        os.Getenv("NAME"),
		DisableArgo: os.Getenv("DISABLE_ARGO") == "true",
		NezhaServer: os.Getenv("NEZHA_SERVER"),
		NezhaPort:   os.Getenv("NEZHA_PORT"),
		NezhaKey:    os.Getenv("NEZHA_KEY"),
		S5Port:      os.Getenv("S5_PORT"),
		HY2Port:     os.Getenv("HY2_PORT"),
		TUICPort:    os.Getenv("TUIC_PORT"),
		AnyTLSPort:  os.Getenv("ANYTLS_PORT"),
		RealityPort: os.Getenv("REALITY_PORT"),
		AnyReality:  os.Getenv("ANYREALITY_PORT"),
		CFIP:        getEnv("CFIP", "spring.io"),
		CFPort:      getEnv("CFPORT", "443"),
	}

	if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
		os.MkdirAll(cfg.FilePath, 0755)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// -------------------- Download Binary --------------------
func downloadBinary(url, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	fmt.Println("Downloading:", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return os.Chmod(dest, 0755)
}

func getArch() string {
	arch := runtime.GOARCH
	if arch == "amd64" {
		return "amd64"
	} else if arch == "arm64" {
		return "arm64"
	} else if arch == "s390x" {
		return "s390x"
	} else {
		return "amd64"
	}
}

// -------------------- Build Sing-box Config --------------------
func buildSingBoxConfig() error {
	configPath := filepath.Join(cfg.FilePath, "config.json")
	conf := map[string]interface{}{
		"log": map[string]interface{}{
			"disabled":  true,
			"level":     "error",
			"timestamp": true,
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":         "vmess-ws-in",
				"type":        "vmess",
				"listen":      "::",
				"listen_port": cfg.ArgoPort,
				"users": []map[string]string{
					{"uuid": cfg.UUID},
				},
				"transport": map[string]string{
					"type":                   "ws",
					"path":                   "/vmess-argo",
					"early_data_header_name": "Sec-WebSocket-Protocol",
				},
			},
		},
	}
	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configPath, data, 0644)
}

// -------------------- Run Services --------------------
func runCmd(bin string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, cmd.Start()
}

func runSingBoxAndArgo() {
	arch := getArch()
	sbxURL := fmt.Sprintf("https://github.com/eooce/test/releases/download/%s/sbx", arch)
	botURL := fmt.Sprintf("https://github.com/eooce/test/releases/download/%s/bot", arch)
	webURL := fmt.Sprintf("https://github.com/eooce/test/releases/download/%s/sbsh", arch)
	
	sbxBin := filepath.Join(cfg.FilePath, "sbx")
	botBin := filepath.Join(cfg.FilePath, "bot")
	webBin := filepath.Join(cfg.FilePath, "sbsh")

	downloadBinary(sbxURL, sbxBin)
	downloadBinary(botURL, botBin)
	downloadBinary(webURL, webBin)

	configFile := filepath.Join(cfg.FilePath, "config.json")
	webProcess, _ = runCmd(webBin, "run", "-c", configFile)
	if !cfg.DisableArgo {
		args := []string{"tunnel", "--edge-ip-version", "auto", "run", "--no-autoupdate"}
		if cfg.ArgoPort != "" {
			args = append(args, "--url", "http://localhost:"+cfg.ArgoPort)
		}
		botProcess, _ = runCmd(botBin, args...)
	}

	fmt.Println("Sing-box, bot, web started")
}

func runNezha() {
	if cfg.NezhaServer != "" && cfg.NezhaKey != "" {
		arch := getArch()
		agentURL := fmt.Sprintf("https://github.com/eooce/test/releases/download/%s/agent", arch)
		agentBin := filepath.Join(cfg.FilePath, "agent")
		downloadBinary(agentURL, agentBin)
		nezhaProcess, _ = runCmd(agentBin,
			"-s", cfg.NezhaServer,
			"-p", cfg.NezhaPort,
			"-k", cfg.NezhaKey)
		fmt.Println("Nezha agent started")
	}
}

// -------------------- Subscription --------------------
func generateSubscriptions() error {
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	subFile := filepath.Join(cfg.FilePath, "sub.txt")

	ip := getIP()
	name := cfg.Name
	if name == "" {
		name = ip
	}

	vmess := fmt.Sprintf(`{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"none","net":"ws","type":"none","host":"","path":"/vmess-argo?ed=2560","tls":"tls","sni":"","alpn":"","fp":"chrome"}`,
		name, cfg.CFIP, cfg.CFPort, cfg.UUID)
	content := []string{vmess}

	ioutil.WriteFile(listFile, []byte(strings.Join(content, "\n")), 0644)
	subBase64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(content, "\n")))
	return ioutil.WriteFile(subFile, []byte(subBase64), 0644)
}

func uploadNodes() {
	if cfg.UploadURL == "" {
		return
	}
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	data, _ := ioutil.ReadFile(listFile)
	nodes := strings.Split(string(data), "\n")
	body, _ := json.Marshal(map[string][]string{"nodes": nodes})
	http.Post(cfg.UploadURL+"/api/add-nodes", "application/json", strings.NewReader(string(body)))
}

func sendTelegram() {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return
	}
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	content, _ := ioutil.ReadFile(listFile)
	msg := fmt.Sprintf("<b>%s 节点推送通知</b>\n<pre>%s</pre>", cfg.Name, string(content))
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken)
	http.Post(url, "application/json",
		strings.NewReader(fmt.Sprintf(`{"chat_id":"%s","text":"%s","parse_mode":"HTML"}`, cfg.ChatID, msg)))
}

// -------------------- Utils --------------------
func getIP() string {
	resp, err := http.Get("https://api.ip.sb/ip")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// -------------------- Cleanup --------------------
func cleanup() {
	for _, f := range []string{"config.json", "list.txt", "sub.txt"} {
		os.Remove(filepath.Join(cfg.FilePath, f))
	}
}

// -------------------- Main --------------------
func main() {
	initConfig()

	if err := buildSingBoxConfig(); err != nil {
		fmt.Println("Build config error:", err)
		return
	}

	runSingBoxAndArgo()
	runNezha()

	if err := generateSubscriptions(); err != nil {
		fmt.Println("Generate subscription error:", err)
	}

	uploadNodes()
	sendTelegram()

	cleanup()
	fmt.Println("All tasks finished!")
	time.Sleep(2 * time.Second)
}