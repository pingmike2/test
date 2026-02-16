package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// -------------------- Build Sing-box Config --------------------
func buildSingBoxConfig() error {
	configPath := filepath.Join(cfg.FilePath, "config.json")
	configJSON := map[string]interface{}{
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
					"type":                    "ws",
					"path":                    "/vmess-argo",
					"early_data_header_name":  "Sec-WebSocket-Protocol",
				},
			},
		},
	}

	data, err := json.MarshalIndent(configJSON, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configPath, data, 0644)
}

// -------------------- Run Services --------------------
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func runSingBoxAndArgo() {
	configFile := filepath.Join(cfg.FilePath, "config.json")
	webBin := filepath.Join(cfg.FilePath, "sbsh-web")
	if _, err := os.Stat(webBin); err == nil {
		if err := runCommand(webBin, "run", "-c", configFile); err == nil {
			fmt.Println("Sing-box web started")
		}
	}

	if !cfg.DisableArgo {
		botBin := filepath.Join(cfg.FilePath, "sbsh-bot")
		if _, err := os.Stat(botBin); err == nil {
			args := []string{"tunnel", "--edge-ip-version", "auto", "run", "--no-autoupdate"}
			if cfg.ArgoPort != "" {
				args = append(args, "--url", "http://localhost:"+cfg.ArgoPort)
			}
			runCommand(botBin, args...)
			fmt.Println("Argo bot started")
		}
	}
}

func runNezha() {
	if cfg.NezhaServer != "" && cfg.NezhaKey != "" {
		// TODO: 根据 v0 / v1 启动 agent
		fmt.Println("Starting Nezha agent...")
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
	// TODO: 根据 TUIC_PORT、HY2_PORT、REALITY_PORT 等生成其他协议

	if err := ioutil.WriteFile(listFile, []byte(strings.Join(content, "\n")), 0644); err != nil {
		return err
	}

	subBase64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(content, "\n")))
	return ioutil.WriteFile(subFile, []byte(subBase64), 0644)
}

func uploadNodes() {
	if cfg.UploadURL == "" {
		return
	}
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	data, err := ioutil.ReadFile(listFile)
	if err != nil {
		return
	}
	nodes := strings.Split(string(data), "\n")
	jsonData := map[string][]string{"nodes": nodes}
	body, _ := json.Marshal(jsonData)

	http.Post(cfg.UploadURL+"/api/add-nodes", "application/json", strings.NewReader(string(body)))
}

func sendTelegram() {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return
	}
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	content, err := ioutil.ReadFile(listFile)
	if err != nil {
		return
	}

	msg := fmt.Sprintf("<b>%s 节点推送通知</b>\n<pre>%s</pre>", cfg.Name, string(content))
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken)
	http.Post(url, "application/json",
		strings.NewReader(fmt.Sprintf(`{"chat_id":"%s","text":"%s","parse_mode":"HTML"}`, cfg.ChatID, msg)))
}

// -------------------- Cleanup --------------------
func cleanup() {
	files := []string{"config.json", "list.txt", "sub.txt"}
	for _, f := range files {
		os.Remove(filepath.Join(cfg.FilePath, f))
	}
}

// -------------------- Utils --------------------
func getIP() string {
	resp, err := http.Get("https://api.ip.sb/ip")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	return string(b)
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