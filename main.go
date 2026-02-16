package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	FilePath   string
	UUID       string
	ArgoPort   string
	UploadURL  string
	BotToken   string
	ChatID     string
	Name       string
	NezhaServer string
	NezhaPort  string
	NezhaKey   string
	DisableArgo bool
	TuicPort    string
	Hy2Port     string
	AnyTLSPort  string
	RealityPort string
	AnyRealityPort string
	S5Port      string
	CFIP        string
	CFPort      string
}

var cfg Config
var privateKey, publicKey string

func initConfig() {
	cfg = Config{
		FilePath:   getenv("FILE_PATH", "./world"),
		UUID:       getenv("UUID", "fe7431cb-ab1b-4205-a14c-d056f821b383"),
		ArgoPort:   os.Getenv("ARGO_PORT"),
		UploadURL:  os.Getenv("UPLOAD_URL"),
		BotToken:   os.Getenv("BOT_TOKEN"),
		ChatID:     os.Getenv("CHAT_ID"),
		Name:       os.Getenv("NAME"),
		NezhaServer: os.Getenv("NEZHA_SERVER"),
		NezhaPort:  os.Getenv("NEZHA_PORT"),
		NezhaKey:   os.Getenv("NEZHA_KEY"),
		DisableArgo: getenv("DISABLE_ARGO", "false") == "true",
		TuicPort:    os.Getenv("TUIC_PORT"),
		Hy2Port:     os.Getenv("HY2_PORT"),
		AnyTLSPort:  os.Getenv("ANYTLS_PORT"),
		RealityPort: os.Getenv("REALITY_PORT"),
		AnyRealityPort: os.Getenv("ANYREALITY_PORT"),
		S5Port:      os.Getenv("S5_PORT"),
		CFIP:        getenv("CFIP", "spring.io"),
		CFPort:      getenv("CFPORT", "443"),
	}

	if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
		os.MkdirAll(cfg.FilePath, 0755)
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

// -------------------- Build Sing-box Config --------------------
func buildSingBoxConfig() {
	configPath := filepath.Join(cfg.FilePath, "config.json")

	// 生成 TLS 私钥和证书
	privPath := filepath.Join(cfg.FilePath, "private.key")
	certPath := filepath.Join(cfg.FilePath, "cert.pem")
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		exec.Command("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", privPath).Run()
		exec.Command("openssl", "req", "-new", "-x509", "-days", "3650", "-key", privPath, "-out", certPath,
			"-subj", "/CN=bing.com").Run()
	}

	// Reality keypair
	keyFile := filepath.Join(cfg.FilePath, "key.txt")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		out, _ := exec.Command(filepath.Join(cfg.FilePath, "sb"), "generate", "reality-keypair").Output()
		os.WriteFile(keyFile, out, 0644)
	}
	keyData, _ := os.ReadFile(keyFile)
	for _, line := range strings.Split(string(keyData), "\n") {
		if strings.HasPrefix(line, "PrivateKey:") {
			privateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		}
		if strings.HasPrefix(line, "PublicKey:") {
			publicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey:"))
		}
	}

	// 简单生成 config.json，inbounds / outbounds 可以根据 Shell 完整逻辑填充
	cfgJSON := map[string]interface{}{
		"log": map[string]interface{}{
			"disabled":   true,
			"level":      "error",
			"timestamp":  true,
		},
		"inbounds": []map[string]interface{}{
			{
				"tag":         "vmess-ws-in",
				"type":        "vmess",
				"listen":      "::",
				"listen_port": cfg.ArgoPort,
				"users": []map[string]interface{}{
					{"uuid": cfg.UUID},
				},
				"transport": map[string]interface{}{
					"type": "ws",
					"path": "/vmess-argo",
					"early_data_header_name": "Sec-WebSocket-Protocol",
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{"type": "direct", "tag": "direct"},
		},
	}

	jsonBytes, _ := json.MarshalIndent(cfgJSON, "", "  ")
	os.WriteFile(configPath, jsonBytes, 0644)
	fmt.Println("config.json generated at", configPath)
}

// -------------------- Run sing-box / Argo --------------------
func runSingBoxAndArgo() {
	webBin := filepath.Join(cfg.FilePath, "sb-web")
	botBin := filepath.Join(cfg.FilePath, "sb-bot")

	if _, err := os.Stat(webBin); err == nil {
		cmd := exec.Command(webBin, "run", "-c", filepath.Join(cfg.FilePath, "config.json"))
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Start()
		fmt.Println("sing-box web started")
	}

	if !cfg.DisableArgo && _, err := os.Stat(botBin); err == nil {
		args := []string{"tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run"}
		cmd := exec.Command(botBin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Start()
		fmt.Println("Argo bot started")
	}
}

// -------------------- Run Nezha --------------------
func runNezha() {
	if cfg.NezhaServer == "" || cfg.NezhaKey == "" {
		fmt.Println("Nezha variables empty, skip running")
		return
	}

	if cfg.NezhaPort != "" {
		// v0
		agent := filepath.Join(cfg.FilePath, "sb-npm")
		if _, err := os.Stat(agent); err == nil {
			cmd := exec.Command(agent, "-s", fmt.Sprintf("%s:%s", cfg.NezhaServer, cfg.NezhaPort), "-p", cfg.NezhaKey)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			cmd.Start()
			fmt.Println("Nezha v0 agent started")
		}
	} else {
		// v1
		agent := filepath.Join(cfg.FilePath, "sb-php")
		if _, err := os.Stat(agent); err == nil {
			cmd := exec.Command(agent, "-c", filepath.Join(cfg.FilePath, "config.yaml"))
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			cmd.Start()
			fmt.Println("Nezha v1 agent started")
		}
	}
}

// -------------------- Subscription --------------------
func generateSubscriptions() {
	ip := getIP()
	name := cfg.Name
	if name == "" {
		name = "Node-" + ip
	}
	list := []string{}
	if cfg.ArgoPort != "" {
		vmess := fmt.Sprintf(`{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"%s","path":"/vmess-argo?ed=2560","tls":"tls"}`,
			name, cfg.CFIP, cfg.CFPort, cfg.UUID, cfg.CFIP)
		vmessB64 := base64.StdEncoding.EncodeToString([]byte(vmess))
		list = append(list, "vmess://"+vmessB64)
	}
	subFile := filepath.Join(cfg.FilePath, "sub.txt")
	os.WriteFile(subFile, []byte(strings.Join(list, "\n")), 0644)
	fmt.Println("Subscription generated at", subFile)
}

func getIP() string {
	ip := "unknown"
	if out, err := exec.Command("curl", "-sm", "3", "ipv4.ip.sb").Output(); err == nil {
		ip = strings.TrimSpace(string(out))
	}
	return ip
}

func uploadNodes() {
	if cfg.UploadURL == "" {
		return
	}
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	data, err := os.ReadFile(listFile)
	if err != nil {
		return
	}
	nodes := strings.Split(string(data), "\n")
	jsonData := map[string]interface{}{"nodes": nodes}
	jsonBytes, _ := json.Marshal(jsonData)
	http.Post(cfg.UploadURL+"/api/add-nodes", "application/json", bytes.NewReader(jsonBytes))
	fmt.Println("Nodes uploaded")
}

func sendTelegram() {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return
	}
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	data, err := os.ReadFile(listFile)
	if err != nil {
		return
	}
	message := fmt.Sprintf("<b>%s Node Update</b>\n<pre>%s</pre>", cfg.Name, string(data))
	http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken),
		"application/x-www-form-urlencoded",
		strings.NewReader(fmt.Sprintf("chat_id=%s&text=%s&parse_mode=HTML", cfg.ChatID, message)))
	fmt.Println("Telegram message sent")
}

// -------------------- Cleanup --------------------
func cleanup() {
	os.RemoveAll(filepath.Join(cfg.FilePath, "boot.log"))
	os.RemoveAll(filepath.Join(cfg.FilePath, "config.json"))
	os.RemoveAll(filepath.Join(cfg.FilePath, "tunnel.json"))
	os.RemoveAll(filepath.Join(cfg.FilePath, "tunnel.yml"))
	os.RemoveAll(filepath.Join(cfg.FilePath, "list.txt"))
}

func main() {
	initConfig()
	buildSingBoxConfig()
	runSingBoxAndArgo()
	runNezha()
	generateSubscriptions()
	uploadNodes()
	sendTelegram()
	cleanup()
	fmt.Println("All tasks completed")
}