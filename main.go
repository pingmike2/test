package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
}

/* ========================
   ENV Loader
======================== */
func loadEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		os.Setenv(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
	}
}

/* ========================
   Utils
======================== */

func ensureDir(path string) {
	os.MkdirAll(path, 0755)
}

func randomName() string {
	b := make([]byte, 6)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

/* ========================
   Downloader
======================== */

func downloadFile(url, dest string) error {
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
	return err
}

/* ========================
   Detect Architecture
======================== */

func baseURL() string {

	switch runtime.GOARCH {
	case "amd64":
		return "https://github.com/eooce/test/releases/download/amd64"
	case "arm64":
		return "https://github.com/eooce/test/releases/download/arm64"
	case "s390x":
		return "https://github.com/eooce/test/releases/download/s390"
	default:
		panic("unsupported arch")
	}
}

/* ========================
   Exec Runner
======================== */

func runCommand(name string, args ...string) (string, error) {

	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

/* ========================
   Reality Keys
======================== */

func realityKeys(sbPath, path string) (string, string) {

	keyFile := filepath.Join(path, "key.txt")

	if data, err := os.ReadFile(keyFile); err == nil {

		lines := strings.Split(string(data), "\n")
		var priv, pub string

		for _, l := range lines {
			if strings.Contains(l, "PrivateKey:") {
				priv = strings.Fields(l)[1]
			}
			if strings.Contains(l, "PublicKey:") {
				pub = strings.Fields(l)[1]
			}
		}
		if priv != "" {
			return priv, pub
		}
	}

	out, _ := runCommand(sbPath, "generate", "reality-keypair")
	os.WriteFile(keyFile, []byte(out), 0644)

	var priv, pub string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "PrivateKey:") {
			priv = strings.Fields(l)[1]
		}
		if strings.Contains(l, "PublicKey:") {
			pub = strings.Fields(l)[1]
		}
	}

	return priv, pub
}

/* ========================
   Certificate Generator
======================== */

func generateCert(path string) {

	key := filepath.Join(path, "private.key")
	cert := filepath.Join(path, "cert.pem")

	if _, err := os.Stat(cert); err == nil {
		return
	}

	exec.Command("openssl",
		"ecparam", "-genkey", "-name", "prime256v1",
		"-out", key).Run()

	exec.Command("openssl",
		"req", "-new", "-x509", "-days", "3650",
		"-key", key,
		"-out", cert,
		"-subj", "/CN=bing.com").Run()
}

/* ========================
   Singbox Config Builder
======================== */

func writeConfig(path, uuid, port, privKey string) {

	cfg := map[string]any{

		"log": map[string]any{
			"disabled": true,
		},

		"inbounds": []any{
			map[string]any{
				"type":        "vmess",
				"listen":      "::",
				"listen_port": port,
				"users": []map[string]string{
					{"uuid": uuid},
				},
			},
		},
	}

	j, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(filepath.Join(path, "config.json"), j, 0644)
}

/* ========================
   Start Process
======================== */

func startBinary(bin, config string) {

	ctx, _ := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, bin, "run", "-c", config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
}

/* ========================
   Node Generator
======================== */

func vmessNode(uuid, ip, port string) string {

	j := fmt.Sprintf(`{
"v":"2",
"ps":"go-node",
"add":"%s",
"port":"%s",
"id":"%s",
"net":"ws",
"tls":"tls"
}`, ip, port, uuid)

	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(j))
}

/* ========================
   Telegram
======================== */

func sendTG(token, chat, msg string) {

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	http.Post(url,
		"application/x-www-form-urlencoded",
		strings.NewReader(fmt.Sprintf("chat_id=%s&text=%s", chat, msg)))
}

/* ========================
   Upload Nodes
======================== */

func uploadNodes(api string, nodes []string) {

	body := map[string]any{"nodes": nodes}
	j, _ := json.Marshal(body)

	http.Post(api+"/api/add-nodes",
		"application/json",
		bytes.NewBuffer(j))
}

/* ========================
   ISP + IP
======================== */

func getIP() string {

	resp, _ := http.Get("https://ipv4.ip.sb")
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

/* ========================
   MAIN
======================== */

func main() {

	loadEnv()

	cfg := Config{
		FilePath:  os.Getenv("FILE_PATH"),
		UUID:      os.Getenv("UUID"),
		ArgoPort:  os.Getenv("ARGO_PORT"),
		UploadURL: os.Getenv("UPLOAD_URL"),
		BotToken:  os.Getenv("BOT_TOKEN"),
		ChatID:    os.Getenv("CHAT_ID"),
		Name:      os.Getenv("NAME"),
	}

	ensureDir(cfg.FilePath)

	base := baseURL()

	sbPath := filepath.Join(cfg.FilePath, randomName())
	botPath := filepath.Join(cfg.FilePath, randomName())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		downloadFile(base+"/sb", sbPath)
	}()

	go func() {
		defer wg.Done()
		downloadFile(base+"/bot", botPath)
	}()

	wg.Wait()

	os.Chmod(sbPath, 0755)
	os.Chmod(botPath, 0755)

	priv, pub := realityKeys(sbPath, cfg.FilePath)
	fmt.Println("Reality Public:", pub)

	generateCert(cfg.FilePath)

	writeConfig(cfg.FilePath, cfg.UUID, cfg.ArgoPort, priv)

	startBinary(sbPath,
		filepath.Join(cfg.FilePath, "config.json"))

	ip := getIP()
	node := vmessNode(cfg.UUID, ip, cfg.ArgoPort)

	fmt.Println(node)

	if cfg.UploadURL != "" {
		uploadNodes(cfg.UploadURL, []string{node})
	}

	if cfg.BotToken != "" {
		sendTG(cfg.BotToken, cfg.ChatID, node)
	}

	time.Sleep(2 * time.Second)
	fmt.Println("Running Done")
}