package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	FILE_PATH       = "./data"
	UUID            = "YOUR_UUID_HERE"
	ARGO_AUTH       = os.Getenv("ARGO_AUTH")
	ARGO_DOMAIN     = os.Getenv("ARGO_DOMAIN")
	ARGO_PORT       = os.Getenv("ARGO_PORT")
	DISABLE_ARGO    = os.Getenv("DISABLE_ARGO")
	NEZHA_SERVER    = os.Getenv("NEZHA_SERVER")
	NEZHA_PORT      = os.Getenv("NEZHA_PORT")
	NEZHA_KEY       = os.Getenv("NEZHA_KEY")
	UPLOAD_URL      = os.Getenv("UPLOAD_URL")
	NAME            = os.Getenv("NAME")
	BOT_TOKEN       = os.Getenv("BOT_TOKEN")
	CHAT_ID         = os.Getenv("CHAT_ID")
	CFIP            = os.Getenv("CFIP")
	CFPORT          = os.Getenv("CFPORT")
	TUIC_PORT       = os.Getenv("TUIC_PORT")
	HY2_PORT        = os.Getenv("HY2_PORT")
	REALITY_PORT    = os.Getenv("REALITY_PORT")
	S5_PORT         = os.Getenv("S5_PORT")
	ANYTLS_PORT     = os.Getenv("ANYTLS_PORT")
	ANYREALITY_PORT = os.Getenv("ANYREALITY_PORT")
)

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

// -------------------- 命令执行 & 下载 --------------------
func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	checkErr(err)
	return string(out)
}

func randomName(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz1234567890"
	b := make([]byte, n)
	_, err := rand.Read(b)
	checkErr(err)
	for i := 0; i < n; i++ {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func downloadFile(url, path string) {
	if _, err := exec.LookPath("curl"); err == nil {
		runCmd("curl", "-L", "-sS", "-o", path, url)
		fmt.Println("Downloaded", path, "by curl")
	} else if _, err := exec.LookPath("wget"); err == nil {
		runCmd("wget", "-q", "-O", path, url)
		fmt.Println("Downloaded", path, "by wget")
	} else {
		fmt.Println("Neither curl nor wget available")
		os.Exit(1)
	}
}

// -------------------- Argo Tunnel --------------------
func configureArgo() (tunnelArgs string, domain string) {
	if DISABLE_ARGO == "true" {
		fmt.Println("Disable argo tunnel")
		return "", ""
	}
	if ARGO_AUTH == "" || ARGO_DOMAIN == "" {
		fmt.Println("ARGO_DOMAIN or ARGO_AUTH empty, using quick tunnels")
	}

	if strings.Contains(ARGO_AUTH, "TunnelSecret") {
		secretFile := filepath.Join(FILE_PATH, "tunnel.json")
		os.WriteFile(secretFile, []byte(ARGO_AUTH), 0644)
		tunnelYml := filepath.Join(FILE_PATH, "tunnel.yml")
		id := strings.Split(ARGO_AUTH, "\"")[11]
		content := fmt.Sprintf(`tunnel: %s
credentials-file: %s
protocol: http2
ingress:
  - hostname: %s
    service: http://localhost:%s
    originRequest:
      noTLSVerify: true
  - service: http_status:404`, id, secretFile, ARGO_DOMAIN, ARGO_PORT)
		os.WriteFile(tunnelYml, []byte(content), 0644)
		tunnelArgs = fmt.Sprintf("tunnel --edge-ip-version auto --config %s run", tunnelYml)
		domain = ARGO_DOMAIN
	} else if len(ARGO_AUTH) > 120 {
		tunnelArgs = fmt.Sprintf("tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token %s", ARGO_AUTH)
		domain = ARGO_DOMAIN
	} else {
		bootLog := filepath.Join(FILE_PATH, "boot.log")
		tunnelArgs = fmt.Sprintf("tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile %s --loglevel info --url http://localhost:%s", bootLog, ARGO_PORT)
		for i := 0; i < 8; i++ {
			time.Sleep(time.Second)
			if data, err := ioutil.ReadFile(bootLog); err == nil {
				re := regexp.MustCompile(`https://([^/]*trycloudflare\.com)`)
				match := re.FindStringSubmatch(string(data))
				if len(match) > 1 {
					domain = match[1]
					break
				}
			}
		}
	}
	// 自动启动 Argo
	if tunnelArgs != "" {
		go func() {
			args := strings.Fields(tunnelArgs)
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Start()
		}()
	}
	return
}

// -------------------- Nezha Agent --------------------
func runNezha() {
	if NEZHA_SERVER == "" || NEZHA_KEY == "" {
		fmt.Println("NEZHA variable empty, skip running")
		return
	}
	var binary string
	var args []string
	if NEZHA_PORT != "" {
		binary = filepath.Join(FILE_PATH, "npm")
		args = []string{"-s", fmt.Sprintf("%s:%s", NEZHA_SERVER, NEZHA_PORT), "-p", NEZHA_KEY}
		tlsPorts := []string{"443", "8443", "2096", "2087", "2083", "2053"}
		for _, p := range tlsPorts {
			if p == NEZHA_PORT {
				args = append(args, "--tls")
				break
			}
		}
	} else {
		binary = filepath.Join(FILE_PATH, "php")
		config := filepath.Join(FILE_PATH, "config.yaml")
		args = []string{"-c", config}
	}
	if _, err := os.Stat(binary); err == nil {
		cmd := exec.Command(binary, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Start()
		fmt.Println(binary, "is running")
	}
}

// -------------------- Reality Key --------------------
func generateRealityKey() (privateKey, publicKey string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err)
	privBytes, err := x509.MarshalECPrivateKey(priv)
	checkErr(err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	checkErr(err)
	privB64 := base64.StdEncoding.EncodeToString(privBytes)
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)
	keyData := fmt.Sprintf("PrivateKey: %s\nPublicKey: %s\n", privB64, pubB64)
	os.WriteFile(filepath.Join(FILE_PATH, "key.txt"), []byte(keyData), 0644)
	return privB64, pubB64
}

// -------------------- TLS 自签证书 --------------------
func generateTLS(domain string) (certPath, keyPath string) {
	certPath = filepath.Join(FILE_PATH, "cert.pem")
	keyPath = filepath.Join(FILE_PATH, "private.key")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err)

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	checkErr(err)

	certFile, _ := os.Create(certPath)
	keyFile, _ := os.Create(keyPath)

	certFile.Write(pemEncode("CERTIFICATE", derBytes))
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyFile.Write(pemEncode("EC PRIVATE KEY", keyBytes))

	certFile.Close()
	keyFile.Close()
	return
}

func pemEncode(blockType string, derBytes []byte) []byte {
	return []byte(fmt.Sprintf("-----BEGIN %s-----\n%s\n-----END %s-----\n",
		blockType, base64.StdEncoding.EncodeToString(derBytes), blockType))
}

// -------------------- Sing-box config.json --------------------
func generateSingBoxConfig(realityPub string) string {
	configFile := filepath.Join(FILE_PATH, "config.json")
	config := map[string]interface{}{
		"inbounds":  []interface{}{},
		"outbounds": []interface{}{},
	}

	ports := map[string]string{
		"TUIC":       TUIC_PORT,
		"HY2":        HY2_PORT,
		"REALITY":    REALITY_PORT,
		"S5":         S5_PORT,
		"ANYTLS":     ANYTLS_PORT,
		"ANYREALITY": ANYREALITY_PORT,
	}

	for name, port := range ports {
		if port != "" {
			node := map[string]interface{}{
				"name": name,
				"port": port,
			}
			// 自动加入 Reality 公钥
			if name == "REALITY" || name == "ANYREALITY" {
				node["publicKey"] = realityPub
			}
			config["inbounds"] = append(config["inbounds"].([]interface{}), node)
		}
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	ioutil.WriteFile(configFile, data, 0644)
	return configFile
}

// -------------------- 生成节点 list.txt/sub.txt --------------------
func generateNodeLists(domain string) (listFile, subFile string) {
	listFile = filepath.Join(FILE_PATH, "list.txt")
	subFile = filepath.Join(FILE_PATH, "sub.txt")

	nodes := []string{}
	ports := []string{TUIC_PORT, HY2_PORT, REALITY_PORT, S5_PORT, ANYTLS_PORT, ANYREALITY_PORT}
	for _, p := range ports {
		if p != "" {
			nodeStr := fmt.Sprintf("tcp://%s:%s", domain, p)
			nodes = append(nodes, nodeStr)
		}
	}

	ioutil.WriteFile(listFile, []byte(strings.Join(nodes, "\n")), 0644)

	subB64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(nodes, "\n")))
	ioutil.WriteFile(subFile, []byte(subB64), 0644)
	return
}

// -------------------- 上传节点 --------------------
func uploadNodes(filePath string) {
	if UPLOAD_URL == "" {
		fmt.Println("UPLOAD_URL empty, skip upload")
		return
	}
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Failed to read node file:", err)
		return
	}
	resp, err := http.Post(UPLOAD_URL, "text/plain", bytes.NewReader(data))
	if err != nil {
		fmt.Println("Upload failed:", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Upload response:", string(body))
}

// -------------------- Telegram --------------------
func sendTelegram(msg string) {
	if BOT_TOKEN != "" && CHAT_ID != "" {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", BOT_TOKEN)
		data := fmt.Sprintf("chat_id=%s&text=%s&parse_mode=Markdown", CHAT_ID, msg)
		http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data))
	} else if CHAT_ID != "" {
		url := "http://api.tg.gvrander.eu.org/api/notify"
		payload := map[string]string{"chat_id": CHAT_ID, "message": msg}
		bs, _ := json.Marshal(payload)
		http.Post(url, "application/json", bytes.NewReader(bs))
	} else {
		fmt.Println("TG variable empty, skip sent")
	}
}

// -------------------- Sing-box 启动 --------------------
func runSingBox(binary, configFile string) {
	if _, err := os.Stat(binary); err == nil {
		cmd := exec.Command(binary, "run", "-c", configFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Start()
		fmt.Println("sing-box is running")
	}
}

// -------------------- 下载 sing-box & Nezha --------------------
func downloadSingBox() map[string]string {
	files := make(map[string]string)
	arch := runtime.GOARCH
	baseURL := ""
	switch arch {
	case "amd64":
		baseURL = "https://github.com/eooce/test/releases/download/amd64"
	case "arm64", "arm":
		baseURL = "https://github.com/eooce/test/releases/download/arm64"
	case "s390x":
		baseURL = "https://github.com/eooce/test/releases/download/s390x"
	default:
		fmt.Println("Unsupported architecture:", arch)
		os.Exit(1)
	}
	os.MkdirAll(FILE_PATH, 0755)
	for _, name := range []string{"web", "bot"} {
		randName := randomName(6)
		dest := filepath.Join(FILE_PATH, randName)
		downloadFile(fmt.Sprintf("%s/sb %s", baseURL, name), dest)
		os.Chmod(dest, 0755)
		files[name] = dest
	}
	if NEZHA_SERVER != "" && NEZHA_KEY != "" {
		agent := "php"
		if NEZHA_PORT != "" {
			agent = "npm"
		}
		randName := randomName(6)
		dest := filepath.Join(FILE_PATH, randName)
		downloadFile(fmt.Sprintf("%s/agent %s", baseURL, agent), dest)
		os.Chmod(dest, 0755)
		files[agent] = dest
	}
	return files
}

// -------------------- Main --------------------
func main() {
	os.MkdirAll(FILE_PATH, 0755)

	// Argo Tunnel
	tunnelArgs, domain := configureArgo()
	fmt.Println("ArgoDomain:", domain)

	// 下载 sing-box
	files := downloadSingBox()

	// Nezha agent
	runNezha()

	// Reality key
	priv, pub := generateRealityKey()
	fmt.Println("Reality PrivateKey:", priv)
	fmt.Println("Reality PublicKey:", pub)

	// TLS证书
	cert, key := generateTLS(domain)
	fmt.Println("TLS Cert:", cert, "Key:", key)

	// Sing-box config.json
	configFile := generateSingBoxConfig(pub)

	// 启动 Sing-box
	runSingBox(files["web"], configFile)

	// 生成节点列表
	listFile, subFile := generateNodeLists(domain)

	// 上传节点
	uploadNodes(listFile)

	// Telegram 推送
	msg := fmt.Sprintf("Services started\nArgo: %s\nReality PubKey: %s\nNode Sub: %s", domain, pub, subFile)
	sendTelegram(msg)

	fmt.Println("All main services started.")
}