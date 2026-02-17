package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// ---------------- Argo Tunnel ----------------
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
	return
}

// ---------------- Nezha ----------------
func runNezha() {
	if NEZHA_SERVER == "" || NEZHA_KEY == "" {
		fmt.Println("NEZHA variable empty, skip running")
		return
	}

	var binary string
	if NEZHA_PORT != "" {
		binary = filepath.Join(FILE_PATH, "npm")
		args := []string{"-s", fmt.Sprintf("%s:%s", NEZHA_SERVER, NEZHA_PORT), "-p", NEZHA_KEY}
		tlsPorts := []string{"443", "8443", "2096", "2087", "2083", "2053"}
		for _, p := range tlsPorts {
			if p == NEZHA_PORT {
				args = append(args, "--tls")
				break
			}
		}
		if _, err := os.Stat(binary); err == nil {
			cmd := exec.Command(binary, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Start()
			fmt.Println(binary, "is running")
		}
	} else {
		binary = filepath.Join(FILE_PATH, "php")
		config := filepath.Join(FILE_PATH, "config.yaml")
		if _, err := os.Stat(binary); err == nil {
			cmd := exec.Command(binary, "-c", config)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Start()
			fmt.Println(binary, "is running")
		}
	}
}

// ---------------- Reality key ----------------
func generateRealityKey() (priv, pub string) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(err)
	privBytes := privKey.D.Bytes()
	priv = base64.StdEncoding.EncodeToString(privBytes)
	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	pub = base64.StdEncoding.EncodeToString(pubBytes)
	return
}

// ---------------- TLS ----------------
func generateTLS(domain string) (certPath, keyPath string) {
	certPath = filepath.Join(FILE_PATH, "cert.pem")
	keyPath = filepath.Join(FILE_PATH, "private.key")

	if _, err := exec.LookPath("openssl"); err == nil {
		runCmd("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", keyPath)
		runCmd("openssl", "req", "-new", "-x509", "-days", "3650", "-key", keyPath, "-out", certPath, "-subj", "/CN="+domain)
	} else {
		os.WriteFile(keyPath, []byte("FAKE_PRIVATE_KEY"), 0644)
		os.WriteFile(certPath, []byte("FAKE_CERT"), 0644)
	}
	return
}

// ---------------- Sing-box ----------------
func generateSingBoxConfig(privKey string) string {
	configFile := filepath.Join(FILE_PATH, "config.json")
	content := fmt.Sprintf(`{
  "log": {"disabled": true, "level": "error", "timestamp": true},
  "inbounds": [
    {"tag": "vmess-ws-in","type": "vmess","listen": "::","listen_port": "%s","users":[{"uuid":"%s"}],"transport":{"type":"ws","path":"/vmess-argo","early_data_header_name":"Sec-WebSocket-Protocol"}},
    {"tag": "tuic-in","type": "tuic","listen": "::","listen_port": "%s","users":[{"uuid":"%s","password":"admin"}],"congestion_control":"bbr","tls":{"enabled":true,"certificate_path":"%s/cert.pem","key_path":"%s/private.key","alpn":["h3"]}},
    {"tag": "hysteria2-in","type": "hysteria2","listen":"::","listen_port":"%s","users":[{"password":"%s"}],"masquerade":"https://bing.com","tls":{"enabled":true,"certificate_path":"%s/cert.pem","key_path":"%s/private.key","alpn":["h3"]}},
    {"tag": "vless-reality","type": "vless","listen":"::","listen_port":"%s","users":[{"uuid":"%s","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"www.nazhumi.com","reality":{"enabled":true,"private_key":"%s","short_id":[""],"handshake":{"server":"www.nazhumi.com","server_port":443}}}}
  ]
}`, ARGO_PORT, UUID,
		TUIC_PORT, UUID, FILE_PATH, FILE_PATH,
		HY2_PORT, UUID, FILE_PATH, FILE_PATH,
		REALITY_PORT, UUID, privKey)
	os.WriteFile(configFile, []byte(content), 0644)
	return configFile
}

// ---------------- Node Lists ----------------
func generateNodeLists(domain string) (listFile, subFile string) {
	listFile = filepath.Join(FILE_PATH, "list.txt")
	subFile = filepath.Join(FILE_PATH, "sub.txt")

	ip := CFIP
	if ip == "" {
		ip = "127.0.0.1"
	}

	var sb strings.Builder

	// vmess
	if ARGO_PORT != "" {
		vmessJSON := fmt.Sprintf(`{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","path":"/vmess-argo","tls":"tls","sni":"%s"}`, NAME, ip, CFPORT, UUID, domain)
		sb.WriteString("vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)) + "\n")
	}
	// tuic
	if TUIC_PORT != "" {
		sb.WriteString(fmt.Sprintf("tuic://%s:admin@%s:%s?sni=www.bing.com&alpn=h3#%s\n", UUID, ip, TUIC_PORT, NAME))
	}
	// hysteria2
	if HY2_PORT != "" {
		sb.WriteString(fmt.Sprintf("hysteria2://%s@%s:%s/?sni=www.bing.com&alpn=h3&insecure=1#%s\n", UUID, ip, HY2_PORT, NAME))
	}
	// reality
	if REALITY_PORT != "" {
		pub := "PUBKEY_PLACEHOLDER"
		sb.WriteString(fmt.Sprintf("vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&pbk=%s#%s\n", UUID, ip, REALITY_PORT, pub, NAME))
	}
	// socks5
	if S5_PORT != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(UUID[:8] + ":" + UUID[len(UUID)-12:]))
		sb.WriteString(fmt.Sprintf("socks://%s@%s:%s#%s\n", auth, ip, S5_PORT, NAME))
	}
	// anytls
	if ANYTLS_PORT != "" {
		sb.WriteString(fmt.Sprintf("anytls://%s@%s:%s?security=tls&sni=%s&fp=chrome#%s\n", UUID, ip, ANYTLS_PORT, ip, NAME))
	}
	// anyreality
	if ANYREALITY_PORT != "" {
		pub := "PUBKEY_PLACEHOLDER"
		sb.WriteString(fmt.Sprintf("anytls://%s@%s:%s?security=reality&sni=www.nazhumi.com&pbk=%s#%s\n", UUID, ip, ANYREALITY_PORT, pub, NAME))
	}

	os.WriteFile(listFile, []byte(sb.String()), 0644)
	subContent := base64.StdEncoding.EncodeToString([]byte(sb.String()))
	os.WriteFile(subFile, []byte(subContent), 0644)
	return
}

// ---------------- Upload ----------------
func uploadNodes(listFile string) {
	if UPLOAD_URL == "" {
		return
	}
	content, err := ioutil.ReadFile(listFile)
	if err != nil {
		return
	}
	nodes := strings.Split(string(content), "\n")
	jsonData := map[string][]string{"nodes": nodes}
	data, _ := json.Marshal(jsonData)
	http.Post(UPLOAD_URL+"/api/add-nodes", "application/json", bytes.NewReader(data))
}

// ---------------- Telegram ----------------
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
	}
}

// ---------------- Sing-box Runner ----------------
func runSingBox(binPath, configFile string) {
	if _, err := os.Stat(binPath); err == nil {
		cmd := exec.Command(binPath, "run", "-c", configFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Start()
		fmt.Println("sing-box is running")
	}
}

// ---------------- Runtime Arch ----------------
func runtimeArch() string {
	return strings.TrimSpace(runCmd("uname", "-m"))
}

// ---------------- Download Sing-box ----------------
func downloadSingBox() map[string]string {
	files := make(map[string]string)
	arch := runtimeArch()
	baseURL := ""
	switch arch {
	case "amd64", "x86_64":
		baseURL = "https://github.com/eooce/test/releases/download/amd64"
	case "arm", "arm64", "aarch64":
		baseURL = "https://github.com/eooce/test/releases/download/arm64"
	case "s390x", "s390":
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

// ---------------- Main ----------------
func main() {
	os.MkdirAll(FILE_PATH, 0755)

	tunnelArgs, domain := configureArgo()
	fmt.Println("ArgoDomain:", domain)
	_ = tunnelArgs

	files := downloadSingBox()
	runNezha()

	priv, pub := generateRealityKey()
	fmt.Println("Reality PrivateKey:", priv)
	fmt.Println("Reality PublicKey:", pub)

	certPath, keyPath := generateTLS(domain)
	fmt.Println("TLS Cert:", certPath, "Key:", keyPath)

	configFile := generateSingBoxConfig(priv)
	runSingBox(files["web"], configFile)

	listFile, subFile := generateNodeLists(domain)
	uploadNodes(listFile)

	msg := fmt.Sprintf("Services started\nArgo: %s\nReality PubKey: %s\nNode Sub: %s", domain, pub, subFile)
	sendTelegram(msg)

	fmt.Println("All main services started.")
}