package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// 配置结构体
type Config struct {
	FilePath string
	UUID     string
	ArgoPort string
	CFIP     string
	CFPort   string
	Name     string
}

var cfg Config

func initConfig() {
	cfg = Config{
		FilePath: getEnv("FILE_PATH", "./world"),
		UUID:     getEnv("UUID", "fe7431cb-ab1b-4205-a14c-d056f821b383"),
		ArgoPort: getEnv("ARGO_PORT", "12345"),
		CFIP:     getEnv("CFIP", "spring.io"),
		CFPort:   getEnv("CFPORT", "443"),
		Name:     getEnv("NAME", ""),
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

// 生成订阅示例
func generateSubscription() error {
	listFile := filepath.Join(cfg.FilePath, "list.txt")
	subFile := filepath.Join(cfg.FilePath, "sub.txt")

	vmess := fmt.Sprintf(`{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"none","net":"ws","type":"none","host":"","path":"/vmess-argo","tls":"tls"}`,
		cfg.Name, cfg.CFIP, cfg.CFPort, cfg.UUID)

	content := []string{vmess}
	if err := ioutil.WriteFile(listFile, []byte(vmess+"\n"), 0644); err != nil {
		return err
	}

	subBase64 := base64.StdEncoding.EncodeToString([]byte(vmess))
	return ioutil.WriteFile(subFile, []byte(subBase64), 0644)
}

func main() {
	initConfig()

	if err := generateSubscription(); err != nil {
		fmt.Println("生成订阅失败:", err)
		return
	}

	fmt.Println("生成订阅完成，路径:", filepath.Join(cfg.FilePath, "sub.txt"))
}