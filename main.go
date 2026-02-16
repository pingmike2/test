package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

func main() {
	loadEnv()
	filePath := getFilePath()
	os.MkdirAll(filePath, 0755)

	downloadFiles(filePath)
	fmt.Println("Files downloaded to", filePath)

	// 生成 Reality key
	genRealityKey(filePath)
}

func loadEnv() {
	if _, err := os.Stat(".env"); err == nil {
		data, _ := ioutil.ReadFile(".env")
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				os.Setenv(kv[0], kv[1])
			}
		}
	}
}

func getFilePath() string {
	fp := os.Getenv("FILE_PATH")
	if fp == "" {
		fp = "./world"
	}
	return fp
}

func downloadFiles(filePath string) {
	files := map[string]string{
		"web": "https://github.com/eooce/test/releases/download/amd64/sb",
		"bot": "https://github.com/eooce/test/releases/download/amd64/bot",
	}
	for name, url := range files {
		out := fmt.Sprintf("%s/%s", filePath, name)
		cmd := exec.Command("curl", "-L", "-sS", "-o", out, url)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
		os.Chmod(out, 0755)
	}
}

func genRealityKey(filePath string) {
	sbPath := fmt.Sprintf("%s/web", filePath)
	cmd := exec.Command(sbPath, "generate", "reality-keypair")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Failed to generate reality key:", err)
		return
	}
	ioutil.WriteFile(filePath+"/key.txt", output, 0644)
	fmt.Println("Reality key generated at", filePath+"/key.txt")
}
