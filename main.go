package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// =====================
// 📌 把 start.sh 文件嵌入 Go 二进制
//go:embed start.sh
var startSh string

const httpPort = 8080

func main() {
	go startHTTPServer()

	// 写入 start.sh 到临时文件
	fmt.Println("写入 start.sh 到临时文件...")
	tmpFile := "/tmp/.temp_start.sh"
	err := os.WriteFile(tmpFile, []byte(startSh), 0755)
	if err != nil {
		fmt.Println("写入 start.sh 出错:", err)
	}

	// 持续运行 start.sh，退出后自动重启
	fmt.Println("启动 start.sh（退出后自动重启）...")
	for {
		runStartSh(tmpFile)
		fmt.Println("start.sh 退出，5秒后重启...")
		time.Sleep(5 * time.Second)
	}
}

func runStartSh(tmpFile string) {
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		fmt.Printf("[启动] 第 %d/%d 次尝试\n", i+1, maxRetries)

		cmd := exec.Command("bash", tmpFile)
		cmd.Env = os.Environ()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Start()
		if err != nil {
			fmt.Printf("[启动] 启动失败: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Printf("[启动] start.sh 已启动, PID: %d\n", cmd.Process.Pid)

		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		// 等待最多 60 秒，防止脚本卡死
		select {
		case err := <-done:
			if err != nil && strings.Contains(err.Error(), "exit status") {
				fmt.Printf("[启动] start.sh 退出（状态码非0）: %v\n", err)
				return
			}
			fmt.Println("[启动] start.sh 正常退出")
			return
		case <-time.After(60 * time.Second):
			fmt.Println("[启动] start.sh 运行超时，正在终止进程...")
			cmd.Process.Kill()
			fmt.Println("[启动] 进程已终止，5秒后重试...")
			time.Sleep(5 * time.Second)
		}
	}
}

func startHTTPServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "服务运行中 %s\n", time.Now().Format(time.RFC3339))
	})

	fmt.Println("HTTP 服务启动在端口", httpPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil); err != nil {
		fmt.Println("HTTP 服务出错:", err)
	}
}