package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	httpPort = 3000
)

func main() {
	go startHTTPServer()

	// 这里是原本的 shell 命令逻辑
	shellCommand := "chmod +x start.sh && ./start.sh &"

	cmd := exec.Command("bash", "-c", shellCommand)

	// ✅ 保留环境变量
	cmd.Env = os.Environ()

	// 输出 shell stdout/stderr 到 Go 控制台
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		fmt.Println("启动 shell 出错:", err)
		return
	}

	fmt.Println("shell 脚本已启动，PID:", cmd.Process.Pid)

	// 等待 shell 执行完成（如果你希望异步可注释下面 Wait）
	go func() {
		err := cmd.Wait()
		if err != nil {
			fmt.Println("shell 执行出错:", err)
		} else {
			fmt.Println("shell 执行完成")
		}
	}()

	// 防止主程序直接退出
	select {}
}

// 简单 HTTP server 示例
func startHTTPServer() {
	httpHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "服务运行中 %s\n", time.Now().Format(time.RFC3339))
	}

	httpServer := http.Server{
		Addr:    fmt.Sprintf(":%d", httpPort),
		Handler: http.HandlerFunc(httpHandler),
	}

	fmt.Println("HTTP 服务启动在端口", httpPort)
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Println("HTTP 服务出错:", err)
	}
}