package main

import (
	"fmt"
	"net/http"  // ✅ 一定要加这个
	"os"
	"os/exec"
	"time"
)

const (
	httpPort = 3000
)

func main() {
	go startHTTPServer()

	// 运行你的 start.sh 脚本
	shellCommand := "chmod +x start.sh && ./start.sh &"
	cmd := exec.Command("bash", "-c", shellCommand)

	// 保留系统环境变量
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		fmt.Println("启动 shell 出错:", err)
		return
	}

	fmt.Println("shell 脚本已启动，PID:", cmd.Process.Pid)

	go func() {
		err := cmd.Wait()
		if err != nil {
			fmt.Println("shell 执行出错:", err)
		} else {
			fmt.Println("shell 执行完成")
		}
	}()

	// 防止主程序退出
	select {}
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