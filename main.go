package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// =====================
// 📌 把 start.sh 文件嵌入 Go 二进制
//go:embed start.sh
var startSh string

const httpPort = 3000

func main() {
	go startHTTPServer()

	fmt.Println("写入 start.sh 到临时文件...")
	tmpFile := "./.temp_start.sh"
	err := os.WriteFile(tmpFile, []byte(startSh), 0755)
	if err != nil {
		fmt.Println("写入 start.sh 出错:", err)
		return
	}

	// 执行 shell 脚本
	cmd := exec.Command("bash", tmpFile)
	cmd.Env = os.Environ() // 保留环境变量
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		fmt.Println("启动 start.sh 出错:", err)
		return
	}

	fmt.Println("start.sh 已启动，PID:", cmd.Process.Pid)

	go func() {
		err := cmd.Wait()
		if err != nil {
			fmt.Println("start.sh 执行出错:", err)
		} else {
			fmt.Println("start.sh 执行完成")
		}
	}()

	// 阻止主程序退出
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