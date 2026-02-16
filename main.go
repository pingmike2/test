package main

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// =====================
// 全局状态
// =====================

var started = false
var lastError error

func setStarted(v bool) {
	started = v
}

func setError(err error) {
	lastError = err
}

// =====================
// 嵌入 start.sh（关键点）
// =====================

//go:embed start.sh
var startShContent []byte

// =====================
// 执行 start.sh
// =====================

func runStartSh() {
	tmpDir := "./temp"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		setError(err)
		log.Println("mkdir failed:", err)
		return
	}

	shPath := filepath.Join(tmpDir, "start.sh")
	if err := os.WriteFile(shPath, startShContent, 0755); err != nil {
		setError(err)
		log.Println("write start.sh failed:", err)
		return
	}

	cmd := exec.Command("bash", shPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		setError(err)
		log.Println("start.sh failed:", err)
		return
	}

	setStarted(true)
	log.Println("start.sh executed successfully")
}

// =====================
// HTTP Server
// =====================

func startHTTPServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !started {
			http.Error(w, "not started", 503)
			return
		}
		if lastError != nil {
			http.Error(w, lastError.Error(), 500)
			return
		}
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/sub", func(w http.ResponseWriter, _ *http.Request) {
		data, err := os.ReadFile("./temp/sub.txt")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(data)
	})

	server := &http.Server{
		Addr:    ":3000",
		Handler: mux,
	}

	log.Println("HTTP server listening on :3000")
	if err := server.ListenAndServe(); err != nil {
		log.Println("HTTP server stopped:", err)
	}
}

// =====================
// Main
// =====================

func main() {
	log.Println("Bootstrap MC platform mode")

	runStartSh()
	startHTTPServer()
}