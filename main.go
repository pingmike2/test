package main

import (
	"context"
	_ "embed"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// =====================
// 全局状态
// =====================

type AppState struct {
	mu        sync.RWMutex
	Started   bool
	LastError error
}

func (s *AppState) SetStarted(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Started = v
}

func (s *AppState) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastError = err
}

func (s *AppState) Snapshot() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Started, s.LastError
}

var state = &AppState{}

// =====================
// 嵌入 start.sh
// =====================

//go:embed start.sh
var startShContent []byte

// =====================
// 进程封装
// =====================

type ManagedProcess struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	running bool
	oneshot bool
	mu      sync.Mutex
}

func NewManagedProcess(ctx context.Context, binary string, args ...string) *ManagedProcess {
	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return &ManagedProcess{
		cmd:     cmd,
		cancel:  cancel,
		oneshot: true, // start.sh 只跑一次
	}
}

func (p *ManagedProcess) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return errors.New("process already running")
	}

	if err := p.cmd.Start(); err != nil {
		return err
	}

	p.running = true

	go func() {
		err := p.cmd.Wait()

		p.mu.Lock()
		defer p.mu.Unlock()
		p.running = false

		if p.oneshot {
			log.Println("start.sh finished (oneshot)")
			return
		}

		if err != nil {
			log.Println("process exited with error:", err)
			state.SetError(err)
		}
	}()

	return nil
}

func (p *ManagedProcess) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		p.cancel()
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		p.running = false
	}
}

func (p *ManagedProcess) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// =====================
// Bootstrap
// =====================

func getenvWithDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func getenvBool(key string, def bool) bool {
	val := getenvWithDefault(key, "")
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return def
	}
	return b
}

func bootstrap(ctx context.Context) (*ManagedProcess, error) {
	log.Println("bootstrap: preparing environment")

	tmpDir := getenvWithDefault("FILE_PATH", "./world")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, err
	}

	shPath := filepath.Join(tmpDir, "start.sh")
	if err := os.WriteFile(shPath, startShContent, 0755); err != nil {
		return nil, err
	}

	// =====================
	// 设置环境变量（全部保留，即使为空）
	// =====================

	vars := map[string]string{
		"UUID":            getenvWithDefault("UUID", "fe7431cb-ab1b-4205-a14c-d056f821b383"),
		"FILE_PATH":       tmpDir,
		"NEZHA_SERVER":    getenvWithDefault("NEZHA_SERVER", ""),
		"NEZHA_PORT":      getenvWithDefault("NEZHA_PORT", ""),
		"NEZHA_KEY":       getenvWithDefault("NEZHA_KEY", ""),
		"ARGO_PORT":       getenvWithDefault("ARGO_PORT", ""),
		"ARGO_DOMAIN":     getenvWithDefault("ARGO_DOMAIN", ""),
		"ARGO_AUTH":       getenvWithDefault("ARGO_AUTH", ""),
		"S5_PORT":         getenvWithDefault("S5_PORT", ""),
		"HY2_PORT":        getenvWithDefault("HY2_PORT", ""),
		"TUIC_PORT":       getenvWithDefault("TUIC_PORT", ""),
		"ANYTLS_PORT":     getenvWithDefault("ANYTLS_PORT", ""),
		"REALITY_PORT":    getenvWithDefault("REALITY_PORT", ""),
		"ANYREALITY_PORT": getenvWithDefault("ANYREALITY_PORT", ""),
		"CFIP":            getenvWithDefault("CFIP", "spring.io"),
		"CFPORT":          getenvWithDefault("CFPORT", "443"),
		"UPLOAD_URL":      getenvWithDefault("UPLOAD_URL", ""),
		"CHAT_ID":         getenvWithDefault("CHAT_ID", ""),
		"BOT_TOKEN":       getenvWithDefault("BOT_TOKEN", ""),
		"NAME":            getenvWithDefault("NAME", ""),
		"DISABLE_ARGO":    getenvWithDefault("DISABLE_ARGO", "false"),
	}

	for k, v := range vars {
		os.Setenv(k, v)
	}

	log.Println("Environment variables:")
	for k := range vars {
		log.Printf("%s=%s\n", k, os.Getenv(k))
	}

	process := NewManagedProcess(ctx, "bash", shPath)
	if err := process.Start(); err != nil {
		return nil, err
	}

	state.SetStarted(true)
	return process, nil
}

// =====================
// Supervisor（只跑一次）
// =====================

func supervisor(ctx context.Context) {
	process, err := bootstrap(ctx)
	if err != nil {
		log.Println("bootstrap failed:", err)
		state.SetError(err)
		return
	}

	for {
		time.Sleep(1 * time.Second)
		if !process.IsRunning() {
			log.Println("bootstrap completed, supervisor exiting")
			return
		}
		select {
		case <-ctx.Done():
			process.Stop()
			return
		default:
		}
	}
}

// =====================
// HTTP Server
// =====================

func startHTTPServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		started, err := state.Snapshot()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !started {
			http.Error(w, "not started", 503)
			return
		}
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    ":3000",
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("http server error:", err)
		}
	}()

	return server
}

// =====================
// Main
// =====================

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go supervisor(ctx)
	_ = startHTTPServer()

	log.Println("sbsh started, entering keep-alive mode")

	select {}
}