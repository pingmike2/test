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
	oneshot bool // 👈 关键：一次性任务
	mu      sync.Mutex
}

func NewManagedProcess(ctx context.Context, binary string, args ...string) *ManagedProcess {
	cctx, cancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(cctx, binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return &ManagedProcess{
		cmd:     cmd,
		cancel:  cancel,
		oneshot: true, // start.sh 本质是一次性
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

		// ✅ oneshot：正常退出 ≠ 错误
		if p.oneshot {
			log.Println("start.sh finished normally (oneshot)")
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

func bootstrap(ctx context.Context) (*ManagedProcess, error) {
	log.Println("bootstrap: preparing environment")

	tmpDir := "./temp"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, err
	}

	shPath := filepath.Join(tmpDir, "start.sh")
	if err := os.WriteFile(shPath, startShContent, 0755); err != nil {
		return nil, err
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

	// 等待 start.sh 执行完成
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
// Main（关键：不退出）
// =====================

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go supervisor(ctx)
	_ = startHTTPServer()

	log.Println("sbsh started, entering keep-alive mode")

	// 👇 核心：MC / 面板只认这个进程在不在
	select {}
}