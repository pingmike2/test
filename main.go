package main

import (
	_ "embed"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"context"
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
	mu      sync.Mutex
}

func NewManagedProcess(ctx context.Context, binary string, args ...string) *ManagedProcess {
	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return &ManagedProcess{cmd: cmd, cancel: cancel}
}

func (p *ManagedProcess) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return nil
	}
	if err := p.cmd.Start(); err != nil {
		return err
	}
	p.running = true

	go func() {
		err := p.cmd.Wait()
		if err != nil {
			log.Println("process exited:", err)
			state.SetError(err)
		}
		p.mu.Lock()
		p.running = false
		p.mu.Unlock()
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
// Supervisor
// =====================

func supervisor(ctx context.Context) {
	backoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		process, err := bootstrap(ctx)
		if err != nil {
			log.Println("bootstrap failed:", err)
			state.SetError(err)
			time.Sleep(backoff)
			continue
		}

		for {
			time.Sleep(3 * time.Second)

			if !process.IsRunning() {
				state.SetStarted(false)
				process.Stop()
				break
			}

			select {
			case <-ctx.Done():
				process.Stop()
				return
			default:
			}
		}

		time.Sleep(backoff)
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

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("HTTP server error:", err)
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
	server := startHTTPServer()

	<-ctx.Done()
	_ = server.Shutdown(context.Background())
}