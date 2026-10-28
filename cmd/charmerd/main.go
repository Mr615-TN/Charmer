package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gen2brain/beeep"
)

const DefaultSocketPath = "/tmp/charmer.sock"
const DefaultHTTPAddr = ":8080"

type Threat struct {
	IsTruePositive  bool    `json:"is_true_positive"`
	ConfidenceScore float64 `json:"confidence_score"`
	AttackType      string  `json:"attack_type"`
	Explanation     string  `json:"explanation"`
	Timestamp       string  `json:"timestamp,omitempty"`
}

type Server struct {
	clients       map[net.Conn]bool
	threatHistory []Threat
	mu            sync.Mutex
	logPath       string
	startTime     time.Time
}

func newServer(logPath string) *Server {
	return &Server{
		clients:       make(map[net.Conn]bool),
		threatHistory: make([]Threat, 0),
		logPath:       logPath,
		startTime:     time.Now(),
	}
}

func (s *Server) recordThreat(t Threat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.Timestamp == "" {
		t.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	s.threatHistory = append(s.threatHistory, t)
	if len(s.threatHistory) > 500 {
		s.threatHistory = s.threatHistory[1:]
	}
}

func (s *Server) getThreats() []Threat {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make([]Threat, len(s.threatHistory))
	copy(copied, s.threatHistory)
	return copied
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func setupHTTPRoutes(srv *Server) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		threats := srv.getThreats()
		resp := map[string]interface{}{
			"status":           "ok",
			"service":          "charmerd",
			"version":          "1.0.0",
			"uptime_seconds":   int(time.Since(srv.startTime).Seconds()),
			"monitoring":       srv.logPath,
			"threats_detected": len(threats),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/threats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
			return
		}
		threats := srv.getThreats()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(threats),
			"threats": threats,
		})
	})

	return securityHeadersMiddleware(mux)
}

func startHTTPServer(addr string, srv *Server) *http.Server {
	server := &http.Server{
		Addr:              addr,
		Handler:           setupHTTPRoutes(srv),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	go func() {
		fmt.Printf("Charmer Daemon HTTP API listening on %s\n", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	return server
}

func main() {
	socketPath := os.Getenv("CHARMER_SOCKET_PATH")
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	httpAddr := os.Getenv("CHARMER_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = DefaultHTTPAddr
	}

	logPath := "/var/log/auth.log"
	if len(os.Args) > 1 {
		logPath = os.Args[1]
	}

	srv := newServer(logPath)

	// Start HTTP API Service (container readiness & DAST target)
	_ = startHTTPServer(httpAddr, srv)

	// Start Unix Socket Listener for local TUI
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Printf("Warning: Failed to bind Unix socket at %s: %v (continuing with HTTP API)\n", socketPath, err)
	} else {
		defer listener.Close()
		defer os.Remove(socketPath)
		fmt.Printf("Charmer Daemon listening on socket %s\n", socketPath)

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				srv.mu.Lock()
				srv.clients[conn] = true
				srv.mu.Unlock()
			}
		}()
	}

	fmt.Printf("Monitoring log file: %s\n", logPath)

	// Start Python AI Engine
	enginePath := os.Getenv("CHARMER_ENGINE_PATH")
	if enginePath == "" {
		enginePath = "engine/service.py"
	}

	cmd := exec.Command("python3", enginePath)
	pyIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Printf("Error creating stdin pipe: %v\n", err)
	}
	pyOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("Error creating stdout pipe: %v\n", err)
	}

	if pyIn != nil && pyOut != nil {
		if err := cmd.Start(); err != nil {
			fmt.Printf("Warning: Failed starting Python AI service (%s): %v\n", enginePath, err)
		}
	}

	lines := make(chan string)
	go watchLog(logPath, lines)

	if pyIn != nil && pyOut != nil {
		outScanner := bufio.NewScanner(pyOut)
		for line := range lines {
			trimmed := strings.TrimRight(line, "\r\n")
			if strings.TrimSpace(trimmed) == "" {
				continue
			}
			_, _ = io.WriteString(pyIn, trimmed+"\n")
			if outScanner.Scan() {
				var t Threat
				if err := json.Unmarshal(outScanner.Bytes(), &t); err == nil && t.IsTruePositive {
					_ = beeep.Alert("Charmer Security Alert", t.AttackType, "")
					srv.recordThreat(t)
					srv.broadcast(outScanner.Bytes())
				}
			}
		}
	} else {
		// If Python AI engine is unavailable, drain lines to keep daemon alive
		for range lines {
		}
	}
}

func (s *Server) broadcast(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.clients {
		_, err := conn.Write(append(data, '\n'))
		if err != nil {
			conn.Close()
			delete(s.clients, conn)
		}
	}
}

func watchLog(path string, out chan<- string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Printf("Warning: cannot open log file %s: %v\n", path, err)
		return
	}
	defer file.Close()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()

	_ = watcher.Add(path)
	_, _ = file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					out <- line
				}
			}
		case <-watcher.Errors:
			return
		}
	}
}
