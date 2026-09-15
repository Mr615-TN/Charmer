package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/gen2brain/beeep"
)

const SocketPath = "/tmp/charmer.sock"

type Threat struct {
	IsTruePositive  bool    `json:"is_true_positive"`
	ConfidenceScore float64 `json:"confidence_score"`
	AttackType      string  `json:"attack_type"`
	Explanation     string  `json:"explanation"`
}

type Server struct {
	clients map[net.Conn]bool
	mu      sync.Mutex
}

func main() {
	_ = os.Remove(SocketPath)
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		fmt.Printf("Failed to bind socket: %v\n", err)
		return
	}
	defer listener.Close()
	defer os.Remove(SocketPath)

	srv := &Server{clients: make(map[net.Conn]bool)}

	// Accept TUI socket connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			srv.mu.Lock()
			srv.clients[conn] = true
			srv.mu.Unlock()
		}
	}()

	logPath := "/var/log/auth.log"
	if len(os.Args) > 1 {
		logPath = os.Args[1]
	}

	fmt.Printf("Charmer Daemon listening on socket %s\nMonitoring log file: %s\n", SocketPath, logPath)

	// Start Python AI Engine
	cmd := exec.Command("python3", "engine/service.py")
	pyIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Printf("Error creating stdin pipe: %v\n", err)
		return
	}
	pyOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("Error creating stdout pipe: %v\n", err)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("Error starting Python AI service: %v\n", err)
		return
	}

	lines := make(chan string)
	go watchLog(logPath, lines)

	outScanner := bufio.NewScanner(pyOut)
	for line := range lines {
		io.WriteString(pyIn, line+"\n")
		if outScanner.Scan() {
			var t Threat
			if err := json.Unmarshal(outScanner.Bytes(), &t); err == nil && t.IsTruePositive {
				_ = beeep.Alert("Charmer Security Alert", t.AttackType, "")
				srv.broadcast(outScanner.Bytes())
			}
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
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()

	watcher.Add(path)
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	file.Seek(0, io.SeekEnd)
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
