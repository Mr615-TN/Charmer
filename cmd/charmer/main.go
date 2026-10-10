package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Threat struct {
	AttackType      string  `json:"attack_type"`
	ConfidenceScore float64 `json:"confidence_score"`
	Explanation     string  `json:"explanation"`
}

type threatMsg Threat

type model struct {
	threats []Threat
	conn    net.Conn
	scanner *bufio.Scanner
}

func (m model) waitForThreat() tea.Cmd {
	return func() tea.Msg {
		if m.scanner.Scan() {
			var t Threat
			if err := json.Unmarshal(m.scanner.Bytes(), &t); err == nil {
				return threatMsg(t)
			}
		}
		return nil
	}
}

func (m model) Init() tea.Cmd {
	return m.waitForThreat()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.conn.Close()
			return m, tea.Quit
		}
	case threatMsg:
		m.threats = append(m.threats, Threat(msg))
		return m, m.waitForThreat()
	}
	return m, nil
}

func (m model) View() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		Render(" CHARMER TUI ")

	s := fmt.Sprintf("%s\n\n[Connected to /tmp/charmer.sock]\n\n", title)

	if len(m.threats) == 0 {
		s += "Listening for real-time security events...\n"
	} else {
		for i, t := range m.threats {
			s += fmt.Sprintf("[%d] %s (Conf: %.2f)\n    %s\n\n", i+1, t.AttackType, t.ConfidenceScore, t.Explanation)
		}
	}
	return s + "\nPress 'q' to detach TUI."
}

func main() {
	sockPath := os.Getenv("CHARMER_SOCKET_PATH")
	if sockPath == "" {
		sockPath = "/tmp/charmer.sock"
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Printf("Charmer daemon isn't running on %s. Please start charmerd first.\n", sockPath)
		os.Exit(1)
	}
	p := tea.NewProgram(model{
		conn:    conn,
		scanner: bufio.NewScanner(conn),
	})
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}
