package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Threat Result parsed from Python IPC
type ThreatResult struct {
	IsTruePositive  bool    `json:"is_true_positive"`
	ConfidenceScore float64 `json:"confidence_score"`
	AttackType      string  `json:"attack_type"`
	Explanation     string  `json:"explanation"`
}

// Msg sent to Bubble Tea when a breach is detected
type breachMsg ThreatResult

type model struct {
	threats   []ThreatResult
	scanning  bool
	logPath   string
	subProcess *exec.Cmd
}

func initialModel(logPath string) model {
	return model{
		threats:  []ThreatResult{},
		scanning: true,
		logPath:  logPath,
	}
}

// Start Python bridge subprocess and read output stream
func (m model) Init() tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("python3", "service.py")
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()

		logFile, err := os.Open(m.logPath)
		if err != nil {
			return nil
		}
		defer logFile.Close()

		fileScanner := bufio.NewScanner(logFile)
		outScanner := bufio.NewScanner(stdout)

		for fileScanner.Scan() {
			line := fileScanner.Text()
			io.WriteString(stdin, line+"\n")

			if outScanner.Scan() {
				var res ThreatResult
				if err := json.Unmarshal(outScanner.Bytes(), &res); err == nil {
					if res.IsTruePositive && res.ConfidenceScore >= 0.70 {
						return breachMsg(res)
					}
				}
			}
		}
		return nil
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case breachMsg:
		m.threats = append(m.threats, ThreatResult(msg))
	}
	return m, nil
}

func (m model) View() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1)
	alertStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F5F"))

	s := titleStyle.Render(" AI SECURITY BREACH DETECTOR ") + "\n\n"
	s += fmt.Sprintf("Log Source: %s\n\n", m.logPath)

	if len(m.threats) == 0 {
		s += "Status: Monitoring stream... No true positive threats detected yet.\n"
	} else {
		s += alertStyle.Render(fmt.Sprintf("CRITICAL THREATS DETECTED: %d", len(m.threats))) + "\n\n"
		for i, t := range m.threats {
			s += fmt.Sprintf("[%d] Type: %s | Conf: %.2f\n    Detail: %s\n\n", i+1, t.AttackType, t.ConfidenceScore, t.Explanation)
		}
	}

	s += "\nPress 'q' to quit."
	return s
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <path_to_log_file>")
		os.Exit(1)
	}
	p := tea.NewProgram(initialModel(os.Args[1]))
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}
