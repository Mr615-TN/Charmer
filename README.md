# 🐍 Charmer 🪄

**Charmer** is an ultra-fast, low-false-positive AI breach detection engine. It combines Go's low-latency stream processing with local Small Language Models (SLMs) via Python to evaluate suspicious log events in real-time.

```
[ Log Stream ] ──► [ charmerd (Go) ] ──► [ Heuristics + Python SLM ]
                          │
                   (Unix Socket)
                          │
                 ┌────────┴────────┐
                 ▼                 ▼
          [ Desktop Alert ]   [ charmer TUI ]
```

## Features

- **Hybrid Triage**: High-speed entropy and pattern filtering (Go/Python) paired with contextual evaluation (Ollama/Qwen2.5) to eliminate false positives.
- **Daemon Architecture**: `charmerd` runs headlessly in the background, consuming minimal system resources.
- **Attach/Detach TUI**: Connect the Bubble Tea terminal UI (`charmer`) at any time without interrupting active monitoring.
- **Native OS Notifications**: Triggers system alerts for high-confidence threats even when the UI is detached.
- **Commercial Licensing**: Free and open-source under GNU AGPLv3 for individual/community use; commercial licenses available for enterprise integrations.

## Prerequisites

- Go `1.22+`
- Python `3.10+`
- [Ollama](https://ollama.ai) installed and running

```bash
ollama pull qwen2.5:3b
pip install -r requirements.txt
```

## Installation

```bash
git clone https://github.com/tanishneema/charmer.git
cd charmer

# Build binaries
go build -o bin/charmerd ./cmd/charmerd
go build -o bin/charmer ./cmd/charmer
```

## Usage

### 1. Start the Background Daemon
Run the daemon process (or configure it as a systemd service):

```bash
sudo ./bin/charmerd
```

### 2. Attach the TUI
In any terminal window, attach the interactive Bubble Tea interface:

```bash
./bin/charmer
```

*Press `q` to detach from the daemon at any time.*

## Architecture

| Component | Tech Stack | Role |
|---|---|---|
| **Daemon (`charmerd`)** | Go + `fsnotify` | Background file watching, OS notifications, Unix socket server |
| **AI Engine** | Python + `ollama` + `pydantic` | Contextual triage and JSON structured evaluations |
| **Front End (`charmer`)** | Go + `Bubble Tea` + `Lipgloss` | Terminal interface attached via IPC |

## License
Dual-licensed under the [GNU AGPLv3](./LICENSE) for open-source usage and a Commercial License for proprietary enterprise deployment.
