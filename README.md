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
git clone https://github.com/Mr615-TN/Charmer.git
cd Charmer

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

## Testing

Charmer includes automated test suites for both Go and Python components, direct pipeline checks, and live end-to-end simulation.

### 1. Automated Unit & Integration Tests

Run the Go daemon test suite (covers HTTP endpoints, security headers, and threat history):

```bash
# Go unit tests & race detector
go test -v ./...
go test -race ./...
```

Run the Python test suite (covers data models, IPC, heuristic rules, and end-to-end integration):

```bash
python3 -m unittest discover -s tests -v
```

### 2. Direct AI Engine Test (Stdio Stream)

Evaluate suspicious or benign log lines directly against the Python triage pipeline without running the daemon:

```bash
# Test SQL injection detection (returns structured JSON threat assessment)
echo "POST /auth - 500 - admin UNION SELECT * FROM users" | python3 engine/service.py

# Test benign log filtering
echo "Oct 18 12:00:01 server CRON[123]: (root) CMD (/backup.sh)" | python3 engine/service.py
```

### 3. End-to-End Live Simulation

Simulate full event streaming between the daemon, Python engine, and TUI using a local test log:

1. **Start the daemon on a test log and isolated socket:**
   ```bash
   touch /tmp/test_auth.log
   CHARMER_SOCKET_PATH=/tmp/charmer_test.sock CHARMER_HTTP_ADDR=:8080 ./bin/charmerd /tmp/test_auth.log
   ```

2. **In a second terminal, attach the TUI:**
   ```bash
   CHARMER_SOCKET_PATH=/tmp/charmer_test.sock ./bin/charmer
   ```

3. **In a third terminal, inject a test breach event:**
   ```bash
   echo "Oct 18 14:00:00 server: user admin' OR 1=1 -- logged in" >> /tmp/test_auth.log
   ```

4. **Verify HTTP API metrics and threat history:**
   ```bash
   curl -s http://localhost:8080/
   curl -s http://localhost:8080/api/threats
   ```

### 4. Security & Static Analysis

```bash
# Go static analysis
go vet ./...

# Python security analysis (Bandit)
bandit -r engine pkg -ll

# Container build verification
docker build -t charmerd:test -f Dockerfile.charmerd .
```

## License
Dual-licensed under the [GNU AGPLv3](./LICENSE) for open-source usage and a Commercial License for proprietary enterprise deployment.

