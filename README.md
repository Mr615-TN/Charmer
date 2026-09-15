# Charmer
**Charmer** is a ultra-fast, low-false-positive AI breach detection engine. It combines Go's low-latency stream processing with local Small Language Models (SLMs) via Python to evaluate suspicious log events in real-time.

## Features

- **Hybrid Triage**: High-speed entropy and pattern filtering (Go/Python) paired with contextual evaluation (Ollama/Qwen2.5) to cut false positives.
- **Daemon Architecture**: `charmerd` runs headlessly in the background, consuming minimal system resources.
- **Attach/Detach TUI**: Connect the Bubble Tea terminal UI (`charmer`) at any time without interrupting active monitoring.
- **Native OS Notifications**: Triggers system alerts for high-confidence threats even when the UI is detached.

## Prerequisites

- Go `1.22+`
- Python `3.10+`
- [Ollama](https://ollama.ai) installed and running

```bash
ollama pull qwen2.5:3b
pip install ollama pydantic
