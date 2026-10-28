#!/usr/bin/env bash
set -euo pipefail

# End-to-End Live Simulation Testing Runner for Charmer
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "Building binaries..."
go build -o bin/charmerd ./cmd/charmerd
go build -o bin/charmer ./cmd/charmer

echo "Starting automated End-to-End Live Simulation..."
python3 "${SCRIPT_DIR}/run_e2e_simulation.py"
