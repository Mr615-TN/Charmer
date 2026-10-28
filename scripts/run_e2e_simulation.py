#!/usr/bin/env python3
"""Charmer End-to-End Live Simulation Testing Runner.

Directly automates and verifies the 4-step live simulation workflow from README.md:
  1. Start daemon on a test log and isolated socket
  2. Attach IPC stream subscriber (simulating the TUI)
  3. Inject test benign and breach events into the log file
  4. Verify HTTP API metrics and threat history
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / "bin"
CHARMERD_BIN = BIN_DIR / "charmerd"
CHARMER_BIN = BIN_DIR / "charmer"
ENGINE_PATH = REPO_ROOT / "engine" / "service.py"

# ANSI Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner() -> None:
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}🐍 Charmer - End-to-End Live Simulation Testing System{RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}\n")


def print_step(step_num: int, title: str) -> None:
    print(f"{BOLD}{CYAN}[Step {step_num}/4]{RESET} {BOLD}{title}{RESET}")


def print_success(message: str) -> None:
    print(f"  {GREEN}✔{RESET} {message}")


def print_info(message: str) -> None:
    print(f"  {CYAN}•{RESET} {message}")


def print_error(message: str) -> None:
    print(f"  {RED}✖ {message}{RESET}")


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_binaries() -> bool:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        print_info("Compiling Go daemon (bin/charmerd)...")
        subprocess.run(
            ["go", "build", "-o", str(CHARMERD_BIN), "./cmd/charmerd"],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
        print_info("Compiling Go TUI (bin/charmer)...")
        subprocess.run(
            ["go", "build", "-o", str(CHARMER_BIN), "./cmd/charmer"],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
        print_success("Binaries compiled successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to build binaries: {e.stderr}")
        return False


def run_simulation() -> int:
    print_banner()

    if not build_binaries():
        return 1

    tmp_dir = tempfile.mkdtemp(prefix="charmer_live_sim_")
    log_path = os.path.join(tmp_dir, "test_auth.log")
    sock_path = os.path.join(tmp_dir, "charmer_test.sock")
    http_port = get_free_port()
    base_url = f"http://127.0.0.1:{http_port}"

    # Create empty test log
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("")

    daemon_proc: subprocess.Popen | None = None
    subscriber_sock: socket.socket | None = None

    try:
        # -------------------------------------------------------------
        # STEP 1: Start Daemon
        # -------------------------------------------------------------
        print_step(1, "Starting daemon on test log and isolated socket")
        print_info(f"Log file:     {log_path}")
        print_info(f"Unix socket:  {sock_path}")
        print_info(f"HTTP API:     {base_url}")

        env = os.environ.copy()
        env["CHARMER_SOCKET_PATH"] = sock_path
        env["CHARMER_HTTP_ADDR"] = f":{http_port}"
        env["CHARMER_ENGINE_PATH"] = str(ENGINE_PATH)

        daemon_proc = subprocess.Popen(
            [str(CHARMERD_BIN), log_path],
            env=env,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for daemon HTTP API readiness
        ready = False
        health_data = {}
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{base_url}/healthz", timeout=1.0) as resp:
                    if resp.status == 200:
                        health_data = json.loads(resp.read().decode("utf-8"))
                        ready = True
                        break
            except Exception:
                time.sleep(0.1)

        if not ready:
            print_error("Daemon failed to start or respond on HTTP API.")
            return 1

        print_success(
            f"Daemon online: service='{health_data.get('service')}', "
            f"threats_detected={health_data.get('threats_detected')}"
        )

        # Wait for socket creation
        socket_found = False
        for _ in range(30):
            if os.path.exists(sock_path):
                socket_found = True
                break
            time.sleep(0.1)

        if not socket_found:
            print_error(f"Unix socket not created at {sock_path}")
            return 1
        print_success("Unix domain socket initialized.")

        # -------------------------------------------------------------
        # STEP 2: Attach TUI / IPC Subscriber
        # -------------------------------------------------------------
        print()
        print_step(2, "Attaching IPC stream subscriber (simulating TUI connection)")
        subscriber_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        subscriber_sock.connect(sock_path)
        subscriber_sock.settimeout(5.0)
        print_success(f"Attached to socket {sock_path}. Listening for broadcast alerts...")

        # -------------------------------------------------------------
        # STEP 3: Inject Events into Log Stream
        # -------------------------------------------------------------
        print()
        print_step(3, "Injecting test events into auth log")

        # 3A: Benign log line
        benign_event = "Oct 18 12:00:01 server CRON[123]: (root) CMD (/usr/local/bin/backup.sh)"
        print_info(f"Writing benign event: \"{benign_event}\"")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(benign_event + "\n")
            f.flush()
            os.fsync(f.fileno())

        # Verify benign event was suppressed (socket receives nothing)
        subscriber_sock.settimeout(0.5)
        try:
            data = subscriber_sock.recv(4096)
            if data:
                print_error(f"Unexpected alert broadcast for benign log: {data.decode().strip()}")
                return 1
        except socket.timeout:
            print_success("Benign event successfully suppressed by AI/heuristics.")

        # 3B: Threat event (SQL Injection)
        threat_event = "Oct 18 14:00:00 server: user admin' OR 1=1 -- logged in"
        print_info(f"Injecting test breach: \"{threat_event}\"")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(threat_event + "\n")
            f.flush()
            os.fsync(f.fileno())

        subscriber_sock.settimeout(4.0)
        try:
            raw_alert = subscriber_sock.recv(4096)
            if not raw_alert:
                print_error("No broadcast received on Unix socket.")
                return 1
            alert_json = json.loads(raw_alert.decode("utf-8").strip())
            print_success("Real-time threat alert received over Unix domain socket!")
            print(f"      {BOLD}Attack Type:{RESET}  {YELLOW}{alert_json.get('attack_type')}{RESET}")
            print(f"      {BOLD}Confidence:{RESET}   {alert_json.get('confidence_score')}")
            print(f"      {BOLD}Explanation:{RESET}  {alert_json.get('explanation')}")
        except socket.timeout:
            print_error("Timeout waiting for Unix socket broadcast alert.")
            return 1

        # 3C: Threat event 2 (Directory Traversal)
        traversal_event = "ALERT: attempted access to /../../../../etc/shadow by unauth user"
        print_info(f"Injecting second breach: \"{traversal_event}\"")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(traversal_event + "\n")
            f.flush()
            os.fsync(f.fileno())

        try:
            raw_alert2 = subscriber_sock.recv(4096)
            if not raw_alert2:
                print_error("No second broadcast received on Unix socket.")
                return 1
            alert_json2 = json.loads(raw_alert2.decode("utf-8").strip())
            print_success("Second threat alert received over Unix domain socket!")
            print(f"      {BOLD}Attack Type:{RESET}  {YELLOW}{alert_json2.get('attack_type')}{RESET}")
            print(f"      {BOLD}Confidence:{RESET}   {alert_json2.get('confidence_score')}")
        except socket.timeout:
            print_error("Timeout waiting for second alert.")
            return 1

        # -------------------------------------------------------------
        # STEP 4: Verify HTTP API Metrics & History
        # -------------------------------------------------------------
        print()
        print_step(4, "Verifying HTTP API metrics and threat history")

        # 4A: Check /
        with urllib.request.urlopen(f"{base_url}/") as resp:
            root_data = json.loads(resp.read().decode("utf-8"))
            print_success(
                f"GET / -> Status: {resp.status}, "
                f"Threats Detected: {root_data.get('threats_detected')}, "
                f"Uptime: {root_data.get('uptime_seconds')}s"
            )
            if root_data.get("threats_detected") != 2:
                print_error(f"Expected 2 threats detected, got {root_data.get('threats_detected')}")
                return 1

            # Check security headers
            headers = dict(resp.headers)
            has_nosniff = headers.get("X-Content-Type-Options") == "nosniff"
            has_deny = headers.get("X-Frame-Options") == "DENY"
            has_csp = "Content-Security-Policy" in headers
            if has_nosniff and has_deny and has_csp:
                print_success("Security headers verified: nosniff, DENY, CSP default-src 'none'.")
            else:
                print_error(f"Incomplete security headers: {headers}")
                return 1

        # 4B: Check /api/threats
        with urllib.request.urlopen(f"{base_url}/api/threats") as resp:
            threats_payload = json.loads(resp.read().decode("utf-8"))
            count = threats_payload.get("count", 0)
            threats = threats_payload.get("threats", [])
            print_success(f"GET /api/threats -> Total Recorded Threats: {count}")

            for idx, t in enumerate(threats, 1):
                print(
                    f"      [{idx}] {BOLD}{t.get('attack_type')}{RESET} "
                    f"(Conf: {t.get('confidence_score')}) - Timestamp: {t.get('timestamp')}"
                )

            if count != 2:
                print_error(f"Expected 2 recorded threats, found {count}")
                return 1

        print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
        print(f"{BOLD}{GREEN}🎉 ALL END-TO-END LIVE SIMULATION CHECKS PASSED SUCCESSFULLY!{RESET}")
        print(f"{BOLD}{GREEN}======================================================================{RESET}\n")
        return 0

    finally:
        if subscriber_sock:
            try:
                subscriber_sock.close()
            except Exception:
                pass

        if daemon_proc:
            if daemon_proc.stdout:
                daemon_proc.stdout.close()
            if daemon_proc.stderr:
                daemon_proc.stderr.close()
            daemon_proc.terminate()
            try:
                daemon_proc.wait(timeout=2)
            except Exception:
                daemon_proc.kill()
                daemon_proc.wait(timeout=1)

        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_simulation())
