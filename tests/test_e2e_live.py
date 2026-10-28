"""End-to-End Live Simulation Test Suite.

Automates and verifies the 4-step live simulation workflow documented in README.md:
1. Start daemon on a test log and isolated socket.
2. Attach IPC subscriber (simulating the TUI).
3. Inject benign and breach events into the log file.
4. Verify real-time socket broadcast and HTTP API metrics/threat history.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from pkg.api.apis import CharmerClient, ThreatEvaluation
from pkg.ipc.ipc import UnixSocketClient
from pkg.security.security import verify_security_headers

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / "bin"
CHARMERD_BIN = BIN_DIR / "charmerd"
CHARMER_BIN = BIN_DIR / "charmer"
ENGINE_PATH = REPO_ROOT / "engine" / "service.py"


def _get_free_port() -> int:
    """Find an available local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ensure_binaries_built() -> None:
    """Build charmerd and charmer binaries if not already present."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    if not CHARMERD_BIN.exists():
        subprocess.run(
            ["go", "build", "-o", str(CHARMERD_BIN), "./cmd/charmerd"],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
        )

    if not CHARMER_BIN.exists():
        subprocess.run(
            ["go", "build", "-o", str(CHARMER_BIN), "./cmd/charmer"],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
        )


class TestEndToEndLiveSimulation(unittest.TestCase):
    """End-to-end integration test verifying the live daemon, engine, socket IPC, and HTTP API."""

    @classmethod
    def setUpClass(cls) -> None:
        _ensure_binaries_built()
        if not CHARMERD_BIN.exists() or not CHARMER_BIN.exists():
            raise RuntimeError("Failed to ensure Go binaries are built.")

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="charmer_e2e_")
        self.log_path = os.path.join(self.tmp_dir, "test_auth.log")
        self.socket_path = os.path.join(self.tmp_dir, "charmer_test.sock")
        self.http_port = _get_free_port()
        self.http_addr = f":{self.http_port}"
        self.base_url = f"http://127.0.0.1:{self.http_port}"

        # Initialize empty test log file
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("")

        self.daemon_proc: subprocess.Popen | None = None
        self.client_sock: UnixSocketClient | None = None

    def tearDown(self) -> None:
        if self.client_sock is not None:
            try:
                self.client_sock.close()
            except Exception:
                pass

        if self.daemon_proc is not None:
            if self.daemon_proc.stdout:
                try:
                    self.daemon_proc.stdout.close()
                except Exception:
                    pass
            if self.daemon_proc.stderr:
                try:
                    self.daemon_proc.stderr.close()
                except Exception:
                    pass
            try:
                self.daemon_proc.terminate()
                self.daemon_proc.wait(timeout=3)
            except Exception:
                try:
                    self.daemon_proc.kill()
                    self.daemon_proc.wait(timeout=2)
                except Exception:
                    pass

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _start_daemon(self) -> subprocess.Popen:
        """Start the background daemon process with isolated configuration."""
        env = os.environ.copy()
        env["CHARMER_SOCKET_PATH"] = self.socket_path
        env["CHARMER_HTTP_ADDR"] = self.http_addr
        env["CHARMER_ENGINE_PATH"] = str(ENGINE_PATH)

        proc = subprocess.Popen(
            [str(CHARMERD_BIN), self.log_path],
            env=env,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.daemon_proc = proc

        # Wait for HTTP readiness and Unix socket creation
        api_client = CharmerClient(base_url=self.base_url, timeout=2.0)
        ready = api_client.wait_until_ready(timeout=6.0, poll_interval=0.2)
        self.assertTrue(ready, "Daemon HTTP API failed to become ready.")

        # Wait for Unix socket file
        socket_ready = False
        for _ in range(30):
            if os.path.exists(self.socket_path):
                socket_ready = True
                break
            time.sleep(0.1)
        self.assertTrue(socket_ready, f"Daemon Unix socket was not created at {self.socket_path}")

        return proc

    def _append_log(self, line: str) -> None:
        """Append a log line and flush to disk so fsnotify triggers."""
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
            f.flush()
            os.fsync(f.fileno())

    def test_end_to_end_live_simulation_full_flow(self) -> None:
        """Execute and verify the full 4-step live simulation."""
        # -----------------------------------------------------------------
        # STEP 1: Start daemon on a test log and isolated socket
        # -----------------------------------------------------------------
        self._start_daemon()

        api_client = CharmerClient(base_url=self.base_url, timeout=3.0)
        health = api_client.get_health()
        self.assertEqual(health.status, "ok")
        self.assertEqual(health.service, "charmerd")
        self.assertEqual(health.monitoring, self.log_path)
        self.assertEqual(health.threats_detected, 0)

        # -----------------------------------------------------------------
        # STEP 2: In a second terminal, attach subscriber (TUI IPC simulation)
        # -----------------------------------------------------------------
        self.client_sock = UnixSocketClient(socket_path=self.socket_path, timeout=3.0)
        self.client_sock.connect()
        self.assertTrue(self.client_sock.is_connected)

        # -----------------------------------------------------------------
        # STEP 3A: Inject benign log event (ensure false-positive suppression)
        # -----------------------------------------------------------------
        benign_log = "Oct 18 12:00:01 server CRON[123]: (root) CMD (/usr/local/bin/backup.sh)"
        self._append_log(benign_log)

        # Benign event should be filtered by heuristics; socket receives no message
        benign_received = self.client_sock.receive_message(timeout=0.6)
        self.assertIsNone(benign_received, "Benign log line should not trigger a threat broadcast.")

        # API threat count should still be 0
        threats_resp = api_client.get_threats()
        self.assertEqual(threats_resp.count, 0)

        # -----------------------------------------------------------------
        # STEP 3B: Inject test breach event (README Step 3: SQL Injection)
        # -----------------------------------------------------------------
        breach_log = "Oct 18 14:00:00 server: user admin' OR 1=1 -- logged in"
        self._append_log(breach_log)

        # Socket client should receive real-time broadcast NDJSON threat alert
        alert = self.client_sock.receive_message(timeout=4.0)
        self.assertIsNotNone(alert, "Expected real-time threat alert over Unix socket.")
        self.assertTrue(alert.get("is_true_positive"))
        self.assertEqual(alert.get("attack_type"), "SQL Injection")
        self.assertGreater(alert.get("confidence_score", 0), 0.5)

        # Validate structured data model
        validated_threat = ThreatEvaluation.model_validate(alert)
        self.assertTrue(validated_threat.is_true_positive)
        self.assertEqual(validated_threat.attack_type, "SQL Injection")

        # -----------------------------------------------------------------
        # STEP 3C: Inject second distinct breach event (Directory Traversal)
        # -----------------------------------------------------------------
        traversal_log = "ALERT: attempted access to /../../../../etc/shadow by unauth user"
        self._append_log(traversal_log)

        alert2 = self.client_sock.receive_message(timeout=4.0)
        self.assertIsNotNone(alert2, "Expected second threat alert over Unix socket.")
        self.assertTrue(alert2.get("is_true_positive"))
        self.assertEqual(alert2.get("attack_type"), "Directory Traversal")

        # -----------------------------------------------------------------
        # STEP 4: Verify HTTP API metrics and threat history
        # -----------------------------------------------------------------
        # 1) Verify GET / health status & threat count
        health_updated = api_client.get_health()
        self.assertEqual(health_updated.status, "ok")
        self.assertEqual(health_updated.threats_detected, 2)

        # 2) Verify GET /api/threats records both threats
        threats_resp = api_client.get_threats()
        self.assertEqual(threats_resp.count, 2)
        self.assertEqual(len(threats_resp.threats), 2)
        self.assertEqual(threats_resp.threats[0].attack_type, "SQL Injection")
        self.assertEqual(threats_resp.threats[1].attack_type, "Directory Traversal")
        self.assertIsNotNone(threats_resp.threats[0].timestamp)

        # 3) Verify Security Headers on HTTP responses
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req) as resp:
            headers = dict(resp.headers)
            is_valid, missing = verify_security_headers(headers)
            self.assertTrue(
                is_valid,
                f"Missing security headers: {missing}. Found: {headers}",
            )

    def test_tui_binary_attaches_and_detaches_cleanly(self) -> None:
        """Verify the charmer TUI binary connects to the daemon and detaches cleanly."""
        if not hasattr(os, "openpty"):
            self.skipTest("PTY not supported on this platform")

        self._start_daemon()

        import pty

        master, slave = pty.openpty()
        env = os.environ.copy()
        env["CHARMER_SOCKET_PATH"] = self.socket_path

        tui_proc = subprocess.Popen(
            [str(CHARMER_BIN)],
            env=env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )

        try:
            # Allow TUI to initialize and connect to daemon socket
            time.sleep(0.5)

            # Send 'q' to request detachment
            os.write(master, b"q")
            ret_code = tui_proc.wait(timeout=3.0)
            self.assertEqual(ret_code, 0, f"TUI exited with non-zero status: {ret_code}")
        finally:
            os.close(master)
            os.close(slave)
            if tui_proc.poll() is None:
                tui_proc.kill()
                tui_proc.wait()

    def test_tui_binary_fails_gracefully_when_daemon_not_running(self) -> None:
        """Verify charmer exits with code 1 if daemon socket does not exist."""
        non_existent_sock = os.path.join(self.tmp_dir, "non_existent.sock")
        env = os.environ.copy()
        env["CHARMER_SOCKET_PATH"] = non_existent_sock

        res = subprocess.run(
            [str(CHARMER_BIN)],
            env=env,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Charmer daemon isn't running", res.stdout + res.stderr)

    def test_http_api_method_and_path_validation(self) -> None:
        """Verify HTTP API restricts invalid methods and unknown paths."""
        self._start_daemon()

        # POST to /api/threats should be 405 Method Not Allowed
        post_req = urllib.request.Request(
            f"{self.base_url}/api/threats",
            data=b"{}",
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(post_req)
        self.assertEqual(ctx.exception.code, 405)

        # GET to unknown path should return 404 Not Found
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.base_url}/unknown_route")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
