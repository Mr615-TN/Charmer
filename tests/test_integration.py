"""Integration tests verifying end-to-end compatibility of api, ipc, security, and engine."""

import json
import os
import tempfile
import time
import unittest

from engine.service import process_log
from pkg.api.apis import CharmerClient, CharmerServer, ThreatEvaluation
from pkg.ipc.ipc import StdioIPC, UnixSocketClient, UnixSocketServer
from pkg.security.security import (
    SECURITY_HEADERS,
    analyze_log_heuristics,
    calculate_entropy,
    is_suspicious_heuristic,
    sanitize_log_line,
    verify_security_headers,
)


class TestCharmerIntegration(unittest.TestCase):
    def test_engine_process_log_benign(self):
        line = "Oct 18 12:00:01 myhost CRON[456]: (root) CMD (/usr/local/bin/backup.sh)"
        result = process_log(line)
        self.assertFalse(result["is_true_positive"])
        self.assertEqual(result["confidence_score"], 0.0)
        self.assertEqual(result["attack_type"], "None")

    def test_engine_process_log_threat(self):
        line = "POST /api/v1/auth - 500 - 10.0.0.1 - UNION SELECT password FROM admin_users"
        result = process_log(line)
        self.assertTrue(result["is_true_positive"])
        self.assertGreater(result["confidence_score"], 0.5)
        self.assertEqual(result["attack_type"], "SQL Injection")
        self.assertIn("UNION SELECT", result["explanation"])

        # Ensure result validates against ThreatEvaluation model
        threat = ThreatEvaluation.model_validate(result)
        self.assertTrue(threat.is_true_positive)

    def test_end_to_end_ipc_stream_and_api(self):
        """Simulates full workflow: log -> engine -> IPC broadcast -> client receive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "charmer_int.sock")
            server = UnixSocketServer(socket_path=sock_path)
            server.start()

            client = UnixSocketClient(socket_path=sock_path)
            client.connect()
            time.sleep(0.1)

            # Process simulated breach event through engine
            raw_event = "ALERT: attempted access to /../../../../etc/shadow by unauth user"
            eval_result = process_log(raw_event)
            self.assertTrue(eval_result["is_true_positive"])

            # Broadcast over IPC socket
            sent = server.broadcast(eval_result)
            self.assertEqual(sent, 1)

            # Receive on attached client
            msg = client.receive_message(timeout=2.0)
            self.assertIsNotNone(msg)
            self.assertEqual(msg["attack_type"], "Directory Traversal")

            client.close()
            server.stop()

    def test_security_headers_consistency(self):
        """Verify python security headers exactly match Go daemon expectations."""
        # Go daemon headers in cmd/charmerd/main.go:
        # "X-Content-Type-Options": "nosniff"
        # "X-Frame-Options": "DENY"
        # "Content-Security-Policy": "default-src 'none'"
        go_expected = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'",
            "X-XSS-Protection": "1; mode=block",
        }
        valid, missing = verify_security_headers(go_expected)
        self.assertTrue(valid)
        self.assertEqual(SECURITY_HEADERS, go_expected)


if __name__ == "__main__":
    unittest.main()
