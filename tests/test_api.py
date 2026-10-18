"""Tests for pkg.api module."""

import socket
import unittest

from pkg.api.apis import (
    CharmerClient,
    CharmerServer,
    DaemonHealth,
    LogEvaluationRequest,
    ThreatEvaluation,
    ThreatListResponse,
    batch_evaluate,
    evaluate_log_line,
)


def _get_free_port() -> int:
    with socket.socket(socket.AF_SOCKET, socket.SOCK_STREAM) if hasattr(socket, "AF_SOCKET") else socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestAPIModule(unittest.TestCase):
    def test_data_models(self):
        threat = ThreatEvaluation(
            is_true_positive=True,
            confidence_score=0.91,
            attack_type="SQL Injection",
            explanation="UNION SELECT query",
        )
        self.assertTrue(threat.is_true_positive)
        self.assertEqual(threat.attack_type, "SQL Injection")

        threat_list = ThreatListResponse(count=1, threats=[threat])
        self.assertEqual(threat_list.count, 1)
        self.assertEqual(len(threat_list.threats), 1)

        health = DaemonHealth(
            status="ok",
            service="charmerd",
            version="1.0.0",
            uptime_seconds=42,
            monitoring="/var/log/auth.log",
            threats_detected=5,
        )
        self.assertEqual(health.status, "ok")
        self.assertEqual(health.threats_detected, 5)

        req = LogEvaluationRequest(log_line="test line")
        self.assertEqual(req.log_line, "test line")
        self.assertEqual(req.system_context, "Production Server")

    def test_evaluate_log_line(self):
        benign = evaluate_log_line("Oct 18 CRON[100]: session closed for root")
        self.assertFalse(benign.is_true_positive)
        self.assertEqual(benign.confidence_score, 0.0)

        malicious = evaluate_log_line(
            "SELECT * FROM accounts WHERE id=5 UNION SELECT null, pass FROM users"
        )
        self.assertTrue(malicious.is_true_positive)
        self.assertEqual(malicious.attack_type, "SQL Injection")

    def test_batch_evaluate(self):
        logs = [
            "Normal log 1",
            "cat /etc/passwd",
            "Normal log 2",
        ]
        results = batch_evaluate(logs)
        self.assertEqual(len(results), 3)
        self.assertFalse(results[0].is_true_positive)
        self.assertTrue(results[1].is_true_positive)
        self.assertEqual(results[1].attack_type, "Directory Traversal")
        self.assertFalse(results[2].is_true_positive)

    def test_charmer_server_and_client(self):
        port = _get_free_port()
        server = CharmerServer(host="127.0.0.1", port=port, log_path="/test/auth.log")
        server.start_background()

        try:
            client = CharmerClient(base_url=f"http://127.0.0.1:{port}", timeout=2.0)

            # Test wait_until_ready and is_healthy
            self.assertTrue(client.wait_until_ready(timeout=3.0))
            self.assertTrue(client.is_healthy())

            # Test get_health
            health = client.get_health()
            self.assertEqual(health.status, "ok")
            self.assertIn("charmerd", health.service)
            self.assertEqual(health.monitoring, "/test/auth.log")
            self.assertEqual(health.threats_detected, 0)

            # Test get_threats
            threats_resp = client.get_threats()
            self.assertEqual(threats_resp.count, 0)

            # Record threat on server
            server.record_threat(
                ThreatEvaluation(
                    is_true_positive=True,
                    confidence_score=0.95,
                    attack_type="Command Injection",
                    explanation="/bin/bash reverse shell",
                )
            )

            threats_resp_after = client.get_threats()
            self.assertEqual(threats_resp_after.count, 1)
            self.assertEqual(threats_resp_after.threats[0].attack_type, "Command Injection")

        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
