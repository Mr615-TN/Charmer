"""Tests for pkg.ipc module."""

import io
import os
import stat
import tempfile
import time
import unittest

from pkg.ipc.ipc import (
    StdioIPC,
    UnixSocketClient,
    UnixSocketServer,
    decode_ipc_message,
    encode_ipc_message,
)


class TestIPCModule(unittest.TestCase):
    def test_encode_decode_message(self):
        msg = {
            "is_true_positive": True,
            "confidence_score": 0.95,
            "attack_type": "SQL Injection",
            "explanation": "UNION SELECT detected",
        }
        encoded = encode_ipc_message(msg)
        self.assertTrue(encoded.endswith(b"\n"))

        decoded = decode_ipc_message(encoded)
        self.assertEqual(decoded["is_true_positive"], True)
        self.assertEqual(decoded["attack_type"], "SQL Injection")
        self.assertEqual(decoded["confidence_score"], 0.95)

    def test_stdio_ipc(self):
        input_stream = io.StringIO("log line 1\r\n\x1b[31mlog line 2\x1b[0m\n\nlog line 3\n")
        output_stream = io.StringIO()

        ipc = StdioIPC(stdin=input_stream, stdout=output_stream)
        lines = list(ipc.lines())

        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[0], "log line 1")
        self.assertEqual(lines[1], "log line 2")
        self.assertEqual(lines[2], "")
        self.assertEqual(lines[3], "log line 3")

        ipc.write_threat(
            is_true_positive=True,
            confidence_score=0.88,
            attack_type="Command Injection",
            explanation="bash -i detected",
        )
        written = output_stream.getvalue()
        self.assertIn("Command Injection", written)
        self.assertTrue(written.endswith("\n"))

    def test_unix_socket_client_server_communication(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "charmer_test.sock")

            server = UnixSocketServer(socket_path=socket_path)
            server.start()

            # Ensure socket file exists and has secure permissions
            self.assertTrue(os.path.exists(socket_path))
            mode = stat.S_IMODE(os.stat(socket_path).st_mode)
            self.assertEqual(mode, 0o600)

            # Connect client
            client = UnixSocketClient(socket_path=socket_path, timeout=2.0)
            client.connect()
            self.assertTrue(client.is_connected)

            # Give a brief moment for server accept thread
            time.sleep(0.1)
            self.assertEqual(server.client_count, 1)

            # Broadcast message
            threat_payload = {
                "is_true_positive": True,
                "confidence_score": 0.92,
                "attack_type": "Directory Traversal",
                "explanation": "/etc/passwd detected",
            }
            delivered = server.broadcast(threat_payload)
            self.assertEqual(delivered, 1)

            # Client receives message
            received = client.receive_message(timeout=1.0)
            self.assertIsNotNone(received)
            self.assertEqual(received["attack_type"], "Directory Traversal")
            self.assertEqual(received["confidence_score"], 0.92)

            # Cleanup
            client.close()
            self.assertFalse(client.is_connected)
            server.stop()
            self.assertFalse(os.path.exists(socket_path))


if __name__ == "__main__":
    unittest.main()
