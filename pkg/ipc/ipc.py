"""Inter-Process Communication (IPC) module for Charmer.

Supports:
- Unix domain socket streaming (connecting to charmerd or serving as mock daemon)
- Subprocess standard stream (stdin/stdout) line-buffered IPC for the AI engine
- Secure socket permissions and NDJSON framing
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import socket
import sys
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from pkg.security.security import (
    sanitize_log_line,
    secure_socket_permissions,
    validate_socket_path,
)

DEFAULT_SOCKET_PATH = os.path.join(os.sep, "tmp", "charmer.sock")


def encode_ipc_message(payload: Any) -> bytes:
    """Encode an IPC payload as a newline-delimited JSON byte string."""
    if isinstance(payload, str):
        # Validate that it's valid JSON if string, or wrap as text
        try:
            parsed = json.loads(payload)
            serialized = json.dumps(parsed, separators=(",", ":"))
        except json.JSONDecodeError:
            serialized = json.dumps({"raw": payload}, separators=(",", ":"))
    elif hasattr(payload, "model_dump"):
        serialized = json.dumps(payload.model_dump(), separators=(",", ":"))
    elif hasattr(payload, "dict"):
        serialized = json.dumps(payload.dict(), separators=(",", ":"))
    elif hasattr(payload, "to_dict"):
        serialized = json.dumps(payload.to_dict(), separators=(",", ":"))
    else:
        serialized = json.dumps(payload, separators=(",", ":"))

    return (serialized + "\n").encode("utf-8")


def decode_ipc_message(data: bytes | str) -> Dict[str, Any]:
    """Decode a newline-delimited JSON message into a dictionary."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    text = text.strip()
    if not text:
        return {}
    return json.loads(text)


class UnixSocketClient:
    """Client for connecting to the Charmer daemon Unix domain socket.

    Streams real-time threat evaluations broadcasted by charmerd.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        timeout: Optional[float] = 5.0,
    ) -> None:
        raw_path = socket_path or os.getenv("CHARMER_SOCKET_PATH") or DEFAULT_SOCKET_PATH
        self.socket_path = validate_socket_path(raw_path)
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._buffer = ""

    def connect(self) -> None:
        """Connect to the Unix domain socket."""
        if self.sock is not None:
            return
        if not os.path.exists(self.socket_path):
            raise FileNotFoundError(
                f"Socket file {self.socket_path} does not exist. Is charmerd running?"
            )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            self.sock = sock
        except Exception:
            sock.close()
            raise

    def close(self) -> None:
        """Close the socket connection."""
        if self.sock is not None:
            with contextlib.suppress(OSError):
                self.sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self.sock.close()
            self.sock = None
        self._buffer = ""

    @property
    def is_connected(self) -> bool:
        """Check if socket is currently connected."""
        return self.sock is not None

    def __enter__(self) -> UnixSocketClient:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def send_message(self, message: Any) -> None:
        """Send a message to the Unix socket."""
        if not self.is_connected or self.sock is None:
            raise ConnectionError("Not connected to Unix socket")
        data = encode_ipc_message(message)
        self.sock.sendall(data)

    def receive_message(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Receive a single JSON line from the socket."""
        if not self.is_connected or self.sock is None:
            raise ConnectionError("Not connected to Unix socket")

        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)

        try:
            while "\n" not in self._buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self._buffer += chunk.decode("utf-8", errors="replace")

            line, self._buffer = self._buffer.split("\n", 1)
            line = line.strip()
            if not line:
                return self.receive_message(timeout=timeout)
            return decode_ipc_message(line)
        except socket.timeout:
            return None
        finally:
            if self.sock is not None:
                self.sock.settimeout(old_timeout)

    def stream_threats(
        self,
        poll_interval: float = 0.1,
        auto_reconnect: bool = False,
        reconnect_delay: float = 1.0,
    ) -> Iterator[Dict[str, Any]]:
        """Continuously yield incoming threat events from the socket."""
        while True:
            try:
                if not self.is_connected:
                    self.connect()
                msg = self.receive_message(timeout=poll_interval)
                if msg is not None:
                    yield msg
            except (ConnectionError, OSError, FileNotFoundError) as err:
                if not auto_reconnect:
                    raise
                self.close()
                time.sleep(reconnect_delay)


class UnixSocketServer:
    """Unix Domain Socket Server for Charmer IPC.

    Used by standalone Python runners, mock servers, or test harnesses.
    Supports secure socket mode (0600) and broadcasting to all clients.
    """

    def __init__(self, socket_path: Optional[str] = None) -> None:
        raw_path = socket_path or os.getenv("CHARMER_SOCKET_PATH") or DEFAULT_SOCKET_PATH
        self.socket_path = validate_socket_path(raw_path)
        self.server_sock: Optional[socket.socket] = None
        self.clients: List[socket.socket] = []
        self._lock = threading.Lock()
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Bind and start listening on the Unix socket."""
        if self.server_sock is not None:
            return

        # Clean up stale socket file if present
        if os.path.exists(self.socket_path):
            with contextlib.suppress(OSError):
                os.unlink(self.socket_path)

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(self.socket_path)
        secure_socket_permissions(self.socket_path, mode=0o600)
        server_sock.listen(16)
        server_sock.settimeout(0.5)

        self.server_sock = server_sock
        self._running = True

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="CharmerSocketServer-Accept"
        )
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        """Background loop accepting incoming client connections."""
        while self._running and self.server_sock:
            try:
                conn, _ = self.server_sock.accept()
                with self._lock:
                    self.clients.append(conn)
            except socket.timeout:
                continue
            except OSError:
                break

    def broadcast(self, message: Any) -> int:
        """Broadcast a message to all connected clients.

        Returns number of successfully reached clients.
        """
        data = encode_ipc_message(message)
        delivered = 0
        with self._lock:
            active_clients: List[socket.socket] = []
            for client in self.clients:
                try:
                    client.sendall(data)
                    active_clients.append(client)
                    delivered += 1
                except (BrokenPipeError, ConnectionResetError, OSError):
                    with contextlib.suppress(OSError):
                        client.close()
            self.clients = active_clients
        return delivered

    @property
    def client_count(self) -> int:
        """Number of currently connected clients."""
        with self._lock:
            return len(self.clients)

    def stop(self) -> None:
        """Stop server and close all client connections."""
        self._running = False
        with self._lock:
            for client in self.clients:
                with contextlib.suppress(OSError):
                    client.close()
            self.clients.clear()

        if self.server_sock is not None:
            with contextlib.suppress(OSError):
                self.server_sock.close()
            self.server_sock = None

        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=1.0)
            self._accept_thread = None

        if os.path.exists(self.socket_path):
            with contextlib.suppress(OSError):
                os.unlink(self.socket_path)

    def __enter__(self) -> UnixSocketServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


class StdioIPC:
    """Standard I/O stream IPC handler for engine/service.py.

    Provides hardened line-buffered reading from stdin and synchronized
    JSON flushing to stdout.
    """

    def __init__(
        self,
        stdin=None,
        stdout=None,
    ) -> None:
        self._stdin = stdin or sys.stdin
        self._stdout = stdout or sys.stdout

    def read_line(self) -> Optional[str]:
        """Read a single line from stdin. Returns None on EOF."""
        try:
            line = self._stdin.readline()
            if not line:
                return None
            return sanitize_log_line(line)
        except Exception:
            return None

    def lines(self) -> Iterator[str]:
        """Yield lines from stdin until EOF."""
        while True:
            line = self.read_line()
            if line is None:
                break
            yield line

    def write_message(self, message: Any) -> None:
        """Serialize payload as JSON and write to stdout with flush."""
        if isinstance(message, str):
            text = message.strip()
        elif hasattr(message, "model_dump_json"):
            text = message.model_dump_json()
        elif hasattr(message, "json"):
            text = message.json()
        else:
            text = json.dumps(message, separators=(",", ":"))

        self._stdout.write(text + "\n")
        self._stdout.flush()

    def write_threat(
        self,
        is_true_positive: bool,
        confidence_score: float,
        attack_type: str,
        explanation: str,
    ) -> None:
        """Write a standardized threat evaluation result."""
        self.write_message(
            {
                "is_true_positive": is_true_positive,
                "confidence_score": round(confidence_score, 2),
                "attack_type": attack_type,
                "explanation": explanation,
            }
        )

    def write_error(self, error_msg: str, attack_type: str = "Error") -> None:
        """Write an error response to stdout."""
        self.write_threat(
            is_true_positive=False,
            confidence_score=0.0,
            attack_type=attack_type,
            explanation=error_msg,
        )
