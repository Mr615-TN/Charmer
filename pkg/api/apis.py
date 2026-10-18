"""API module for Charmer.

Provides:
- Data models for threats, health checks, and evaluation requests
- HTTP client for communicating with the charmerd daemon REST API
- Programmatic log evaluation API (Stage 1 Heuristics + Stage 2 Local SLM)
- Standalone HTTP server for testing or pure Python deployments
"""

from __future__ import annotations

import contextlib
import http.client
import json
import logging
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pkg.security.security import (
    SECURITY_HEADERS,
    analyze_log_heuristics,
    is_suspicious_heuristic,
    sanitize_log_line,
)

logger = logging.getLogger(__name__)

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8080
DEFAULT_HTTP_ADDR = f"http://{DEFAULT_HTTP_HOST}:{DEFAULT_HTTP_PORT}"


# ==========================================
# Data Models
# ==========================================


class ThreatEvaluation(BaseModel):
    """Structured evaluation of a potential security breach."""

    is_true_positive: bool
    confidence_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Score between 0.0 and 1.0"
    )
    attack_type: str = "None"
    explanation: str = ""
    timestamp: Optional[str] = None


# Alias for backward compatibility with engine/service.py and earlier versions
AlertEvaluation = ThreatEvaluation


class DaemonHealth(BaseModel):
    """Health and status metadata returned by the charmerd daemon."""

    status: str
    service: str
    version: str
    uptime_seconds: int
    monitoring: str
    threats_detected: int


class ThreatListResponse(BaseModel):
    """Response containing threat history from /api/threats."""

    count: int
    threats: List[ThreatEvaluation] = Field(default_factory=list)


class LogEvaluationRequest(BaseModel):
    """Request payload to evaluate an individual log line."""

    log_line: str
    system_context: str = "Production Server"
    model: str = "qwen2.5:3b"
    force_ai: bool = False


# ==========================================
# Exceptions
# ==========================================


class CharmerAPIError(Exception):
    """Base exception for Charmer API errors."""


class CharmerConnectionError(CharmerAPIError):
    """Raised when unable to connect to charmerd."""


class CharmerHTTPError(CharmerAPIError):
    """Raised when charmerd returns an HTTP error status."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message


# ==========================================
# HTTP API Client
# ==========================================


class CharmerClient:
    """HTTP Client for interacting with the Go charmerd daemon REST API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        if base_url is None:
            addr = os.getenv("CHARMER_HTTP_ADDR")
            if addr:
                if addr.startswith(":"):
                    base_url = f"http://{DEFAULT_HTTP_HOST}{addr}"
                elif not addr.startswith("http://") and not addr.startswith("https://"):
                    base_url = f"http://{addr}"
                else:
                    base_url = addr
            else:
                base_url = DEFAULT_HTTP_ADDR

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        path: str,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with security headers and timeout."""
        url = f"{self.base_url}{path}"
        data = None
        headers = {"Accept": "application/json"}

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            raise ValueError(f"Invalid URL scheme: {parsed_url.scheme}")

        host = parsed_url.hostname or DEFAULT_HTTP_HOST
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += f"?{parsed_url.query}"

        try:
            if parsed_url.scheme == "https":
                import ssl
                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(  # nosemgrep
                    host, port, timeout=self.timeout, context=context
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

            conn.request(method, path, body=data, headers=headers)
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            status = response.status

            if status >= 400:
                raise CharmerHTTPError(status, raw)

            return json.loads(raw) if raw.strip() else {}
        except CharmerHTTPError:
            raise
        except Exception as err:
            raise CharmerConnectionError(
                f"Failed to connect to charmerd at {url}: {err}"
            ) from err
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def get_health(self) -> DaemonHealth:
        """Fetch daemon health status from /healthz."""
        data = self._request("/healthz")
        return DaemonHealth.model_validate(data)

    def get_threats(self) -> ThreatListResponse:
        """Fetch all recorded threats from /api/threats."""
        data = self._request("/api/threats")
        return ThreatListResponse.model_validate(data)

    def is_healthy(self) -> bool:
        """Return True if daemon responds and reports status 'ok'."""
        try:
            health = self.get_health()
            return health.status == "ok"
        except CharmerAPIError:
            return False

    def wait_until_ready(
        self, timeout: float = 10.0, poll_interval: float = 0.5
    ) -> bool:
        """Wait until charmerd is reachable and healthy."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_healthy():
                return True
            time.sleep(poll_interval)
        return False


# Alias for client naming clarity
CharmerDaemonClient = CharmerClient


# ==========================================
# Programmatic Log Evaluation API
# ==========================================


def evaluate_log_line(
    log_line: str,
    system_context: str = "Production Server",
    model: str = "qwen2.5:3b",
    force_ai: bool = False,
) -> ThreatEvaluation:
    """Evaluate a log line using hybrid triage (Stage 1 Heuristics -> Stage 2 Local SLM).

    - If heuristics pass and force_ai is False, returns benign result without invoking LLM.
    - If heuristics trigger or force_ai is True, attempts local Ollama evaluation.
    - If Ollama is offline or uninstalled, gracefully falls back to heuristic classification.
    """
    clean_line = sanitize_log_line(log_line)
    if not clean_line.strip():
        return ThreatEvaluation(
            is_true_positive=False,
            confidence_score=0.0,
            attack_type="None",
            explanation="Empty line",
        )

    # Stage 1: Fast Heuristic Filter
    heuristics = analyze_log_heuristics(clean_line)
    if not heuristics.is_suspicious and not force_ai:
        return ThreatEvaluation(
            is_true_positive=False,
            confidence_score=0.0,
            attack_type="None",
            explanation="Filtered by heuristics",
        )

    # Stage 2: AI Evaluation via Ollama
    prompt = (
        "Analyze this log entry for genuine security breaches. "
        "Filter benign admin tasks, automated tests, or routine commands:\n"
        f"Context: {system_context}\n"
        f"Log: {clean_line}"
    )

    try:
        from ollama import chat

        response = chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            format=ThreatEvaluation.model_json_schema(),
        )
        content = response.message.content
        data = json.loads(content)
        return ThreatEvaluation.model_validate(data)
    except Exception as err:
        # Fallback to heuristic evaluation if Ollama is unavailable
        logger.warning("Ollama evaluation unavailable (%s); falling back to heuristics", err)
        return ThreatEvaluation(
            is_true_positive=heuristics.is_suspicious,
            confidence_score=heuristics.confidence_score,
            attack_type=heuristics.attack_type,
            explanation=f"[Heuristic Fallback] {heuristics.explanation}",
        )


def batch_evaluate(
    log_lines: List[str],
    system_context: str = "Production Server",
    model: str = "qwen2.5:3b",
) -> List[ThreatEvaluation]:
    """Evaluate multiple log lines sequentially."""
    return [
        evaluate_log_line(line, system_context=system_context, model=model)
        for line in log_lines
    ]


# ==========================================
# Standalone Python HTTP Server (for testing / pure Python runs)
# ==========================================


class _CharmerHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request handler matching charmerd routes with security headers."""

    def _set_security_headers(self, status_code: int = 200) -> None:
        self.send_response(status_code)
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        server: CharmerServer = self.server  # type: ignore

        if parsed.path in ("/", "/healthz"):
            self._set_security_headers(200)
            resp = {
                "status": "ok",
                "service": "charmerd-py",
                "version": "1.0.0",
                "uptime_seconds": int(time.time() - server.start_time),
                "monitoring": server.log_path,
                "threats_detected": len(server.threat_history),
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        elif parsed.path == "/api/threats":
            self._set_security_headers(200)
            resp = {
                "count": len(server.threat_history),
                "threats": [t.model_dump() for t in server.threat_history],
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        else:
            self._set_security_headers(404)
            self.wfile.write(b'{"error": "not found"}')

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        server: CharmerServer = self.server  # type: ignore

        if parsed.path == "/api/evaluate":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
                log_line = data.get("log_line", "")
                context = data.get("system_context", "Production Server")
                eval_result = evaluate_log_line(log_line, system_context=context)
                if eval_result.is_true_positive:
                    server.record_threat(eval_result)

                self._set_security_headers(200)
                self.wfile.write(eval_result.model_dump_json().encode("utf-8"))
            except Exception as err:
                self._set_security_headers(400)
                self.wfile.write(json.dumps({"error": str(err)}).encode("utf-8"))
        else:
            self._set_security_headers(404)
            self.wfile.write(b'{"error": "not found"}')

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Suppress noisy standard HTTP logs in test runs
        return


class CharmerServer(HTTPServer):
    """Charmer standalone HTTP API server with thread-safe threat tracking."""

    def __init__(
        self,
        host: str = DEFAULT_HTTP_HOST,
        port: int = DEFAULT_HTTP_PORT,
        log_path: str = "/var/log/auth.log",
    ) -> None:
        super().__init__((host, port), _CharmerHTTPRequestHandler)
        self.log_path = log_path
        self.start_time = time.time()
        self.threat_history: List[ThreatEvaluation] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def record_threat(self, threat: ThreatEvaluation) -> None:
        with self._lock:
            self.threat_history.append(threat)
            if len(self.threat_history) > 500:
                self.threat_history = self.threat_history[-500:]

    def start_background(self) -> None:
        """Start the server on a background daemon thread."""
        self._thread = threading.Thread(
            target=self.serve_forever, daemon=True, name="CharmerServerThread"
        )
        self._thread.start()

    def stop(self) -> None:
        """Shutdown the server and release port."""
        self.shutdown()
        self.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
            self._thread = None

    def __enter__(self) -> CharmerServer:
        self.start_background()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
