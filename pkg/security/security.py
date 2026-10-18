"""Security module for Charmer.

Provides log sanitization, heuristic breach detection, entropy calculations,
Unix domain socket hardening, security header enforcement, and rate limiting.
"""

from __future__ import annotations

import math
import os
import re
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

# Pre-compiled ANSI escape code regex for terminal injection prevention
_ANSI_ESCAPE_RE: Pattern[str] = re.compile(
    r"(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])"
)

# Standard security headers enforced by charmerd
SECURITY_HEADERS: Dict[str, str] = {
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'",
    "X-XSS-Protection": "1; mode=block",
}

# Core heuristic attack signatures
ATTACK_SIGNATURES: Dict[str, List[Pattern[str]]] = {
    "SQL Injection": [
        re.compile(r"UNION\s+SELECT", re.IGNORECASE),
        re.compile(r"OR\s+1\s*=\s*1", re.IGNORECASE),
        re.compile(r"'\s*OR\s*'\w+'\s*=\s*'\w+", re.IGNORECASE),
        re.compile(r";\s*DROP\s+TABLE", re.IGNORECASE),
        re.compile(r"EXEC(?:UTE)?\s*\(", re.IGNORECASE),
        re.compile(r"INFORMATION_SCHEMA", re.IGNORECASE),
        re.compile(r"--\s*$", re.MULTILINE),
    ],
    "Directory Traversal": [
        re.compile(r"(?:\.\.[/\\]){2,}"),
        re.compile(r"/etc/passwd", re.IGNORECASE),
        re.compile(r"/etc/shadow", re.IGNORECASE),
        re.compile(r"/etc/sudoers", re.IGNORECASE),
        re.compile(r"win\.ini", re.IGNORECASE),
        re.compile(r"boot\.ini", re.IGNORECASE),
    ],
    "Command Injection": [
        re.compile(r"/bin/bash\b", re.IGNORECASE),
        re.compile(r"/bin/sh\b", re.IGNORECASE),
        re.compile(r"sudo\s+su\b", re.IGNORECASE),
        re.compile(r"(?:curl|wget)\s+[^\n|]+\|\s*(?:ba)?sh\b", re.IGNORECASE),
        re.compile(r"nc\s+-[a-zA-Z]*e\s+", re.IGNORECASE),
        re.compile(r"bash\s+-i\s+>&", re.IGNORECASE),
        re.compile(r"powershell(?:\.exe)?\s+(?:-[eE]n?c?o?d?e?d?C?o?m?m?a?n?d?|-c)", re.IGNORECASE),
    ],
    "Code Injection": [
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"exec\s*\(", re.IGNORECASE),
        re.compile(r"base64_decode\s*\(", re.IGNORECASE),
        re.compile(r"system\s*\(", re.IGNORECASE),
        re.compile(r"passthru\s*\(", re.IGNORECASE),
        re.compile(r"shell_exec\s*\(", re.IGNORECASE),
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"<script[\s>]", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"onload\s*=", re.IGNORECASE),
    ],
    "Credential Access": [
        re.compile(r"\.ssh/id_rsa", re.IGNORECASE),
        re.compile(r"\.aws/credentials", re.IGNORECASE),
        re.compile(r"\.env\b", re.IGNORECASE),
        re.compile(r"wp-config\.php", re.IGNORECASE),
    ],
}


@dataclass
class HeuristicEvaluation:
    """Structured result of heuristic rule matching."""

    is_suspicious: bool
    confidence_score: float
    attack_type: str
    explanation: str
    entropy: float = 0.0
    matched_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_true_positive": self.is_suspicious,
            "confidence_score": self.confidence_score,
            "attack_type": self.attack_type,
            "explanation": self.explanation,
            "entropy": round(self.entropy, 2),
            "matched_patterns": self.matched_patterns,
        }


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given text.

    High entropy indicates encrypted, base64-encoded, or obfuscated payloads.
    """
    if not text:
        return 0.0
    length = len(text)
    prob = [float(text.count(c)) / length for c in set(text)]
    return -sum(p * math.log(p, 2) for p in prob)


def is_high_entropy(text: str, threshold: float = 4.5) -> bool:
    """Return True if text or any substantial token within text exceeds entropy threshold."""
    if not text:
        return False
    # If text has no whitespace, evaluate directly
    stripped = text.strip()
    if " " not in stripped:
        return calculate_entropy(stripped) > threshold

    # Check for overall extreme entropy
    if calculate_entropy(stripped) > 5.2:
        return True

    # Check individual tokens for high-entropy obfuscation (base64, hex payloads)
    tokens = re.split(r"[\s,;=]+", stripped)
    for token in tokens:
        cleaned = token.strip("'\"()[]{}<>")
        if len(cleaned) >= 16 and calculate_entropy(cleaned) > threshold:
            return True

    return False


def is_suspicious_heuristic(log_line: str, entropy_threshold: float = 4.5) -> bool:
    """Fast-path heuristic filter matching entropy and known attack patterns.

    Compatible with the original engine heuristic detection.
    """
    for patterns in ATTACK_SIGNATURES.values():
        if any(p.search(log_line) for p in patterns):
            return True

    if is_high_entropy(log_line, entropy_threshold):
        return True

    return False


def detect_attack_types(log_line: str) -> List[str]:
    """Identify which specific attack categories match the log line."""
    matched: List[str] = []
    for category, patterns in ATTACK_SIGNATURES.items():
        if any(p.search(log_line) for p in patterns):
            matched.append(category)
    if is_high_entropy(log_line):
        matched.append("High Entropy Obfuscation")
    return matched


def analyze_log_heuristics(
    log_line: str, entropy_threshold: float = 4.5
) -> HeuristicEvaluation:
    """Perform in-depth heuristic evaluation of a log line."""
    sanitized = sanitize_log_line(log_line)
    if not sanitized.strip():
        return HeuristicEvaluation(
            is_suspicious=False,
            confidence_score=0.0,
            attack_type="None",
            explanation="Empty log entry",
            entropy=0.0,
            matched_patterns=[],
        )

    entropy = calculate_entropy(sanitized)
    matched_cats: List[str] = []
    matched_details: List[str] = []

    for category, patterns in ATTACK_SIGNATURES.items():
        for p in patterns:
            match = p.search(sanitized)
            if match:
                if category not in matched_cats:
                    matched_cats.append(category)
                matched_details.append(f"{category}: '{match.group(0)}'")

    if is_high_entropy(sanitized, entropy_threshold):
        matched_cats.append("High Entropy Payload")
        matched_details.append(f"High entropy payload detected ({entropy:.2f} bits)")

    if not matched_cats:
        return HeuristicEvaluation(
            is_suspicious=False,
            confidence_score=0.0,
            attack_type="None",
            explanation="Filtered by heuristics",
            entropy=entropy,
            matched_patterns=[],
        )

    primary_type = matched_cats[0] if matched_cats else "Suspicious Pattern"
    confidence = min(0.60 + (0.10 * len(matched_cats)), 0.95)
    explanation = f"Detected {primary_type} ({', '.join(matched_details)})"

    return HeuristicEvaluation(
        is_suspicious=True,
        confidence_score=confidence,
        attack_type=primary_type,
        explanation=explanation,
        entropy=entropy,
        matched_patterns=matched_details,
    )


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences to prevent terminal injection."""
    return _ANSI_ESCAPE_RE.sub("", text)


def sanitize_log_line(log_line: str, max_length: int = 4096) -> str:
    """Sanitize log line against CRLF injection, ANSI escapes, and excessive length.

    - Removes CRLF characters (\\r, \\n) to prevent log forging.
    - Strips ANSI escape sequences.
    - Removes null bytes.
    - Limits line length to prevent ReDoS or memory exhaustion.
    """
    if not log_line:
        return ""
    # Strip null bytes and ANSI codes
    cleaned = strip_ansi(log_line.replace("\x00", ""))
    # Strip carriage returns and newlines
    cleaned = cleaned.replace("\r", " ").replace("\n", " ").strip()
    # Enforce max length
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def validate_socket_path(
    socket_path: str, allowed_dirs: Optional[List[str]] = None
) -> str:
    """Validate that the Unix domain socket path is safe and in an allowed directory.

    Raises ValueError if path is invalid or traverses outside allowed directories.
    """
    if not socket_path or not socket_path.strip():
        raise ValueError("Socket path cannot be empty")

    path = Path(socket_path).resolve()

    if allowed_dirs is None:
        import tempfile

        allowed_dirs = [
            tempfile.gettempdir(),
            os.path.join(os.sep, "tmp"),
            "/var/run",
            "/run",
            str(Path.home()),
        ]

    allowed_paths = [Path(d).resolve() for d in allowed_dirs]
    is_safe = any(
        path == allowed or allowed in path.parents for allowed in allowed_paths
    )

    if not is_safe:
        raise ValueError(
            f"Socket path {path} is not in an authorized directory ({allowed_dirs})"
        )

    return str(path)


def secure_socket_permissions(socket_path: str, mode: int = 0o600) -> bool:
    """Set restrictive permissions on Unix domain socket file (default 0600).

    Ensures only the owner can read/write to the socket, preventing local hijacking.
    """
    try:
        if os.path.exists(socket_path):
            os.chmod(socket_path, mode)
            return True
    except OSError:
        return False
    return False


def verify_security_headers(headers: Dict[str, str]) -> Tuple[bool, List[str]]:
    """Verify that HTTP response headers contain required security headers."""
    missing: List[str] = []
    normalized = {k.lower(): v for k, v in headers.items()}
    for key, expected_val in SECURITY_HEADERS.items():
        low_key = key.lower()
        if low_key not in normalized:
            missing.append(f"Missing header: {key}")
        elif (
            expected_val
            and normalized[low_key].lower() != expected_val.lower()
        ):
            missing.append(
                f"Mismatch {key}: expected '{expected_val}', got '{normalized[low_key]}'"
            )
    return (len(missing) == 0, missing)


class TokenBucketLimiter:
    """Thread-safe token bucket rate limiter to defend against log flooding / API DoS."""

    def __init__(self, rate: float = 100.0, capacity: float = 200.0) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, tokens_needed: float = 1.0) -> bool:
        """Check if request is allowed under current rate limit."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= tokens_needed:
                self.tokens -= tokens_needed
                return True
            return False
