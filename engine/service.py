import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path so pkg modules can be imported
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from pkg.api.apis import AlertEvaluation, ThreatEvaluation
from pkg.ipc.ipc import StdioIPC
from pkg.security.security import (
    analyze_log_heuristics,
    calculate_entropy,
    is_suspicious_heuristic,
    sanitize_log_line,
)


def process_log(log_line: str) -> dict:
    """Process a log line through hybrid triage (Heuristics -> AI SLM)."""
    clean_line = sanitize_log_line(log_line)
    if not clean_line.strip():
        return {
            "is_true_positive": False,
            "confidence_score": 0.0,
            "attack_type": "None",
            "explanation": "Empty line",
        }

    # Stage 1: Fast Heuristic Filter
    if not is_suspicious_heuristic(clean_line):
        return {
            "is_true_positive": False,
            "confidence_score": 0.0,
            "attack_type": "None",
            "explanation": "Filtered by heuristics",
        }

    # Stage 2: AI False-Positive Suppressor
    prompt = (
        "Analyze this log entry for genuine security breaches. "
        "Filter benign admin tasks, automated tests, or routine commands:\n"
        f"Log: {clean_line}"
    )
    try:
        from ollama import chat

        response = chat(
            model="qwen2.5:3b",
            messages=[{"role": "user", "content": prompt}],
            format=AlertEvaluation.model_json_schema(),
        )
        return json.loads(response.message.content)
    except Exception as e:
        # Fallback to rich heuristic evaluation if Ollama is unavailable
        heuristics = analyze_log_heuristics(clean_line)
        if heuristics.is_suspicious:
            return {
                "is_true_positive": True,
                "confidence_score": heuristics.confidence_score,
                "attack_type": heuristics.attack_type,
                "explanation": f"[Heuristic Fallback] {heuristics.explanation}",
            }
        return {
            "is_true_positive": False,
            "confidence_score": 0.0,
            "attack_type": "Error",
            "explanation": str(e),
        }


if __name__ == "__main__":
    ipc = StdioIPC()
    for line in ipc.lines():
        if not line:
            ipc.write_message(
                {
                    "is_true_positive": False,
                    "confidence_score": 0.0,
                    "attack_type": "None",
                    "explanation": "Empty line",
                }
            )
            continue
        result = process_log(line)
        ipc.write_message(result)
