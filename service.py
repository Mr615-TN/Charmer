import sys
import json
import math
import re
from ollama import chat
from pydantic import BaseModel, Field

class AlertEvaluation(BaseModel):
    is_true_positive: bool
    confidence_score: float = Field(description="Score between 0.0 and 1.0")
    attack_type: str
    explanation: str

def calculate_entropy(text: str) -> float:
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in prob)

def is_suspicious_heuristic(log_line: str) -> bool:
    if calculate_entropy(log_line) > 4.5:
        return True
    patterns = [r"UNION\s+SELECT", r"\.\./\.\./", r"eval\(", r"base64_decode", r"OR\s+1=1"]
    return any(re.search(p, log_line, re.IGNORECASE) for p in patterns)

def process_log(log_line: str) -> dict:
    # Stage 1: Fast Heuristic Filter
    if not is_suspicious_heuristic(log_line):
        return {"is_true_positive": False, "confidence_score": 0.0, "attack_type": "None", "explanation": "Filtered by heuristics"}

    # Stage 2: AI False-Positive Suppressor
    prompt = f"Analyze log entry for genuine breaches. Filter benign admin tasks:\nLog: {log_line}"
    response = chat(
        model='qwen2.5:3b',
        messages=[{'role': 'user', 'content': prompt}],
        format=AlertEvaluation.model_json_schema()
    )
    return json.loads(response.message.content)

if __name__ == "__main__":
    # Stdout-based IPC loop for CLI integration
    for line in sys.stdin:
        line = line.strip()
        if line:
            result = process_log(line)
            print(json.dumps(result), flush=True)
