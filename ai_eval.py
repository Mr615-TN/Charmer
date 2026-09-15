import json
from ollama import chat
from pydantic import BaseModel, Field

class AlertEvaluation(BaseModel):
    is_true_positive: bool
    confidence_score: float = Field(description="Score between 0.0 and 1.0")
    attack_type: str
    explanation: str

def evaluate_with_ai(log_line: str, system_context: str = "") -> AlertEvaluation:
    prompt = f"""
    You are an expert SOC analyst. Analyze the following log entry for genuine security breaches.
    Reduce false positives by filtering out benign administrative tasks, scheduled cron jobs, and scanner traffic.
    
    System Context: {system_context}
    Log Line: {log_line}
    """

    response = chat(
        model='qwen2.5:3b',  # Lightweight local model optimized for JSON output
        messages=[{'role': 'user', 'content': prompt}],
        format=AlertEvaluation.model_json_schema()
    )

    return AlertEvaluation.model_validate_json(response.message.content)
