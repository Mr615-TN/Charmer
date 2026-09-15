import re
import math

def calculate_entropy(text: str) -> float:
    """Detects obfuscated strings or encoded shellcode payloads."""
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in prob)

def is_suspicious_heuristic(log_line: str) -> bool:
    # 1. High entropy strings (e.g., base64 or encoded malware)
    if calculate_entropy(log_line) > 4.5:
        return True
    
    # 2. Known attack signatures (SQLi, Directory Traversal, Command Injection)
    attack_patterns = [
        r"UNION\s+SELECT", r"\.\./\.\./", r"eval\(", r"base64_decode",
        r"OR\s+1=1", r"/bin/bash", r"sudo\s+su"
    ]
    if any(re.search(p, log_line, re.IGNORECASE) for p in attack_patterns):
        return True
        
    return False
