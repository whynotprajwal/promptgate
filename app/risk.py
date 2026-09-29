from math import prod
from .models import Detection

WEIGHTS = {"LOW": 0.20, "MEDIUM": 0.50, "HIGH": 0.80, "CRITICAL": 1.00}

def calculate_risk(detections: list[Detection]) -> float:
    if not detections:
        return 0.0
    values = [WEIGHTS.get(d.severity, 0.5) * d.confidence for d in detections]
    return round(1 - prod(1 - v for v in values), 3)

def risk_level(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    return "LOW"
