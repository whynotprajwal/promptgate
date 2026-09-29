import re
from .models import Detection

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
    "GENERIC_API_KEY": r"\b(?:api[_ -]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-]{12,}\b",
    "PASSWORD": r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}\b",
    "BEARER_TOKEN": r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b",
}

SEVERITY = {
    "AWS_ACCESS_KEY": "CRITICAL",
    "GENERIC_API_KEY": "CRITICAL",
    "BEARER_TOKEN": "CRITICAL",
    "PASSWORD": "HIGH",
}

def regex_detect(text: str) -> list[Detection]:
    out = []
    for entity_type, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text, flags=re.IGNORECASE):
            out.append(Detection(
                entity_type=entity_type,
                start=m.start(),
                end=m.end(),
                confidence=1.0,
                severity=SEVERITY[entity_type],
                source="regex",
            ))
    return out

def presidio_detect(text: str) -> list[Detection]:
    try:
        from presidio_analyzer import AnalyzerEngine
        engine = AnalyzerEngine()
        results = engine.analyze(text=text, language="en")
    except Exception:
        # Keep the first demo usable even if the Presidio/NLP environment is not ready.
        return []

    severity = {
        "EMAIL_ADDRESS": "MEDIUM",
        "PHONE_NUMBER": "MEDIUM",
        "PERSON": "LOW",
        "LOCATION": "LOW",
        "IP_ADDRESS": "MEDIUM",
        "CREDIT_CARD": "HIGH",
    }
    return [Detection(
        entity_type=r.entity_type,
        start=r.start,
        end=r.end,
        confidence=min(max(float(r.score), 0.0), 1.0),
        severity=severity.get(r.entity_type, "MEDIUM"),
        source="presidio",
    ) for r in results]

def merge_detections(detections: list[Detection]) -> list[Detection]:
    # Prefer higher confidence when spans overlap.
    detections = sorted(detections, key=lambda d: (d.start, -d.confidence, -(d.end-d.start)))
    result = []
    for d in detections:
        if any(d.start < x.end and x.start < d.end for x in result):
            continue
        result.append(d)
    return sorted(result, key=lambda d: d.start)

def detect_all(text: str) -> list[Detection]:
    return merge_detections(presidio_detect(text) + regex_detect(text))
