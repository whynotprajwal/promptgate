from .models import Detection
from .ldp import k_rr

def typed_redact(text: str, detections: list[Detection]) -> str:
    if not detections:
        return text
    result = []
    cursor = 0
    for d in sorted(detections, key=lambda x: x.start):
        if d.start < cursor:
            continue
        result.append(text[cursor:d.start])
        result.append(f"[{d.entity_type}_REDACTED]")
        cursor = d.end
    result.append(text[cursor:])
    return "".join(result)

def ldp_protect(text: str, epsilon: float) -> str:
    return k_rr(text, epsilon, seed=42)
