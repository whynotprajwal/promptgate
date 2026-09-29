import time
import uuid
from fastapi import FastAPI, HTTPException
from .audit import init_db, log_event, get_logs
from .config import load_policy
from .detection import detect_all
from .models import ScanRequest, ScanResponse, ChatRequest
from .policy import choose_action
from .risk import calculate_risk, risk_level
from .sanitize import typed_redact, ldp_protect

app = FastAPI(title="PromptGate MVP", version="0.1.0")
init_db()

@app.get("/")
def root():
    return {"name": "PromptGate", "status": "running", "docs": "/docs"}

@app.get("/v1/audit")
def audit(limit: int = 100):
    return {"logs": get_logs(limit)}

@app.post("/v1/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    detections = detect_all(request.text)
    score = calculate_risk(detections)
    level = risk_level(score)
    action = choose_action(detections)
    epsilon = float(load_policy().get("ldp", {}).get("epsilon", 5.5))

    sanitized = typed_redact(request.text, detections)
    ldp_text = ldp_protect(request.text, epsilon)

    log_event(
        request_id=str(uuid.uuid4()), risk_score=score, risk_level=level,
        action=action, entity_types=[d.entity_type for d in detections],
        model_used=None, prompt_length=len(request.text)
    )
    return ScanResponse(
        risk_score=score, risk_level=level, action=action,
        detections=detections, sanitized_text=sanitized, ldp_text=ldp_text
    )

@app.post("/v1/chat/completions")
def chat(request: ChatRequest):
    if not request.messages:
        raise HTTPException(status_code=400, detail="messages cannot be empty")

    original = request.messages[-1].content
    start = time.perf_counter()
    detections = detect_all(original)
    score = calculate_risk(detections)
    level = risk_level(score)
    action = choose_action(detections)

    if action == "BLOCK":
        protected = None
        model = None
        content = "Request blocked by PromptGate because sensitive information was detected."
    elif action == "PRIVATE_ROUTE":
        protected = typed_redact(original, detections)
        model = "private-demo"
        content = f"[Demo private-model response]\nProtected prompt: {protected}"
    else:
        protected = typed_redact(original, detections) if action == "SANITIZE" else original
        model = "cloud-demo"
        content = f"[Demo cloud-model response]\nProtected prompt: {protected}"

    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    request_id = str(uuid.uuid4())
    log_event(request_id=request_id, risk_score=score, risk_level=level,
              action=action, entity_types=[d.entity_type for d in detections],
              model_used=model, prompt_length=len(original))

    return {
        "id": request_id,
        "object": "chat.completion",
        "model": request.model,
        "promptgate": {
            "risk_score": score,
            "risk_level": level,
            "action": action,
            "latency_ms": latency_ms,
            "detections": [
                {"type": d.entity_type, "confidence": d.confidence,
                 "severity": d.severity, "source": d.source}
                for d in detections
            ],
        },
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]
    }
