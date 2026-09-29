from typing import Literal
from pydantic import BaseModel

Action = Literal["ALLOW", "SANITIZE", "PRIVATE_ROUTE", "BLOCK"]

class Detection(BaseModel):
    entity_type: str
    start: int
    end: int
    confidence: float
    severity: str
    source: str

class ScanRequest(BaseModel):
    text: str

class ScanResponse(BaseModel):
    risk_score: float
    risk_level: str
    action: Action
    detections: list[Detection]
    sanitized_text: str
    ldp_text: str

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str = "demo"
    messages: list[Message]
