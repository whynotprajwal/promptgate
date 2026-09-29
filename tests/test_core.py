from app.detection import regex_detect
from app.risk import calculate_risk
from app.policy import choose_action
from app.sanitize import typed_redact


def test_api_key_detection():
    text = "api_key=ABCDEFGHIJKL1234"
    detections = regex_detect(text)
    assert any(d.entity_type == "GENERIC_API_KEY" for d in detections)


def test_block_policy():
    text = "AWS key AKIAIOSFODNN7EXAMPLE"
    detections = regex_detect(text)
    assert choose_action(detections) == "BLOCK"
    assert calculate_risk(detections) >= 0.9


def test_redaction():
    text = "email=test@example.com"
    d = [type("D", (), {"start": 6, "end": 22, "entity_type": "EMAIL_ADDRESS"})()]
    assert "[EMAIL_ADDRESS_REDACTED]" in typed_redact(text, d)
