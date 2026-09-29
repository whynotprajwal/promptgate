from .config import load_policy
from .models import Action, Detection

POLICY = load_policy()

PRIORITY = {"ALLOW": 0, "SANITIZE": 1, "PRIVATE_ROUTE": 2, "BLOCK": 3}

def choose_action(detections: list[Detection]) -> Action:
    if not detections:
        return "ALLOW"
    actions = []
    for d in detections:
        rule = POLICY.get("entities", {}).get(d.entity_type)
        if rule:
            actions.append(rule.get("action", "ALLOW"))
    return max(actions, key=lambda a: PRIORITY.get(a, 0), default=POLICY.get("default_action", "ALLOW"))
