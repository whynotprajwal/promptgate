from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = ROOT / "policies.yaml"

def load_policy() -> dict:
    with POLICY_FILE.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)
