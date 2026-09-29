# PromptGate — First Working MVP

This is the first implementation slice for the semester project.

## What is already implemented

- FastAPI gateway
- `/v1/scan` security-analysis endpoint
- `/v1/chat/completions` demo endpoint
- Presidio-based PII detection when the NLP environment is available
- Regex/custom secret detection
- Detection merging
- Risk scoring
- YAML-based security policies
- Typed redaction
- Character-level LDP/k-RR demo mode
- SQLite privacy-safe audit logging
- Basic automated tests

The current chat endpoint intentionally uses a **demo model response**. This lets you demonstrate the core security middleware before connecting a real cloud model or Ollama.

## Setup on Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

Then run the API:

```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## Showcase UI

A Streamlit security console has been added to demonstrate the implemented pipeline visually. Start the API first, then in a second terminal run:

```powershell
streamlit run dashboard.py
```

The UI includes a live scanner, chat-gateway demo, detection findings, typed redaction, character-level LDP output, and privacy-safe SQLite audit logs.

The dashboard uses the new `GET /v1/audit` endpoint, which exposes metadata only and does not return original prompt text.

## Demo request

Use Swagger `/docs` and call `POST /v1/scan` with:

```json
{
  "text": "My email is test@example.com and my AWS key is AKIAIOSFODNN7EXAMPLE. Help me debug login."
}
```

You should see detections, risk level, action, a typed-redacted prompt, and an LDP-protected version.

## What to show your teacher

1. `/docs` page of the FastAPI service.
2. `/v1/scan` with a safe prompt → ALLOW.
3. `/v1/scan` with an email → SANITIZE.
4. `/v1/scan` with an AWS key → BLOCK.
5. Same sensitive text's LDP-protected version.
6. `promptgate.db` showing privacy-safe audit records.

## Next steps

- Integrate LiteLLM for a real cloud model.
- Integrate Ollama for the private-model path.
- Add response scanning.
- Add Streamlit dashboard.
- Build labelled evaluation data and measure precision/recall/F1, sensitive reconstruction, semantic utility, and latency.
