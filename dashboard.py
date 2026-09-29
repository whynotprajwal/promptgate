import html
from pathlib import Path

import httpx
import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="PromptGate Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_URL = st.sidebar.text_input("PromptGate API", "http://127.0.0.1:8000").rstrip("/")

st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top left, #111827 0%, #080b12 42%, #05070b 100%);
    }
    .block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
    .hero {
        border: 1px solid rgba(255,255,255,.10);
        border-radius: 22px;
        padding: 26px 28px;
        background: linear-gradient(135deg, rgba(30,41,59,.92), rgba(15,23,42,.62));
        box-shadow: 0 15px 45px rgba(0,0,0,.25);
        margin-bottom: 18px;
    }
    .hero h1 {margin: 0; font-size: 2.25rem;}
    .hero p {margin: 6px 0 0; color: #a5b4fc; font-size: 1rem;}
    .pill {
        display: inline-block;
        padding: 5px 10px;
        border-radius: 999px;
        margin: 4px 6px 0 0;
        background: rgba(255,255,255,.06);
        color: #dbeafe;
        border: 1px solid rgba(255,255,255,.08);
        font-size: .82rem;
    }
    .pipeline {
        display: flex;
        align-items: center;
        gap: 7px;
        flex-wrap: wrap;
        padding: 14px 16px;
        border-radius: 16px;
        background: rgba(15,23,42,.85);
        border: 1px solid rgba(255,255,255,.08);
        margin: 10px 0 18px;
    }
    .step {
        padding: 8px 11px;
        border-radius: 10px;
        background: rgba(99,102,241,.12);
        border: 1px solid rgba(129,140,248,.18);
        color: #e0e7ff;
        font-size: .82rem;
        font-weight: 600;
    }
    .arrow {color: #64748b; font-weight: 700;}
    .result-card {
        border-radius: 18px;
        padding: 18px;
        border: 1px solid rgba(255,255,255,.08);
        background: rgba(15,23,42,.78);
        min-height: 130px;
    }
    .label {color:#94a3b8; font-size:.78rem; text-transform:uppercase; letter-spacing:.08em;}
    .big {font-size:2rem; font-weight:800; margin-top:5px;}
    .muted {color:#94a3b8;}
    .codebox {
        padding: 15px 17px;
        border-radius: 14px;
        background: #020617;
        border: 1px solid #1e293b;
        color: #dbeafe;
        white-space: pre-wrap;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: .92rem;
        line-height: 1.5;
    }
    .finding {
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,.07);
        background: rgba(30,41,59,.65);
        margin-bottom: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
        <h1>🛡️ PromptGate Security Console</h1>
        <p>Privacy-preserving middleware for secure interaction with cloud-based LLMs</p>
        <span class="pill">Regex / Presidio detection</span>
        <span class="pill">Risk engine</span>
        <span class="pill">YAML policies</span>
        <span class="pill">Typed redaction</span>
        <span class="pill">Character-level LDP</span>
        <span class="pill">SQLite audit</span>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="pipeline">
        <span class="step">Detect</span><span class="arrow">→</span>
        <span class="step">Assess risk</span><span class="arrow">→</span>
        <span class="step">Decide policy</span><span class="arrow">→</span>
        <span class="step">Sanitize / Block / Route</span><span class="arrow">→</span>
        <span class="step">Generate</span><span class="arrow">→</span>
        <span class="step">Audit</span>
    </div>
    """,
    unsafe_allow_html=True,
)


def api_get(path: str):
    return httpx.get(f"{API_URL}{path}", timeout=3.0)


def api_post(path: str, payload: dict):
    return httpx.post(f"{API_URL}{path}", json=payload, timeout=15.0)


def action_help(action: str) -> str:
    return {
        "ALLOW": "Prompt passed without typed redaction.",
        "SANITIZE": "Sensitive entities are replaced before model use.",
        "PRIVATE_ROUTE": "Request is intended for the private-model path.",
        "BLOCK": "Request is stopped because policy treats the detected data as critical.",
    }.get(action, "Policy decision returned by PromptGate.")


def risk_label_color(level: str) -> str:
    return {
        "LOW": "#22c55e",
        "MEDIUM": "#eab308",
        "HIGH": "#f97316",
        "CRITICAL": "#ef4444",
    }.get(level, "#94a3b8")


with st.sidebar:
    st.subheader("Demo prompts")
    if st.button("✅ Safe", use_container_width=True):
        st.session_state.prompt = "Explain the difference between supervised and unsupervised learning."
    if st.button("📧 Email", use_container_width=True):
        st.session_state.prompt = "Please send the report to test@example.com."
    if st.button("🔑 AWS key", use_container_width=True):
        st.session_state.prompt = "My AWS key is AKIAIOSFODNN7EXAMPLE. Help me debug login."
    if st.button("🔐 Password", use_container_width=True):
        st.session_state.prompt = "My password: TestPass123!. Help me debug login."

    st.divider()
    try:
        r = api_get("/")
        api_ok = r.status_code == 200
    except Exception:
        api_ok = False
    st.metric("API status", "ONLINE" if api_ok else "OFFLINE")
    st.caption("Start FastAPI first, then run this dashboard.")

if "prompt" not in st.session_state:
    st.session_state.prompt = "My AWS key is AKIAIOSFODNN7EXAMPLE. Help me debug login."

scan_tab, chat_tab, audit_tab, about_tab = st.tabs(
    ["🔍 Live Scanner", "💬 Chat Gateway", "📊 Audit Logs", "ℹ️ Implementation"]
)

with scan_tab:
    st.subheader("Live prompt security scan")
    prompt = st.text_area(
        "Prompt to inspect",
        key="prompt",
        height=140,
        placeholder="Type a prompt containing an email, token, password, or normal text...",
    )

    scan_col, clear_col = st.columns([1, 5])
    with scan_col:
        scan_clicked = st.button("🔎 Scan prompt", type="primary", use_container_width=True)
    with clear_col:
        st.caption("The audit log stores metadata only: no original prompt text is written to SQLite.")

    if scan_clicked:
        if not prompt.strip():
            st.warning("Enter a prompt first.")
        else:
            try:
                response = api_post("/v1/scan", {"text": prompt})
                response.raise_for_status()
                data = response.json()
                st.session_state.last_scan = data
            except Exception as exc:
                st.error(f"Could not reach PromptGate API: {exc}")

    if "last_scan" in st.session_state:
        data = st.session_state.last_scan
        color = risk_label_color(data["risk_level"])
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk score", data["risk_score"])
        c2.markdown(
            f'<div class="result-card"><div class="label">Risk level</div>'
            f'<div class="big" style="color:{color}">{html.escape(data["risk_level"])}</div></div>',
            unsafe_allow_html=True,
        )
        c3.markdown(
            f'<div class="result-card"><div class="label">Policy action</div>'
            f'<div class="big">{html.escape(data["action"])}</div></div>',
            unsafe_allow_html=True,
        )
        c4.metric("Detections", len(data.get("detections", [])))

        st.caption(action_help(data["action"]))

        left, right = st.columns(2)
        with left:
            st.markdown("### Detection findings")
            detections = data.get("detections", [])
            if not detections:
                st.success("No matching sensitive entities were detected by the active detectors.")
            else:
                for d in detections:
                    st.markdown(
                        f'<div class="finding"><b>{html.escape(d["entity_type"])}</b>'
                        f' · {html.escape(d["severity"])} · confidence {d["confidence"]:.2f}'
                        f'<br><span class="muted">source: {html.escape(d["source"])} · span: '
                        f'{d["start"]}:{d["end"]}</span></div>',
                        unsafe_allow_html=True,
                    )

        with right:
            st.markdown("### Protection outputs")
            st.markdown("**Typed redaction**")
            st.markdown(f'<div class="codebox">{html.escape(data["sanitized_text"])}</div>', unsafe_allow_html=True)
            st.markdown("**Character-level LDP**")
            st.markdown(f'<div class="codebox">{html.escape(data["ldp_text"])}</div>', unsafe_allow_html=True)

with chat_tab:
    st.subheader("Chat gateway demonstration")
    chat_prompt = st.text_area(
        "Message sent through /v1/chat/completions",
        value=st.session_state.get("prompt", ""),
        height=130,
        key="chat_prompt",
    )
    model_name = st.text_input("Requested model", "demo")
    if st.button("🚀 Send through PromptGate", type="primary"):
        if not chat_prompt.strip():
            st.warning("Enter a message first.")
        else:
            try:
                payload = {"model": model_name, "messages": [{"role": "user", "content": chat_prompt}]}
                response = api_post("/v1/chat/completions", payload)
                response.raise_for_status()
                chat = response.json()
                pg = chat["promptgate"]
                st.session_state.last_chat = chat
            except Exception as exc:
                st.error(f"Could not reach PromptGate API: {exc}")

    if "last_chat" in st.session_state:
        chat = st.session_state.last_chat
        pg = chat["promptgate"]
        a, b, c, d = st.columns(4)
        a.metric("Action", pg["action"])
        b.metric("Risk", pg["risk_level"])
        c.metric("Latency", f'{pg["latency_ms"]} ms')
        d.metric("Model", chat["model"])
        st.markdown("### Model response")
        st.markdown(f'<div class="codebox">{html.escape(chat["choices"][0]["message"]["content"])}</div>', unsafe_allow_html=True)
        st.markdown("### Gateway detections")
        st.json(pg.get("detections", []))

with audit_tab:
    st.subheader("Privacy-safe audit trail")
    st.caption("This table exposes request metadata from promptgate.db, not raw prompt contents.")
    try:
        response = api_get("/v1/audit?limit=100")
        response.raise_for_status()
        logs = response.json().get("logs", [])
        if logs:
            df = pd.DataFrame(logs)
            st.dataframe(df, use_container_width=True, hide_index=True)
            m1, m2, m3 = st.columns(3)
            m1.metric("Total events shown", len(df))
            m2.metric("Blocked", int((df["action"] == "BLOCK").sum()))
            m3.metric("Sanitized", int((df["action"] == "SANITIZE").sum()))
        else:
            st.info("No audit events yet. Run a scan or chat request first.")
    except Exception as exc:
        st.error(f"Could not load audit data: {exc}")

with about_tab:
    st.subheader("What this UI demonstrates")
    st.markdown(
        """
        **PromptGate MVP components visible here**

        - **Detection:** regex/custom rules, plus Presidio when its NLP environment is available.
        - **Risk engine:** converts detections into a risk score and level.
        - **Policy engine:** chooses `ALLOW`, `SANITIZE`, `PRIVATE_ROUTE`, or `BLOCK`.
        - **Sanitization:** typed redaction preserves the rest of the prompt context.
        - **LDP prototype:** character-level perturbation is shown as a separate privacy mechanism.
        - **Gateway:** `/v1/chat/completions` demonstrates the security decision before a model call.
        - **Audit:** SQLite stores privacy-safe metadata for later monitoring.
        """
    )

    st.markdown("### Endpoints used")
    st.code(
        "GET  /\nPOST /v1/scan\nPOST /v1/chat/completions\nGET  /v1/audit?limit=100",
        language="text",
    )

    st.markdown("### Suggested teacher demo flow")
    st.markdown(
        "Run the **Safe → Email → AWS key** samples, then open **Audit Logs** and show that the original prompt is not stored there."
    )
