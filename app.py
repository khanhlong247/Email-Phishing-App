# app.py
import os, base64, uuid, re
from typing import Optional, List
from fastapi import FastAPI, Body, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
import joblib
import secrets

# ---- .env optional ----
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ---------- Model bootstrap (singleton) ----------
CANDIDATE_MODEL_PATHS = [
    os.getenv("MODEL_PATH"),
    os.path.join("models", "svm_phishing_detector.pkl"),
    os.path.join("models", "svm_email_classifier.pkl"),
    "svm_phishing_detector.pkl",
    "svm_email_classifier.pkl",
]
def _resolve_model_path() -> str:
    for p in CANDIDATE_MODEL_PATHS:
        if p and os.path.exists(p):
            return p
    raise FileNotFoundError("Model .pkl not found. Set MODEL_PATH or put model in ./models/")

MODEL_PATH = _resolve_model_path()
MODEL = joblib.load(MODEL_PATH)

# ---------- Security (very simple token) ----------
API_TOKEN = os.getenv("API_TOKEN") or secrets.token_hex(16)
print(f"🔑 API_TOKEN (dev): {API_TOKEN}")

def _require_auth(token: Optional[str]):
    if API_TOKEN and token != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

# ---------- Schemas ----------
class PredictJSON(BaseModel):
    # Option A: raw EML base64
    raw_eml_b64: Optional[str] = None

    # Option B: decomposed fields
    subject: Optional[str] = None
    from_addr: Optional[str] = Field(default=None, alias="from")
    text: Optional[str] = None
    html: Optional[str] = None
    # attachments ignored for now

class PredictBatchJSON(BaseModel):
    items: List[PredictJSON]

# ---------- Utils ----------
_HTML_TAG_RE = re.compile(r"<[^>]+>")
def html_to_text(html: str) -> str:
    text = _HTML_TAG_RE.sub(" ", html)
    return re.sub(r"\s+", " ", text).strip()

def parse_eml(raw_bytes: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw_bytes)

def extract_text_from_msg(msg: EmailMessage):
    subject = msg.get("Subject", "") or ""
    from_addr = msg.get("From", "") or ""
    plain_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
            if not isinstance(content, str): 
                continue
            if ctype == "text/plain":
                plain_parts.append(content)
            elif ctype == "text/html":
                html_parts.append(html_to_text(content))
    else:
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
        if msg.get_content_type() == "text/html":
            html_parts.append(html_to_text(content))
        else:
            plain_parts.append(content)
    body = "\n".join([p for p in plain_parts if p.strip()]) or "\n".join([p for p in html_parts if p.strip()])
    return from_addr, subject, body

def build_text(subject: str, body: str) -> str:
    return f"subject: {subject}\n\n{body}".strip()

def predict_one(combined_text: str):
    pred = MODEL.predict([combined_text])[0]
    margin = None
    # Pipeline forwards decision_function to last step if supported
    try:
        margin_val = MODEL.decision_function([combined_text])
        # often returns array-like
        margin = float(margin_val[0]) if hasattr(margin_val, "__iter__") else float(margin_val)
    except Exception:
        margin = None
    return int(pred), margin

def make_response(label_id: int, margin: Optional[float], subject: str, from_addr: str, body: str):
    return {
        "request_id": str(uuid.uuid4()),
        "label_id": label_id,
        "label": "spam" if label_id == 1 else "non_spam",
        "margin": margin,
        "subject": subject,
        "from": from_addr,
        "preview": (body[:400] + " ...") if body and len(body) > 400 else body or "",
        "model": os.path.basename(MODEL_PATH),
    }

# ---------- FastAPI ----------
app = FastAPI(title="Email Phishing Detector API", version="1.0.0")

@app.get("/health")
def health():
    return {"status": "ok", "model": os.path.basename(MODEL_PATH)}

@app.post("/predict")
async def predict_endpoint(
    request: Request,
    auth: Optional[str] = Header(default=None, alias="Authorization"),
    content_type: Optional[str] = Header(default=None, alias="Content-Type"),
):
    _require_auth(auth)

    subject = ""
    from_addr = ""
    body_text = ""

    ct = (content_type or "").lower()

    # ---- RAW EML MODE ----
    if ("message/rfc822" in ct) or ("text/plain" in ct) or ("application/octet-stream" in ct):
        raw = await request.body()
        if not raw:
            raise HTTPException(400, "Empty body for EML")
        msg = parse_eml(raw)
        from_addr, subject, body_text = extract_text_from_msg(msg)

    # ---- JSON MODE ----
    else:
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid or missing JSON body")
        # validate theo schema đã định nghĩa
        payload = PredictJSON.model_validate(data)

        if payload.raw_eml_b64:
            try:
                raw = base64.b64decode(payload.raw_eml_b64)
            except Exception:
                raise HTTPException(400, "raw_eml_b64 is not valid base64")
            msg = parse_eml(raw)
            from_addr, subject, body_text = extract_text_from_msg(msg)
        else:
            subject = payload.subject or ""
            from_addr = payload.from_addr or ""
            body_text = (payload.text or "").strip()
            if not body_text and payload.html:
                body_text = html_to_text(payload.html)

    if not (subject or body_text):
        raise HTTPException(422, "No usable content (subject/body) to classify")

    combined_text = build_text(subject, body_text)
    label_id, margin = predict_one(combined_text)
    
    result = make_response(label_id, margin, subject, from_addr, body_text)
    print(">>> Prediction Result:", result, flush=True)
    
    return {"Email Classification": "spam" if label_id == 1 else "non_spam"}

@app.post("/predict/batch")
async def predict_batch(
    body: PredictBatchJSON,
    auth: Optional[str] = Header(default=None, alias="Authorization"),
):
    _require_auth(auth)
    results = []
    for item in body.items:
        try:
            if item.raw_eml_b64:
                raw = base64.b64decode(item.raw_eml_b64)
                msg = parse_eml(raw)
                from_addr, subject, body_text = extract_text_from_msg(msg)
            else:
                subject = item.subject or ""
                from_addr = item.from_addr or ""
                body_text = (item.text or "").strip()
                if not body_text and item.html:
                    body_text = html_to_text(item.html)

            combined_text = build_text(subject, body_text)
            if not combined_text:
                results.append({"error": "empty_item"})
                continue
            label_id, margin = predict_one(combined_text)
            results.append(make_response(label_id, margin, subject, from_addr, body_text))
        except Exception as e:
            results.append({"error": str(e)})
    return {"items": results}
