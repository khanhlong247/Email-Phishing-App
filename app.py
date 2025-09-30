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

# ---- Additional imports for URL classification ----
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import ipaddress
import pandas as pd
import socket
import xgboost as xgb

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

# ---------- URL Model bootstrap (singleton) ----------
CANDIDATE_URL_MODEL_PATHS = [
    os.getenv("URL_MODEL_PATH"),
    os.path.join("models", "xgb_phishing_url_model.json"),  # Ưu tiên thư mục models
    "xgb_phishing_url_model.json",  # Fallback đến root nếu cần
]
def _resolve_url_model_path() -> str:
    for p in CANDIDATE_URL_MODEL_PATHS:
        if p and os.path.exists(p):
            return p
    raise FileNotFoundError("URL Model .json not found. Set URL_MODEL_PATH or put model in ./models/")

URL_MODEL_PATH = _resolve_url_model_path()
URL_MODEL = xgb.XGBClassifier()
URL_MODEL.load_model(URL_MODEL_PATH)

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

# ---------- URL Feature Functions ----------
def having_ip_address(url):
    try:
        ipaddress.ip_address(urlparse(url).hostname)
        return -1  # Phishing nếu dùng IP
    except:
        return 1  # Legitimate

def url_length(url):
    if len(url) < 54:
        return 1
    elif 54 <= len(url) <= 75:
        return 0
    else:
        return -1

def shortening_service(url):
    shorteners = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' \
                 r'url|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' \
                 r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|' \
                 r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|omf\.gd|to\.ly|bit\.do|t\.co|lnkd\.in|'
    match = re.search(shorteners, url)
    return -1 if match else 1

def having_at_symbol(url):
    return -1 if "@" in url else 1

def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1  # >6 vì http:// or https://

def prefix_suffix(url):
    return -1 if '-' in urlparse(url).netloc else 1

def having_sub_domain(url):
    domain = urlparse(url).netloc
    dots = domain.count('.')
    if dots == 1:
        return 1
    elif dots == 2:
        return 0
    else:
        return -1

def ssl_final_state(url):
    if url.startswith('https'):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return 1  # Có HTTPS và valid
            else:
                return 0
        except:
            return -1
    return -1

def domain_registration_length(url):
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        registration_length = (expiration_date - datetime.now()).days / 365
        return 1 if registration_length > 1 else -1
    except:
        return -1

def favicon(url, response):
    if response == "":
        return -1
    soup = BeautifulSoup(response.text, 'html.parser')
    favicon_link = soup.find("link", rel="shortcut icon")
    if favicon_link and urlparse(favicon_link['href']).netloc != urlparse(url).netloc:
        return -1
    return 1

def port(url):
    parsed = urlparse(url)
    return -1 if parsed.port and parsed.port not in [80, 443] else 1

def https_token(url):
    return -1 if 'https' in urlparse(url).netloc else 1

def request_url(url, response):
    if response == "":
        return -1
    soup = BeautifulSoup(response.text, 'html.parser')
    external = 0
    total = 0
    for img in soup.find_all('img'):
        total += 1
        if img['src'] and urlparse(img['src']).netloc != urlparse(url).netloc:
            external += 1
    # Tương tự cho script, audio, etc. (giản hóa)
    percent = external / total if total > 0 else 0
    if percent < 0.22:
        return 1
    elif 0.22 <= percent <= 0.61:
        return 0
    else:
        return -1

def url_of_anchor(url, response):
    if response == "":
        return -1
    soup = BeautifulSoup(response.text, 'html.parser')
    external = 0
    total = 0
    for a in soup.find_all('a'):
        total += 1
        if a.get('href') and urlparse(a['href']).netloc != urlparse(url).netloc:
            external += 1
    percent = external / total if total > 0 else 0
    if percent < 0.31:
        return 1
    elif 0.31 <= percent <= 0.67:
        return 0
    else:
        return -1

def links_in_tags(url, response):
    if response == "":
        return -1
    soup = BeautifulSoup(response.text, 'html.parser')
    external = 0
    total = 0
    for tag in soup.find_all(['meta', 'script', 'link']):
        total += 1
        href = tag.get('href') or tag.get('content')
        if href and urlparse(href).netloc != urlparse(url).netloc:
            external += 1
    percent = external / total if total > 0 else 0
    if percent < 0.17:
        return 1
    elif 0.17 <= percent <= 0.81:
        return 0
    else:
        return -1

def sfh(url, response):
    if response == "":
        return -1
    soup = BeautifulSoup(response.text, 'html.parser')
    for form in soup.find_all('form'):
        action = form.get('action')
        if not action or action == 'about:blank':
            return -1
        if urlparse(action).netloc != urlparse(url).netloc:
            return 0
    return 1

def submitting_to_email(response):
    if response == "":
        return -1
    soup = BeautifulSoup(response.text, 'html.parser')
    for form in soup.find_all('form'):
        action = form.get('action')
        if action and 'mailto:' in action:
            return -1
    return 1

def abnormal_url(url, response):
    if response == "":
        return -1
    hostname = urlparse(url).hostname
    return 1 if hostname in response.text else -1

def redirect(response):
    if response == "":
        return -1
    return 0 if len(response.history) <= 1 else -1 if len(response.history) > 4 else 0

def on_mouseover(response):
    if response == "":
        return -1
    if re.findall(r"onmouseover", response.text.lower()):
        return -1
    return 1

def right_click(response):
    if response == "":
        return -1
    if re.findall(r"event.button ?== ?2", response.text):
        return 1
    return -1

def popup_window(response):
    if response == "":
        return -1
    if re.findall(r"alert\(", response.text):
        return -1
    return 1

def iframe(response):
    if response == "":
        return -1
    if re.findall(r"[<iframe>|<frameBorder>]", response.text):
        return -1
    return 1

def age_of_domain(url):
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days / 30
        return 1 if age >= 6 else -1
    except:
        return -1

def dns_record(url):
    try:
        socket.gethostbyname(urlparse(url).netloc)
        return 1
    except:
        return -1

def web_traffic(url):
    # Alexa ngừng, dùng approximate dựa trên giả định hoặc skip, ở đây return 0 cho suspicious
    return 0  # Cần API thay thế nếu có

def page_rank(url):
    # Google PageRank ngừng, return 0
    return 0

def google_index(url):
    try:
        response = requests.get("https://www.google.com/search?q=site:" + url)
        return 1 if "No information is available for this page" not in response.text else -1
    except:
        return -1

def links_pointing_to_page(url):
    # Cần công cụ backlink, giả định return 0
    return 0

def statistical_report(url):
    # Check PhishTank or similar, nhưng cần API, return 1 nếu không check được
    return 1

def extract_features(url, perform_network=True):
    response = ""
    if perform_network:
        try:
            response = requests.get(url, timeout=5)
        except:
            response = ""
    else:
        response = ""  # Skip network hoàn toàn nếu False
    
    features = {
        'having_IP_Address': having_ip_address(url),
        'URL_Length': url_length(url),
        'Shortening_Service': shortening_service(url),
        'having_At_Symbol': having_at_symbol(url),
        'double_slash_redirecting': double_slash_redirecting(url),
        'Prefix_Suffix': prefix_suffix(url),
        'having_Sub_Domain': having_sub_domain(url),
        'SSLfinal_State': ssl_final_state(url) if perform_network else 0,
        'Domain_registration_length': domain_registration_length(url) if perform_network else 0,
        'Favicon': favicon(url, response) if perform_network else 0,
        'port': port(url),
        'HTTPS_token': https_token(url),
        'Request_URL': request_url(url, response) if perform_network else 0,
        'URL_of_Anchor': url_of_anchor(url, response) if perform_network else 0,
        'Links_in_tags': links_in_tags(url, response) if perform_network else 0,
        'SFH': sfh(url, response) if perform_network else 0,
        'Submitting_to_email': submitting_to_email(response) if perform_network else 0,
        'Abnormal_URL': abnormal_url(url, response) if perform_network else 0,
        'Redirect': redirect(response) if perform_network else 0,
        'on_mouseover': on_mouseover(response) if perform_network else 0,
        'RightClick': right_click(response) if perform_network else 0,
        'popUpWindow': popup_window(response) if perform_network else 0,
        'Iframe': iframe(response) if perform_network else 0,
        'age_of_domain': age_of_domain(url) if perform_network else 0,
        'DNSRecord': dns_record(url) if perform_network else 0,
        'web_traffic': web_traffic(url),  # Không cần network, giữ nguyên
        'Page_Rank': page_rank(url),  # Không cần network
        'Google_Index': google_index(url) if perform_network else 0,
        'Links_pointing_to_page': links_pointing_to_page(url),  # Không cần network
        'Statistical_report': statistical_report(url)  # Không cần network
    }
    return features

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
    
    # ---- Additional URL check if content is non_spam ----
    if label_id == 0:
        urls = re.findall(r'http[s]?://[^\s/$.?#].[^\s]*', body_text)
        if not urls:
            result = make_response(label_id, margin, subject, from_addr, body_text)
            print(">>> Prediction Result (No URL):", result, flush=True)
            return {"Email Classification": "non_spam"}
        else:
            is_phishing_url = False
            for url in urls:
                try:
                    features = extract_features(url, perform_network=True)
                    df_features = pd.DataFrame([features])
                    if hasattr(URL_MODEL, 'feature_names_in_'):
                        df_features = df_features[URL_MODEL.feature_names_in_]
                    url_pred = URL_MODEL.predict(df_features)[0]  # 0: phishing, 1: legitimate
                    if url_pred == 0:
                        is_phishing_url = True
                        break
                except Exception as e:
                    print(f"Error processing URL {url}: {e}")
                    continue  # Skip URL nếu lỗi
            if is_phishing_url:
                label_id = 1  # Override to spam
            result = make_response(label_id, margin, subject, from_addr, body_text)
            print(">>> Prediction Result (With URL Check):", result, flush=True)
            return {"Email Classification": "spam" if label_id == 1 else "non_spam"}
    else:
        result = make_response(label_id, margin, subject, from_addr, body_text)
        print(">>> Prediction Result (Content Spam):", result, flush=True)
        return {"Email Classification": "spam"}

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
            
            # ---- Additional URL check if content is non_spam ----
            if label_id == 0:
                urls = re.findall(r'(https?://[^\s]+)', body_text)
                if not urls:
                    results.append(make_response(label_id, margin, subject, from_addr, body_text))
                else:
                    is_phishing_url = False
                    for url in urls:
                        try:
                            features = extract_features(url, perform_network=True)
                            df_features = pd.DataFrame([features])
                            if hasattr(URL_MODEL, 'feature_names_in_'):
                                df_features = df_features[URL_MODEL.feature_names_in_]
                            url_pred = URL_MODEL.predict(df_features)[0]  # 0: phishing, 1: legitimate
                            if url_pred == 0:
                                is_phishing_url = True
                                break
                        except Exception as e:
                            print(f"Error processing URL {url}: {e}")
                            continue  # Skip URL nếu lỗi
                    if is_phishing_url:
                        label_id = 1  # Override to spam
                    results.append(make_response(label_id, margin, subject, from_addr, body_text))
            else:
                results.append(make_response(label_id, margin, subject, from_addr, body_text))
        except Exception as e:
            results.append({"error": str(e)})
    return {"items": results}