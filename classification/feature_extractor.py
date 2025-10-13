import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from tldextract import extract
from config import FEATURE_ORDER_PATH
import pickle, os

if os.path.exists(FEATURE_ORDER_PATH):
    with open(FEATURE_ORDER_PATH, "rb") as f:
        FEATURE_ORDER = pickle.load(f)
else:
    FEATURE_ORDER = []

def extract_url_features(url: str) -> pd.DataFrame:
    feats = {}
    try:
        parsed = urlparse(url)
        ext = extract(url)
        host = parsed.netloc or ext.registered_domain or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # Đặc trưng cơ bản đã có
        feats["url_length"] = len(url)
        feats["hostname_length"] = len(host)
        feats["path_length"] = len(path)  # Thêm tạm vì không có trong danh sách gốc
        feats["nb_dots"] = url.count(".")
        feats["nb_hyphens"] = url.count("-")
        feats["nb_at"] = url.count("@")
        feats["nb_qm"] = url.count("?")
        feats["nb_and"] = url.count("&")
        feats["nb_or"] = url.count("|")
        feats["nb_eq"] = url.count("=")
        feats["nb_underscore"] = url.count("_")
        feats["nb_tilde"] = url.count("~")
        feats["nb_percent"] = url.count("%")
        feats["nb_slash"] = url.count("/")
        feats["nb_star"] = url.count("*")
        feats["nb_colon"] = url.count(":")
        feats["nb_comma"] = url.count(",")
        feats["nb_semicolumn"] = url.count(";")
        feats["nb_dollar"] = url.count("$")
        feats["nb_space"] = url.count(" ")
        feats["nb_www"] = 1 if "www" in host.lower() else 0
        feats["nb_com"] = 1 if ".com" in url.lower() else 0
        feats["nb_dslash"] = url.count("//")
        feats["http_in_path"] = 1 if "http" in path.lower() else 0
        feats["https_token"] = 1 if parsed.scheme == "https" else 0
        feats["ratio_digits_url"] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
        feats["ratio_digits_host"] = sum(c.isdigit() for c in host) / len(host) if len(host) > 0 else 0
        feats["punycode"] = 1 if any(ord(c) > 127 for c in url) else 0  # Kiểm tra ký tự không ASCII
        feats["port"] = 1 if ":" in host.split("@")[-1] and host.split(":")[-1].isdigit() else 0
        feats["tld_in_path"] = 1 if ext.suffix in path.lower() else 0
        feats["tld_in_subdomain"] = 1 if ext.suffix in host.lower() and ext.subdomain else 0
        feats["abnormal_subdomain"] = 1 if ext.subdomain and len(ext.subdomain.split(".")) > 2 else 0
        feats["nb_subdomains"] = host.count(".") if host else 0
        feats["prefix_suffix"] = 1 if "-" in host else 0  # Heuristic đơn giản
        feats["random_domain"] = 0  # Cần thêm kiểm tra (tạm thời 0)
        feats["shortening_service"] = 0  # Cần danh sách dịch vụ (tạm thời 0)
        feats["path_extension"] = 1 if "." in path.split("/")[-1] else 0
        feats["nb_redirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["nb_external_redirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["length_words_raw"] = len(url.split())  # Số từ thô
        feats["char_repeat"] = 1 if any(url.count(c) > 3 for c in url) else 0  # Heuristic lặp ký tự
        feats["shortest_words_raw"] = min(len(w) for w in url.split()) if url.split() else 0
        feats["shortest_word_host"] = min(len(w) for w in host.split(".")) if host.split(".") else 0
        feats["shortest_word_path"] = min(len(w) for w in path.split("/")) if path.split("/") else 0
        feats["longest_words_raw"] = max(len(w) for w in url.split()) if url.split() else 0
        feats["longest_word_host"] = max(len(w) for w in host.split(".")) if host.split(".") else 0
        feats["longest_word_path"] = max(len(w) for w in path.split("/")) if path.split("/") else 0
        feats["avg_words_raw"] = sum(len(w) for w in url.split()) / len(url.split()) if url.split() else 0
        feats["avg_word_host"] = sum(len(w) for w in host.split(".")) / len(host.split(".")) if host.split(".") else 0
        feats["avg_word_path"] = sum(len(w) for w in path.split("/")) / len(path.split("/")) if path.split("/") else 0
        feats["phish_hints"] = 1 if any(w in url.lower() for w in ["verify", "login", "account"]) else 0
        feats["domain_in_brand"] = 0  # Cần danh sách thương hiệu (tạm thời 0)
        feats["brand_in_subdomain"] = 0  # Cần danh sách thương hiệu (tạm thời 0)
        feats["brand_in_path"] = 0  # Cần danh sách thương hiệu (tạm thời 0)
        feats["suspecious_tld"] = 1 if ext.suffix not in ["com", "org", "net"] else 0  # Heuristic đơn giản
        feats["statistical_report"] = 0  # Cần dữ liệu thống kê (tạm thời 0)
        feats["nb_hyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_intHyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_extHyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_nullHyperlinks"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["nb_extCSS"] = 0  # Cần nội dung trang (tạm thời 0)
        feats["ratio_intRedirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["ratio_extRedirection"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["ratio_intErrors"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["ratio_extErrors"] = 0  # Cần phân tích HTTP (tạm thời 0)
        feats["login_form"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["external_favicon"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["links_in_tags"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["submit_email"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["ratio_intMedia"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["ratio_extMedia"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["sfh"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["iframe"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["popup_window"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["safe_anchor"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["onmouseover"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["right_clic"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["empty_title"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["domain_in_title"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["domain_with_copyright"] = 0  # Cần nội dung HTML (tạm thời 0)
        feats["whois_registered_domain"] = 0  # Cần WHOIS (tạm thời 0)
        feats["domain_registration_length"] = 0  # Cần WHOIS (tạm thời 0)
        feats["domain_age"] = -1  # Heuristic đơn giản
        feats["web_traffic"] = 0  # Cần dữ liệu lưu lượng (tạm thời 0)
        feats["dns_record"] = 1 if re.match(r".+\.[a-z]{2,}$", host) else 0  # Heuristic đơn giản
        feats["google_index"] = 1  # Giả định (tạm thời 1)
        feats["page_rank"] = 0  # Cần API PageRank (tạm thời 0)

        # Điền các đặc trưng còn thiếu bằng 0
        for f in FEATURE_ORDER:
            if f not in feats:
                feats[f] = 0.0

        df = pd.DataFrame([[feats[f] for f in FEATURE_ORDER]], columns=FEATURE_ORDER)
        return df
    except Exception as e:
        print(f"[ERROR] Failed to extract features for URL '{url}': {e}")
        return pd.DataFrame([[0] * len(FEATURE_ORDER)], columns=FEATURE_ORDER)