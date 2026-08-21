"""
feature_extraction.py
----------------------
Extracts numerical/binary features from a URL string for the phishing
detection ML model. No network requests are made — everything is derived
purely from the URL text itself, so this is fast and safe to run on any
URL a user types in.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "password", "reset", "billing", "banking", "bank", "unlock", "security",
    "webscr", "ebayisapi", "suspend", "limited", "alert",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st",
}

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "num_query_params",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_port",
    "is_shortened",
    "suspicious_keyword_count",
    "brand_keyword_in_subdomain",
    "digit_letter_ratio",
    "tld_suspicious",
]

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "info", "work"}


def _safe_parse(url: str):
    """Ensure URL has a scheme so urlparse behaves consistently."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return urlparse(url)


def extract_features(url: str) -> list:
    """
    Given a raw URL string, return a fixed-length list of numeric features
    in the same order as FEATURE_NAMES.
    """
    url = url.strip()
    parsed = _safe_parse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    domain_parts = hostname.split(".") if hostname else []
    # crude subdomain count: everything before the registrable domain
    num_subdomains = max(len(domain_parts) - 2, 0)

    tld = domain_parts[-1].lower() if len(domain_parts) >= 1 else ""

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    features = {
        "url_length": len(url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": digits,
        "num_special_chars": len(re.findall(r"[^a-zA-Z0-9./:\-_]", url)),
        "num_subdomains": num_subdomains,
        "num_query_params": query.count("=") if query else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_ip_address": 1 if IP_PATTERN.match(hostname) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_double_slash_redirect": 1 if url.rfind("//") > 7 else 0,
        "has_port": 1 if parsed.port else 0,
        "is_shortened": 1 if hostname in SHORTENER_DOMAINS else 0,
        "suspicious_keyword_count": sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()
        ),
        "brand_keyword_in_subdomain": 1 if num_subdomains >= 2 else 0,
        "digit_letter_ratio": round(digits / letters, 3) if letters else 0.0,
        "tld_suspicious": 1 if tld in SUSPICIOUS_TLDS else 0,
    }

    return [features[name] for name in FEATURE_NAMES]


def extract_features_dict(url: str) -> dict:
    """Same as extract_features but returns a name->value dict (used by
    the Flask app to build human-readable 'reasons' for a prediction)."""
    values = extract_features(url)
    return dict(zip(FEATURE_NAMES, values))


def explain_reasons(url: str, feats: dict = None) -> list:
    """
    Produce a short list of human-readable reasons based on the extracted
    features. This is a lightweight, rule-based explanation layer (a
    simple stand-in for full SHAP-based explainability, mentioned in the
    project write-up as a future enhancement).
    """
    if feats is None:
        feats = extract_features_dict(url)

    reasons = []

    if feats["has_https"] == 0:
        reasons.append("Connection is not using HTTPS")
    if feats["has_ip_address"]:
        reasons.append("URL uses a raw IP address instead of a domain name")
    if feats["has_at_symbol"]:
        reasons.append("URL contains an '@' symbol, which can hide the real destination")
    if feats["suspicious_keyword_count"] > 0:
        reasons.append(
            f"Contains {feats['suspicious_keyword_count']} suspicious keyword(s) "
            f"(e.g. login, verify, secure, account)"
        )
    if feats["num_subdomains"] >= 2:
        reasons.append("URL has an unusually high number of subdomains")
    if feats["num_hyphens"] >= 3:
        reasons.append("URL contains many hyphens, common in lookalike domains")
    if feats["tld_suspicious"]:
        reasons.append("Domain uses a top-level domain often associated with abuse")
    if feats["is_shortened"]:
        reasons.append("URL uses a link-shortening service, hiding the real destination")
    if feats["url_length"] > 75:
        reasons.append("URL is unusually long")
    if feats["has_port"]:
        reasons.append("URL specifies a non-standard port")

    if not reasons:
        reasons.append("No strong red-flag patterns detected in the URL structure")

    return reasons
