import difflib
import ipaddress
import itertools
import logging
import math
import re
import urllib.parse
import tldextract
from typing import Tuple, Dict, Any
from app.integrations import get_behavioral_signals
from app.ai_utils import load_ml_model, predict_with_ai, explain_prediction

logger = logging.getLogger(__name__)

try:
    extractor = tldextract.TLDExtract(cache_dir=".tld_cache", suffix_list_urls=())
except Exception as exc:
    logger.warning(f"Failed to initialize tldextract with cache: {exc}")
    extractor = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_TERMS = [
    "login", "secure", "update", "verify", "account", "bank", "signin",
    "confirm", "paypal", "amazon", "apple", "invoice", "validate",
    "security", "support", "admin", "wp-login", "ebay", "microsoft",
    "billing", "payment", "reset", "alert", "verification", "auth"
]

HIGH_RISK_TLDS = {
    "zip", "review", "country", "kim", "work", "loan", "cricket",
    "download", "racing", "stream", "vip", "click", "faith",
    "xyz", "top", "club", "info", "online", "space", "solutions"
}

COMMON_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "linkedin", "instagram", "whatsapp", "office", "icloud",
    "dropbox", "bank", "wellsfargo", "chase", "citibank", "bankofamerica"
]

IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def get_brand_similarity(host: str) -> float:
    host = host.lower()
    tokens = re.split(r"[\.\-_/]+", host)
    best = 0.0
    for brand in COMMON_BRANDS:
        for token in tokens:
            if not token:
                continue
            ratio = difflib.SequenceMatcher(None, token, brand).ratio()
            if ratio > best:
                best = ratio
            if best >= 0.55:
                return best
    return best


def count_repeated_query_keys(query_params: Dict[str, list]) -> int:
    return sum(1 for value in query_params.values() if len(value) > 1)


def get_lexical_features(url: str) -> Dict[str, Any]:
    parsed = urllib.parse.urlparse(url if URL_PATTERN.match(url) else f"http://{url}")
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full_url = parsed.geturl()

    try:
        ext = extractor(full_url)
    except Exception as exc:
        logger.warning(f"tldextract failed for URL {url}: {exc}")
        ext = tldextract.TLDExtract(cache_file=None, suffix_list_urls=None)(full_url)

    encoded_ratio = sum(1 for c in full_url if c == "%") / len(full_url) if full_url else 0.0
    query_params = urllib.parse.parse_qs(query)
    path_segments = [seg for seg in path.split("/") if seg]
    suspicious_path_tokens = ["login", "secure", "account", "bank", "verify", "password"]

    features = {
        "url_length": len(full_url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "dot_count": full_url.count("."),
        "hyphen_count": host.count("-"),
        "underscore_count": full_url.count("_"),
        "semicolon_count": full_url.count(";"),
        "colon_count": full_url.count(":"),
        "at_symbol": 1 if "@" in full_url else 0,
        "multiple_at_symbols": full_url.count("@"),
        "double_slash_in_path": 1 if "//" in path else 0,
        "encoded_char_ratio": encoded_ratio,
        "suspicious_token_count": sum(1 for term in SUSPICIOUS_TERMS if term in full_url.lower()),
        "suspicious_path_token_count": sum(1 for term in suspicious_path_tokens if term in path.lower()),
        "param_count": len(query_params),
        "repeated_param_count": count_repeated_query_keys(query_params),
        "digit_count": sum(c.isdigit() for c in full_url),
        "digit_ratio": sum(c.isdigit() for c in full_url) / len(full_url) if len(full_url) > 0 else 0.0,
        "subdomain_count": max(ext.subdomain.count(".") + 1, 0) if ext.subdomain else 0,
        "path_segment_count": len(path_segments),
        "longest_path_segment": max((len(seg) for seg in path_segments), default=0),
        "entropy": calculate_entropy(full_url),
        "is_ip_address": 1 if host and is_ip_address(host) else 0,
        "uses_https": 1 if parsed.scheme == "https" else 0,
        "uses_http": 1 if parsed.scheme == "http" else 0,
        "uses_non_standard_port": 1 if parsed.port and parsed.port not in (80, 443) else 0,
        "has_punycode": 1 if "xn--" in full_url else 0,
        "has_high_risk_tld": 1 if ext.suffix in HIGH_RISK_TLDS else 0,
        "has_non_ascii": 1 if any(ord(ch) > 127 for ch in full_url) else 0,
        "has_fragment": 1 if fragment else 0,
        "has_query": 1 if query else 0,
        "has_suspicious_scheme": 1 if parsed.scheme not in ("http", "https", "") else 0,
        "brand_similarity": get_brand_similarity(host or ext.domain or full_url),
        "special_char_count": sum(full_url.count(c) for c in ["@", "%", ";", "_", "=", "?"]),
        "suspicious_path": 1 if any(term in path.lower() for term in suspicious_path_tokens) else 0,
    }
    return features


def detect_homograph_attacks(url: str) -> float:
    risk = 0.0
    if any(c in url for c in ["0", "O"]) and any(c in url for c in ["1", "l", "I"]):
        risk += 0.18
    if "xn--" in url:
        risk += 0.25
    if any(ord(ch) > 127 for ch in url):
        risk += 0.20
    return risk


def detect_url_obfuscation(url: str) -> float:
    risk = 0.0
    if url.count("@") > 0:
        risk += 0.25
    if url.count("//") > 1:
        risk += 0.20
    if url.count("%") > 3:
        risk += 0.15
    if url.count("?") > 2:
        risk += 0.10
    if url.count("#") > 1:
        risk += 0.10
    if "//" in url and url.split("//", 1)[1].count("/") > 4:
        risk += 0.10
    if url.count(";") > 0:
        risk += 0.08
    return risk


async def analyze_url_pipeline(url: str) -> Tuple[str, float, Dict[str, Any]]:
    try:
        lexical = get_lexical_features(url)
    except Exception as exc:
        logger.error(f"Lexical extraction failed for URL {url}: {exc}")
        return "Unknown", 0.0, {"error": f"Lexical extraction failed: {str(exc)}"}

    try:
        behavioral = await get_behavioral_signals(url) or {}
    except Exception as exc:
        logger.warning(f"Behavioral analysis failed for URL {url}: {exc}")
        behavioral = {
            "whois": {},
            "dns": {"resolved": False, "ttl": None, "ips": []},
            "mx": {"records": [], "count": 0},
            "txt": {"records": []},
            "http_headers": {},
            "tls": {},
            "redirects": {"redirect_count": 0, "final_url": url},
            "threat_intel": {"match": False},
            "error": str(exc),
        }

    risk_score = 0.0

    if lexical["entropy"] > 4.0:
        risk_score += 0.20
    if lexical["url_length"] > 90:
        risk_score += 0.18
    if lexical["host_length"] > 40:
        risk_score += 0.12
    if lexical["path_length"] > 50:
        risk_score += 0.12
    if lexical["query_length"] > 40:
        risk_score += 0.10
    if lexical["digit_ratio"] > 0.18:
        risk_score += 0.18
    if lexical["dot_count"] > 5:
        risk_score += 0.10
    if lexical["hyphen_count"] > 2:
        risk_score += 0.10
    if lexical["suspicious_token_count"] > 0:
        risk_score += min(0.35, 0.07 * lexical["suspicious_token_count"])
    if lexical["suspicious_path_token_count"] > 0:
        risk_score += 0.10
    if lexical["is_ip_address"]:
        risk_score += 0.35
    if lexical["has_high_risk_tld"]:
        risk_score += 0.22
    if lexical["has_punycode"]:
        risk_score += 0.22
    if lexical["has_non_ascii"]:
        risk_score += 0.18
    if lexical["encoded_char_ratio"] > 0.03:
        risk_score += 0.12
    if lexical["param_count"] > 5:
        risk_score += 0.12
    if lexical["repeated_param_count"] > 0:
        risk_score += 0.12
    if lexical["special_char_count"] >= 4:
        risk_score += 0.12
    if lexical["longest_path_segment"] > 40:
        risk_score += 0.12
    if lexical["path_segment_count"] > 6:
        risk_score += 0.08
    if lexical["at_symbol"]:
        risk_score += 0.25
    if lexical["multiple_at_symbols"] > 1:
        risk_score += 0.18
    if lexical["double_slash_in_path"]:
        risk_score += 0.15
    if lexical["uses_http"] and not lexical["uses_https"]:
        risk_score += 0.10
    if lexical["uses_non_standard_port"]:
        risk_score += 0.08
    if lexical["has_fragment"] and lexical["fragment_length"] > 20:
        risk_score += 0.08
    if lexical["has_suspicious_scheme"]:
        risk_score += 0.10
    if lexical["brand_similarity"] >= 0.80:
        risk_score -= 0.28
    elif lexical["brand_similarity"] >= 0.65:
        risk_score -= 0.12

    risk_score += detect_homograph_attacks(url)
    risk_score += detect_url_obfuscation(url)

    if behavioral and "error" not in behavioral:
        whois_info = behavioral.get("whois", {})
        age = whois_info.get("age_days")
        if age is not None:
            if age < 30:
                risk_score += 0.55
            elif age < 180:
                risk_score += 0.10  # Further reduced for safety
            elif age >= 365:
                risk_score -= 0.10

        dns_info = behavioral.get("dns", {})
        if not dns_info.get("resolved", False):
            risk_score += 0.22
        elif dns_info.get("ttl") and dns_info["ttl"] < 120:
            risk_score += 0.12
        if len(dns_info.get("ips", [])) > 3:
            risk_score += 0.10

        mx_info = behavioral.get("mx", {})
        if mx_info.get("count", 0) == 0:
            risk_score += 0.10

        txt_info = behavioral.get("txt", {})
        spf_present = any("v=spf1" in rec.lower() for rec in txt_info.get("records", []))
        dmarc_present = any("_dmarc" in rec.lower() or "v=dmarc1" in rec.lower() for rec in txt_info.get("records", []))
        if not spf_present:
            risk_score += 0.08
        if not dmarc_present:
            risk_score += 0.08

        redirects = behavioral.get("redirects", {})
        if redirects.get("redirect_count", 0) >= 2:
            risk_score += 0.12
        if str(redirects.get("final_url", "")).lower() != str(url).lower():
            risk_score += 0.08

        tls_info = behavioral.get("tls", {})
        if tls_info.get("self_signed"):
            risk_score += 0.22
        if tls_info.get("expiry_days") is not None:
            if tls_info["expiry_days"] < 30:
                risk_score += 0.18
            elif tls_info["expiry_days"] < 90:
                risk_score += 0.08

        http_headers = behavioral.get("http_headers", {})
        if http_headers.get("status_code") and http_headers["status_code"] >= 400:
            risk_score += 0.15
        if not http_headers.get("server"):
            risk_score += 0.08

        if behavioral.get("threat_intel", {}).get("match"):
            risk_score += 0.50

        # Safe side: If DNS resolves and TLS is valid, reduce risk
        if dns_info.get("resolved") and tls_info.get("valid"):
            risk_score -= 0.10

    # AI-Powered Ensemble
    load_ml_model()
    ai_score = predict_with_ai(lexical, behavioral)
    risk_score = (risk_score + ai_score) / 2.0

    final_confidence = max(0.0, min(risk_score, 1.0))

    if final_confidence >= 0.70:
        verdict = "Critical Phishing"
    elif final_confidence >= 0.40:
        verdict = "Suspicious"
    elif final_confidence >= 0.15:
        verdict = "Moderate Risk"
    else:
        verdict = "Benign"

    features = {
        **lexical,
        "behavioral_summary": behavioral,
        "homograph_risk": detect_homograph_attacks(url),
        "obfuscation_risk": detect_url_obfuscation(url),
        "ai_score": ai_score,
        "ai_explanations": explain_prediction(lexical, behavioral, url),
    }

    logger.info(f"URL Analysis: {url} | Verdict: {verdict} | Confidence: {final_confidence:.2f}")
    return verdict, final_confidence, features
