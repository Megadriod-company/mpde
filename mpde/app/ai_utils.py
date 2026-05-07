import json
import urllib.request
from typing import Dict, List
from app.core import logger

def load_ml_model():
    """Rule-based detection engine initialized."""
    logger.info("Rule-based AI detection engine initialized.")

def predict_with_ai(features: Dict, behavioral: Dict) -> float:
    """
    Calculates a real-time risk score (0.0 to 1.0).
    Fully synced with your extensive rule set.
    """
    score = 0.0
    
    # === Lexical Weightings ===
    if features.get("entropy", 0) > 4.0: score += 0.15
    if features.get("suspicious_token_count", 0) > 0: score += 0.15
    if features.get("brand_similarity", 0) > 0.80: score += 0.20
    if features.get("has_high_risk_tld", 0): score += 0.20
    if features.get("is_ip_address", 0): score += 0.40
    if features.get("has_punycode", 0): score += 0.20
    if features.get("encoded_char_ratio", 0) > 0.03: score += 0.10
    if features.get("homograph_risk", 0) > 0.5: score += 0.30
    if features.get("obfuscation_risk", 0) > 0.3: score += 0.20
    if features.get("at_symbol", 0) or features.get("multiple_at_symbols", 0) > 1: score += 0.20
    if features.get("double_slash_in_path", 0): score += 0.15
    if features.get("url_length", 0) > 90: score += 0.05
    if features.get("param_count", 0) > 5: score += 0.05
    if features.get("subdomain_count", 0) > 3: score += 0.10
    if features.get("has_non_ascii", 0): score += 0.10
    
    # === Behavioral Weightings ===
    whois_age = behavioral.get("whois", {}).get("age_days", 999)
    if whois_age < 7: score += 0.30
    elif whois_age < 30: score += 0.15

    if behavioral.get("threat_intel", {}).get("match"): score += 0.90 # Instant Critical
    
    if not behavioral.get("dns", {}).get("resolved", True): score += 0.20
    
    dns_ttl = behavioral.get("dns", {}).get("ttl")
    if dns_ttl and dns_ttl < 120: score += 0.10
    
    if len(behavioral.get("dns", {}).get("ips", [])) > 3: score += 0.10
    
    # === Email Authentication Weightings ===
    if behavioral.get("mx", {}).get("count", 0) == 0: score += 0.10
    
    txt_records = behavioral.get("txt", {}).get("records", [])
    if not any("v=spf1" in rec.lower() for rec in txt_records): score += 0.10
    if not any("v=dmarc1" in rec.lower() for rec in txt_records): score += 0.10

    # === TLS & HTTP Weightings ===
    if behavioral.get("tls", {}).get("valid") is False: score += 0.15
    if behavioral.get("tls", {}).get("self_signed"): score += 0.15
    
    redirect_count = behavioral.get("redirects", {}).get("redirect_count", 0)
    if redirect_count >= 2: score += 0.10

    # Return clamped value between 0.0 and 1.0
    return min(max(score, 0.0), 1.0)


def explain_prediction(features: Dict, behavioral: Dict, url: str) -> List[str]:
    """Your full, comprehensive list of AI explanations."""
    explanations = []
    
    # Lexical
    if features.get("entropy", 0) > 4.0: explanations.append("High entropy indicates randomized or DGA-style domain structure")
    if features.get("suspicious_token_count", 0) > 0: explanations.append(f"{features.get('suspicious_token_count', 0)} suspicious keyword(s) found in URL")
    if features.get("brand_similarity", 0) > 0.95: explanations.append("Domain closely matches a known brand")
    elif features.get("brand_similarity", 0) > 0.80: explanations.append("Moderate brand similarity detected")
    if features.get("has_high_risk_tld", 0): explanations.append("High-risk top-level domain detected")
    if features.get("has_punycode", 0): explanations.append("Punycode detected, which can indicate homograph attack risk")
    if features.get("is_ip_address", 0): explanations.append("URL uses a raw IP address instead of a domain name")
    if features.get("url_length", 0) > 90: explanations.append("URL length is unusually long")
    if features.get("encoded_char_ratio", 0) > 0.03: explanations.append("High URL encoding ratio detected")
    if features.get("at_symbol", 0): explanations.append("URL contains '@' symbol, which is often used to obfuscate the real destination")
    if features.get("double_slash_in_path", 0): explanations.append("URL contains a double slash in the path")
    if features.get("param_count", 0) > 5: explanations.append("Excessive query parameters detected")
    if features.get("subdomain_count", 0) > 3: explanations.append("Multiple subdomains detected")
    if features.get("has_non_ascii", 0): explanations.append("Non-ASCII characters are present in the URL")
    if features.get("multiple_at_symbols", 0) > 1: explanations.append("Multiple '@' symbols found in URL")
    if features.get("homograph_risk", 0) > 0.5: explanations.append("Homograph risk is elevated")
    if features.get("obfuscation_risk", 0) > 0.3: explanations.append("URL obfuscation risk is elevated")

    # Behavioral
    whois_age = behavioral.get("whois", {}).get("age_days")
    if whois_age is not None:
        if whois_age < 7: explanations.append("Domain registration is very recent")
        elif whois_age < 30: explanations.append("Domain is recently registered")
        elif whois_age >= 365: explanations.append("Domain is established")
    
    dns_resolved = behavioral.get("dns", {}).get("resolved")
    if dns_resolved is False: explanations.append("DNS resolution failed")
    elif dns_resolved is True: explanations.append("DNS resolves successfully")
    
    dns_ttl = behavioral.get("dns", {}).get("ttl")
    if dns_ttl and dns_ttl < 120: explanations.append("DNS TTL is low, which may indicate frequently changing infrastructure")
    
    dns_ips = behavioral.get("dns", {}).get("ips", [])
    if len(dns_ips) > 3: explanations.append("Multiple IP addresses are associated with the domain")
    
    mx_count = behavioral.get("mx", {}).get("count", 0)
    if mx_count == 0: explanations.append("No MX records found")
    
    txt_records = behavioral.get("txt", {}).get("records", [])
    spf_present = any("v=spf1" in rec.lower() for rec in txt_records)
    dmarc_present = any("v=dmarc1" in rec.lower() for rec in txt_records)
    dkim_present = any("v=dkim1" in rec.lower() for rec in txt_records)
    
    if not spf_present: explanations.append("SPF record is missing")
    if not dmarc_present: explanations.append("DMARC policy is missing")
    if not dkim_present: explanations.append("DKIM is not configured")
    if spf_present: explanations.append("SPF is configured")
    if dmarc_present: explanations.append("DMARC is configured")
    if dkim_present: explanations.append("DKIM is configured")
    
    tls_valid = behavioral.get("tls", {}).get("valid")
    if tls_valid is True: explanations.append("TLS certificate is valid")
    elif tls_valid is False: explanations.append("TLS certificate is invalid or missing")
    if behavioral.get("tls", {}).get("self_signed"): explanations.append("TLS certificate is self-signed")
    tls_expiry = behavioral.get("tls", {}).get("expiry_days")
    if tls_expiry and tls_expiry < 30: explanations.append("TLS certificate expires soon")
    
    redirect_count = behavioral.get("redirects", {}).get("redirect_count", 0)
    if redirect_count >= 2: explanations.append("Multiple redirects detected")
    final_url = behavioral.get("redirects", {}).get("final_url", "")
    if final_url and final_url.lower() != url.lower(): explanations.append("Final redirect destination differs from original URL")
    
    http_headers = behavioral.get("http_headers", {})
    status_code = http_headers.get("status_code")
    if status_code and status_code >= 400: explanations.append(f"HTTP response status indicates error: {status_code}")
    if not http_headers.get("server"): explanations.append("Server header is missing")
    if not http_headers.get("x_frame_options"): explanations.append("X-Frame-Options header is missing")
    if not http_headers.get("content_security_policy"): explanations.append("Content-Security-Policy header is missing")
    
    if behavioral.get("threat_intel", {}).get("match"): explanations.append("URL matches known phishing or malware intelligence")
    
    return explanations if explanations else ["No significant risk indicators detected."]

def load_frameworks_from_config() -> Dict:
    url = "https://raw.githubusercontent.com/Megadriod-company/mpde/main/app/config/frameworks.json"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        logger.warning(f"Failed to load frameworks from internet: {e}")
        return {}

def build_business_impact_report(url: str, verdict: str, confidence: float, features: Dict, behavioral: Dict) -> Dict:
    """Builds the dynamic report based on the explanations."""
    
    # Recalculate AI score properly
    confidence = predict_with_ai(features, behavioral)
    explanations = explain_prediction(features, behavioral, url)
    
    # Determine Severity based on the new math
    if confidence >= 0.75: severity = "Critical"
    elif confidence >= 0.50: severity = "High"
    elif confidence >= 0.25: severity = "Moderate"
    else: severity = "Low"

    # Dynamic Impact Mapping
    impact = []
    if "brand" in str(explanations) or "keyword" in str(explanations): impact.append("Potential credential theft, account compromise, or fraudulent access")
    if "intelligence" in str(explanations): impact.append("Known malicious infrastructure increases operational and reputational risk")
    if "recent" in str(explanations) or "failed" in str(explanations): impact.append("Disposable domain suggests short-lived phishing campaign")
    if "IP address" in str(explanations): impact.append("Raw IP usage may bypass DNS reputation controls")
    if "invalid" in str(explanations) or "missing" in str(explanations): impact.append("Security misconfigurations increase exposure to interception and trust abuse")
    if not impact: impact.append("Minimal immediate business impact; continue monitoring for anomalies")

    # Dynamic Prevention Mapping
    prevention = []
    if "TLS" in str(explanations): prevention.append("Enforce TLS certificate validation and block invalid HTTPS endpoints")
    if "obfuscate" in str(explanations) or "slash" in str(explanations): prevention.append("Detect and block obfuscated URLs before end-user exposure")
    if "keyword" in str(explanations) or "top-level" in str(explanations): prevention.append("Apply URL reputation filtering and content inspection for suspicious domains")
    if "SPF" in str(explanations): prevention.append("Implement SPF to reduce email sender spoofing")
    if "DMARC" in str(explanations): prevention.append("Deploy DMARC for stronger email authentication and reporting")
    if "intelligence" in str(explanations): prevention.append("Deliver indicators to threat intelligence and endpoint protection systems")
    if not prevention: prevention.append("Maintain continuous URL analysis and security awareness monitoring")

    # Escalation
    escalation = "Immediate incident response and SOC escalation" if severity in ("Critical", "High") else "Review and monitor with security operations"
    if "intelligence" in str(explanations): escalation = "Immediate SOC escalation, IOC distribution, and phishing response workflow"

    # Framework Alignment
    frameworks = load_frameworks_from_config()
    baseline = frameworks.get("baseline", {
        "NIST CSF": {"Protect": ["PR.AC", "PR.DS"], "Detect": ["DE.CM"]},
        "MITRE ATT&CK": {"T1566": "Phishing awareness and detection"},
        "ISO 27001": {"A.12.4": "Logging and monitoring"},
        "CIS Controls": {"CIS 17": "Incident Response Management"}
    })

    return {
        "severity": severity,
        "confidence": round(confidence, 3),
        "verdict": "Phishing" if confidence >= 0.50 else "Benign",
        "url": url,
        "likely_impact": list(set(impact)),
        "prevention_recommendations": list(set(prevention)),
        "escalation_recommendation": escalation,
        "framework_alignment": baseline
    }