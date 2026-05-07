import math
import logging
import tldextract
from typing import Tuple, Dict
from app.integrations import get_behavioral_signals

# Configure logging
logger = logging.getLogger(__name__)

# Initialize tldextract with offline mode to prevent network calls
try:
    extractor = tldextract.TLDExtract(cache_dir=".tld_cache", suffix_list_urls=())
except Exception as exc:
    logger.warning(f"Failed to initialize tldextract with cache: {exc}")
    extractor = tldextract.TLDExtract(suffix_list_urls=())

# ==========================================
# 1. LEXICAL ANALYSIS (Static Features)
# ==========================================

def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy. 
    High entropy in a URL often indicates randomized, machine-generated domains (DGA).
    """
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

def get_lexical_features(url: str) -> Dict:
    """
    Extracts surface-level features from the URL string.
    Protected against network failures and parse errors.
    """
    try:
        ext = extractor(url)
    except Exception as exc:
        logger.warning(f"tldextract failed for URL {url}: {exc}")
        ext = tldextract.TLDExtract(cache_file=None, suffix_list_urls=None)(url)
    
    # Feature extraction
    features = {
        "url_length": len(url),
        "digit_count": sum(c.isdigit() for c in url),
        "digit_ratio": sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        "subdomain_count": url.count('.') - 1 if url.count('.') > 1 else 0,
        "entropy": calculate_entropy(url),
        "has_ip_address": 1 if any(char.isdigit() for char in ext.domain) and ext.suffix == "" else 0,
        "special_char_count": sum(url.count(c) for c in ['@', '-', '_', '=', '?']),
        "has_https": 1 if url.startswith("https://") else 0,
        "has_http": 1 if url.startswith("http://") else 0,
    }
    return features

def detect_homograph_attacks(url: str) -> float:
    """
    Detects homograph/lookalike domain attacks.
    Looks for mixed scripts or character confusion patterns.
    """
    risk = 0.0
    
    # Check for mixed alphanumeric patterns that could trick users
    if any(c in url for c in ['0', 'O']) and any(c in url for c in ['1', 'l', 'I']):
        risk += 0.15
    
    # Check for suspicious punycode (xn--)
    if 'xn--' in url:
        risk += 0.20
    
    return risk

def detect_url_obfuscation(url: str) -> float:
    """
    Detects obfuscation techniques used in phishing URLs.
    """
    risk = 0.0
    
    # URL fragment tricks
    if '#' in url and url.count('#') > 1:
        risk += 0.15
    
    # Query parameter confusion
    if url.count('?') > 2:
        risk += 0.10
    
    # Port confusion
    if ':' in url.split('//')[1] if '//' in url else '':
        risk += 0.10
    
    return risk

# ==========================================
# 2. SCORING ENGINE (The Logic Matrix)
# ==========================================

async def analyze_url_pipeline(url: str) -> Tuple[str, float, Dict]:
    """
    The Master Pipeline. Aggregates Lexical and Behavioral signals
    to produce a final Enterprise Verdict.
    """
    # --- Global Safety Net ---
    try:
        # 1. Extract Lexical features (Now protected)
        lexical = get_lexical_features(url)
    except Exception as exc:
        logger.error(f"Lexical extraction failed for URL {url}: {exc}")
        return "Unknown", 0.0, {"error": f"Lexical extraction failed: {str(exc)}"}

    # 2. Extract Behavioral features (Async DNS/WHOIS)
    try:
        behavioral = await get_behavioral_signals(url) or {}
    except Exception as exc:
        logger.warning(f"Behavioral analysis failed for URL {url}: {exc}")
        behavioral = {
            "whois": {},
            "dns": {"resolved": False, "ttl": None},
            "error": str(exc)
        }
    
    # 3. Decision Matrix (Weighted Scoring)
    # Start with 0 risk.
    risk_score = 0.0

    # --- Lexical Risk Factors ---
    if lexical['entropy'] > 4.2:
        risk_score += 0.35  # Suspicious randomness
    if lexical['url_length'] > 100:
        risk_score += 0.15  # Obfuscated length
    if lexical['digit_ratio'] > 0.25:
        risk_score += 0.20  # DGA signature
    if lexical['subdomain_count'] > 3:
        risk_score += 0.15  # Subdomain tunneling
    if lexical['has_ip_address'] == 1:
        risk_score += 0.30  # IP-based host instead of domain
    if lexical['special_char_count'] >= 3:
        risk_score += 0.10  # Lots of suspicious punctuation
    
    # HTTPS/HTTP check
    if lexical['has_https'] == 0 and lexical['has_http'] == 1:
        risk_score += 0.05  # Unencrypted connection slight risk

    # Suspicious terms detection
    suspicious_terms = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'signin', 'confirm', 'paypal', 'amazon', 'apple']
    if any(term in url.lower() for term in suspicious_terms):
        risk_score += 0.15  # Increased weight for phishing keywords

    # Advanced detection: Homograph attacks
    homograph_risk = detect_homograph_attacks(url)
    risk_score += homograph_risk

    # Advanced detection: URL obfuscation
    obfuscation_risk = detect_url_obfuscation(url)
    risk_score += obfuscation_risk

    # --- Behavioral Risk Factors (The "Enterprise" weight) ---
    if behavioral and "error" not in behavioral:
        # Check Domain Age (Critical Factor)
        age = behavioral.get('whois', {}).get('age_days')
        if age is not None:
            if age < 30:
                risk_score += 0.50  # Extremely High Risk: Brand new domain
            elif age < 180:
                risk_score += 0.20  # Moderate Risk: Young domain
            elif age > 730:
                risk_score -= 0.15  # Reputation Bonus: Domain > 2 years old
        
        # Check DNS Status
        dns_info = behavioral.get('dns', {})
        if not dns_info or not dns_info.get('resolved', False):
            risk_score += 0.15  # Unresolved DNS is suspicious

    # --- Final Calculation ---
    final_confidence = max(0.0, min(risk_score, 1.0))
    
    # Enhanced verdict classification
    if final_confidence >= 0.80:
        verdict = "Critical Phishing"
    elif final_confidence >= 0.60:
        verdict = "Suspicious"
    elif final_confidence >= 0.30:
        verdict = "Moderate Risk"
    else:
        verdict = "Benign"

    all_features = {
        **lexical,
        "behavioral_summary": behavioral,
        "homograph_risk": homograph_risk,
        "obfuscation_risk": obfuscation_risk
    }
    
    logger.info(f"URL Analysis: {url} | Verdict: {verdict} | Confidence: {final_confidence:.2f}")
    
    return verdict, final_confidence, all_features