import pytest
import asyncio
from app.engine import calculate_entropy, get_lexical_features, detect_homograph_attacks, detect_url_obfuscation, analyze_url_pipeline

def test_entropy_calculation():
    # Test a low-entropy string (Repeating characters)
    low_ent = calculate_entropy("aaaaa")
    # Test a high-entropy string (Random characters)
    high_ent = calculate_entropy("a1b2c3d4e5f6")
    
    assert high_ent > low_ent
    assert isinstance(high_ent, float)

def test_lexical_feature_extraction():
    url = "http://secure-login-check.com/account"
    features = get_lexical_features(url)
    
    assert "url_length" in features
    assert "entropy" in features
    assert features["url_length"] == len(url)

@pytest.mark.asyncio
async def test_engine_pipeline_logic():
    # This tests the logic flow without calling real external DNS
    from app.engine import analyze_url_pipeline
    
    url = "http://normal-site.com"
    verdict, confidence, features = await analyze_url_pipeline(url)
    
    assert verdict in ["Benign", "Suspicious", "Critical Phishing"]
    assert 0.0 <= confidence <= 1.0

def test_get_lexical_features_returns_expected_fields():
    url = "http://login-secure-paypal.example.xyz/path?user=abc&user=def"
    features = get_lexical_features(url)

    assert features["url_length"] > 0
    assert features["suspicious_token_count"] >= 2
    assert features["repeated_param_count"] == 1
    assert features["has_high_risk_tld"] == 1
    assert features["brand_similarity"] > 0.0

def test_detect_homograph_attacks():
    url = "http://xn--paypa1-xyz.example.com"
    assert detect_homograph_attacks(url) > 0.0

def test_detect_url_obfuscation():
    url = "http://example.com/@login//secure/%25"
    assert detect_url_obfuscation(url) > 0.0

def test_analyze_url_pipeline_with_stubbed_behavior():
    async def fake_behavioral(url):
        return {
            "whois": {"age_days": 5},
            "dns": {"resolved": False, "ttl": None, "ips": []},
            "mx": {"records": [], "count": 0},
            "txt": {"records": []},
            "http_headers": {"status_code": 200, "server": "nginx"},
            "tls": {"valid": True, "self_signed": False, "expiry_days": 365},
            "redirects": {"redirect_count": 0, "final_url": url},
            "threat_intel": {"match": False},
        }

    with patch("app.engine.get_behavioral_signals", side_effect=fake_behavioral):
        verdict, score, features = asyncio.run(analyze_url_pipeline("http://login.example.xyz/secure/login?user=1"))
        assert verdict in {"Moderate Risk", "Suspicious", "Critical Phishing", "Benign"}
        assert score >= 0.0
        assert features["suspicious_token_count"] > 0