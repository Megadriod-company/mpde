import pytest
from app.engine import calculate_entropy, get_lexical_features

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