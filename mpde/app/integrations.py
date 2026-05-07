import asyncio
import httpx
import dns.asyncresolver
import whois
from datetime import datetime
from typing import Dict, List, Optional
from app.core import logger

# ==========================================
# 1. ASYNC REDIRECT CLIENT
# ==========================================

async def get_redirect_chain(url: str) -> Dict:
    """
    Follows a URL to its final destination to detect obfuscation layers.
    Enterprise phishing often uses 3-4 redirects to hide the final payload.
    """
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            chain = [str(r.url) for r in response.history] + [str(response.url)]
            return {
                "final_url": str(response.url),
                "redirect_count": len(response.history),
                "chain": chain,
                "status_code": response.status_code
            }
        except Exception as e:
            logger.debug("redirect_check_failed", url=url, error=str(e))
            return {"final_url": url, "redirect_count": 0, "error": "Connection failed"}

# ==========================================
# 2. ASYNC DNS RESOLVER
# ==========================================

async def resolve_dns(domain: str) -> Dict:
    """
    Checks if a domain has valid A records and retrieves the Time-To-Live (TTL).
    Short TTLs (e.g., < 60s) are often used in "Fast-Flux" phishing networks.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    try:
        answers = await resolver.resolve(domain, 'A')
        return {
            "ips": [str(rdata) for rdata in answers],
            "ttl": answers.rrset.ttl,
            "resolved": True
        }
    except Exception:
        return {"ips": [], "ttl": 0, "resolved": False}

# ==========================================
# 3. WHOIS DATA (Thread-Wrapped)
# ==========================================

def _fetch_whois_sync(domain: str) -> Optional[Dict]:
    """Internal synchronous call to be wrapped in an executor."""
    try:
        w = whois.whois(domain)
        # Handle cases where creation_date is a list or a single datetime
        c_date = w.creation_date
        if isinstance(c_date, list):
            c_date = c_date[0]
        
        if not c_date:
            return None

        age_days = (datetime.now() - c_date).days
        return {
            "creation_date": c_date.isoformat(),
            "age_days": age_days,
            "registrar": w.registrar,
            "org": w.org
        }
    except Exception:
        return None

async def get_whois_data(domain: str) -> Optional[Dict]:
    """
    Retrieves domain registration data without blocking the event loop.
    Domain age is the #1 predictor of phishing in enterprise security.
    """
    loop = asyncio.get_event_loop()
    # Runs the sync whois lookup in a separate thread
    return await loop.run_in_executor(None, _fetch_whois_sync, domain)

# ==========================================
# 4. MASTER INTEGRATION WRAPPER
# ==========================================

async def get_behavioral_signals(url: str) -> Dict:
    """
    Aggregates all external signals in parallel for maximum performance.
    """
    import tldextract
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    # Fire off all requests simultaneously
    tasks = [
        get_redirect_chain(url),
        resolve_dns(domain),
        get_whois_data(domain)
    ]
    
    results = await asyncio.gather(*tasks)
    
    return {
        "redirects": results[0],
        "dns": results[1],
        "whois": results[2]
    }