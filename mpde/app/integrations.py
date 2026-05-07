import asyncio
import httpx
import dns.asyncresolver
import whois
import ssl
import socket
import urllib.parse
import tldextract
from datetime import datetime
from typing import Dict, Optional
from app.core import logger, settings

THREAT_INTEL_CACHE = {
    "loaded": False,
    "domains": set(),
    "urls": set()
}


def _normalize_url(url: str) -> str:
    return url if "://" in url else f"http://{url}"


def _get_effective_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(_normalize_url(url))
    ext = tldextract.extract(parsed.netloc)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    if ext.domain:
        return ext.domain
    return parsed.hostname or url


async def get_redirect_chain(url: str) -> Dict:
    normalized = _normalize_url(url)
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            response = await client.get(normalized)
            chain = [str(r.url) for r in response.history] + [str(response.url)]
            return {
                "final_url": str(response.url),
                "redirect_count": len(response.history),
                "chain": chain,
                "status_code": response.status_code
            }
    except Exception as exc:
        logger.debug("redirect_chain_failure", url=url, error=str(exc))
        return {"final_url": url, "redirect_count": 0, "chain": [], "error": str(exc)}


async def resolve_dns(domain: str) -> Dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    try:
        answers = await resolver.resolve(domain, "A")
        return {
            "ips": [str(rdata) for rdata in answers],
            "ttl": answers.rrset.ttl,
            "resolved": True
        }
    except Exception as exc:
        logger.debug("dns_resolution_failure", domain=domain, error=str(exc))
        return {"ips": [], "ttl": 0, "resolved": False, "error": str(exc)}


async def resolve_mx(domain: str) -> Dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    try:
        answers = await resolver.resolve(domain, "MX")
        return {
            "records": [str(r.exchange).rstrip(".") for r in answers],
            "count": len(answers)
        }
    except Exception as exc:
        logger.debug("mx_resolution_failure", domain=domain, error=str(exc))
        return {"records": [], "count": 0, "error": str(exc)}


async def resolve_txt(domain: str) -> Dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    try:
        answers = await resolver.resolve(domain, "TXT")
        records = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
        return {"records": records}
    except Exception as exc:
        logger.debug("txt_resolution_failure", domain=domain, error=str(exc))
        return {"records": [], "error": str(exc)}


def _fetch_whois_sync(domain: str) -> Optional[Dict]:
    try:
        result = whois.whois(domain)
        creation = result.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        age_days = (datetime.utcnow() - creation).days
        return {
            "creation_date": creation.isoformat(),
            "age_days": age_days,
            "registrar": result.registrar,
            "org": result.org,
            "name": getattr(result, "name", None)
        }
    except Exception as exc:
        logger.debug("whois_lookup_failure", domain=domain, error=str(exc))
        return None


async def get_whois_data(domain: str) -> Optional[Dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _fetch_whois_sync, domain)


def _fetch_tls_certificate_sync(host: str, port: int = 443) -> Dict:
    details = {"host": host, "port": port, "valid": False, "self_signed": False, "expiry_days": None, "issuer": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                details["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                details["valid"] = True
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    details["expiry_days"] = max((expiry - datetime.utcnow()).days, 0)
                if cert.get("subject") == cert.get("issuer"):
                    details["self_signed"] = True
    except ssl.SSLError as ssl_exc:
        details["self_signed"] = "self signed" in str(ssl_exc).lower()
        details["error"] = str(ssl_exc)
    except Exception as exc:
        details["error"] = str(exc)
    return details


async def get_tls_certificate(host: str, port: int = 443) -> Dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _fetch_tls_certificate_sync, host, port)


async def get_http_headers(url: str) -> Dict:
    normalized = _normalize_url(url)
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            response = await client.get(normalized)
            return {
                "status_code": response.status_code,
                "server": response.headers.get("server"),
                "content_type": response.headers.get("content-type"),
                "headers": dict(response.headers)
            }
    except Exception as exc:
        logger.debug("http_header_fetch_failure", url=url, error=str(exc))
        return {"status_code": None, "server": None, "content_type": None, "headers": {}, "error": str(exc)}


async def load_threat_intel_feed() -> None:
    enabled = getattr(settings, "TI_ENABLED", False)
    feed_url = getattr(settings, "TI_FEED_URL", "")
    if THREAT_INTEL_CACHE["loaded"] or not enabled or not feed_url:
        return

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(feed_url)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("http://") or line.startswith("https://"):
                        THREAT_INTEL_CACHE["urls"].add(line.lower())
                    else:
                        THREAT_INTEL_CACHE["domains"].add(line.lower())
    except Exception as exc:
        logger.warning("threat_intel_feed_failed", url=feed_url, error=str(exc))
    finally:
        THREAT_INTEL_CACHE["loaded"] = True


async def get_threat_intel_signal(url: str, domain: str) -> Dict:
    await load_threat_intel_feed()
    normalized_url = url.lower()
    normalized_domain = domain.lower()
    match = normalized_domain in THREAT_INTEL_CACHE["domains"] or normalized_url in THREAT_INTEL_CACHE["urls"]
    return {"match": match, "feed_url": getattr(settings, "TI_FEED_URL", None)}


async def get_behavioral_signals(url: str) -> Dict:
    domain = _get_effective_domain(url)
    parsed = urllib.parse.urlparse(_normalize_url(url))
    host = parsed.hostname or domain

    tasks = [
        get_redirect_chain(url),
        resolve_dns(domain),
        resolve_mx(domain),
        resolve_txt(domain),
        get_whois_data(domain),
        get_http_headers(url),
        get_tls_certificate(host),
        get_threat_intel_signal(url, domain),
    ]

    results = await asyncio.gather(*tasks)
    return {
        "redirects": results[0],
        "dns": results[1],
        "mx": results[2],
        "txt": results[3],
        "whois": results[4] or {},
        "http_headers": results[5],
        "tls": results[6],
        "threat_intel": results[7],
    }