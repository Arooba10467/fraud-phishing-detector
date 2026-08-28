"""
Rule-based security checks for the fraud/phishing detector.

Each function is defensive: if a lookup fails (network issue, no WHOIS
record, etc.) it returns a result dict with ok=False and a human-readable
reason, instead of raising, so the Streamlit app can always show *something*
rather than crashing.
"""

import re
import ssl
import socket
import difflib
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract

from brand_domains import KNOWN_BRAND_DOMAINS

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at",
    "qrco.de", "t.ly", "rb.gy", "shrtco.de", "v.gd", "s.id",
    "lnkd.in", "qr.link", "bl.ink", "tiny.cc",
}


def extract_urls(text: str) -> list[str]:
    """Pull out anything that looks like a URL from a pasted message.

    Handles a common copy-paste artifact where a line break lands right
    after the scheme (e.g. "https://\\nexample.com"), which would otherwise
    split one URL into two non-matching fragments.
    """
    # Join a scheme immediately followed by whitespace/newline back onto
    # the rest of the URL — a real URL never has whitespace right after
    # "http://" or "https://".
    cleaned = re.sub(r"(https?://)\s+", r"\1", text, flags=re.IGNORECASE)

    found = URL_REGEX.findall(cleaned)
    normalized = []
    for u in found:
        if not u.lower().startswith("http"):
            u = "http://" + u
        normalized.append(u.rstrip(".,)"))
    return normalized


def registered_domain(url: str) -> str:
    """Return the registrable domain, e.g. 'jazzcash-pk-verify.com'."""
    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix:
        return urlparse(url).netloc
    return f"{ext.domain}.{ext.suffix}"


def is_ip_based(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def check_typosquatting(url: str) -> dict:
    """Compare the domain against known brand domains via edit-distance similarity."""
    domain = registered_domain(url).lower()

    if domain in KNOWN_BRAND_DOMAINS:
        return {"ok": True, "flagged": False, "domain": domain,
                "reason": "Exact match with a known legitimate brand domain."}

    best_match, best_score = None, 0.0
    for brand in KNOWN_BRAND_DOMAINS:
        score = difflib.SequenceMatcher(None, domain, brand).ratio()
        if score > best_score:
            best_match, best_score = brand, score

    # High similarity but not an exact match = classic typosquat pattern
    flagged = best_score >= 0.75 and domain != best_match
    return {
        "ok": True,
        "flagged": flagged,
        "domain": domain,
        "closest_brand": best_match,
        "similarity": round(best_score, 2),
        "reason": (
            f"Domain closely resembles '{best_match}' (similarity {best_score:.0%}) "
            "but is not the real domain — likely typosquatting."
            if flagged else "No strong resemblance to known brand domains."
        ),
    }


def check_domain_age(url: str) -> dict:
    """WHOIS lookup for domain creation date. Newly registered = higher risk."""
    domain = registered_domain(url)
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return {"ok": False, "reason": "No creation date returned by WHOIS."}

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days

        return {
            "ok": True,
            "domain": domain,
            "created": created.isoformat(),
            "age_days": age_days,
            "flagged": age_days < 90,
            "reason": (
                f"Domain registered only {age_days} days ago — newly "
                "registered domains are commonly used for scams."
                if age_days < 90 else
                f"Domain is {age_days} days old — not newly registered."
            ),
        }
    except Exception as e:
        return {"ok": False, "reason": f"WHOIS lookup failed/unavailable: {e}"}


def check_ssl_certificate(url: str) -> dict:
    """Check whether the host presents a valid SSL certificate."""
    host = urlparse(url).hostname
    if not host:
        return {"ok": False, "reason": "Could not parse hostname."}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return {"ok": True, "flagged": False, "reason": "Valid SSL certificate presented."}
    except ssl.SSLCertVerificationError as e:
        return {"ok": True, "flagged": True, "reason": f"Invalid/untrusted SSL certificate: {e}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"ok": False, "flagged": True,
                "reason": f"Could not establish HTTPS connection (possibly no SSL at all): {e}"}


def check_url_structure(url: str) -> dict:
    """Flag structural red flags: IP-based host, shorteners, excessive subdomains, '@' redirect trick."""
    host = urlparse(url).hostname or ""
    flags = []

    if is_ip_based(url):
        flags.append("URL uses a raw IP address instead of a domain name.")
    if host in SHORTENER_DOMAINS:
        flags.append("URL uses a link shortener, which hides the real destination.")
    if host.count(".") >= 4:
        flags.append("Unusually long subdomain chain — often used to disguise fake domains.")
    if "@" in url:
        flags.append("URL contains '@', which can be used to disguise the real destination.")

    return {"ok": True, "flagged": bool(flags), "reasons": flags or ["No structural red flags found."]}


def run_all_url_checks(url: str) -> dict:
    """Run every rule-based check on a single URL and bundle the results."""
    return {
        "url": url,
        "typosquatting": check_typosquatting(url),
        "domain_age": check_domain_age(url),
        "ssl": check_ssl_certificate(url),
        "structure": check_url_structure(url),
    }