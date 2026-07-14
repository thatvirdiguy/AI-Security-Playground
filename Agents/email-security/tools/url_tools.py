"""
tools/url_tools.py
URL and link analysis: redirect resolution, TLS check,
PhishTank (free, no key).
"""

import ssl
import socket
import urllib.request
import urllib.error
import json
import re
import os
import hashlib
import time
from typing import Any
from urllib.parse import urlparse

# ── Redirect Chain Resolution ──────────────────────────────────────────────

def resolve_redirect_chain(url: str, max_hops: int = 10) -> dict[str, Any]:
    """
    Follow redirect chain and return all hops + final destination.
    Does NOT execute JavaScript — only follows HTTP 3xx headers.
    """
    chain = []
    current = url
    seen = set()

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    for _ in range(max_hops):
        if current in seen:
            chain.append({"url": current, "status": "redirect_loop"})
            break
        seen.add(current)

        try:
            req = urllib.request.Request(current, headers=headers, method="HEAD")
            # Don't auto-follow — we want to capture each hop
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            # Monkey-patch to not follow
            import http.client

            class NoRedirect(urllib.request.HTTPErrorProcessor):
                def http_response(self, request, response):
                    return response
                https_response = http_response

            no_redirect_opener = urllib.request.build_opener(NoRedirect)
            response = no_redirect_opener.open(urllib.request.Request(current, headers=headers, method="HEAD"), timeout=8)
            status = response.status
            location = response.getheader("Location")
            chain.append({"url": current, "status": status, "location": location})

            if status in (301, 302, 303, 307, 308) and location:
                # Resolve relative redirects
                if location.startswith("/"):
                    parsed = urlparse(current)
                    current = f"{parsed.scheme}://{parsed.netloc}{location}"
                elif not location.startswith("http"):
                    current = f"{current.rstrip('/')}/{location}"
                else:
                    current = location
            else:
                break

        except Exception as e:
            chain.append({"url": current, "status": "error", "error": str(e)})
            break

    final_url = chain[-1]["url"] if chain else url
    final_domain = urlparse(final_url).netloc

    # Flag suspicious final destinations
    suspicious_patterns = [
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Raw IP
        r'\.tk$|\.ml$|\.ga$|\.cf$|\.gq$',       # Free TLDs
        r'ngrok\.io|\.repl\.co|\.glitch\.me',   # Dev tunnels used for phishing
    ]
    is_suspicious = any(
        re.search(p, final_domain) for p in suspicious_patterns
    )

    return {
        "original_url": url,
        "chain": chain,
        "hop_count": len(chain),
        "final_url": final_url,
        "final_domain": final_domain,
        "suspicious_destination": is_suspicious,
    }

# ── TLS Certificate Check ──────────────────────────────────────────────────

def check_tls_certificate(domain: str) -> dict[str, Any]:
    """
    Check TLS certificate validity, issuer, and age.
    Note: valid TLS ≠ safe — Let's Encrypt is free and widely abused by phishers.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        # Parse cert dates
        from datetime import datetime, timezone
        fmt = "%b %d %H:%M:%S %Y %Z"
        issued = datetime.strptime(not_before, fmt).replace(tzinfo=timezone.utc)
        expires = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        cert_age_days = (now - issued).days
        days_until_expiry = (expires - now).days

        # SANs
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        issuer_org = issuer.get("organizationName", "Unknown")
        is_lets_encrypt = "Let's Encrypt" in issuer_org

        return {
            "domain": domain,
            "valid": True,
            "issuer_org": issuer_org,
            "is_lets_encrypt": is_lets_encrypt,
            "cert_age_days": cert_age_days,
            "days_until_expiry": days_until_expiry,
            "subject_cn": subject.get("commonName", ""),
            "sans": sans[:10],
            "note": (
                "Let's Encrypt cert — free and easy to obtain. "
                "Valid TLS does NOT indicate legitimacy."
            ) if is_lets_encrypt else None,
        }

    except ssl.SSLCertVerificationError as e:
        return {"domain": domain, "valid": False,
                "error": "Certificate verification failed", "detail": str(e)}
    except Exception as e:
        return {"domain": domain, "valid": False, "error": str(e)}

# ── PhishTank (free, no API key required for basic checks) ─────────────────

def check_phishtank(url: str) -> dict[str, Any]:
    """
    Check URL against PhishTank's online database.
    PhishTank allows limited anonymous queries.
    """
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    payload = f"url={urllib.parse.quote_plus(url)}&format=json&app_key="

    try:
        import urllib.parse
        data = payload.encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "phishing-agent/1.0",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())

        in_db = result.get("results", {}).get("in_database", False)
        is_phish = result.get("results", {}).get("valid", False)
        return {
            "url": url,
            "in_phishtank_database": in_db,
            "confirmed_phish": is_phish,
        }
    except Exception as e:
        return {"url": url, "error": str(e), "confirmed_phish": False}

# ── Brand Impersonation in URL ─────────────────────────────────────────────

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "chase": "chase.com",
    "irs": "irs.gov",
}

def detect_brand_in_url(url: str) -> dict[str, Any]:
    """
    Detect if a brand name appears in a URL that isn't the brand's real domain.
    For example, paypal.account-verify.com — brand is in subdomain, not apex.
    """
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()

    findings = []
    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in netloc and not netloc.endswith(legit_domain):
            findings.append({
                "brand": brand,
                "legitimate_domain": legit_domain,
                "detected_in": netloc,
                "pattern": "brand_name_in_non_brand_domain",
            })

    return {
        "url": url,
        "brand_impersonation_detected": bool(findings),
        "findings": findings,
    }
