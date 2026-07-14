"""
tools/dns_tools.py
DNS-based checks: SPF, DMARC, domain age via WHOIS, typosquatting.
Uses: dnspython, python-whois (both free, no API key needed).
"""

import re
import socket
from datetime import datetime, timezone
from typing import Any

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as pythonwhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

# ── SPF / DMARC ────────────────────────────────────────────────────────────

def check_spf(domain: str) -> dict[str, Any]:
    """Check SPF record existence and policy."""
    if not HAS_DNS:
        return {"error": "dnspython not installed"}
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text().strip('"')
            for r in answers
            if "v=spf1" in r.to_text()
        ]
        if not spf_records:
            return {"found": False, "policy": "none", "raw": None}
        raw = spf_records[0]
        if "~all" in raw:
            policy = "softfail"
        elif "-all" in raw:
            policy = "fail"
        elif "+all" in raw:
            policy = "pass_all (dangerous)"
        elif "?all" in raw:
            policy = "neutral"
        else:
            policy = "unknown"
        return {"found": True, "policy": policy, "raw": raw}
    except Exception as e:
        return {"error": str(e), "found": False}

def check_dmarc(domain: str) -> dict[str, Any]:
    """Check DMARC record and policy."""
    if not HAS_DNS:
        return {"error": "dnspython not installed"}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            raw = r.to_text().strip('"')
            if "v=DMARC1" in raw:
                p_match = re.search(r'p=(\w+)', raw)
                policy = p_match.group(1) if p_match else "unknown"
                return {"found": True, "policy": policy, "raw": raw}
        return {"found": False, "policy": "none"}
    except Exception as e:
        return {"error": str(e), "found": False}

def check_mx(domain: str) -> dict[str, Any]:
    """Check whether the domain has MX records."""
    if not HAS_DNS:
        return {"error": "dnspython not installed"}
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = [str(r.exchange) for r in answers]
        return {"found": True, "mx_records": mx_records}
    except Exception:
        return {"found": False, "mx_records": []}

# ── WHOIS / Domain Age ─────────────────────────────────────────────────────

def check_domain_age(domain: str) -> dict[str, Any]:
    """Query WHOIS for domain registration date. Age < 30 days is high risk."""
    if not HAS_WHOIS:
        return {"error": "python-whois not installed"}
    try:
        w = pythonwhois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return {"error": "No creation date found", "domain": domain}
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - creation).days
        return {
            "domain": domain,
            "registered": creation.isoformat(),
            "age_days": age_days,
            "registrar": w.registrar,
            "registrant_country": getattr(w, "country", None),
            "risk_flag": age_days < 30,
        }
    except Exception as e:
        return {"error": str(e), "domain": domain}

# ── Typosquatting Detection ────────────────────────────────────────────────

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "spotify": "spotify.com",
    "steam": "steampowered.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "irs": "irs.gov",
}

HOMOGLYPHS = str.maketrans({
    "0": "o", 
    "1": "l", 
    "3": "e", 
    "4": "a",
    "5": "s", 
    "6": "g", 
    "7": "t", 
    "8": "b",
    "@": "a", 
    "!": "i", 
    "|": "l",
})

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]

def detect_typosquatting(domain: str) -> dict[str, Any]:
    """
    Check if a domain is a typosquat of any known brand.
    Checks each hyphen-delimited segment separately, using Levenshtein distance and homoglyph normalization.
    Examples caught: paypa1-alerts.net, arnazon-orders.com, micros0ft.co
    """
    domain_lower = domain.lower()
    # Strip TLD, split on hyphens to check each part independently
    no_tld = re.sub(r'\.[a-z]{2,}$', '', domain_lower)
    parts = no_tld.split('-')

    matches = []
    seen_brands = set()

    for brand, legit_domain in KNOWN_BRANDS.items():
        if brand in seen_brands:
            continue
        legit_base = legit_domain.split(".")[0]

        # Skip if this IS the real domain
        if domain_lower.endswith(legit_domain):
            continue

        for part in parts:
            part_normalized = part.translate(HOMOGLYPHS)
            dist = _levenshtein(part_normalized, legit_base)

            if dist == 0 and part != legit_base:
                # Exact match after homoglyph normalization
                matches.append({
                    "brand": brand,
                    "legitimate_domain": legit_domain,
                    "match_type": "homoglyph_substitution",
                    "segment": part,
                    "normalized_to": part_normalized,
                    "distance": 0,
                })
                seen_brands.add(brand)
                break
            elif 0 < dist <= 2:
                matches.append({
                    "brand": brand,
                    "legitimate_domain": legit_domain,
                    "match_type": "typosquat",
                    "segment": part,
                    "distance": dist,
                })
                seen_brands.add(brand)
                break

        # Catch brand substring in non-brand domain (e.g. paypal.verify-now.com)
        if brand not in seen_brands and brand in domain_lower:
            matches.append({
                "brand": brand,
                "legitimate_domain": legit_domain,
                "match_type": "brand_substring_in_non_brand_domain",
                "distance": 0,
            })
            seen_brands.add(brand)

    return {
        "domain": domain,
        "typosquatting_detected": bool(matches),
        "matches": matches,
    }

# ── Display Name Spoofing ──────────────────────────────────────────────────

def check_display_name_spoofing(display_name: str, from_domain: str) -> dict[str, Any]:
    """
    Check if the display name claims to be a brand whose domain does not match the actual From domain.
    """
    display_lower = display_name.lower()
    spoofing_detected = False
    spoofed_brand = None

    for brand, legit_domain in KNOWN_BRANDS.items():
        if brand in display_lower:
            if not from_domain.lower().endswith(legit_domain):
                spoofing_detected = True
                spoofed_brand = brand
                break

    return {
        "display_name": display_name,
        "from_domain": from_domain,
        "spoofing_detected": spoofing_detected,
        "impersonated_brand": spoofed_brand,
    }
