"""
tools/content_tools.py
Email body content analysis: urgency language, reply-to divergence, attachment risk scoring. No external APIs — pure Python.
"""

import re
from typing import Any

# ── Urgency / Manipulation Language Detector ───────────────────────────────

URGENCY_PATTERNS = [
    # Threat / consequence
    (r'\baccount.{0,20}(suspend|terminat|clos|block|restrict|lock)', 3),
    (r'\b(suspend|terminat|clos|block|restrict|lock).{0,20}account', 3),
    (r'\bunusual.{0,20}(activity|sign.?in|login|access)', 2),
    (r'\bverif(y|ication).{0,20}(immediately|now|urgent|required)', 2),
    (r'\byour.{0,20}(password|credential).{0,20}(expir|reset|comprom)', 3),
    # Deadline pressure
    (r'\b(24|48|72)\s*hours?', 2),
    (r'\bimmediately\b', 1),
    (r'\burgently?\b', 1),
    (r'\baction required\b', 2),
    (r'\bdeadline\b', 1),
    (r'\blast.{0,10}(chance|warning|notice)', 2),
    # Reward / too good to be true
    (r'\b(won|winner|selected|chosen).{0,20}(prize|reward|gift|lottery)', 3),
    (r'\bfree.{0,10}(gift|offer|trial|money|cash)', 2),
    (r'\bclaim.{0,10}(reward|prize|refund)', 2),
    # Credential harvesting triggers
    (r'\bconfirm.{0,20}(identity|account|details|information)', 2),
    (r'\bupdate.{0,20}(billing|payment|credit card|bank)', 2),
    (r'\bclick.{0,20}(here|below|link|button).{0,20}(verify|confirm|update)', 2),
    (r'\blog.{0,5}in.{0,20}(secure|verify|confirm)', 2),
]

MANIPULATION_KEYWORDS = [
    "urgent", 
    "immediately", 
    "suspended", 
    "verify", 
    "confirm", 
    "click here", 
    "act now", 
    "limited time", 
    "expires", 
    "locked", 
    "unusual activity", 
    "security alert", 
    "account access",
]

def analyze_urgency_language(text: str) -> dict[str, Any]:
    """
    Score email body for urgency and manipulation language.
    Returns score (0-10), matched patterns, and risk level.
    """
    text_lower = text.lower()
    matched = []
    total_score = 0

    for pattern, weight in URGENCY_PATTERNS:
        m = re.search(pattern, text_lower)
        if m:
            matched.append({
                "pattern": pattern,
                "match": m.group(0),
                "weight": weight,
            })
            total_score += weight

    # Count keyword hits
    keyword_hits = [kw for kw in MANIPULATION_KEYWORDS if kw in text_lower]

    # Normalize score to 0-10
    normalized = min(total_score / 2, 10)

    if normalized >= 7:
        risk = "high"
    elif normalized >= 4:
        risk = "medium"
    elif normalized >= 1:
        risk = "low"
    else:
        risk = "none"

    return {
        "urgency_score": round(normalized, 1),
        "risk_level": risk,
        "matched_patterns": [m["match"] for m in matched],
        "keyword_hits": keyword_hits,
        "note": (
            "Low urgency score does not rule out phishing — sophisticated attacks often avoid urgency language."
        ) if normalized < 2 else None,
    }

# ── Reply-To Divergence ────────────────────────────────────────────────────

def check_reply_to_divergence(
    from_domain: str,
    reply_to: str,
    return_path: str
) -> dict[str, Any]:
    """
    Check whether Reply-To or Return-Path domains differ from From domain.
    Divergence is a classic phishing signal — replies go to the attacker.
    """
    issues = []

    def extract_domain(addr: str) -> str:
        m = re.search(r'@([\w.\-]+)', addr)
        return m.group(1).lower() if m else ""

    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    if reply_to_domain and reply_to_domain != from_domain.lower():
        # Gmail/Outlook divergence is normal (mailing lists etc.)
        # Flag only if reply-to is a free mail provider or completely unrelated
        free_providers = {"gmail.com", "yahoo.com", "hotmail.com",
                          "outlook.com", "protonmail.com", "icloud.com"}
        severity = "high" if reply_to_domain in free_providers else "medium"
        issues.append({
            "type": "reply_to_divergence",
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "severity": severity,
            "description": (
                f"Reply-To ({reply_to_domain}) differs from From domain "
                f"({from_domain}). Replies go to a different address than sender."
            ),
        })

    if return_path_domain and return_path_domain != from_domain.lower():
        issues.append({
            "type": "return_path_divergence",
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "severity": "medium",
            "description": (
                f"Return-Path ({return_path_domain}) differs from From domain "
                f"({from_domain}). Bounce messages go to a different address."
            ),
        })

    return {
        "reply_to_domain": reply_to_domain or None,
        "return_path_domain": return_path_domain or None,
        "from_domain": from_domain,
        "divergence_detected": bool(issues),
        "issues": issues,
    }

# ── Attachment Risk Scorer ─────────────────────────────────────────────────

HIGH_RISK_EXTENSIONS = {
    ".exe", 
    ".msi", 
    ".bat", 
    ".cmd", 
    ".ps1", 
    ".vbs", 
    ".js",
    ".jar", 
    ".scr", 
    ".pif", 
    ".com", 
    ".lnk",
}
MEDIUM_RISK_EXTENSIONS = {
    ".zip", 
    ".rar", 
    ".7z", 
    ".gz", 
    ".tar",
    ".docm", ".xlsm", ".pptm",     # Macro-enabled Office
    ".iso", 
    ".img", 
    ".dmg",
    ".html", ".htm",                # HTML smuggling
}
DOUBLE_EXTENSION_PATTERN = re.compile(
    r'\.(pdf|docx?|xlsx?|jpg|png)\.(exe|msi|bat|cmd|ps1|vbs)$',
    re.IGNORECASE
)

def score_attachments(attachments: list[dict]) -> dict[str, Any]:
    """
    Risk-score a list of email attachments.
    Returns per-attachment risk and overall assessment.
    """
    if not attachments:
        return {"count": 0, "overall_risk": "none", "details": []}

    scored = []
    max_risk = "none"
    risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for att in attachments:
        filename = att.get("filename", "")
        mime = att.get("mime_type", "")
        size = att.get("size_bytes", 0)

        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        flags = []
        risk = "low"

        if ext in HIGH_RISK_EXTENSIONS:
            risk = "critical"
            flags.append(f"Executable file type ({ext})")
        elif ext in MEDIUM_RISK_EXTENSIONS:
            risk = "medium"
            flags.append(f"Potentially dangerous file type ({ext})")

        if DOUBLE_EXTENSION_PATTERN.search(filename):
            risk = "critical"
            flags.append("Double extension detected — disguised executable")

        if filename.lower().endswith(".pdf") and "html" in mime:
            risk = "high"
            flags.append("PDF extension but HTML MIME type — possible HTML smuggling")

        if size > 50_000_000:
            flags.append("Large attachment (>50MB)")

        scored.append({
            "filename": filename,
            "mime_type": mime,
            "size_bytes": size,
            "risk": risk,
            "flags": flags,
        })

        if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
            max_risk = risk

    return {
        "count": len(attachments),
        "overall_risk": max_risk,
        "details": scored,
    }
