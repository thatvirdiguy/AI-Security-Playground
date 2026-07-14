"""
tools/input_loader.py
Format-agnostic email loader.

Accepts a file path ending in .eml or .msg and returns a normalised raw string + format tag that the rest of the agent treats identically.

.eml  -- parsed with the Python standard-library email module.
.msg  -- parsed with extract-msg (pure Python, no Outlook/COM needed).
         Install: pip install extract-msg

Outlook .msg caveat
-------------------
When Outlook saves a .msg file it may omit or truncate SMTP transport headers (Received chain, Authentication-Results, DKIM-Signature). The agent will warn you and continue, but auth signals may be incomplete.  
For full signal coverage, export from your mail client as RFC-822 (.eml) instead.
"""

import pathlib

# ── Entry point ────────────────────────────────────────────────────────────

def load_email(file_path: str) -> dict:
    """
    Accept a .eml or .msg file path.

    Returns a dict with:
        raw_eml           str  -- RFC-822 / pseudo-RFC-822 string for parse_email()
        format            str  -- "eml" or "msg"
        warnings          list -- data-quality warnings to print before the agent
        _msg_attachments  list -- pre-parsed attachments (msg only; eml gets them from parse_email() via the stdlib)
    """
    path = pathlib.Path(file_path)
    if not path.exists():
        raise FileNotFoundError("Email file not found: " + str(file_path))

    suffix = path.suffix.lower()
    if suffix == ".eml":
        return _load_eml(path)
    elif suffix == ".msg":
        return _load_msg(path)
    else:
        raise ValueError(
            "Unsupported format '" + suffix + "'. "
            "Pass a .eml (RFC-822) or .msg (Outlook) file."
        )

# ── .eml loader (behaviour identical to the original direct read in agent.py) ──

def _load_eml(path: pathlib.Path) -> dict:
    raw = path.read_text(encoding="utf-8", errors="replace")
    return {
        "raw_eml": raw,
        "format": "eml",
        "warnings": [],
        "_msg_attachments": [],
    }

# ── .msg loader ────────────────────────────────────────────────────────────

def _load_msg(path: pathlib.Path) -> dict:
    try:
        import extract_msg          # pip install extract-msg
    except ImportError:
        raise ImportError(
            "extract-msg is required for .msg files.\n"
            "Install it with:  pip install extract-msg\n"
            "Then retry."
        )

    msg = extract_msg.openMsg(str(path))
    warnings = []

    # ── Pull envelope fields ────────────────────────────────────────────────
    sender      = msg.sender or ""
    to          = msg.to or ""
    subject     = msg.subject or ""
    date        = str(msg.date) if msg.date else ""
    reply_to    = _hdr(msg, "Reply-To")
    return_path = _hdr(msg, "Return-Path")
    message_id  = _hdr(msg, "Message-ID")
    received    = _hdr_all(msg, "Received")
    auth_res    = _hdr(msg, "Authentication-Results")
    dkim_sig    = _hdr(msg, "DKIM-Signature")
    x_mailer    = _hdr(msg, "X-Mailer") or _hdr(msg, "User-Agent")

    body_text = msg.body or ""

    # htmlBody can be bytes or str depending on extract-msg version
    if hasattr(msg, "htmlBody") and msg.htmlBody:
        body_html = (
            msg.htmlBody.decode("utf-8", errors="replace")
            if isinstance(msg.htmlBody, bytes)
            else msg.htmlBody
        )
    else:
        body_html = ""

    # Attachments
    attachments_raw = []
    for att in (msg.attachments or []):
        attachments_raw.append({
            "filename":   att.longFilename or att.shortFilename or "unnamed",
            "mime_type":  getattr(att, "mimetype", None) or "application/octet-stream",
            "size_bytes": len(att.data or b""),
        })

    # ── Warn on missing SMTP transport headers ───────────────────────────────
    if not received:
        warnings.append(
            "WARNING: No 'Received' headers found in .msg file. "
            "Outlook may have stripped the SMTP transport chain. "
            "SPF/DKIM/DMARC signals may be incomplete; "
            "the agent will fall back to live DNS lookups."
        )
    if not auth_res:
        warnings.append(
            "WARNING: No 'Authentication-Results' header. "
            "Auth checks will rely on live DNS lookups rather than recorded results."
        )
    if not dkim_sig:
        warnings.append(
            "WARNING: No DKIM-Signature header. "
            "DKIM verification is unavailable for this .msg file."
        )

    # ── Reconstruct a pseudo RFC-822 string ──────────────────────────────────
    # parse_email() in header_parser.py accepts a raw RFC-822 string.
    lines = []

    def _add(name, value):
        if value:
            lines.append(name + ": " + value)

    _add("From",                   sender)
    _add("To",                     to)
    _add("Subject",                subject)
    _add("Date",                   date)
    _add("Reply-To",               reply_to)
    _add("Return-Path",            return_path)
    _add("Message-ID",             message_id)
    _add("X-Mailer",               x_mailer)
    _add("Authentication-Results", auth_res)
    _add("DKIM-Signature",         dkim_sig)
    for r in received:
        lines.append("Received: " + r)

    body_for_raw = body_html if body_html else body_text
    raw_eml = "\r\n".join(lines) + "\r\n\r\n" + body_for_raw

    return {
        "raw_eml":          raw_eml,
        "format":           "msg",
        "warnings":         warnings,
        "_msg_attachments": attachments_raw,
    }

# ── extract-msg header helpers ─────────────────────────────────────────────

def _hdr(msg, field: str) -> str:
    """Return the first value of a header field, or ''."""
    if msg.header:
        val = msg.header.get(field, "")
        return str(val) if val else ""
    return ""

def _hdr_all(msg, field: str) -> list:
    """Return all values of a repeated header field (e.g. Received)."""
    if msg.header:
        vals = msg.header.get_all(field, [])
        return [str(v) for v in vals] if vals else []
    return []
