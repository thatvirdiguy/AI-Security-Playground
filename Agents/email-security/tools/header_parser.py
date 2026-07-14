"""
tools/header_parser.py
Parse raw .eml content into structured envelope and body data.
Uses only the Python standard library.
"""

import email
import email.policy
import re
import quopri
import base64
from email import message_from_string
from email.header import decode_header
from typing import Any

def _decode_header_value(value: str) -> str:
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)

def _extract_text(msg) -> tuple[str, str]:
    """Return (plain_text, html_text) from a message."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cte = part.get("Content-Transfer-Encoding", "").lower()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if ct == "text/plain" and not plain:
                plain = text
            elif ct == "text/html" and not html:
                html = text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                html = text
            else:
                plain = text
    return plain, html

def _extract_links(html: str) -> list[str]:
    """Pull all href values from HTML."""
    return re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)

def _extract_received_ips(headers: list) -> list[str]:
    """Pull IPs from Received headers (last hop = origin)."""
    ip_pattern = re.compile(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]')
    ips = []
    for h in headers:
        found = ip_pattern.findall(h)
        ips.extend(found)
    return ips

def parse_email(raw_eml: str) -> dict[str, Any]:
    """
    Parse a raw .eml string into structured data.
    Returns a dict with envelope, auth headers, body, links, attachments.
    """
    msg = message_from_string(raw_eml, policy=email.policy.compat32)

    from_raw = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    to = msg.get("To", "")
    subject = _decode_header_value(msg.get("Subject", ""))
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    x_mailer = msg.get("X-Mailer", msg.get("User-Agent", ""))

    # Extract display name and actual domain from From
    from_match = re.match(r'^"?([^"<]*)"?\s*<?([^>]*)>?$', from_raw.strip())
    from_display = from_match.group(1).strip() if from_match else from_raw
    from_address = from_match.group(2).strip() if from_match else from_raw
    from_domain = from_address.split("@")[-1] if "@" in from_address else ""

    reply_to_domain = ""
    if reply_to:
        rt_match = re.search(r'@([\w.\-]+)', reply_to)
        reply_to_domain = rt_match.group(1) if rt_match else ""

    received_headers = msg.get_all("Received") or []
    originating_ips = _extract_received_ips(received_headers)

    # Auth results
    auth_results = msg.get("Authentication-Results", "")
    dkim_raw = msg.get("DKIM-Signature", "")

    plain_text, html_body = _extract_text(msg)
    links = _extract_links(html_body) if html_body else _extract_links(plain_text)

    # Attachments
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename() or "unknown",
                "mime_type": part.get_content_type(),
                "size_bytes": len(part.get_payload(decode=True) or b""),
            })

    return {
        "envelope": {
            "from_raw": from_raw,
            "from_display_name": from_display,
            "from_address": from_address,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "return_path": return_path,
            "to": to,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "x_mailer": x_mailer,
        },
        "auth_headers": {
            "authentication_results": auth_results,
            "dkim_signature_present": bool(dkim_raw),
            "received_chain": received_headers[:5],  # cap at 5
            "originating_ips": originating_ips,
        },
        "body": {
            "plain_text": plain_text[:3000],  # truncate for LLM
            "html_present": bool(html_body),
            "html_snippet": html_body[:2000] if html_body else "",
        },
        "links": list(set(links))[:30],  # dedupe, cap at 30
        "attachments": attachments,
    }
