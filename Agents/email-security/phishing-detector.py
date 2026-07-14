#!/usr/bin/env python3
"""
Phishing Detector AI Agent
==========================
A ReAct-style agent that investigates email files for phishing indicators.

Configuration (environment variables):
    OPENAI_API_KEY               (required)

Usage:
    python phishing_detector.py path/to/email.eml
    python phishing_detector.py path/to/email.eml --quiet
    python phishing_detector.py path/to/email.msg
    python phishing_detector.py path/to/email.msg --quiet

Both .eml (RFC-822) and .msg (Outlook saved email) are supported.
For .msg support install the optional dependency first:
    pip install extract-msg
"""

import json
import os
import re
import sys
import textwrap
from typing import Any
# ── LangChain ─────────────────────────────────────────────────────────────────────
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
# ── Tool function imports ─────────────────────────────────────────────────────────
from tools.input_loader import load_email
from tools.header_parser import parse_email
from tools.dns_tools import (
    check_spf, check_dmarc, check_mx,
    check_domain_age, detect_typosquatting,
    check_display_name_spoofing,
)
from tools.url_tools import (
    resolve_redirect_chain, check_tls_certificate,
    check_google_safe_browsing, check_phishtank,
    detect_brand_in_url,
)
from tools.content_tools import (
    analyze_urgency_language, check_reply_to_divergence,
    score_attachments,
)

# ─────────────────────────────────────────────────────────────────────────────
# LangChain @tool wrappers
# ─────────────────────────────────────────────────────────────────────────────

@tool
def tool_check_spf(domain: str) -> str:
    """
    Check SPF DNS record for a domain.
    Returns whether SPF exists, the policy (pass/softfail/fail/none), and the raw record. 
    Call this to determine if the sending domain has proper email authentication configured.
    """
    return json.dumps(check_spf(domain), default=str)

@tool
def tool_check_dmarc(domain: str) -> str:
    """
    Check DMARC DNS record for a domain.
    Returns the DMARC policy (none/quarantine/reject) and raw record. 
    A missing or 'none' DMARC policy means the domain owner does not enforce email authentication - and cannot prevent spoofing.
    """
    return json.dumps(check_dmarc(domain), default=str)

@tool
def tool_check_mx(domain: str) -> str:
    """
    Check whether a domain has MX records (real mail infrastructure).
    A domain sending email without MX records is suspicious - it suggests the domain was set up purely for sending phishing mail.
    """
    return json.dumps(check_mx(domain), default=str)

@tool
def tool_check_domain_age(domain: str) -> str:
    """
    Query WHOIS to find when a domain was registered and how old it is.
    Domains registered less than 30 days ago are a major red flag for phishing. 
    Returns registration date, age in days, registrar, and a risk flag.
    """
    return json.dumps(check_domain_age(domain), default=str)

@tool
def tool_detect_typosquatting(domain: str) -> str:
    """
    Check whether a domain is a typosquat of a known brand.
    Uses Levenshtein distance and homoglyph normalization to detect lookalike domains like 'paypa1.com', 'arnazon.com', 'micros0ft.com'.
    """
    return json.dumps(detect_typosquatting(domain), default=str)

@tool
def tool_check_display_name_spoofing(display_name: str, from_domain: str) -> str:
    """
    Check if the email display name claims to be a known brand while the actual From domain is unrelated. 
    For example, a display name of 'PayPal Security' with a From domain of 'paypal-alert.net' is display name spoofing.
    """
    return json.dumps(
        check_display_name_spoofing(display_name, from_domain), default=str
    )

@tool
def tool_resolve_redirect_chain(url: str) -> str:
    """
    Follow all HTTP redirects for a URL and return the full chain. 
    Resolves link shorteners and multi-hop redirects. 
    A final destination on a raw IP or a free TLD (.tk, .ml) is a strong phishing indicator.
    """
    return json.dumps(resolve_redirect_chain(url), default=str)

@tool
def tool_check_tls_certificate(domain: str) -> str:
    """
    Check the TLS certificate for a domain: validity, issuer, and age.
    IMPORTANT: A valid TLS certificate does NOT mean the site is safe - Let's Encrypt is free and widely used by phishing sites. 
    A certificate younger than 7 days is suspicious.
    """
    return json.dumps(check_tls_certificate(domain), default=str)

@tool
def tool_check_phishtank(url: str) -> str:
    """
    Check a URL against PhishTank's community-verified phishing database.
    Free, no API key required.
    """
    return json.dumps(check_phishtank(url), default=str)

@tool
def tool_detect_brand_in_url(url: str) -> str:
    """
    Detect if a known brand name appears in a URL that doesn't belong to the brand's legitimate domain. 
    For example, 'paypal.account-verify.com' contains 'paypal' but is not paypal.com - a classic phishing pattern.
    """
    return json.dumps(detect_brand_in_url(url), default=str)

@tool
def tool_analyze_urgency_language(text: str) -> str:
    """
    Analyze email body text for urgency and manipulation language: account suspension threats, artificial deadlines, prize claims.
    Returns a 0-10 urgency score.
    NOTE: Low score does NOT mean legitimate - sophisticated phishing increasingly avoids urgency language.
    """
    return json.dumps(analyze_urgency_language(text), default=str)

@tool
def tool_check_reply_to_divergence(
    from_domain: str, reply_to: str, return_path: str
) -> str:
    """
    Check whether Reply-To or Return-Path addresses differ from the From domain.
    Divergence means replies reach a different address than the apparent sender - a classic phishing pattern where the attacker harvests credentials or replies.
    """
    return json.dumps(
        check_reply_to_divergence(from_domain, reply_to, return_path),
        default=str,
    )

@tool
def tool_score_attachments(attachments_json: str) -> str:
    """
    Risk-score email attachments by file type and name.
    Detects executables, macro-enabled Office docs, double extensions (invoice.pdf.exe), and HTML smuggling.
    Pass a JSON list of objects with 'filename', 'mime_type', 'size_bytes'.
    """
    try:
        attachments = json.loads(attachments_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON for attachments"})
    return json.dumps(score_attachments(attachments), default=str)

ALL_TOOLS = [
    tool_check_spf,
    tool_check_dmarc,
    tool_check_mx,
    tool_check_domain_age,
    tool_detect_typosquatting,
    tool_check_display_name_spoofing,
    tool_resolve_redirect_chain,
    tool_check_tls_certificate,
    tool_check_google_safe_browsing,
    tool_check_phishtank,
    tool_detect_brand_in_url,
    tool_analyze_urgency_language,
    tool_check_reply_to_divergence,
    tool_score_attachments,
]

# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert email security analyst investigating whether an email is a phishing attempt, spam, or legitimate.

You have been given the parsed contents of an email. Your job is to determine the verdict with enough evidence to explain your reasoning clearly to a non-technical recipient.

## Your investigation process
1. Review the envelope: who claims to send this, what is the actual From domain, is there a Reply-To divergence, what does the subject line suggest?
2. Form an early hypothesis after your first 2-3 observations.
3. Use tools to CONFIRM or REFUTE that hypothesis -- every tool call should answer a specific question you have.
4. Check the From domain: SPF, DMARC, domain age, typosquatting.
5. If links are present, resolve at least the primary CTA link and check for brand impersonation in URLs.
6. Analyze the body for urgency and manipulation language.
7. If attachments are present, score them.
8. Stop when confidence >= 0.80, or after 12 tool calls.

## Critical reasoning rules
- DKIM passing on a brand-new domain is MORE suspicious, not less. It means the attacker properly set up mail infrastructure.
- Valid TLS is not safe. Let's Encrypt is free. New cert on new domain = red flag.
- Low urgency score does NOT indicate legitimacy. Sophisticated phishing increasingly avoids urgency language.
- Reply-To pointing to a free provider (Gmail, Yahoo) = strong indicator.
- Cross-reference signals: one flag alone may be benign; 3+ together is conclusive.

## Output format
After your investigation, output a structured verdict in this EXACT format:

---VERDICT---
VERDICT: [PHISHING | SUSPICIOUS | LEGITIMATE | UNCERTAIN]
CONFIDENCE: [0.0-1.0]

PRIMARY INDICATORS:
- [HIGH/MED/LOW] [indicator description]

REASONING:
[2-4 sentences. Explain how signals combine. Note any contradictions resolved.]

RECOMMENDED ACTION:
[One concrete action for the recipient]
---END VERDICT---
"""

# ─────────────────────────────────────────────────────────────────────────────
# Agent loop
# ─────────────────────────────────────────────────────────────────────────────

def _build_agent(verbose: bool = True) -> AgentExecutor:
    llm = ChatOpenAI(model="gpt-4o", temperature=0, streaming=False)
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])
    agent = create_openai_tools_agent(llm, ALL_TOOLS, prompt)
    return AgentExecutor(
        agent=agent,
        tools=ALL_TOOLS,
        verbose=verbose,
        max_iterations=14,
        handle_parsing_errors=True,
    )

def _investigate(
    raw_eml: str,
    verbose: bool = True,
    msg_attachments: list = None,
    email_format: str = "eml",
) -> dict[str, Any]:
    """
    Parse the email and run the ReAct investigation.

    raw_eml:         RFC-822 string (or pseudo-RFC-822 reconstructed from .msg).
    verbose:         Show the LangChain ReAct trace while running.
    msg_attachments: Pre-parsed attachments for .msg files (Outlook strips MIME).
    email_format:    "eml" or "msg" -- surfaced in the report footer.
    """
    parsed = parse_email(raw_eml)

    if msg_attachments:
        # Outlook strips MIME parts from .msg -- use attachments from extract-msg
        parsed["attachments"] = msg_attachments

    parsed["email_format"] = email_format

    env  = parsed["envelope"]
    auth = parsed["auth_headers"]
    body = parsed["body"]

    msg_note = (
        " (Outlook .msg -- some transport headers may be absent)"
        if email_format == "msg" else ""
    )

    context_lines = [
        "Parsed email for investigation:",
        "Input format: " + email_format.upper() + msg_note,
        "",
        "=== ENVELOPE ===",
        "From (display name): " + env["from_display_name"],
        "From (address):      " + env["from_address"],
        "From (domain):       " + env["from_domain"],
        "Reply-To:            " + (env["reply_to"] or "none"),
        "Return-Path:         " + (env["return_path"] or "none"),
        "Subject:             " + env["subject"],
        "Date:                " + env["date"],
        "X-Mailer:            " + (env["x_mailer"] or "not set"),
        "",
        "=== AUTH HEADERS ===",
        "Authentication-Results: " + (auth["authentication_results"] or "not present"),
        "DKIM Signature present: " + str(auth["dkim_signature_present"]),
        "Originating IPs: " + str(auth["originating_ips"]),
        "",
        "=== BODY ===",
        "Plain text preview:",
        body["plain_text"][:1500] if body["plain_text"] else "[no plain text body]",
        "",
        "=== LINKS FOUND (" + str(len(parsed["links"])) + ") ===",
        "\n".join(parsed["links"][:15]) if parsed["links"] else "none",
        "",
        "=== ATTACHMENTS (" + str(len(parsed["attachments"])) + ") ===",
        json.dumps(parsed["attachments"], indent=2) if parsed["attachments"] else "none",
        "",
        "Begin your investigation now.",
    ]

    executor = _build_agent(verbose=verbose)
    result = executor.invoke({"input": "\n".join(context_lines)})

    return {
        "parsed_email":       parsed,
        "agent_output":       result["output"],
        "steps_taken":        len(result.get("intermediate_steps", [])),
        "intermediate_steps": result.get("intermediate_steps", []),
        "email_format":       email_format,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Console output
# ─────────────────────────────────────────────────────────────────────────────

class _C:
    """ANSI colour codes."""
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"

def _section(title: str, width: int = 72) -> str:
    pad = width - len(title) - 4
    return "\n" + _C.DIM + ("-- " + title + " " + "-" * pad) + _C.RESET

def _wrap(text: str, indent: int = 2, width: int = 70) -> str:
    return textwrap.fill(
        text, width=width,
        initial_indent=" " * indent,
        subsequent_indent=" " * indent,
    )

def _parse_verdict_block(output: str) -> dict[str, str]:
    block_match = re.search(
        r"---VERDICT---(.*?)---END VERDICT---", output, re.DOTALL
    )
    if not block_match:
        return {"raw": output}

    block = block_match.group(1)

    def _grab(pattern):
        m = re.search(pattern, block, re.DOTALL)
        return m.group(1).strip() if m else ""

    return {
        "verdict":    _grab(r"VERDICT:\s*(.+)"),
        "confidence": _grab(r"CONFIDENCE:\s*([\d.]+)"),
        "indicators": _grab(r"PRIMARY INDICATORS:(.*?)(?:REASONING:|$)"),
        "reasoning":  _grab(r"REASONING:(.*?)(?:RECOMMENDED ACTION:|$)"),
        "action":     _grab(r"RECOMMENDED ACTION:(.*?)$"),
    }

_VERDICT_STYLE = {
    "PHISHING":   (_C.BG_RED,    _C.RED,    "PHISHING DETECTED"),
    "SUSPICIOUS": (_C.BG_YELLOW, _C.YELLOW, "SUSPICIOUS EMAIL"),
    "LEGITIMATE": (_C.BG_GREEN,  _C.GREEN,  "LIKELY LEGITIMATE"),
    "UNCERTAIN":  (_C.BG_BLUE,   _C.WHITE,  "UNCERTAIN"),
}

def _print_report(result: dict[str, Any]) -> None:
    W = 72
    parsed = result["parsed_email"]
    output = result["agent_output"]
    steps  = result["steps_taken"]
    env    = parsed["envelope"]

    divider = _C.BOLD + _C.CYAN + ("=" * W) + _C.RESET

    print()
    print(divider)
    print(_C.BOLD + _C.WHITE + "  PHISHING INVESTIGATION REPORT" + _C.RESET)
    print(divider)

    # ── Email summary ─────────────────────────────────────────────────────────
    print(_section("EMAIL SUMMARY", W))
    print("  " + _C.DIM + "From:    " + _C.RESET + _C.BOLD + env["from_display_name"] + _C.RESET + " " + _C.DIM + "<" + env["from_address"] + ">" + _C.RESET)
    print("  " + _C.DIM + "Domain:  " + _C.RESET + _C.YELLOW + env["from_domain"] + _C.RESET)
    print("  " + _C.DIM + "Subject: " + _C.RESET + env["subject"])
    print("  " + _C.DIM + "Date:    " + _C.RESET + env["date"])
    if env.get("reply_to"):
        print("  " + _C.DIM + "Reply-To:" + _C.RESET + _C.YELLOW + " " + env["reply_to"] + _C.RESET)
    print("  " + _C.DIM + "Links: " + _C.RESET + str(len(parsed["links"])) + "  " + _C.DIM + "Attachments: " + _C.RESET + str(len(parsed["attachments"])) + "  " + _C.DIM + "Tool calls: " + _C.RESET + str(steps))

    # ── Parse verdict ─────────────────────────────────────────────────────────
    v = _parse_verdict_block(output)

    if "raw" in v:
        # Agent didn't follow the format - print raw output as fallback
        print(_section("AGENT OUTPUT", W))
        print(_wrap(output, indent=2, width=W))
        return

    verdict_key = v["verdict"].split()[0].upper()
    bg, fg, label = _VERDICT_STYLE.get(verdict_key, (_C.BG_BLUE, _C.WHITE, v["verdict"]))

    # ── Verdict banner ────────────────────────────────────────────────────────
    print()
    banner = "  " + label + "  --  Confidence: " + v["confidence"]
    pad = max(W - len(banner) - 2, 0)
    print(bg + _C.BOLD + _C.WHITE + banner + (" " * pad) + _C.RESET)

    # ── Primary indicators ────────────────────────────────────────────────────
    if v["indicators"]:
        print(_section("PRIMARY INDICATORS", W))
        for line in v["indicators"].splitlines():
            line = line.strip().lstrip("- ").strip()
            if not line:
                continue
            color = (
                _C.RED    if any(m in line for m in ("red_circle", "HIGH", "FAIL")) else
                _C.YELLOW if any(m in line for m in ("yellow_circle", "MED", "SOFT")) else
                _C.GREEN  if any(m in line for m in ("green_circle", "PASS", "OK")) else
                _C.WHITE
            )
            print("  " + color + line + _C.RESET)

    # ── Reasoning ─────────────────────────────────────────────────────────────
    if v["reasoning"]:
        print(_section("REASONING", W))
        print(_C.DIM + _wrap(v["reasoning"], indent=2, width=W) + _C.RESET)

    # ── Recommended action ────────────────────────────────────────────────────
    if v["action"]:
        print(_section("RECOMMENDED ACTION", W))
        print(_wrap(v["action"], indent=2, width=W))

    # ── Footer ────────────────────────────────────────────────────────────────
    print()
    thin = _C.DIM + ("-" * W) + _C.RESET
    print(thin)
    fmt = result.get("email_format", "eml").upper()
    print(
        _C.DIM
        + "  Investigated via " + str(steps) + " tool calls"
        + " | Input: " + fmt
        + " | Model: GPT-4o"
        + " | phishing-detector v3.0"
        + _C.RESET
    )
    print(thin + "\n")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not set.  Run: export OPENAI_API_KEY=sk-...")
        sys.exit(1)

    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    email_path = args[0]
    verbose    = "--quiet" not in args

    if not os.path.isfile(email_path):
        print("Error: File not found:", email_path)
        sys.exit(1)

    # Load - handles both .eml and .msg transparently
    try:
        loaded = load_email(email_path)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        print("Error:", exc)
        sys.exit(1)

    # Print data-quality warnings before the agent starts
    if loaded["warnings"]:
        print()
        for w in loaded["warnings"]:
            print("  WARNING:", w)
        print()

    fmt = loaded["format"].upper()
    print("Loading [" + fmt + "]: " + email_path)
    print("Verbose : " + str(verbose))

    result = _investigate(
        raw_eml=loaded["raw_eml"],
        verbose=verbose,
        msg_attachments=loaded.get("_msg_attachments", []),
        email_format=loaded["format"],
    )
    _print_report(result)


if __name__ == "__main__":
    main()
