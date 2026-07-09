#!/usr/bin/env python3
"""
Web Scanner AI Agent
====================
The LLM (Claude) is the orchestrator.  It decides which tools to call, inspects the results, and reasons about what to do next — following the ReAct loop: Reason → Act → Observe → Reason → ... → Final Report.

Enforced tool-calling order: nmap_scan  →  nvd_lookup (once per service)  →  scan_web_headers
  1. nmap_scan          – discovers open ports and running services
  2. nvd_lookup         – queries the National Vulnerability Database for CVEs
  3. scan_web_headers   – checks HTTP security headers and cookie flags

Configuration (environment variables):
    ANTHROPIC_API_KEY   (required)
    ANTHROPIC_MODEL     (optional, default: claude-opus-4-5)

Usage:
    python web-scanner.py                        # interactive prompt
    python web-scanner.py https://example.com    # direct argument
"""

import os
import re
import sys
import json
import socket
import subprocess
import urllib.request
import urllib.parse
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-5")
ANTHROPIC_VERSION = "2023-06-01"
MAX_TOKENS        = 8192
MAX_ITERATIONS    = 20   # safety cap — prevents runaway loops

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[91m"
DIM    = "\033[2m"

def _log_agent(msg: str): print(f"\n{CYAN}{BOLD}[agent]{RESET}  {msg}")
def _log_tool(name: str): print(f"{YELLOW}{BOLD}[tool ]{RESET}  → calling {BOLD}{name}{RESET}")
def _log_obs(msg: str):   print(f"{GREEN}{BOLD}[obs  ]{RESET}  {msg}")
def _log_warn(msg: str):  print(f"{RED}{BOLD}[warn ]{RESET}  {msg}")

# ─────────────────────────────────────────────────────────────────────────────
# Tool implementations
# ─────────────────────────────────────────────────────────────────────────────

# ── nmap ─────────────────────────────────────────────────────────────────────

def tool_nmap_scan(host: str) -> dict:
    """
    Run nmap -sV against host.
    Returns open ports and detected services/versions.
    Falls back to a socket scan if nmap is unavailable.
    """
    _log_tool("nmap_scan")
    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--open", "-T4", "--host-timeout", "60s", host],
            capture_output=True, text=True, timeout=120,
        )
        return _parse_nmap_output(proc.stdout, host)
    except FileNotFoundError:
        _log_warn("nmap not found — falling back to socket scan.")
        return _socket_scan(host)
    except subprocess.TimeoutExpired:
        _log_warn("nmap timed out — falling back to socket scan.")
        return _socket_scan(host)

def _parse_nmap_output(raw: str, host: str) -> dict:
    services = []
    port_re  = re.compile(r"(\d+)/(\w+)\s+open\s+([\w\-]+)\s*(.*)")
    for line in raw.splitlines():
        m = port_re.search(line)
        if m:
            port, proto, svc, ver = m.groups()
            services.append({
                "port":     int(port),
                "protocol": proto,
                "service":  svc.strip(),
                "version":  ver.strip(),
            })
    return {
        "host":       host,
        "open_ports": [s["port"] for s in services],
        "services":   services,
    }

def _socket_scan(host: str) -> dict:
    COMMON_PORTS = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
        27017: "mongodb",
    }
    services = []
    for port, svc in COMMON_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=1):
                services.append({
                    "port": port, "protocol": "tcp",
                    "service": svc, "version": "",
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return {
        "host":       host,
        "open_ports": [s["port"] for s in services],
        "services":   services,
    }

# ── NVD lookup ───────────────────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def tool_nvd_lookup(service: str, version: str = "") -> dict:
    """
    Query NVD for CVEs matching a service name and optional version.
    Returns up to 5 CVE records (id, severity, cvss_score, description, url).
    """
    _log_tool("nvd_lookup")
    keyword = f"{service} {version}".strip() if version else service
    params  = urllib.parse.urlencode({
        "keywordSearch":  keyword,
        "resultsPerPage": 5,
    })
    url = f"{NVD_API_URL}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve    = item["cve"]
            cve_id = cve.get("id", "")
            score, severity = _extract_cvss(cve.get("metrics", {}))
            desc = next(
                (d["value"] for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"),
                "No description available.",
            )
            cves.append({
                "cve_id":     cve_id,
                "severity":   severity,
                "cvss_score": score,
                "description": desc,
                "url":        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return {"keyword": keyword, "cves": cves}
    except Exception as exc:
        return {"keyword": keyword, "cves": [], "error": str(exc)}

def _extract_cvss(metrics: dict) -> tuple:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                score = float(entries[0]["cvssData"]["baseScore"])
                if score >= 9.0: return score, "CRITICAL"
                if score >= 7.0: return score, "HIGH"
                if score >= 4.0: return score, "MEDIUM"
                return score, "LOW"
            except (KeyError, TypeError, ValueError):
                pass
    return None, "MEDIUM"

# ── Web header scanner ────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
]
LEAKY_HEADERS = ["Server", "X-Powered-By"]

def tool_scan_web_headers(url: str) -> dict:
    """
    Fetch HTTP response headers for a URL and return:
      - present_headers         : dict of all response headers
      - missing_security_headers: list of absent recommended headers
      - leaking_headers         : headers that disclose server internals
      - cookie_issues           : list of insecure cookie flag problems
      - uses_https              : bool
    """
    _log_tool("scan_web_headers")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    missing = [h for h in SECURITY_HEADERS if h.lower() not in raw_headers]
  
    leaking = {
        h: raw_headers[h.lower()]
        for h in LEAKY_HEADERS
        if h.lower() in raw_headers
    }

    cookie_issues = []
    set_cookie = raw_headers.get("set-cookie", "")
    if set_cookie:
        c = set_cookie.lower()
        if "secure"   not in c: cookie_issues.append("Missing Secure flag")
        if "httponly" not in c: cookie_issues.append("Missing HttpOnly flag")
        if "samesite" not in c: cookie_issues.append("Missing SameSite attribute")

    return {
        "url":                     url,
        "uses_https":              url.startswith("https://"),
        "present_headers":         dict(raw_headers),
        "missing_security_headers": missing,
        "leaking_headers":         leaking,
        "cookie_issues":           cookie_issues,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Tool registry
# ─────────────────────────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    "nmap_scan":        tool_nmap_scan,
    "nvd_lookup":       tool_nvd_lookup,
    "scan_web_headers": tool_scan_web_headers,
}

# Anthropic tool schema format
TOOLS = [
    {
        "name": "nmap_scan",
        "description": (
            "Run an nmap service-version scan against a hostname or IP address. Returns open ports and the services/versions detected on them. ALWAYS call this first — you cannot call nvd_lookup until you know which services are running."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Hostname or IP address to scan — no protocol prefix.",
                }
            },
            "required": ["host"],
        },
    },
    {
        "name": "nvd_lookup",
        "description": (
            "Query the National Vulnerability Database (NVD) for known CVEs matching a service name and optional version string. Call this once per discovered service AFTER nmap_scan has returned. Do NOT call scan_web_headers until all nvd_lookup calls are done."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name as returned by nmap, e.g. 'apache httpd', 'openssh', 'nginx'.",
                },
                "version": {
                    "type": "string",
                    "description": "Version string from nmap, e.g. '2.4.51'. Pass empty string if unknown.",
                },
            },
            "required": ["service"],
        },
    },
    {
        "name": "scan_web_headers",
        "description": (
            "Fetch the HTTP response headers for a URL and analyse them for security issues: missing security headers, information-leaking headers, and insecure cookie attributes. Call this LAST — only after nmap_scan and all nvd_lookup calls are complete."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL including scheme, e.g. https://example.com.",
                }
            },
            "required": ["url"],
        },
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior offensive and defensive security analyst running an automated security assessment against a target URL provided by the user.

You have access to three tools. You MUST use them in this exact order:

  1. nmap_scan          — discover open ports and running services on the host.
  2. nvd_lookup         — find known CVEs for each discovered service.
                          Make one nvd_lookup call per service that has an
                          identifiable name (skip bare port numbers).
  3. scan_web_headers   — check HTTP security headers and cookie hygiene.

Do NOT skip any step. Do NOT produce the final report until all three tool types have been used at least once.

## Final report format
Once all tool results are in hand, write the report in plain text:

SECURITY ASSESSMENT REPORT
Target: <url>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY
<3–5 sentence narrative covering: overall security posture, the most critical risks, how the findings interact, and the combined business impact.>

FINDINGS
For each issue, write one block in this format:

  [SEVERITY] Title
  Source: <nmap | nvd | web_scanner>
  CVE: <id>  CVSS: <score>          ← include only for NVD findings
  Description:
    <concise technical description of the specific issue on this target>
  Recommended Mitigation:
    <specific, actionable guidance — reference exact config directives, OWASP controls, CIS Benchmarks, CVE patch advisories, or RFC numbers. Cross-reference related findings where relevant.>

Sort all findings by severity: CRITICAL → HIGH → MEDIUM → LOW → INFO.

SEVERITY SUMMARY
  CRITICAL : N
  HIGH     : N
  MEDIUM   : N
  LOW      : N

END OF REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ─────────────────────────────────────────────────────────────────────────────
# Anthropic API  (native — no SDK)
# ─────────────────────────────────────────────────────────────────────────────

def _call_anthropic(messages: list) -> dict:
    """
    POST to the Anthropic Messages API and return the parsed response body.
    Raises ValueError if the API key is missing.
    Raises RuntimeError on HTTP errors.
    """
    if not ANTHROPIC_API_KEY:
        raise ValueError(
            "ANTHROPIC_API_KEY is not set.\n"
            "Export it before running:  export ANTHROPIC_API_KEY=sk-ant-..."
        )

    body = {
        "model":      ANTHROPIC_MODEL,
        "max_tokens": MAX_TOKENS,
        "system":     SYSTEM_PROMPT,
        "tools":      TOOLS,
        "messages":   messages,
    }

    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=data,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         ANTHROPIC_API_KEY,
            "anthropic-version": ANTHROPIC_VERSION,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        raise RuntimeError(
            f"Anthropic API error {exc.code}: {body_text}"
        ) from exc

def _parse_response(raw: dict) -> dict:
    """
    Extract a normalised response from the Anthropic Messages API response:
      {
        "stop_reason":  "tool_use" | "end_turn" | ...,
        "text":         str | None,
        "tool_calls":   [ {"id": str, "name": str, "input": dict} ]
        "_raw_content": list   ← kept for conversation history
      }
    """
    content     = raw.get("content", [])
    stop_reason = raw.get("stop_reason", "")
    text        = None
    tool_calls  = []

    for block in content:
        if block["type"] == "text":
            text = block["text"]
        elif block["type"] == "tool_use":
            tool_calls.append({
                "id":    block["id"],
                "name":  block["name"],
                "input": block["input"],   # already a dict — no JSON parsing needed
            })

    return {
        "stop_reason":  stop_reason,
        "text":         text,
        "tool_calls":   tool_calls,
        "_raw_content": content,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Agent loop
# ─────────────────────────────────────────────────────────────────────────────

def run_agent(url: str) -> str:
    """
    ReAct loop — Claude decides which tools to call and when.

      1. Send system prompt + user request to Claude.
      2. If Claude requests tool calls → execute them → return results.
      3. Repeat until Claude's stop_reason is "end_turn" (no more tool calls).
      4. Return Claude's final text as the security report.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"\n{BOLD}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║      Security AI Agent  —  Powered by Claude         ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════╝{RESET}")
    print(f"  Target : {url}")
    print(f"  Model  : {ANTHROPIC_MODEL}")

    # Full conversation history sent on every API call
    messages: list[dict] = [
        {
            "role":    "user",
            "content": f"Please run a full security assessment on: {url}",
        }
    ]

    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"\n{DIM}── Agent iteration {iteration} {'─' * 45}{RESET}")

        raw      = _call_anthropic(messages)
        response = _parse_response(raw)

        # ── end_turn → Claude is done; return its text ────────────────────────
        if response["stop_reason"] == "end_turn" or not response["tool_calls"]:
            _log_agent("Claude has finished — generating final report.")
            return response["text"] or ""

        # ── tool_use → execute every tool Claude requested ────────────────────

        # 1. Append the full assistant turn (all content blocks) to history
        messages.append({
            "role":    "assistant",
            "content": response["_raw_content"],
        })

        # 2. Execute each tool and collect results into a single user turn
        tool_results = []
        for tc in response["tool_calls"]:
            tool_name = tc["name"]
            tool_args = tc["input"]
            tool_id   = tc["id"]

            _log_agent(
                f"Claude requested: {BOLD}{tool_name}{RESET} "
                f"with args {json.dumps(tool_args)}"
            )

            if tool_name not in TOOL_REGISTRY:
                result = {"error": f"Unknown tool '{tool_name}'"}
                _log_warn(f"Claude requested an unknown tool: {tool_name}")
            else:
                try:
                    result = TOOL_REGISTRY[tool_name](**tool_args)
                    _log_observation(tool_name, result)
                except Exception as exc:
                    result = {"error": str(exc)}
                    _log_warn(f"Tool '{tool_name}' raised an exception: {exc}")

            tool_results.append({
                "type":        "tool_result",
                "tool_use_id": tool_id,
                "content":     json.dumps(result),
            })

        # 3. Return all tool results in one user message (Anthropic requirement)
        messages.append({
            "role":    "user",
            "content": tool_results,
        })

    _log_warn("Maximum iterations reached — returning last available text.")
    return response.get("text") or "Assessment incomplete: iteration limit reached."

def _log_observation(tool_name: str, result: dict):
    """Print a compact one-line observation after a tool returns."""
    if tool_name == "nmap_scan":
        ports = result.get("open_ports", [])
        svcs  = [s["service"] for s in result.get("services", [])]
        _log_obs(f"nmap → {len(ports)} open port(s): {ports}  |  services: {svcs}")
    elif tool_name == "nvd_lookup":
        kw   = result.get("keyword", "")
        cves = result.get("cves", [])
        _log_obs(f"nvd [{kw}] → {len(cves)} CVE(s) returned")
    elif tool_name == "scan_web_headers":
        missing = result.get("missing_security_headers", [])
        leaking = result.get("leaking_headers", {})
        _log_obs(
            f"headers → {len(missing)} missing security header(s), "
            f"{len(leaking)} leaking header(s)"
        )

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    url = (
        sys.argv[1].strip()
        if len(sys.argv) > 1
        else input("Enter target URL (e.g. https://example.com): ").strip()
    )

    if not url:
        print("No URL provided. Exiting.")
        sys.exit(1)

    report = run_agent(url)

    sep = "═" * 72
    print(f"\n{BOLD}{sep}{RESET}")
    print(report)
    print(f"{BOLD}{sep}{RESET}\n")

    # Save a clean (ANSI-stripped) copy to disk
    host      = urlparse(url if "://" in url else f"https://{url}").hostname or "target"
    safe_name = re.sub(r"[^\w\-.]", "_", host)
    out_path  = f"security_report_{safe_name}.txt"
    clean     = re.sub(r"\033\[[0-9;]*m", "", report)
    with open(out_path, "w") as fh:
        fh.write(clean)
    print(f"[+] Report saved to: {out_path}\n")


if __name__ == "__main__":
    main()
