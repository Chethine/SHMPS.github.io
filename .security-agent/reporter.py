"""
reporter.py — Converts agent findings into Markdown PR comments and SARIF.
"""

import json
from datetime import datetime, timezone

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

STATUS_LABEL = {
    "EXPLOITED":      "💥 Exploited (live PoC)",
    "CONFIRMED":      "⚠️  Confirmed (code-verified)",
    "UNCONFIRMED":    "🟡 Unconfirmed",
    "FALSE_POSITIVE": "✅ False positive",
    "FAILED":         "🛡️  PT: defence held",
    "INCONCLUSIVE":   "❓ PT: inconclusive",
}


# ── PUBLIC ────────────────────────────────────────────────────────────────────

def generate_pr_comment(
    findings: list[dict],
    build_result: dict,
    run_url: str,
    commit_sha: str,
) -> str:
    exploited   = _filter(findings, "EXPLOITED")
    confirmed   = _filter(findings, "CONFIRMED")
    unconfirmed = _filter(findings, "UNCONFIRMED")
    fp_count    = len(_filter(findings, "FALSE_POSITIVE"))

    result_icon = (
        "❌ **BUILD BLOCKED**" if build_result.get("result") == "FAIL"
        else "✅ **BUILD PASSED**"
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sha = commit_sha[:8]

    lines: list[str] = [
        f"## 🤖 AI Security Agent — `{sha}`",
        "",
        f"{result_icon} — {build_result.get('reason', '')}",
        "",
        "| Status | Count |",
        "|--------|------:|",
        f"| {STATUS_LABEL['EXPLOITED']} | **{len(exploited)}** |",
        f"| {STATUS_LABEL['CONFIRMED']} | **{len(confirmed)}** |",
        f"| {STATUS_LABEL['UNCONFIRMED']} | {len(unconfirmed)} |",
        f"| {STATUS_LABEL['FALSE_POSITIVE']} | {fp_count} |",
        "",
    ]

    if exploited:
        lines += ["### 💥 Exploited Vulnerabilities", ""]
        for f in exploited:
            lines += _render_finding(f, show_evidence=True)

    if confirmed:
        lines += ["### ⚠️ Confirmed (not yet exploited in PT)", ""]
        for f in confirmed:
            lines += _render_finding(f, show_evidence=False)

    if unconfirmed:
        lines += [
            "<details>",
            f"<summary>🟡 {len(unconfirmed)} Unconfirmed findings</summary>",
            "",
        ]
        for f in unconfirmed:
            file_loc = f"{f.get('file', 'unknown')}:{f.get('line', '?')}"
            lines.append(
                f"- **{f.get('title', 'Unknown')}** — "
                f"`{file_loc}` {f.get('cwe', '')}"
            )
        lines += ["", "</details>", ""]

    lines += [
        "---",
        f"*AI Security Agent · [Full run]({run_url}) · {now}*",
    ]

    return "\n".join(lines)


def generate_sarif(
    findings: list[dict],
    tool_name: str = "claude-security-agent",
    tool_version: str = "1.0.0",
) -> dict:
    """Generate SARIF 2.1.0 for GitHub Security tab upload."""

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        if f.get("status") == "FALSE_POSITIVE":
            continue

        rule_id = f.get("cwe") or f.get("id") or "UNKNOWN"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": _slugify(f.get("title", rule_id)),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {"text": f.get("description", "")[:1000]},
                "properties": {
                    "tags": [f.get("cwe", ""), "security"],
                    "security-severity": _cvss_score(f.get("severity", "MEDIUM")),
                },
            }

        level = {
            "CRITICAL": "error",
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "note",
            "INFO":     "none",
        }.get(f.get("severity", "MEDIUM"), "warning")

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": (
                    f"[{f.get('status')}] {f.get('description', f.get('title', ''))}"
                )
            },
            "properties": {
                "severity":    f.get("severity"),
                "status":      f.get("status"),
                "ai_verified": f.get("status") in ("CONFIRMED", "EXPLOITED"),
            },
        }

        if f.get("file"):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"], "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.get("line", 1)},
                }
            }]

        if f.get("evidence"):
            result["message"]["text"] += f"\n\nEvidence:\n{f['evidence'][:500]}"

        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":    tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/your-org/security-agent",
                    "rules":   list(rules.values()),
                }
            },
            "results": results,
            "automationDetails": {
                "id": f"security-agent/{datetime.now(timezone.utc).date()}",
            },
        }],
    }


# ── PRIVATE ───────────────────────────────────────────────────────────────────

def _filter(findings: list[dict], status: str) -> list[dict]:
    return [f for f in findings if f.get("status") == status]


def _render_finding(f: dict, show_evidence: bool) -> list[str]:
    sev   = f.get("severity", "MEDIUM")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    cwe   = f.get("cwe", "")
    loc   = f"{f.get('file', 'unknown')}:{f.get('line', '?')}"

    lines = [
        f"#### {emoji} [{sev}] {f.get('title', 'Unknown')} `{cwe}`",
        "",
        f.get("description", ""),
        "",
        f"**Location:** `{loc}`",
    ]

    if f.get("remediation"):
        lines.append(f"**Remediation:** {f['remediation']}")

    if f.get("payload_used"):
        lines += ["", f"**Payload used:** `{f['payload_used']}`"]

    if show_evidence and f.get("evidence"):
        lines += [
            "",
            "<details>",
            "<summary>📎 PoC Evidence</summary>",
            "",
            "```",
            f["evidence"][:3000],
            "```",
            "",
            "</details>",
        ]

    lines.append("")
    return lines


def _slugify(text: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9]+", "", text.title())[:64]


def _cvss_score(severity: str) -> str:
    """Approximate CVSS score for GitHub security-severity property."""
    return {
        "CRITICAL": "9.0",
        "HIGH":     "7.0",
        "MEDIUM":   "4.0",
        "LOW":      "2.0",
        "INFO":     "0.0",
    }.get(severity, "4.0")
