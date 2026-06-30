"""
prompts.py — System prompts, tool schemas, and context builders.

The system prompts are the most critical part of the agent's design.
Edit them carefully — they define the agent's reasoning strategy.
"""

import json
import subprocess
from pathlib import Path


# ── ANALYST AGENT ─────────────────────────────────────────────────────────────

ANALYST_SYSTEM_PROMPT = """
You are an expert Application Security Engineer embedded in a CI/CD pipeline.
Your role is to perform a rigorous, context-aware security analysis of the
provided repository.

CAPABILITIES YOU HAVE:
- Read any file in the repository
- Search code for patterns (grep/AST style)
- Run automated scanning tools (Semgrep, Trivy, Gitleaks) as data sources
- List directory structure

CAPABILITIES YOU DO NOT HAVE:
- You cannot access the running application
- You cannot execute arbitrary code
- You cannot make network requests

ANALYSIS METHODOLOGY — follow this order:

1. RECONNAISSANCE
   a. Call list_directory(".") to understand the project structure
   b. Identify the tech stack (language, framework, database, auth mechanism)
   c. Find entry points: API routes, form handlers, GraphQL resolvers, CLI commands
   d. Read the dependency manifest to identify third-party libraries

2. AUTOMATED SCAN (data collection only)
   a. Call run_semgrep() to collect raw SAST findings
   b. Call run_trivy() to collect dependency vulnerabilities
   c. Treat these as UNVERIFIED HYPOTHESES, not confirmed findings

3. TRIAGE (your core value)
   For each raw finding, you MUST:
   a. Read the flagged file and surrounding context (±20 lines)
   b. Find where user-controlled input enters the system (source)
   c. Trace the data flow through transformation functions
   d. Determine if it reaches a dangerous sink without sanitization
   e. Check for sanitization that the tool may have missed
   f. Assign one of:
      - CONFIRMED: You traced a complete source→sink path with no effective sanitization
      - UNCONFIRMED: You cannot fully trace the path (missing context, complex framework magic)
      - FALSE_POSITIVE: You found effective sanitization the tool missed

4. ATTACK SURFACE GENERATION
   For each CONFIRMED finding, generate an attack_briefing that the
   penetration testing agent can act on. Be specific: exact URL path,
   parameter name, payload pattern.

5. DEPENDENCY VULNERABILITIES
   For CVEs from Trivy:
   a. Check if the vulnerable package is actually imported and used in
      a reachable code path (not just a transitive test dependency)
   b. Check if the specific vulnerable function/class is called
   c. Mark as CONFIRMED only if the vulnerable code path is reachable

OUTPUT REQUIREMENTS:
- Call log_finding() for every finding you assess (including FALSE_POSITIVEs)
- After all analysis, call set_build_result() with your final verdict
- Be conservative: only CONFIRM findings you can actually trace
- A well-reasoned UNCONFIRMED finding is better than a false CONFIRMED

EFFICIENCY RULES:
- Maximum 40 tool calls. Budget carefully.
- NEVER read or search these — they are vendor bundles, not your code:
    *.min.js  *.min.css  *.bundle.js  vendor/  dist/  node_modules/  assets/js/libs/
  If read_file returns "file appears to be minified", skip it immediately.
- When calling read_file, always set start_line and end_line (max 80 line window).
- When calling search_code, use specific file_glob values like "**/*.py" or
  "**/*.js" — never use "**/*" alone as it will match vendor bundles.
- Focus on HIGH and CRITICAL severity raw findings first.
- Skip test files (test_*.py, *.spec.ts) unless they contain real credentials.
- If a file read comes back truncated, request a smaller line range next time.
"""


ANALYST_TOOLS = [
    {
        "name": "list_directory",
        "description": "List the contents of a directory in the repository.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repo-relative path (default: '.')"}
            },
        }
    },
    {
        "name": "read_file",
        "description": "Read a source file. Always narrow the line range for large files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "default": 100}
            },
            "required": ["path"]
        }
    },
    {
        "name": "search_code",
        "description": "Search for a regex pattern across the codebase. "
                       "Use this to trace data flow (find callers, find where "
                       "a variable is used, find sanitization functions).",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern"},
                "file_glob": {"type": "string", "default": "**/*",
                              "description": "Glob to limit scope, e.g. '**/*.py'"},
                "context_lines": {"type": "integer", "default": 3}
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "get_dependency_manifest",
        "description": "Read package manifests (requirements.txt, package.json, etc.)",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "run_semgrep",
        "description": "Run Semgrep SAST scan. Returns raw, unverified findings. "
                       "You must verify each one manually.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rules": {"type": "string", "default": "auto"},
                "path": {"type": "string", "default": "."}
            }
        }
    },
    {
        "name": "log_finding",
        "description": "Record a finding (confirmed, unconfirmed, or false positive). "
                       "Call this for every finding you assess.",
        "input_schema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Unique ID, e.g. 'AS-001'"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                "status": {"type": "string", "enum": ["CONFIRMED", "UNCONFIRMED", "FALSE_POSITIVE"]},
                "title": {"type": "string"},
                "description": {"type": "string", "description": "What the vulnerability is and why it's exploitable"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "cwe": {"type": "string", "description": "e.g. 'CWE-89'"},
                "remediation": {"type": "string"},
                "attack_briefing": {
                    "type": "object",
                    "description": "Only for CONFIRMED findings. Briefing for the PT agent.",
                    "properties": {
                        "target_url": {"type": "string"},
                        "method": {"type": "string"},
                        "parameter": {"type": "string"},
                        "payload_pattern": {"type": "string"},
                        "expected_indicator": {"type": "string"},
                        "notes": {"type": "string"}
                    }
                }
            },
            "required": ["id", "severity", "status", "title", "description"]
        }
    },
    {
        "name": "set_build_result",
        "description": "Set the final build verdict. Call this ONCE after all analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "result": {"type": "string", "enum": ["PASS", "FAIL"]},
                "reason": {"type": "string"},
                "confirmed_count": {"type": "integer"},
                "false_positive_count": {"type": "integer"}
            },
            "required": ["result", "reason"]
        }
    }
]


# ── ATTACKER AGENT ────────────────────────────────────────────────────────────

ATTACKER_SYSTEM_PROMPT = """
You are an ethical penetration tester. You have been given a structured
attack briefing from a static analysis agent. Your job is to prove or disprove
exploitability by executing targeted exploit scripts against an isolated
test deployment.

TARGET: {target_url}
SCOPE: Only endpoints listed in your attack briefing.

EXECUTION METHODOLOGY:
1. Read the attack briefing for the first target
2. Write a minimal Python 3 exploit script using only: requests, time, json, re, base64
3. Run it via execute_in_sandbox()
4. Analyze the output:
   - If you see an indicator of success (data leak, timing difference, reflected payload,
     RCE output, auth bypass), it's EXPLOITED
   - If the server returned an error or defense response, it's FAILED
   - If the response is ambiguous, try one variation, then mark INCONCLUSIVE
5. For EXPLOITED findings, capture a screenshot if it's a browser-visible issue
6. Call log_finding() with the result
7. Proceed to the next target

EXPLOIT SCRIPT RULES (strictly enforced by sandbox):
- Python 3 only
- Imports allowed: requests, time, json, re, base64, urllib.parse, sys
- No file writes (except via write_poc_file tool)
- No shell commands, no subprocess
- Target only: {target_url}
- Payloads must be READ-ONLY: use SELECT queries, not DROP/DELETE/UPDATE
- For RCE: use `id`, `whoami`, `echo test` — not `rm` or `wget`
- For timing attacks: SLEEP(3) or time.sleep(3) to confirm blind injection
- Print evidence as JSON to stdout: {{"result": "...", "evidence": "..."}}
- Exit 0 = exploited, Exit 1 = failed, Exit 2 = inconclusive

EVIDENCE CAPTURE:
- Save full HTTP response bodies for successful exploits via write_poc_file()
- Call capture_screenshot() for XSS, open redirect, or UI-visible exploits
- Include the exact payload in your log_finding() call
"""


ATTACKER_TOOLS = [
    {
        "name": "execute_in_sandbox",
        "description": "Execute an exploit script in an isolated Docker container "
                       "against the test deployment. Returns stdout, stderr, exit_code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "Complete Python 3 script"},
                "language": {"type": "string", "enum": ["python3", "bash"], "default": "python3"},
                "timeout_seconds": {"type": "integer", "default": 30}
            },
            "required": ["script", "language"]
        }
    },
    {
        "name": "http_request",
        "description": "Make a direct HTTP request to the test target. "
                       "Use execute_in_sandbox for complex multi-step exploits.",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                "url": {"type": "string"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "timeout": {"type": "integer", "default": 10}
            },
            "required": ["method", "url"]
        }
    },
    {
        "name": "capture_screenshot",
        "description": "Take a Playwright screenshot of the target URL. "
                       "Use for XSS confirmation (detects alert() calls) "
                       "and visual vulnerability evidence.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"}
            },
            "required": ["url"]
        }
    },
    {
        "name": "write_poc_file",
        "description": "Save exploit script or evidence to the PoC artifacts directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Filename, e.g. 'sqli-AS001.py'"},
                "content": {"type": "string"}
            },
            "required": ["name", "content"]
        }
    },
    {
        "name": "log_finding",
        "description": "Record the exploitation result for this finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "status": {"type": "string", "enum": ["EXPLOITED", "FAILED", "INCONCLUSIVE"]},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "payload_used": {"type": "string"},
                "evidence": {"type": "string", "description": "Truncated stdout or response body"},
                "screenshot_path": {"type": "string"},
                "poc_script": {"type": "string"}
            },
            "required": ["id", "severity", "status", "title", "description"]
        }
    },
    {
        "name": "set_build_result",
        "description": "Finalize the PT phase result. Call once after all targets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "result": {"type": "string", "enum": ["PASS", "FAIL"]},
                "reason": {"type": "string"},
                "exploited_count": {"type": "integer"},
                "failed_count": {"type": "integer"}
            },
            "required": ["result", "reason"]
        }
    }
]


# ── CONTEXT BUILDERS ──────────────────────────────────────────────────────────

def build_initial_context(repo_path: str, diff_only: bool = False) -> str:
    """
    Build the first user message for the Analyst agent.
    Provides lightweight structural context; agent uses read_file for details.
    """
    repo = Path(repo_path)

    # Directory tree (shallow)
    try:
        tree_result = subprocess.run(
            ["find", ".", "-maxdepth", "3",
             "-not", "-path", "*/node_modules/*",
             "-not", "-path", "*/.git/*",
             "-not", "-path", "*/__pycache__/*",
             "-not", "-path", "*/dist/*",
             "-not", "-path", "*/.venv/*"],
            cwd=repo, capture_output=True, text=True, timeout=10
        )
        tree = tree_result.stdout[:3000]
    except Exception:
        tree = "(unable to list directory)"

    # Changed files for PR mode
    changed_section = ""
    if diff_only:
        try:
            diff_result = subprocess.run(
                ["git", "diff", "--name-only", "origin/main...HEAD"],
                cwd=repo, capture_output=True, text=True, timeout=10
            )
            changed_files = diff_result.stdout.strip()
            changed_section = f"\nFILES CHANGED IN THIS PR (prioritize these):\n{changed_files}\n"
        except Exception:
            pass

    return f"""You are analyzing a repository for security vulnerabilities.

REPOSITORY STRUCTURE:
{tree}
{changed_section}
Begin with list_directory(".") to orient yourself, then run_semgrep() to
collect raw findings. Triage every finding by tracing the data flow in code.
Do not confirm any finding without reading the relevant source files yourself.
"""


def build_attacker_briefing(confirmed_findings: list[dict]) -> str:
    """
    Build the first user message for the Attacker agent.
    Packages the Analyst's CONFIRMED findings as structured targets.
    """
    targets = []
    for f in confirmed_findings:
        if not f.get("attack_briefing"):
            continue
        targets.append({
            "id": f["id"],
            "type": f.get("title"),
            "severity": f.get("severity"),
            "cwe": f.get("cwe"),
            "description": f.get("description"),
            "attack_briefing": f["attack_briefing"],
        })

    return f"""You have {len(targets)} confirmed vulnerability target(s) to attempt.

ATTACK TARGETS:
{json.dumps(targets, indent=2)}

For each target, write a targeted exploit script, execute it in the sandbox,
and log the result. Work through them in order of severity (CRITICAL first).
After all targets, call set_build_result().
"""
