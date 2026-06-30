"""
main.py — Pipeline entrypoint.

Usage (local):
  python main.py \\
    --repo-path /path/to/repo \\
    --target-url http://localhost:8080 \\
    --github-token ghp_... \\
    --commit-sha abc1234 \\
    --run-url https://github.com/owner/repo/actions/runs/1

Usage (GitHub Actions):
  See .github/workflows/ai-security-agent.yml
"""

import argparse
import json
import os
import sys
from pathlib import Path

from agent import SecurityAgent
from github import post_pr_comment, upload_sarif, set_commit_status
from prompts import (
    ANALYST_SYSTEM_PROMPT,
    ANALYST_TOOLS,
    ATTACKER_SYSTEM_PROMPT,
    ATTACKER_TOOLS,
    build_initial_context,
    build_attacker_briefing,
)
from reporter import generate_pr_comment, generate_sarif

POC_DIR = Path("/tmp/security-agent-pocs")


def main() -> None:
    args = _parse_args()
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
    fail_severities = {s.strip().upper() for s in args.fail_on.split(",")}

    # ── Set pending commit status ──────────────────────────────────────
    if args.github_token and args.commit_sha:
        _try(set_commit_status,
             token=args.github_token,
             repo=repo,
             commit_sha=args.commit_sha,
             state="pending",
             description="AI security scan in progress…",
             target_url=args.run_url)

    # ── PHASE 1: ANALYST ──────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  PHASE 1 — AI Analyst (SAST + SCA Triage)")
    print("═" * 60 + "\n")

    analyst = SecurityAgent(
        repo_path=args.repo_path,
        target_url=args.target_url,
        tool_schemas=ANALYST_TOOLS,
        system_prompt=ANALYST_SYSTEM_PROMPT,
        mode="analyst",
    )
    analyst_result = analyst.run(
        build_initial_context(
            repo_path=args.repo_path,
            diff_only=(args.pr_number is not None),
        )
    )

    all_findings: list[dict] = list(analyst_result["findings"])
    print(f"\nAnalyst: {len(all_findings)} finding(s), "
          f"{analyst_result['iterations_used']} iterations, "
          f"~${_estimate_cost(analyst_result):.2f} API cost")

    # ── PHASE 2: ATTACKER (optional) ──────────────────────────────────
    if not args.skip_pentest:
        targets = [
            f for f in all_findings
            if f.get("status") == "CONFIRMED"
            and f.get("attack_briefing")
            and f.get("severity") in fail_severities
        ]

        if targets:
            print("\n" + "═" * 60)
            print(f"  PHASE 2 — AI Attacker ({len(targets)} target(s))")
            print("═" * 60 + "\n")

            attacker = SecurityAgent(
                repo_path=args.repo_path,
                target_url=args.target_url,
                tool_schemas=ATTACKER_TOOLS,
                system_prompt=ATTACKER_SYSTEM_PROMPT.format(
                    target_url=args.target_url
                ),
                mode="attacker",
            )
            attacker_result = attacker.run(build_attacker_briefing(targets))

            # Merge: attacker findings override analyst findings by ID
            attacker_by_id = {f["id"]: f for f in attacker_result["findings"]}
            for finding in all_findings:
                if finding["id"] in attacker_by_id:
                    finding.update(attacker_by_id[finding["id"]])

            print(f"\nAttacker: {attacker_result['iterations_used']} iterations, "
                  f"~${_estimate_cost(attacker_result):.2f} API cost")
        else:
            print("\nPhase 2 skipped — no CONFIRMED findings with attack briefings.")

    # ── BUILD GATE ────────────────────────────────────────────────────
    blocking = [
        f for f in all_findings
        if f.get("status") in ("CONFIRMED", "EXPLOITED")
        and f.get("severity", "").upper() in fail_severities
    ]

    build_passed = len(blocking) == 0
    build_result = {
        "result": "PASS" if build_passed else "FAIL",
        "reason": (
            "No confirmed high-severity vulnerabilities found."
            if build_passed
            else f"{len(blocking)} confirmed finding(s) at {args.fail_on} "
                 f"severity require remediation."
        ),
    }

    # ── OUTPUTS ───────────────────────────────────────────────────────

    # 1. SARIF file
    sarif = generate_sarif(all_findings)
    sarif_path = "security-agent.sarif"
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"\nSARIF written to: {sarif_path}")

    # 2. Raw findings JSON (useful for debugging)
    findings_path = "security-agent-findings.json"
    with open(findings_path, "w") as f:
        json.dump({"build_result": build_result, "findings": all_findings}, f, indent=2)
    print(f"Findings JSON written to: {findings_path}")

    # 3. GitHub API calls (best-effort — don't fail the build if they error)
    if args.github_token:
        # PR comment
        if args.pr_number:
            comment = generate_pr_comment(
                findings=all_findings,
                build_result=build_result,
                run_url=args.run_url,
                commit_sha=args.commit_sha,
            )
            _try(post_pr_comment,
                 token=args.github_token,
                 repo=repo,
                 pr_number=args.pr_number,
                 body=comment)
            print("PR comment posted.")

        # SARIF upload
        _try(upload_sarif,
             token=args.github_token,
             repo=repo,
             sarif_path=sarif_path,
             commit_sha=args.commit_sha)
        print("SARIF uploaded to GitHub Security tab.")

        # Final commit status
        _try(set_commit_status,
             token=args.github_token,
             repo=repo,
             commit_sha=args.commit_sha,
             state="success" if build_passed else "failure",
             description=build_result["reason"],
             target_url=args.run_url)

    # ── FINAL SUMMARY ─────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print(f"  Result: {build_result['result']}")
    print(f"  {build_result['reason']}")
    print("═" * 60)

    sys.exit(0 if build_passed else 1)


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AI Security Agent")
    p.add_argument("--repo-path",     required=True,  help="Local path to the repository")
    p.add_argument("--target-url",    required=True,  help="Base URL of the test deployment")
    p.add_argument("--github-token",  default="",     help="GitHub token for API calls")
    p.add_argument("--pr-number",     type=int,       help="PR number (omit for push scans)")
    p.add_argument("--commit-sha",    default="",     help="Commit SHA being scanned")
    p.add_argument("--run-url",       default="",     help="Link to this CI run")
    p.add_argument("--fail-on",       default="CRITICAL,HIGH",
                   help="Comma-separated severities that fail the build")
    p.add_argument("--skip-pentest",  action="store_true",
                   help="Skip Phase 2 (active exploitation)")
    return p.parse_args()


def _estimate_cost(result: dict) -> float:
    """Rough cost estimate using Opus pricing (input $15/M, output $75/M tokens)."""
    return (result.get("input_tokens", 0) / 1_000_000 * 15 +
            result.get("output_tokens", 0) / 1_000_000 * 75)


def _try(fn, **kwargs) -> None:
    """Call fn(**kwargs), print a warning on failure, never raise."""
    try:
        fn(**kwargs)
    except Exception as e:
        print(f"[WARNING] {fn.__name__} failed: {e}")


if __name__ == "__main__":
    main()
