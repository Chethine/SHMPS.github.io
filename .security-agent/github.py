"""
github.py — Thin wrappers around the GitHub REST API.

Handles:
  - Posting / updating a sticky PR comment
  - Uploading SARIF to the GitHub Security tab
  - Setting a commit status check

All functions raise on non-2xx responses so the caller can decide
whether to treat failures as fatal.
"""

import base64
import gzip
import json
import os
import time
from pathlib import Path

import requests

GITHUB_API = "https://api.github.com"
COMMENT_MARKER = "<!-- security-agent-report -->"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ── PR COMMENT ────────────────────────────────────────────────────────────────

def post_pr_comment(
    token: str,
    repo: str,           # "owner/repo"
    pr_number: int,
    body: str,
) -> dict:
    """
    Post or update a sticky PR comment.
    Looks for an existing comment with COMMENT_MARKER and edits it in-place
    so repeated runs don't spam the PR with duplicate comments.
    """
    marked_body = f"{COMMENT_MARKER}\n{body}"

    # Try to find an existing comment from this bot
    existing_id = _find_existing_comment(token, repo, pr_number)

    if existing_id:
        url = f"{GITHUB_API}/repos/{repo}/issues/comments/{existing_id}"
        resp = requests.patch(url, headers=_headers(token),
                              json={"body": marked_body}, timeout=15)
    else:
        url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
        resp = requests.post(url, headers=_headers(token),
                             json={"body": marked_body}, timeout=15)

    resp.raise_for_status()
    return resp.json()


def _find_existing_comment(token: str, repo: str, pr_number: int) -> int | None:
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
    resp = requests.get(url, headers=_headers(token),
                        params={"per_page": 100}, timeout=15)
    resp.raise_for_status()
    for comment in resp.json():
        if COMMENT_MARKER in comment.get("body", ""):
            return comment["id"]
    return None


# ── SARIF UPLOAD ──────────────────────────────────────────────────────────────

def upload_sarif(
    token: str,
    repo: str,
    sarif_path: str,
    commit_sha: str,
    ref: str | None = None,
    category: str = "ai-security-agent",
) -> dict:
    """
    Upload a SARIF file to GitHub Code Scanning.

    GitHub requires the SARIF to be gzip-compressed and base64-encoded.
    ref defaults to refs/heads/main if not provided.
    """
    sarif_data = Path(sarif_path).read_bytes()
    compressed = gzip.compress(sarif_data)
    encoded = base64.b64encode(compressed).decode()

    payload = {
        "commit_sha": commit_sha,
        "ref": ref or os.environ.get("GITHUB_REF", "refs/heads/main"),
        "sarif": encoded,
        "tool_name": "claude-security-agent",
        "category": category,
    }

    url = f"{GITHUB_API}/repos/{repo}/code-scanning/sarifs"
    resp = requests.post(url, headers=_headers(token),
                         json=payload, timeout=30)

    if resp.status_code == 202:
        return resp.json()

    # 403 means Code Scanning is not enabled on this repo
    if resp.status_code == 403:
        print("[github] WARNING: Code Scanning not enabled — SARIF upload skipped")
        return {"skipped": True, "reason": "code_scanning_not_enabled"}

    resp.raise_for_status()
    return resp.json()


# ── COMMIT STATUS ─────────────────────────────────────────────────────────────

def set_commit_status(
    token: str,
    repo: str,
    commit_sha: str,
    state: str,          # "success" | "failure" | "pending" | "error"
    description: str,
    context: str = "security-agent",
    target_url: str | None = None,
) -> dict:
    """Set a GitHub commit status check."""
    payload: dict = {
        "state": state,
        "description": description[:140],  # GitHub limit
        "context": context,
    }
    if target_url:
        payload["target_url"] = target_url

    url = f"{GITHUB_API}/repos/{repo}/statuses/{commit_sha}"
    resp = requests.post(url, headers=_headers(token),
                         json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


# ── REPO INFO ─────────────────────────────────────────────────────────────────

def get_pr_info(token: str, repo: str, pr_number: int) -> dict:
    """Fetch basic PR metadata (head SHA, base branch, title)."""
    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}"
    resp = requests.get(url, headers=_headers(token), timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return {
        "head_sha":    data["head"]["sha"],
        "head_ref":    data["head"]["ref"],
        "base_ref":    data["base"]["ref"],
        "title":       data["title"],
        "author":      data["user"]["login"],
        "html_url":    data["html_url"],
    }
