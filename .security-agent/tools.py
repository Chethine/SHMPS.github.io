"""
tools.py — Concrete implementations of every tool Claude can call.

ToolDispatcher.dispatch(name, inputs) is the single entry point.
Each tool_ method receives the exact JSON Claude sent and returns
a JSON-serialisable dict that becomes the tool_result content.
"""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from sandbox import execute_in_sandbox


class ToolDispatcher:
    def __init__(self, repo_path: str, target_url: str):
        self.repo_path = Path(repo_path).resolve()
        self.target_url = target_url.rstrip("/")

    def dispatch(self, name: str, inputs: dict) -> dict:
        handler = getattr(self, f"tool_{name}", None)
        if handler is None:
            return {"error": f"Unknown tool: {name}"}
        try:
            return handler(**inputs)
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}

    # ── PATH GUARD ────────────────────────────────────────────────────

    def _safe_path(self, rel: str) -> Path | None:
        """Resolve and validate a repo-relative path. Returns None on traversal."""
        full = (self.repo_path / rel).resolve()
        if not str(full).startswith(str(self.repo_path)):
            return None
        return full

    # ── INTELLIGENCE TOOLS (read-only) ───────────────────────────────

    def tool_list_directory(self, path: str = ".") -> dict:
        full = self._safe_path(path)
        if full is None:
            return {"error": "Path traversal denied"}
        if not full.is_dir():
            return {"error": f"Not a directory: {path}"}

        entries = []
        for item in sorted(full.iterdir()):
            if item.name.startswith("."):
                continue
            entries.append({
                "name": item.name,
                "type": "dir" if item.is_dir() else "file",
                "size": item.stat().st_size if item.is_file() else None,
            })
        return {"path": path, "entries": entries, "count": len(entries)}

    def tool_read_file(
        self, path: str, start_line: int = 1, end_line: int = 100
    ) -> dict:
        full = self._safe_path(path)
        if full is None:
            return {"error": "Path traversal denied"}
        if not full.exists():
            return {"error": f"File not found: {path}"}
        if not full.is_file():
            return {"error": f"Not a file: {path}"}

        # Refuse to read files over 500 KB — likely a build artifact
        size = full.stat().st_size
        if size > 500_000:
            return {
                "error": f"File too large ({size // 1024} KB). "
                         "This is likely a bundled/minified file — skip it."
            }

        try:
            all_lines = full.read_text(errors="replace").splitlines()
        except Exception as e:
            return {"error": str(e)}

        # Detect minified files: first line > 500 chars = bundled JS
        if all_lines and len(all_lines[0]) > 500:
            return {
                "error": "File appears to be minified (first line > 500 chars). "
                         "Skip this file — it is a vendor bundle, not source code."
            }

        total = len(all_lines)
        start_line = max(1, start_line)
        # Cap window to 100 lines max to protect context
        end_line = min(end_line, start_line + 99, total)
        selected = all_lines[start_line - 1 : end_line]

        content = "\n".join(
            f"{start_line + i:4d}: {line}"
            for i, line in enumerate(selected)
        )

        # Hard cap output at 6000 chars
        if len(content) > 6000:
            content = content[:6000] + "\n... [truncated — request a narrower line range]"

        return {
            "path": path,
            "total_lines": total,
            "shown": f"{start_line}-{end_line}",
            "content": content,
        }

    # Files that are always skipped — vendor bundles, build artifacts
    _SKIP_GLOBS = [
        "!*.min.js", "!*.min.css", "!*.bundle.js",
        "!**/vendor/**", "!**/dist/**", "!**/node_modules/**",
        "!**/.git/**",
    ]

    def tool_search_code(
        self,
        pattern: str,
        file_glob: str = "**/*",
        context_lines: int = 2,
    ) -> dict:
        # Cap context lines to avoid flooding context window
        context_lines = min(context_lines, 2)

        cmd = ["rg", "--json"]
        # Always add skip globs first
        for sg in self._SKIP_GLOBS:
            cmd += ["-g", sg]
        cmd += [
            "-g", file_glob,
            "-C", str(context_lines),
            "--max-count", "3",       # max 3 matches per file
            "--max-filesize", "100K", # skip files > 100 KB
            pattern,
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except FileNotFoundError:
            return self._grep_fallback(pattern, context_lines)
        except subprocess.TimeoutExpired:
            return {"error": "Search timed out after 15 s"}

        matches = []
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "match":
                data = obj["data"]
                text = data["lines"]["text"].rstrip()
                # Skip minified lines (> 300 chars = minified code)
                if len(text) > 300:
                    continue
                matches.append({
                    "file": data["path"]["text"],
                    "line": data["line_number"],
                    "text": text[:200],
                })
            if len(matches) >= 15:
                break

        # Hard cap total output to prevent context overflow
        output = json.dumps({"matches": matches, "total_shown": len(matches)})
        if len(output) > 8000:
            # Keep only enough matches to fit
            while matches and len(json.dumps({"matches": matches})) > 7500:
                matches.pop()
            return {
                "matches": matches,
                "total_shown": len(matches),
                "note": "Results truncated to protect context window.",
            }

        return {"matches": matches, "total_shown": len(matches)}

    def _grep_fallback(self, pattern: str, context: int) -> dict:
        try:
            result = subprocess.run(
                ["grep", "-rn", f"-C{context}", "--include=*", pattern, "."],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return {"raw": result.stdout[:8000]}
        except Exception as e:
            return {"error": str(e)}

    def tool_get_dependency_manifest(self) -> dict:
        candidates = [
            "package.json", "package-lock.json",
            "requirements.txt", "Pipfile", "pyproject.toml",
            "go.mod", "go.sum",
            "pom.xml", "build.gradle",
            "Gemfile", "Gemfile.lock",
            "Cargo.toml",
        ]
        found = {}
        for name in candidates:
            p = self.repo_path / name
            if p.exists():
                found[name] = p.read_text(errors="replace")[:4000]
        return found if found else {"error": "No dependency manifest found"}

    # ── SCAN TOOLS ────────────────────────────────────────────────────

    def tool_run_semgrep(self, rules: str = "auto", path: str = ".") -> dict:
        full = self._safe_path(path)
        if full is None:
            return {"error": "Path traversal denied"}

        try:
            result = subprocess.run(
                ["semgrep", "--config", rules, "--json", "--quiet", str(full)],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except FileNotFoundError:
            return {"error": "semgrep not installed. Run: pip install semgrep"}
        except subprocess.TimeoutExpired:
            return {"error": "Semgrep timed out after 3 minutes"}

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": "Semgrep JSON parse failed", "raw": result.stdout[:2000]}

        findings = []
        for r in data.get("results", []):
            findings.append({
                "rule": r.get("check_id", ""),
                "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
                "file": r.get("path", ""),
                "line": r.get("start", {}).get("line"),
                "message": r.get("extra", {}).get("message", "")[:300],
                "code": r.get("extra", {}).get("lines", "")[:200],
                "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", ""),
            })

        return {
            "findings": findings,
            "count": len(findings),
            "errors": [e.get("message") for e in data.get("errors", [])],
        }

    def tool_run_trivy(self, target: str = ".") -> dict:
        full = self._safe_path(target)
        target_arg = str(full) if full else target

        try:
            result = subprocess.run(
                ["trivy", "fs", "--format", "json", "--quiet", target_arg],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return {"error": "trivy not installed. See https://trivy.dev"}
        except subprocess.TimeoutExpired:
            return {"error": "Trivy timed out"}

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": "Trivy JSON parse failed", "raw": result.stdout[:2000]}

        vulns = []
        for result_item in data.get("Results", []):
            for v in result_item.get("Vulnerabilities") or []:
                vulns.append({
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "severity": v.get("Severity"),
                    "title": v.get("Title", "")[:200],
                    "description": v.get("Description", "")[:400],
                    "target": result_item.get("Target"),
                })

        return {"vulnerabilities": vulns, "count": len(vulns)}

    def tool_run_gitleaks(self) -> dict:
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--source", ".", "--report-format", "json",
                 "--report-path", "/tmp/gitleaks-report.json", "--exit-code", "0"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            report_path = Path("/tmp/gitleaks-report.json")
            if report_path.exists():
                data = json.loads(report_path.read_text())
                return {"leaks": data[:30], "count": len(data)}
            return {"leaks": [], "count": 0}
        except FileNotFoundError:
            return {"error": "gitleaks not installed. See https://gitleaks.io"}
        except Exception as e:
            return {"error": str(e)}

    # ── EXECUTION TOOLS (attacker agent only) ─────────────────────────

    def tool_execute_in_sandbox(
        self,
        script: str,
        language: str = "python3",
        timeout_seconds: int = 30,
    ) -> dict:
        host = self.target_url.split("://")[-1].split(":")[0].split("/")[0]
        port_str = self.target_url.split("://")[-1].split(":")[1].split("/")[0] \
                   if ":" in self.target_url.split("://")[-1] else "80"
        try:
            port = int(port_str)
        except ValueError:
            port = 80

        return execute_in_sandbox(
            script=script,
            language=language,
            timeout_seconds=min(timeout_seconds, 60),
            target_host=host,
            target_port=port,
        )

    def tool_http_request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str | None = None,
        timeout: int = 10,
    ) -> dict:
        if not url.startswith(self.target_url):
            return {"error": f"Out of scope. Only {self.target_url} is allowed."}
        try:
            import requests as req
            resp = req.request(
                method.upper(),
                url,
                headers=headers or {},
                data=body,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:10_000],
                "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
            }
        except Exception as e:
            return {"error": str(e)}

    def tool_capture_screenshot(self, url: str) -> dict:
        if not url.startswith(self.target_url):
            return {"error": "Out of scope"}
        try:
            import base64
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(args=["--no-sandbox"])
                page = browser.new_page()
                xss_dialogs: list[str] = []
                page.on("dialog", lambda d: (xss_dialogs.append(d.message), d.dismiss()))

                try:
                    page.goto(url, wait_until="networkidle", timeout=8000)
                except Exception:
                    pass  # Partial load is fine for PoC purposes

                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                    page.screenshot(path=f.name, full_page=True)
                    img_b64 = base64.b64encode(Path(f.name).read_bytes()).decode()
                    os.unlink(f.name)

                browser.close()

            return {
                "url": url,
                "screenshot_base64": img_b64[:500_000],  # cap at ~375 KB image
                "xss_triggered": bool(xss_dialogs),
                "xss_message": xss_dialogs[0] if xss_dialogs else None,
            }
        except ImportError:
            return {"error": "playwright not installed. Run: pip install playwright && playwright install chromium"}
        except Exception as e:
            return {"error": str(e)}

    # ── EVIDENCE TOOLS ────────────────────────────────────────────────

    def tool_write_poc_file(self, name: str, content: str) -> dict:
        safe_name = re.sub(r"[^\w\-.]", "_", name)[:80]
        poc_dir = Path("/tmp/security-agent-pocs")
        poc_dir.mkdir(exist_ok=True)
        out = poc_dir / safe_name
        out.write_text(content)
        return {"path": str(out), "bytes_written": len(content)}

    def tool_log_finding(self, **kwargs) -> dict:
        # Side-effect is captured in agent.py; just ack here.
        return {"logged": True, "id": kwargs.get("id")}

    def tool_set_build_result(self, result: str, reason: str, **kwargs) -> dict:
        # Side-effect captured in agent.py.
        return {"acknowledged": True, "result": result}
