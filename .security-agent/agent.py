"""
agent.py — Core agentic loop.

Runs Claude with tool use until it calls set_build_result()
or exhausts MAX_ITERATIONS. All tool calls are dispatched through
ToolDispatcher so the actual implementations stay in tools.py.
"""

import json
import time
from typing import Any

import anthropic

from tools import ToolDispatcher

MAX_ITERATIONS = 60
MODEL = "claude-opus-4-5"
TOKEN_LIMIT = 200_000
TOKEN_TRIM_THRESHOLD = 150_000   # start trimming at 75% of limit
TOKEN_CHARS_RATIO = 4            # rough chars-per-token estimate

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from environment


class SecurityAgent:
    """
    Wraps one Claude conversation (one agent role).
    Instantiate separately for the Analyst and the Attacker.
    """

    def __init__(
        self,
        repo_path: str,
        target_url: str,
        tool_schemas: list[dict],
        system_prompt: str,
        mode: str = "analyst",
    ):
        self.repo_path = repo_path
        self.target_url = target_url
        self.tool_schemas = tool_schemas
        self.system_prompt = system_prompt
        self.mode = mode
        self.dispatcher = ToolDispatcher(repo_path=repo_path, target_url=target_url)

        # Accumulated state
        self.findings: list[dict] = []
        self.build_result: dict | None = None
        self.messages: list[dict] = []
        self.iteration = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    # ── PUBLIC ────────────────────────────────────────────────────────

    def run(self, initial_user_message: str) -> dict:
        """
        Execute the agentic loop.

        Returns:
            {
                "findings": list[dict],
                "build_result": dict | None,
                "iterations_used": int,
                "input_tokens": int,
                "output_tokens": int,
            }
        """
        self.messages = [{"role": "user", "content": initial_user_message}]

        while self.iteration < MAX_ITERATIONS:
            self.iteration += 1
            self._log(f"Iteration {self.iteration}/{MAX_ITERATIONS}")

            # ── CALL CLAUDE ───────────────────────────────────────────
            response = self._call_claude()
            self.total_input_tokens += response.usage.input_tokens
            self.total_output_tokens += response.usage.output_tokens

            self._log(f"Stop reason: {response.stop_reason}  "
                      f"(tokens in/out: {response.usage.input_tokens}/"
                      f"{response.usage.output_tokens})")

            # Append Claude's full response to conversation history
            self.messages.append({
                "role": "assistant",
                "content": response.content,
            })

            # ── TERMINAL: NATURAL END ─────────────────────────────────
            if response.stop_reason == "end_turn":
                for block in response.content:
                    if hasattr(block, "text") and block.text:
                        self._log(f"Agent concluded: {block.text[:200]}")
                break

            # ── TERMINAL: UNEXPECTED STOP ─────────────────────────────
            if response.stop_reason not in ("tool_use", "end_turn"):
                self._log(f"Unexpected stop reason: {response.stop_reason}")
                break

            # ── EXECUTE TOOL CALLS ────────────────────────────────────
            tool_results = self._execute_tool_calls(response.content)

            # Feed all results back in a single user turn
            self.messages.append({
                "role": "user",
                "content": tool_results,
            })

            # If set_build_result was the only tool called this turn,
            # Claude is done — break after feeding back the ack.
            all_names = [
                b.name for b in response.content
                if hasattr(b, "name")
            ]
            if self.build_result is not None and all_names == ["set_build_result"]:
                break

        self._log(
            f"Done. {len(self.findings)} finding(s) logged. "
            f"Tokens: {self.total_input_tokens} in / {self.total_output_tokens} out"
        )

        return {
            "findings": self.findings,
            "build_result": self.build_result,
            "iterations_used": self.iteration,
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
        }

    # ── PRIVATE ───────────────────────────────────────────────────────

    def _estimate_tokens(self) -> int:
        """Rough token estimate from conversation character count.
        Uses str() instead of json.dumps() because assistant messages
        contain Anthropic SDK objects (ToolUseBlock etc.) that aren't
        JSON-serialisable directly."""
        total_chars = sum(len(str(m)) for m in self.messages)
        return total_chars // TOKEN_CHARS_RATIO

    def _trim_conversation(self) -> None:
        """
        When approaching the token limit, shrink old tool_result content
        so Claude can keep reasoning without hitting a 400 error.

        Strategy: walk backwards from the oldest messages and replace
        large tool_result content with a short summary. Never touch the
        first user message or the last two assistant/user turn pairs.
        """
        estimated = self._estimate_tokens()
        if estimated < TOKEN_TRIM_THRESHOLD:
            return

        self._log(f"⚠️  Context ~{estimated:,} tokens — trimming old tool results")

        # Never trim: index 0 (initial user message) or the last 4 messages
        # (last two assistant+user pairs — Claude needs these for continuity)
        trim_candidates = list(range(1, max(1, len(self.messages) - 4)))

        for idx in trim_candidates:
            msg = self.messages[idx]
            if msg["role"] != "user":
                continue
            content = msg.get("content", [])
            if not isinstance(content, list):
                continue

            changed = False
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_result":
                    continue
                raw = block.get("content", "")
                if len(raw) > 500:
                    block["content"] = raw[:200] + " ... [trimmed to save context]"
                    changed = True

            if changed:
                # Re-check after trimming this message
                if self._estimate_tokens() < TOKEN_TRIM_THRESHOLD:
                    break

        new_estimate = self._estimate_tokens()
        self._log(f"   After trim: ~{new_estimate:,} tokens")

    def _call_claude(self) -> Any:
        """Call the Anthropic API with retry on transient errors."""
        # Trim conversation history before every call
        self._trim_conversation()

        for attempt in range(3):
            try:
                return client.messages.create(
                    model=MODEL,
                    max_tokens=8096,
                    system=self.system_prompt,
                    tools=self.tool_schemas,
                    messages=self.messages,
                )
            except anthropic.RateLimitError:
                wait = 2 ** attempt * 5
                self._log(f"Rate limited — waiting {wait}s")
                time.sleep(wait)
            except anthropic.BadRequestError as e:
                # Context still too long after trim — force-drop half the history
                if "prompt is too long" in str(e) and attempt < 2:
                    self._log("Context still too long — force-dropping older messages")
                    self._force_drop_old_messages()
                    continue
                raise
            except anthropic.APIStatusError as e:
                if e.status_code >= 500 and attempt < 2:
                    time.sleep(3)
                    continue
                raise
        raise RuntimeError("Claude API call failed after 3 attempts")

    def _force_drop_old_messages(self) -> None:
        """
        Last resort: drop the oldest assistant+user turn pairs (keep first
        user message + last 6 messages). This loses some context but prevents
        a hard crash.
        """
        if len(self.messages) <= 7:
            return
        # Keep: messages[0] (initial context) + messages[-6:]
        dropped = len(self.messages) - 7
        self.messages = [self.messages[0]] + self.messages[-6:]
        self._log(f"   Force-dropped {dropped} old messages from history")

    def _execute_tool_calls(self, content_blocks: list) -> list[dict]:
        """Dispatch all tool_use blocks and return a list of tool_result blocks."""
        results = []

        for block in content_blocks:
            if not hasattr(block, "type") or block.type != "tool_use":
                continue

            name = block.name
            inputs = block.input
            use_id = block.id

            short_inputs = json.dumps(inputs)[:120]
            self._log(f"  → {name}({short_inputs})")

            try:
                result = self.dispatcher.dispatch(name, inputs)
            except Exception as e:
                result = {"error": str(e), "success": False}

            # Capture side-effects from special tools
            if name == "log_finding":
                self.findings.append(dict(inputs))
            elif name == "set_build_result":
                self.build_result = dict(inputs)

            results.append({
                "type": "tool_result",
                "tool_use_id": use_id,
                "content": json.dumps(result),
            })

        return results

    def _log(self, msg: str) -> None:
        print(f"[{self.mode.upper()}] {msg}", flush=True)
