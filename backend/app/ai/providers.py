"""
AI Provider implementations — Azure OpenAI, Claude CLI, Claude API, Gemini,
and generic CLI/local-LLM providers auto-detected from the system PATH.
Each provider wraps its respective API/CLI to provide a uniform generate() interface.
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("vulnscan.ai")

# Prefix that addresses one specific ai_provider_configs row, so two providers
# of the same type (two OpenRouter models, say) stay distinguishable.
DB_PROVIDER_PREFIX = "db:"


@dataclass
class AiResponse:
    """Standardized AI response across all providers."""
    content: str          # Raw text response
    tokens_used: int      # Total tokens (prompt + completion)
    model: str            # Model identifier used
    # Per-call diagnostics (finish_reason, token split, upstream provider…),
    # stored with the analysis result — worker logs do not survive a redeploy.
    meta: dict = field(default_factory=dict)


class EmptyResponseError(RuntimeError):
    """The provider returned 200 OK but no usable answer (empty or truncated).

    Reasoning models do this when the reasoning trace uses up max_tokens
    before any answer is written (finish_reason == "length"). Treating it as
    a parsed-but-empty result silently turns every finding into the default
    verdict, so it is raised instead.
    """

    def __init__(self, message: str, finish_reason: str | None = None,
                 tokens_used: int = 0):
        super().__init__(message)
        self.finish_reason = finish_reason
        self.tokens_used = tokens_used


class TurnLimitError(RuntimeError):
    """An agentic session used its whole turn budget without a final answer."""


class ProviderUnavailableError(RuntimeError):
    """The provider cannot serve this kind of call at all.

    Raised separately so a multi-call run stops at the first one: every later
    call would fail the same way, slowly.
    """


class ProviderAuthError(ProviderUnavailableError):
    """The provider rejected our credentials."""


class ToolsUnsupportedError(ProviderUnavailableError):
    """The model (or every upstream host serving it) does not do tool calls."""


class AiProvider:
    """Base class for all AI providers."""
    name: str = "base"
    # True when investigate() is implemented: an agentic session over the
    # read-only tools in ai/tools.py.
    supports_tools: bool = False

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        raise NotImplementedError


class AzureOpenAIProvider(AiProvider):
    """Azure OpenAI — GPT-4o via Azure-hosted endpoint."""
    name = "azure_openai"

    def __init__(self, endpoint: str, api_key: str, deployment: str, api_version: str):
        from openai import AzureOpenAI
        self.client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )
        self.deployment = deployment

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        logger.info("Azure OpenAI: sending request (model=%s)", self.deployment)
        resp = self.client.chat.completions.create(
            model=self.deployment,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or ""
        tokens = resp.usage.total_tokens if resp.usage else 0
        logger.info("Azure OpenAI: received %d tokens", tokens)
        return AiResponse(content=content, tokens_used=tokens, model=self.deployment)


class ClaudeCLIProvider(AiProvider):
    """Claude CLI — uses locally installed claude command via subprocess.

    This is a plain text-in / text-out completion, so the CLI must NOT enter
    its agentic tool loop. Left to its own devices the model answers a security
    analysis prompt by first reaching for Bash/Read/Grep to go look at the
    target, burns every available turn on tool calls, and then exits with
    ``Error: Reached max turns (N)`` on **stdout with returncode 0** — no
    analysis at all. Disabling the tools forces a direct single-shot answer.
    """
    name = "claude_cli"
    supports_tools = True

    _DISALLOWED_TOOLS = [
        "Bash", "Read", "Write", "Edit", "Glob", "Grep",
        "WebFetch", "WebSearch", "Task", "TodoWrite", "NotebookEdit",
    ]

    def __init__(self, cli_path: str, model: str, timeout: int | None = None):
        from app.core.config import settings as _s

        self.cli_path = cli_path
        self.model = model
        self.timeout = timeout or _s.AI_CLI_TIMEOUT

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        logger.info(
            "Claude CLI: sending request via subprocess (model=%s, timeout=%ds)",
            self.model, self.timeout,
        )

        # Build the combined prompt (system + user)
        combined = f"{system_prompt}\n\n---\n\n{user_prompt}"

        cmd = [
            self.cli_path,
            "--print",
            "--model", self.model,
            "--max-turns", "1",
            "--disallowed-tools", *self._DISALLOWED_TOOLS,
        ]

        try:
            proc = subprocess.run(
                cmd,
                input=combined,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Claude CLI timed out after {self.timeout} seconds. "
                f"Raise AI_CLI_TIMEOUT (and AI_ANALYSIS_TIMEOUT with it) or "
                f"analyse fewer findings per run."
            )

        if proc.returncode != 0:
            stderr = proc.stderr[:500] if proc.stderr else "no stderr"
            raise RuntimeError(f"Claude CLI failed (rc={proc.returncode}): {stderr}")

        content = proc.stdout.strip()
        if not content:
            stderr = (proc.stderr or "").strip()[:500]
            raise RuntimeError(
                f"Claude CLI returned empty response (rc=0). stderr: {stderr or 'none'}"
            )

        # The CLI reports several fatal conditions on stdout with returncode 0,
        # so a plain rc check is not enough to tell success from failure.
        if "Reached max turns" in content and len(content) < 200:
            raise RuntimeError(
                f"Claude CLI exhausted its turn budget without answering "
                f"({content}). The CLI ran agentically instead of replying "
                f"directly — check that --disallowed-tools is still accepted "
                f"by the installed CLI version."
            )
        if content.startswith("Error:") and len(content) < 200:
            raise RuntimeError(f"Claude CLI error: {content}")

        # Estimate tokens (Claude CLI doesn't always report usage)
        estimated_tokens = len(combined.split()) + len(content.split())

        logger.info("Claude CLI: received ~%d estimated tokens", estimated_tokens)
        return AiResponse(
            content=content,
            tokens_used=estimated_tokens,
            model=self.model,
        )

    def investigate(self, system_prompt: str, user_prompt: str, *, workspace_id: int,
                    job_id: int, trail_path: str, max_turns: int) -> AiResponse:
        """One agentic session over the read-only tools in ai/tools.py.

        The opposite of generate(): here the tool loop is the point. It stays
        safe because the only tools that exist are ours — `--tools ""` removes
        every built-in one (Bash, Read, WebFetch…), an allowlist that a CLI
        update cannot widen, unlike the denylist generate() relies on.

        The CLI starts ai/mcp_server.py itself and passes it this worker's
        environment, so the config written here carries only the scope ids.
        """
        from app.ai.tools import TOOLS

        # backend/app/ai/providers.py -> backend/. Not app.__file__: `app` is a
        # namespace package and has none.
        backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cfg = {"mcpServers": {"vulnscan": {
            "command": sys.executable,
            "args": ["-m", "app.ai.mcp_server"],
            "env": {
                "PYTHONPATH": backend_root,
                "VULNSCAN_WORKSPACE_ID": str(workspace_id),
                "VULNSCAN_JOB_ID": str(job_id),
                "VULNSCAN_TRAIL": trail_path,
            },
        }}}
        fd, cfg_path = tempfile.mkstemp(prefix="vs-mcp-", suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(cfg, fh)

        cmd = [
            self.cli_path,
            "--print",
            "--output-format", "stream-json",
            "--verbose",                       # stream-json in --print mode requires it
            "--model", self.model,
            "--system-prompt", system_prompt,  # replaces the coding-agent persona
            "--tools", "",
            "--strict-mcp-config", "--mcp-config", cfg_path,
            "--allowedTools", *[f"mcp__vulnscan__{n}" for n in TOOLS],
            "--max-turns", str(max_turns),
        ]
        try:
            proc = subprocess.run(cmd, input=user_prompt, capture_output=True,
                                  text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Claude CLI investigation timed out after {self.timeout}s "
                f"(AI_CLI_TIMEOUT)."
            )
        finally:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass

        init, result = None, None
        for line in proc.stdout.splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "system" and ev.get("subtype") == "init":
                init = ev
            elif ev.get("type") == "result":
                result = ev

        # A tool server that failed to start would leave the model answering
        # without tools — a plain validate wearing the investigate label.
        servers = {s.get("name"): s.get("status") for s in (init or {}).get("mcp_servers") or []}
        if init is not None and servers.get("vulnscan") != "connected":
            raise RuntimeError(f"VulnScan tool server did not connect: {servers}")

        if result is None:
            tail = (proc.stderr or proc.stdout or "").strip()[-500:]
            raise RuntimeError(f"Claude CLI investigation ended without a result "
                               f"(rc={proc.returncode}): {tail or 'no output'}")

        text = (result.get("result") or "").strip()
        # The CLI reports failures as subtype "success" with is_error=true
        # (an expired login does exactly that), so neither the return code nor
        # the subtype alone can be trusted.
        if result.get("is_error") or result.get("subtype") != "success":
            if result.get("subtype") == "error_max_turns" or "max turns" in text.lower():
                raise TurnLimitError(f"no verdict within {max_turns} turns")
            if "authenticate" in text.lower() or "oauth" in text.lower():
                raise ProviderAuthError(
                    f"Claude CLI login is no longer valid: {text[:200]}. Renew it with "
                    f"`docker compose exec -it worker-ai claude`, then /login."
                )
            raise RuntimeError(f"Claude CLI investigation failed "
                               f"({result.get('subtype')}): {text[:300]}")

        usage = result.get("usage") or {}
        tokens = sum(int(usage.get(k) or 0) for k in (
            "input_tokens", "output_tokens",
            "cache_creation_input_tokens", "cache_read_input_tokens"))
        return AiResponse(
            content=text,
            tokens_used=tokens,
            model=self.model,
            meta={
                "turns": result.get("num_turns"),
                "duration_ms": result.get("duration_ms"),
                "cost_usd": result.get("total_cost_usd"),
            },
        )


class ClaudeAPIProvider(AiProvider):
    """Anthropic API — uses the official anthropic SDK with ANTHROPIC_API_KEY.
    Use this when the Claude CLI segfaults on the host (e.g. CPUs without AVX).
    """
    name = "claude_api"

    def __init__(self, api_key: str, model: str):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        logger.info("Claude API: sending request (model=%s)", self.model)

        # Anthropic API requires max_tokens; cap at model limit.
        # Opus / Sonnet 4.x support up to 64K-128K output tokens but 8K is plenty for our prompts.
        msg = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=0.2,
        )

        # Concatenate all text blocks (Anthropic returns a list of content blocks)
        content = "".join(
            getattr(block, "text", "") for block in msg.content if getattr(block, "type", "") == "text"
        )

        # Token usage — input + output
        usage = getattr(msg, "usage", None)
        tokens = (getattr(usage, "input_tokens", 0) + getattr(usage, "output_tokens", 0)) if usage else 0

        logger.info("Claude API: received %d tokens (in=%d, out=%d)",
                    tokens,
                    getattr(usage, "input_tokens", 0) if usage else 0,
                    getattr(usage, "output_tokens", 0) if usage else 0)
        return AiResponse(content=content, tokens_used=tokens, model=self.model)


class GeminiProvider(AiProvider):
    """Google Gemini — via google-generativeai SDK."""
    name = "gemini"

    def __init__(self, api_key: str, model: str):
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self.genai = genai
        self.model_name = model

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        logger.info("Gemini: sending request (model=%s)", self.model_name)

        model = self.genai.GenerativeModel(
            self.model_name,
            system_instruction=system_prompt,
            generation_config=self.genai.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=0.2,
                response_mime_type="application/json",
            ),
        )

        resp = model.generate_content(user_prompt)
        content = resp.text or ""

        # Extract token usage
        tokens = 0
        usage = getattr(resp, "usage_metadata", None)
        if usage:
            tokens = getattr(usage, "total_token_count", 0)

        logger.info("Gemini: received %d tokens", tokens)
        return AiResponse(content=content, tokens_used=tokens, model=self.model_name)


class OpenAIProvider(AiProvider):
    """OpenAI API (and OpenAI-compatible endpoints like Qwen, local LLMs)."""
    name = "openai"
    supports_tools = True

    def __init__(self, api_key: str, model: str, base_url: str | None = None):
        from openai import OpenAI
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)
        self.model_name = model

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        logger.info("OpenAI: sending request (model=%s)", self.model_name)

        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        choice = resp.choices[0]
        message = choice.message
        content = message.content or ""
        finish_reason = choice.finish_reason
        usage = resp.usage
        tokens = usage.total_tokens if usage else 0
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0
        details = getattr(usage, "completion_tokens_details", None)
        reasoning_tokens = getattr(details, "reasoning_tokens", 0) or 0
        # OpenRouter returns the reasoning trace as a non-standard field.
        reasoning = getattr(message, "reasoning", None) or \
            (getattr(message, "model_extra", None) or {}).get("reasoning") or ""
        # OpenRouter routes one model id to different upstream hosts, which can
        # behave very differently (GLM's reasoning length varied 10x between
        # runs). It reports the host as a non-standard top-level "provider".
        upstream = getattr(resp, "provider", None) or \
            (getattr(resp, "model_extra", None) or {}).get("provider") or ""
        served_model = getattr(resp, "model", "") or ""

        logger.info(
            "OpenAI: received %d tokens (model=%s served=%s upstream=%s "
            "finish_reason=%s prompt=%d completion=%d reasoning_tokens=%d "
            "reasoning_chars=%d content_chars=%d max_tokens=%d)",
            tokens, self.model_name, served_model, upstream or "-", finish_reason,
            prompt_tokens, completion_tokens, reasoning_tokens, len(reasoning),
            len(content), max_tokens,
        )
        # A length-truncated answer is as unusable as an empty one: the JSON is
        # cut mid-object and parses to nothing, yet looks like a normal reply.
        if not content.strip() or finish_reason == "length":
            what = "a truncated answer" if content.strip() else "an empty answer"
            raise EmptyResponseError(
                f"{self.model_name} returned {what} "
                f"(finish_reason={finish_reason}, completion={completion_tokens}/"
                f"{max_tokens}, reasoning_tokens={reasoning_tokens})",
                finish_reason=finish_reason, tokens_used=tokens,
            )
        return AiResponse(
            content=content, tokens_used=tokens, model=self.model_name,
            meta={
                "finish_reason": finish_reason,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "reasoning_tokens": reasoning_tokens,
                "upstream_provider": upstream,
                "served_model": served_model,
            },
        )

    def investigate(self, system_prompt: str, user_prompt: str, *, workspace_id: int,
                    job_id: int, trail_path: str, max_turns: int) -> AiResponse:
        """One agentic session, with the tool loop run here in Python.

        Same tools, scope and trail as the Claude CLI path — call_tool() is the
        only way in. One API call is one turn. No response_format: several
        hosts reject json_object alongside tools, and the final answer goes
        through _extract_json() like every other reply.
        """
        import openai
        from app.ai.tools import TOOLS, ToolScope, call_tool
        from app.core.config import settings

        scope = ToolScope(workspace_id=workspace_id, job_id=job_id)
        tools = [{"type": "function", "function": {
                    "name": name, "description": desc, "parameters": schema}}
                 for name, (_fn, desc, schema) in TOOLS.items()]
        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]
        t0, tokens = time.monotonic(), 0

        for turn in range(1, max_turns + 1):
            # The engine budgets one session at AI_CLI_TIMEOUT; hold to it,
            # including the call in flight.
            remaining = settings.AI_CLI_TIMEOUT - (time.monotonic() - t0)
            if remaining <= 5:
                raise RuntimeError(f"investigation exceeded AI_CLI_TIMEOUT "
                                   f"({settings.AI_CLI_TIMEOUT}s) after {turn - 1} turns")
            try:
                resp = self.client.with_options(timeout=remaining).chat.completions.create(
                    model=self.model_name, messages=messages, tools=tools,
                    max_tokens=settings.AI_MAX_TOKENS, temperature=0.2,
                )
            except openai.AuthenticationError as e:
                raise ProviderAuthError(f"{self.model_name}: credentials rejected: {e}")
            except (openai.NotFoundError, openai.BadRequestError) as e:
                if "tool" in str(e).lower():
                    raise ToolsUnsupportedError(f"{self.model_name} does not support tool calls: {e}")
                raise

            choice = resp.choices[0]
            msg = choice.message
            tokens += resp.usage.total_tokens if resp.usage else 0

            if msg.tool_calls:
                turn_msg = {"role": "assistant", "content": msg.content or "",
                            "tool_calls": [{"id": tc.id, "type": "function",
                                            "function": {"name": tc.function.name,
                                                         "arguments": tc.function.arguments}}
                                           for tc in msg.tool_calls]}
                # OpenRouter asks for reasoning to be passed back across tool
                # calls so reasoning models keep their train of thought.
                details = (getattr(msg, "model_extra", None) or {}).get("reasoning_details")
                if details:
                    turn_msg["reasoning_details"] = details
                messages.append(turn_msg)
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                        result = call_tool(scope, tc.function.name, args, trail_path)
                    except json.JSONDecodeError:
                        result = {"error": "arguments were not valid JSON"}
                    messages.append({"role": "tool", "tool_call_id": tc.id,
                                     "content": json.dumps(result, default=str)[:30_000]})
                continue

            content = (msg.content or "").strip()
            if not content or choice.finish_reason == "length":
                raise EmptyResponseError(
                    f"{self.model_name} ended the investigation with "
                    f"{'a truncated' if content else 'an empty'} answer "
                    f"(finish_reason={choice.finish_reason}, turn {turn})",
                    finish_reason=choice.finish_reason, tokens_used=tokens,
                )
            return AiResponse(content=content, tokens_used=tokens, model=self.model_name,
                              meta={"turns": turn,
                                    "duration_ms": int((time.monotonic() - t0) * 1000)})

        raise TurnLimitError(f"no verdict within {max_turns} turns")

    def agent_run(self, system_prompt: str, user_prompt: str, *, tool_specs: list[dict],
                  dispatch, max_turns: int, budget_s: float) -> AiResponse:
        """Generic agentic tool loop (sibling of investigate) with an injected
        tool set, so callers other than the finding-investigator can reuse it.

        tool_specs : list of {"name", "description", "parameters"} (JSON schema).
        dispatch   : callable(name, args_dict) -> dict — already scoped and
                     trailed by the caller; must never raise.
        """
        import openai
        from app.core.config import settings

        tools = [{"type": "function", "function": s} for s in tool_specs]
        messages = [{"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}]
        t0, tokens = time.monotonic(), 0

        for turn in range(1, max_turns + 1):
            remaining = budget_s - (time.monotonic() - t0)
            if remaining <= 5:
                raise RuntimeError(f"agent session exceeded budget ({budget_s}s) "
                                   f"after {turn - 1} turns")
            try:
                resp = self.client.with_options(timeout=remaining).chat.completions.create(
                    model=self.model_name, messages=messages, tools=tools,
                    max_tokens=settings.AI_MAX_TOKENS, temperature=0.2,
                )
            except openai.AuthenticationError as e:
                raise ProviderAuthError(f"{self.model_name}: credentials rejected: {e}")
            except (openai.NotFoundError, openai.BadRequestError) as e:
                if "tool" in str(e).lower():
                    raise ToolsUnsupportedError(f"{self.model_name} does not support tool calls: {e}")
                raise

            choice = resp.choices[0]
            msg = choice.message
            tokens += resp.usage.total_tokens if resp.usage else 0

            if msg.tool_calls:
                turn_msg = {"role": "assistant", "content": msg.content or "",
                            "tool_calls": [{"id": tc.id, "type": "function",
                                            "function": {"name": tc.function.name,
                                                         "arguments": tc.function.arguments}}
                                           for tc in msg.tool_calls]}
                details = (getattr(msg, "model_extra", None) or {}).get("reasoning_details")
                if details:
                    turn_msg["reasoning_details"] = details
                messages.append(turn_msg)
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                        result = dispatch(tc.function.name, args)
                    except json.JSONDecodeError:
                        result = {"error": "arguments were not valid JSON"}
                    messages.append({"role": "tool", "tool_call_id": tc.id,
                                     "content": json.dumps(result, default=str)[:30_000]})
                continue

            content = (msg.content or "").strip()
            if not content or choice.finish_reason == "length":
                raise EmptyResponseError(
                    f"{self.model_name} ended the session with "
                    f"{'a truncated' if content else 'an empty'} answer "
                    f"(finish_reason={choice.finish_reason}, turn {turn})",
                    finish_reason=choice.finish_reason, tokens_used=tokens,
                )
            return AiResponse(content=content, tokens_used=tokens, model=self.model_name,
                              meta={"turns": turn,
                                    "duration_ms": int((time.monotonic() - t0) * 1000)})

        raise TurnLimitError(f"no answer within {max_turns} turns")

    def chat_turn(self, messages: list[dict], tools: list[dict], budget_s: float = 60.0) -> dict:
        """One completion turn for a caller-driven tool loop that must pause and
        resume across worker invocations (the agentic exploit harness). Returns a
        normalised, JSON-serialisable dict; executes no tools itself."""
        import openai
        from app.core.config import settings
        try:
            resp = self.client.with_options(timeout=budget_s).chat.completions.create(
                model=self.model_name, messages=messages, tools=tools,
                max_tokens=settings.AI_MAX_TOKENS, temperature=0.2,
            )
        except openai.AuthenticationError as e:
            raise ProviderAuthError(f"{self.model_name}: credentials rejected: {e}")
        except (openai.NotFoundError, openai.BadRequestError) as e:
            if "tool" in str(e).lower():
                raise ToolsUnsupportedError(f"{self.model_name} does not support tool calls: {e}")
            raise
        choice = resp.choices[0]
        msg = choice.message
        tool_calls = [{"id": tc.id, "name": tc.function.name, "arguments": tc.function.arguments}
                      for tc in (msg.tool_calls or [])]
        details = (getattr(msg, "model_extra", None) or {}).get("reasoning_details")
        return {
            "content": msg.content or "",
            "tool_calls": tool_calls,
            "finish_reason": choice.finish_reason,
            "reasoning_details": details,
            "tokens": resp.usage.total_tokens if resp.usage else 0,
        }


# ── CLI auto-detection ─────────────────────────────────────────────────────

# Each entry describes how to invoke a CLI tool for text generation.
# "style" controls how prompts are passed and output is read:
#   - "claude"  : claude --print --model M --max-turns 1, input via stdin
#   - "ollama"  : ollama run <model>, input via stdin
#   - "stdin"   : generic binary that reads stdin, writes stdout (codex, qwen, aichat, mods, fabric, llm)
#   - "openai_compat" : tool exposes an OpenAI-compatible local server (lmstudio, localai, jan)

_CLI_BINARIES = [
    # ── Cloud / proprietary CLIs ──────────────────────────────
    {"binary": "claude",    "id": "claude_cli",    "name": "Claude CLI",        "default_model": "claude-opus-4-6",        "style": "claude"},
    {"binary": "codex",     "id": "codex_cli",     "name": "Codex CLI",         "default_model": "codex",                  "style": "stdin"},
    {"binary": "gemini",    "id": "gemini_cli",    "name": "Gemini CLI",        "default_model": "gemini-2.5-flash",       "style": "stdin"},
    {"binary": "copilot",   "id": "copilot_cli",   "name": "GitHub Copilot CLI","default_model": "copilot",                "style": "stdin"},

    # ── Local LLM runners ────────────────────────────────────
    {"binary": "ollama",    "id": "ollama",        "name": "Ollama",            "default_model": "llama3.1",               "style": "ollama"},
    {"binary": "llama-cli", "id": "llamacpp",      "name": "llama.cpp",         "default_model": "default",                "style": "stdin"},
    {"binary": "lmstudio",  "id": "lmstudio",      "name": "LM Studio",         "default_model": "default",                "style": "openai_compat", "endpoint": "http://localhost:1234/v1"},
    {"binary": "localai",   "id": "localai",       "name": "LocalAI",           "default_model": "default",                "style": "openai_compat", "endpoint": "http://localhost:8080/v1"},
    {"binary": "jan",       "id": "jan",           "name": "Jan",               "default_model": "default",                "style": "openai_compat", "endpoint": "http://localhost:1337/v1"},

    # ── Multi-provider CLI wrappers ──────────────────────────
    {"binary": "aichat",    "id": "aichat",        "name": "aichat",            "default_model": "default",                "style": "stdin"},
    {"binary": "mods",      "id": "mods",          "name": "Mods (charmbracelet)","default_model": "default",              "style": "stdin"},
    {"binary": "fabric",    "id": "fabric",        "name": "Fabric",            "default_model": "default",                "style": "stdin"},
    {"binary": "llm",       "id": "llm",           "name": "llm (Simon Willison)","default_model": "default",              "style": "stdin"},
    {"binary": "qwen",      "id": "qwen_cli",      "name": "Qwen CLI",          "default_model": "qwen",                  "style": "stdin"},
]

# Detection cache: (timestamp, results).  Avoids shutil.which() on every request.
_cli_cache: tuple[float, list[dict]] = (0.0, [])
_CLI_CACHE_TTL = 30  # seconds


def detect_cli_providers() -> list[dict]:
    """Scan for installed CLI tools and return available ones (cached)."""
    import shutil
    global _cli_cache
    now = time.time()
    if now - _cli_cache[0] < _CLI_CACHE_TTL and _cli_cache[1] is not None:
        return _cli_cache[1]

    found = []
    for cli in _CLI_BINARIES:
        path = shutil.which(cli["binary"])
        if path:
            entry = {
                "id": cli["id"],
                "name": cli["name"],
                "model": cli["default_model"],
                "source": "cli",
                "cli_path": path,
                "style": cli["style"],
            }
            if cli.get("endpoint"):
                entry["endpoint"] = cli["endpoint"]
            found.append(entry)

    _cli_cache = (now, found)
    return found


def _find_cli_entry(provider_id: str) -> dict | None:
    """Look up a CLI entry from the detected list by id."""
    for cli in detect_cli_providers():
        if cli["id"] == provider_id:
            return cli
    return None


# ── Generic CLI provider ──────────────────────────────────────────────────

class GenericCLIProvider(AiProvider):
    """Invokes any stdin/stdout CLI tool for text generation."""
    name = "generic_cli"

    def __init__(self, cli_path: str, model: str, style: str = "stdin",
                 endpoint: str | None = None):
        self.cli_path = cli_path
        self.model = model
        self.style = style
        self.endpoint = endpoint

    def _build_cmd(self) -> list[str]:
        if self.style == "claude":
            return [self.cli_path, "--print", "--model", self.model, "--max-turns", "5"]
        if self.style == "ollama":
            return [self.cli_path, "run", self.model]
        # stdin-style: just invoke the binary (aichat, mods, fabric, llm, codex, qwen …)
        return [self.cli_path]

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        # OpenAI-compatible local servers (LM Studio, LocalAI, Jan)
        if self.style == "openai_compat" and self.endpoint:
            return self._generate_openai_compat(system_prompt, user_prompt, max_tokens)

        logger.info("CLI [%s]: sending request via subprocess (model=%s)", self.style, self.model)
        combined = f"{system_prompt}\n\n---\n\n{user_prompt}"
        cmd = self._build_cmd()

        try:
            proc = subprocess.run(
                cmd, input=combined, capture_output=True, text=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{self.cli_path} timed out after 600s")

        if proc.returncode != 0:
            stderr = proc.stderr[:500] if proc.stderr else "no stderr"
            raise RuntimeError(f"{self.cli_path} failed (rc={proc.returncode}): {stderr}")

        content = proc.stdout.strip()
        if not content:
            raise RuntimeError(f"{self.cli_path} returned empty response")

        # Detect CLI error messages that arrive on stdout with rc=0
        if content.startswith("Error:") and len(content) < 200:
            raise RuntimeError(f"CLI error ({self.style}): {content}")

        estimated_tokens = len(combined.split()) + len(content.split())
        logger.info("CLI [%s]: received ~%d estimated tokens", self.style, estimated_tokens)
        return AiResponse(content=content, tokens_used=estimated_tokens, model=self.model)

    def _generate_openai_compat(self, system_prompt: str, user_prompt: str,
                                max_tokens: int) -> AiResponse:
        """Call a local OpenAI-compatible server (LM Studio, LocalAI, Jan)."""
        import urllib.request
        import urllib.error

        logger.info("CLI/OpenAI-compat [%s]: sending request (model=%s)", self.cli_path, self.model)
        url = f"{self.endpoint.rstrip('/')}/chat/completions"
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }).encode()

        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError) as e:
            raise RuntimeError(f"Local server {url} unreachable: {e}")

        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        tokens = data.get("usage", {}).get("total_tokens", 0)
        if not tokens:
            tokens = len(system_prompt.split()) + len(user_prompt.split()) + len(content.split())
        logger.info("CLI/OpenAI-compat: received %d tokens", tokens)
        return AiResponse(content=content, tokens_used=tokens, model=self.model)


# ── Provider factory ───────────────────────────────────────────────────────

def get_provider_from_db_config(cfg) -> AiProvider:
    """Create a provider instance from a DB AiProviderConfig record."""
    from app.core.crypto import decrypt_str

    api_key = decrypt_str(cfg.api_key_enc) if cfg.api_key_enc else None
    pt = cfg.provider_type

    if pt == "openai" or pt == "openai_compat":
        # openai_compat with a local endpoint (Ollama, LM Studio) may not need a real key
        return OpenAIProvider(api_key=api_key or "local", model=cfg.model, base_url=cfg.endpoint or None)

    elif pt == "azure_openai":
        if not api_key or not cfg.endpoint:
            raise ValueError(f"Azure provider '{cfg.name}' needs API key and endpoint")
        extra = json.loads(cfg.extra_json or "{}")
        return AzureOpenAIProvider(
            endpoint=cfg.endpoint,
            api_key=api_key,
            deployment=cfg.model,
            api_version=extra.get("api_version", "2025-01-01-preview"),
        )

    elif pt == "claude_api":
        if not api_key:
            raise ValueError(f"Claude API provider '{cfg.name}' has no API key")
        return ClaudeAPIProvider(api_key=api_key, model=cfg.model)

    elif pt == "gemini":
        if not api_key:
            raise ValueError(f"Gemini provider '{cfg.name}' has no API key")
        return GeminiProvider(api_key=api_key, model=cfg.model)

    raise ValueError(f"Unsupported provider type: {pt}")


def get_provider(provider_name: str, workspace_id: int | None = None) -> AiProvider:
    """Factory — returns an AI provider instance.

    `provider_name` is either:
      * "db:<row id>" — one specific provider added via Settings > AI Providers
      * a provider type ("claude_cli", "gemini", "openai_compat", …)

    Resolution order:
      1. DB (per-workspace config added via Settings UI)
      2. Env vars (.env / docker-compose)
      3. Auto-detected CLI tools on the system PATH

    A bare type is kept working for settings saved before row-addressing
    existed, but it cannot distinguish two rows of the same type — it resolves
    to the most recently added one.
    """
    from app.core.config import settings

    # 1. Check DB for workspace-specific provider config
    if workspace_id is not None:
        row_id = None
        if isinstance(provider_name, str) and provider_name.startswith(DB_PROVIDER_PREFIX):
            try:
                row_id = int(provider_name[len(DB_PROVIDER_PREFIX):])
            except ValueError:
                raise ValueError(f"Malformed provider reference: {provider_name}")

        try:
            from app.db.session import SessionLocal
            from app.db import models as m
            db = SessionLocal()
            try:
                q = db.query(m.AiProviderConfig).filter(
                    # Always scope to the workspace: a row id must never reach
                    # across tenants.
                    m.AiProviderConfig.workspace_id == workspace_id,
                    m.AiProviderConfig.enabled == True,
                )
                if row_id is not None:
                    cfg = q.filter(m.AiProviderConfig.id == row_id).first()
                    if cfg is None:
                        raise ValueError(
                            f"AI provider #{row_id} not found, disabled, or not in "
                            f"this workspace"
                        )
                    return get_provider_from_db_config(cfg)

                cfg = (
                    q.filter(m.AiProviderConfig.provider_type == provider_name)
                    .order_by(m.AiProviderConfig.id.desc())
                    .first()
                )
                if cfg:
                    return get_provider_from_db_config(cfg)
            finally:
                # Without this the session leaks whenever the query raises.
                db.close()
        except ValueError:
            raise
        except Exception as e:
            logger.warning("DB provider lookup failed for %s: %s", provider_name, e)

    # 2. Fall back to env-configured providers
    if provider_name == "azure_openai":
        if not settings.AZURE_OPENAI_ENDPOINT or not settings.AZURE_OPENAI_API_KEY:
            raise ValueError("Azure OpenAI not configured: set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY")
        return AzureOpenAIProvider(
            endpoint=settings.AZURE_OPENAI_ENDPOINT,
            api_key=settings.AZURE_OPENAI_API_KEY,
            deployment=settings.AZURE_OPENAI_DEPLOYMENT,
            api_version=settings.AZURE_OPENAI_API_VERSION,
        )

    elif provider_name == "claude_cli":
        import shutil
        if not shutil.which(settings.CLAUDE_CLI_PATH):
            raise ValueError(f"Claude CLI not found at: {settings.CLAUDE_CLI_PATH}")
        return ClaudeCLIProvider(
            cli_path=settings.CLAUDE_CLI_PATH,
            model=settings.CLAUDE_CLI_MODEL,
        )

    elif provider_name == "claude_api":
        if not settings.ANTHROPIC_API_KEY:
            raise ValueError("Claude API not configured: set ANTHROPIC_API_KEY in .env")
        return ClaudeAPIProvider(
            api_key=settings.ANTHROPIC_API_KEY,
            model=settings.ANTHROPIC_MODEL,
        )

    elif provider_name == "gemini":
        if not settings.GEMINI_API_KEY:
            raise ValueError("Gemini not configured: set GEMINI_API_KEY")
        return GeminiProvider(
            api_key=settings.GEMINI_API_KEY,
            model=settings.GEMINI_MODEL,
        )

    elif provider_name in ("openai", "openai_compat"):
        raise ValueError("OpenAI provider not configured: add via Settings > AI Providers")

    # 3. Fall back to auto-detected CLI tools
    cli = _find_cli_entry(provider_name)
    if cli:
        return GenericCLIProvider(
            cli_path=cli["cli_path"],
            model=cli["model"],
            style=cli["style"],
            endpoint=cli.get("endpoint"),
        )

    raise ValueError(f"Unknown AI provider: {provider_name}")

