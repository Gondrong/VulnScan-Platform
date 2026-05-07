"""
AI Provider implementations — Azure OpenAI, Claude CLI, Claude API, Gemini.
Each provider wraps its respective API/CLI to provide a uniform generate() interface.
"""
import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("vulnscan.ai")


@dataclass
class AiResponse:
    """Standardized AI response across all providers."""
    content: str          # Raw text response
    tokens_used: int      # Total tokens (prompt + completion)
    model: str            # Model identifier used


class AiProvider:
    """Base class for all AI providers."""
    name: str = "base"

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
    """Claude CLI — uses locally installed claude command via subprocess."""
    name = "claude_cli"

    def __init__(self, cli_path: str, model: str):
        self.cli_path = cli_path
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 8192) -> AiResponse:
        logger.info("Claude CLI: sending request via subprocess (model=%s)", self.model)

        # Build the combined prompt (system + user)
        combined = f"{system_prompt}\n\n---\n\n{user_prompt}"

        cmd = [
            self.cli_path,
            "--print",
            "--model", self.model,
            "--max-turns", "1",
        ]

        try:
            proc = subprocess.run(
                cmd,
                input=combined,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Claude CLI timed out after 600 seconds")

        if proc.returncode != 0:
            stderr = proc.stderr[:500] if proc.stderr else "no stderr"
            raise RuntimeError(f"Claude CLI failed (rc={proc.returncode}): {stderr}")

        content = proc.stdout.strip()
        if not content:
            raise RuntimeError("Claude CLI returned empty response")

        # Estimate tokens (Claude CLI doesn't always report usage)
        estimated_tokens = len(combined.split()) + len(content.split())

        logger.info("Claude CLI: received ~%d estimated tokens", estimated_tokens)
        return AiResponse(
            content=content,
            tokens_used=estimated_tokens,
            model=self.model,
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

        content = resp.choices[0].message.content or ""
        tokens = resp.usage.total_tokens if resp.usage else 0

        logger.info("OpenAI: received %d tokens (model=%s)", tokens, self.model_name)
        return AiResponse(content=content, tokens_used=tokens, model=self.model_name)


# ── CLI auto-detection ─────────────────────────────────────────────────────

_CLI_BINARIES = [
    {"binary": "claude", "id": "claude_cli", "name": "Claude CLI", "default_model": "claude-opus-4-6"},
    {"binary": "codex",  "id": "codex_cli",  "name": "Codex CLI",  "default_model": "codex"},
    {"binary": "qwen",   "id": "qwen_cli",   "name": "Qwen CLI",   "default_model": "qwen"},
]


def detect_cli_providers() -> list[dict]:
    """Scan for installed CLI tools and return available ones."""
    import shutil
    found = []
    for cli in _CLI_BINARIES:
        path = shutil.which(cli["binary"])
        if path:
            found.append({
                "id": cli["id"],
                "name": cli["name"],
                "model": cli["default_model"],
                "source": "cli",
                "cli_path": path,
            })
    return found


# ── Provider factory ───────────────────────────────────────────────────────

def get_provider_from_db_config(cfg) -> AiProvider:
    """Create a provider instance from a DB AiProviderConfig record."""
    from app.core.crypto import decrypt_str

    api_key = decrypt_str(cfg.api_key_enc) if cfg.api_key_enc else None
    pt = cfg.provider_type

    if pt == "openai" or pt == "openai_compat":
        if not api_key:
            raise ValueError(f"Provider '{cfg.name}' has no API key")
        return OpenAIProvider(api_key=api_key, model=cfg.model, base_url=cfg.endpoint or None)

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

    Checks DB first (per-workspace config), then falls back to env vars.
    """
    from app.core.config import settings

    # Check DB for workspace-specific provider config
    if workspace_id is not None:
        try:
            from app.db.session import SessionLocal
            from app.db import models as m
            db = SessionLocal()
            cfg = (
                db.query(m.AiProviderConfig)
                .filter(
                    m.AiProviderConfig.workspace_id == workspace_id,
                    m.AiProviderConfig.provider_type == provider_name,
                    m.AiProviderConfig.enabled == True,
                )
                .order_by(m.AiProviderConfig.id.desc())
                .first()
            )
            if cfg:
                provider = get_provider_from_db_config(cfg)
                db.close()
                return provider
            db.close()
        except Exception as e:
            logger.debug("DB provider lookup failed for %s: %s", provider_name, e)

    # Fall back to env-configured providers
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
        raise ValueError(f"OpenAI provider not configured: add via Settings > AI Providers")

    raise ValueError(f"Unknown AI provider: {provider_name}")

