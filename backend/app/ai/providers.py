"""
AI Provider implementations — Azure OpenAI, Claude CLI, Gemini.
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


def get_provider(provider_name: str) -> AiProvider:
    """Factory — returns the configured AI provider instance."""
    from app.core.config import settings

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

    elif provider_name == "gemini":
        if not settings.GEMINI_API_KEY:
            raise ValueError("Gemini not configured: set GEMINI_API_KEY")
        return GeminiProvider(
            api_key=settings.GEMINI_API_KEY,
            model=settings.GEMINI_MODEL,
        )

    raise ValueError(f"Unknown AI provider: {provider_name}")

