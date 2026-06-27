"""
ShieldIQ Enterprise — Multi-Model Router
──────────────────────────────────────────
Abstracts Claude, Gemini, and GPT-4o behind a single interface.
If one provider is down, auto-switches to the next.

Provider order: Gemini (primary) → Claude → GPT-4o
This matches ShieldIQ's existing Gemini-first architecture.
"""

import os
import time
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


class ModelTier(Enum):
    GUARD = "guard"          # Fast, cheap — Pass 1 injection guard
    DETECTIVE = "detective"  # Powerful, thorough — Pass 2 deep analysis


@dataclass
class ModelResponse:
    content: str
    provider: str
    model: str
    latency_ms: int
    tokens_used: Optional[int] = None


class ShieldIQEngineError(Exception):
    """Raised when all model providers fail."""
    pass

class ProviderUnavailableError(Exception):
    """Raised when a specific provider fails."""
    pass


# ── Individual provider clients ───────────────────────────────────────────────

def _call_gemini(prompt: str, system: str, tier: ModelTier) -> ModelResponse:
    """Call Google Gemini API (ShieldIQ's primary provider)."""
    try:
        import google.generativeai as genai
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ProviderUnavailableError("GEMINI_API_KEY not configured")
        genai.configure(api_key=api_key)

        model_name = (
            os.environ.get("GEMINI_GUARD_MODEL", "gemini-2.5-flash")
            if tier == ModelTier.GUARD
            else os.environ.get("GEMINI_DETECTIVE_MODEL", "gemini-2.5-flash")
        )

        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=system
        )

        start = time.time()
        response = model.generate_content(prompt)
        latency = int((time.time() - start) * 1000)

        return ModelResponse(
            content=response.text,
            provider="gemini",
            model=model_name,
            latency_ms=latency
        )

    except ProviderUnavailableError:
        raise
    except Exception as e:
        raise ProviderUnavailableError(f"Gemini call failed: {str(e)}")


def _call_anthropic(prompt: str, system: str, tier: ModelTier) -> ModelResponse:
    """Call Anthropic Claude API."""
    try:
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ProviderUnavailableError("ANTHROPIC_API_KEY not configured")
        client = anthropic.Anthropic(api_key=api_key)

        model = (
            os.environ.get("ANTHROPIC_GUARD_MODEL", "claude-haiku-4-5-20251001")
            if tier == ModelTier.GUARD
            else os.environ.get("ANTHROPIC_DETECTIVE_MODEL", "claude-sonnet-4-6")
        )

        start = time.time()
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        )
        latency = int((time.time() - start) * 1000)

        return ModelResponse(
            content=response.content[0].text,
            provider="anthropic",
            model=model,
            latency_ms=latency,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens
        )

    except ProviderUnavailableError:
        raise
    except Exception as e:
        raise ProviderUnavailableError(f"Anthropic call failed: {str(e)}")


def _call_openai(prompt: str, system: str, tier: ModelTier) -> ModelResponse:
    """Call OpenAI GPT-4o API."""
    try:
        from openai import OpenAI
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ProviderUnavailableError("OPENAI_API_KEY not configured")
        client = OpenAI(api_key=api_key)

        model = (
            os.environ.get("OPENAI_GUARD_MODEL", "gpt-4o-mini")
            if tier == ModelTier.GUARD
            else os.environ.get("OPENAI_DETECTIVE_MODEL", "gpt-4o")
        )

        start = time.time()
        response = client.chat.completions.create(
            model=model,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        )
        latency = int((time.time() - start) * 1000)

        return ModelResponse(
            content=response.choices[0].message.content,
            provider="openai",
            model=model,
            latency_ms=latency,
            tokens_used=response.usage.total_tokens
        )

    except ProviderUnavailableError:
        raise
    except Exception as e:
        raise ProviderUnavailableError(f"OpenAI call failed: {str(e)}")


# ── The router ────────────────────────────────────────────────────────────────

_PROVIDER_ORDER = {
    "gemini":    [_call_gemini, _call_anthropic, _call_openai],
    "anthropic": [_call_anthropic, _call_gemini, _call_openai],
    "openai":    [_call_openai, _call_anthropic, _call_gemini],
}

PRIMARY_PROVIDER = os.environ.get("PRIMARY_PROVIDER", "gemini")


def call_model(
    prompt: str,
    system: str,
    tier: ModelTier,
    preferred_provider: Optional[str] = None
) -> ModelResponse:
    """
    Call the best available model for the given tier.
    Tries the preferred provider first, then falls back automatically.
    """
    primary = preferred_provider or PRIMARY_PROVIDER
    providers = _PROVIDER_ORDER.get(primary, _PROVIDER_ORDER["gemini"])

    errors = []
    for provider_fn in providers:
        try:
            response = provider_fn(prompt, system, tier)
            if response.provider != primary:
                logger.warning(
                    "Provider fallback: %s → %s (tier=%s)",
                    primary, response.provider, tier.value
                )
            return response

        except ProviderUnavailableError as e:
            errors.append(str(e))
            logger.warning("Provider failed, trying next: %s", str(e))
            continue

    raise ShieldIQEngineError(
        f"All AI providers failed for tier={tier.value}. "
        f"Errors: {'; '.join(errors)}"
    )
