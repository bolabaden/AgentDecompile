"""Bounded, fail-closed Claude API client for challenger-lane candidate rewriting.

One call, one candidate: the caller supplies fully-formed system/user prompt
strings and gets back a single extracted C source blob or a typed failure.
Never retries internally (``max_retries=0``) -- the autonomous loop's own
budget (``AutonomyBudget.max_llm_calls_per_function``) owns retry/backoff
decisions, not this client.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import anthropic

DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
DEFAULT_MAX_TOKENS = 4096

# Truncated or context-exceeded responses hand back incomplete/invalid C and
# must not be treated as a usable rewrite.
_INCOMPLETE_STOP_REASONS = {"max_tokens", "model_context_window_exceeded"}

_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]*\n)?(.*?)```", re.DOTALL)

# Transient: this call failed, no SDK-internal retry, count against the
# per-function LLM budget, move on to the next function.
_TRANSIENT_EXCEPTIONS: tuple[type[Exception], ...] = (
    anthropic.RateLimitError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    anthropic.InternalServerError,
)

# Fatal/config: broken setup, not a transient per-call failure. One occurrence
# should stop the campaign rather than being retried per-function.
_FATAL_EXCEPTIONS: tuple[type[Exception], ...] = (
    anthropic.AuthenticationError,
    anthropic.BadRequestError,
    anthropic.PermissionDeniedError,
    anthropic.NotFoundError,
)


@dataclass(frozen=True)
class LlmRewriteResult:
    """Outcome of a single bounded LLM rewrite call."""

    status: str  # "ok" | "llm-unavailable" | "llm-fatal"
    source: str | None = None
    stop_reason: str | None = None
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    error: str | None = None


def _extract_fenced_source(text: str) -> str | None:
    """Extract the single fenced code block from a text response.

    Deterministic, not model-trusted: plain-text output with delimiters
    avoids JSON-escaping an entire C file (backslashes, quotes, newlines).
    """

    matches = _FENCE_RE.findall(text)
    if not matches:
        return None
    source = matches[0].strip()
    return source or None


def request_llm_rewrite(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    client: "anthropic.Anthropic | None" = None,
) -> LlmRewriteResult:
    """One bounded, fail-closed Claude API call requesting a single C rewrite."""

    active_client = client or anthropic.Anthropic(max_retries=0)
    try:
        message = active_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except _FATAL_EXCEPTIONS as exc:
        return LlmRewriteResult(status="llm-fatal", error=f"{type(exc).__name__}: {exc}")
    except _TRANSIENT_EXCEPTIONS as exc:
        return LlmRewriteResult(status="llm-unavailable", error=f"{type(exc).__name__}: {exc}")
    except anthropic.APIStatusError as exc:
        # Unclassified status errors (e.g. OverloadedError, ServiceUnavailableError,
        # DeadlineExceededError) -- treat as transient rather than crashing the loop.
        return LlmRewriteResult(status="llm-unavailable", error=f"{type(exc).__name__}: {exc}")

    usage = getattr(message, "usage", None)
    input_tokens = getattr(usage, "input_tokens", None)
    output_tokens = getattr(usage, "output_tokens", None)
    stop_reason = getattr(message, "stop_reason", None)

    if stop_reason in _INCOMPLETE_STOP_REASONS:
        return LlmRewriteResult(
            status="llm-unavailable",
            stop_reason=stop_reason,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            error=f"incomplete response (stop_reason={stop_reason})",
        )

    text_parts: list[str] = [
        block.text for block in (message.content or []) if getattr(block, "type", None) == "text"
    ]
    source = _extract_fenced_source("\n".join(text_parts))
    if source is None:
        return LlmRewriteResult(
            status="llm-unavailable",
            stop_reason=stop_reason,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            error="no fenced code block found in response",
        )

    return LlmRewriteResult(
        status="ok",
        source=source,
        stop_reason=stop_reason,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
