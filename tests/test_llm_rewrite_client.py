"""Unit tests for the bounded, fail-closed Claude API rewrite client.

All Anthropic client interaction is mocked -- no real network calls, no
ANTHROPIC_API_KEY required.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import anthropic
import pytest

from agentdecompile_recovery.llm_rewrite_client import LlmRewriteResult, request_llm_rewrite

pytestmark = pytest.mark.unit


class _FakeMessagesOk:
    def __init__(self, text: str, *, stop_reason: str = "end_turn") -> None:
        self._text = text
        self._stop_reason = stop_reason

    def create(self, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=self._text)],
            stop_reason=self._stop_reason,
            usage=SimpleNamespace(input_tokens=120, output_tokens=340),
        )


class _FakeMessagesRaises:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def create(self, **_kwargs: Any) -> SimpleNamespace:
        raise self._exc


class _FakeClient:
    def __init__(self, messages: Any) -> None:
        self.messages = messages


def _mk_response(exc: Exception) -> _FakeClient:
    return _FakeClient(_FakeMessagesRaises(exc))


def test_happy_path_extracts_single_fenced_block() -> None:
    text = "Here is the rewrite:\n```c\nint add(int a, int b) { return a + b; }\n```\n"
    client = _FakeClient(_FakeMessagesOk(text))
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "ok"
    assert result.source == "int add(int a, int b) { return a + b; }"
    assert result.input_tokens == 120
    assert result.output_tokens == 340
    assert result.stop_reason == "end_turn"


def test_max_tokens_stop_reason_is_treated_as_unavailable() -> None:
    client = _FakeClient(_FakeMessagesOk("```c\nint x(void) {\n", stop_reason="max_tokens"))
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-unavailable"
    assert result.source is None
    assert "max_tokens" in (result.error or "")


def test_model_context_window_exceeded_is_treated_as_unavailable() -> None:
    client = _FakeClient(_FakeMessagesOk("truncated", stop_reason="model_context_window_exceeded"))
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-unavailable"
    assert result.source is None


def test_no_fenced_block_is_llm_unavailable() -> None:
    client = _FakeClient(_FakeMessagesOk("I cannot help with this rewrite."))
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-unavailable"
    assert result.source is None
    assert "no fenced code block" in (result.error or "")


def test_multiple_fenced_blocks_uses_first_deterministically() -> None:
    text = "```c\nint a(void) { return 1; }\n```\nand also\n```c\nint b(void) { return 2; }\n```"
    client = _FakeClient(_FakeMessagesOk(text))
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "ok"
    assert result.source == "int a(void) { return 1; }"


def test_rate_limit_error_is_llm_unavailable_no_exception_propagates() -> None:
    exc = anthropic.RateLimitError(
        message="rate limited",
        response=SimpleNamespace(headers={}, status_code=429, request=SimpleNamespace()),
        body=None,
    )
    client = _mk_response(exc)
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-unavailable"
    assert result.source is None


def test_api_connection_error_is_llm_unavailable() -> None:
    exc = anthropic.APIConnectionError(request=SimpleNamespace())
    client = _mk_response(exc)
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-unavailable"


def test_api_timeout_error_is_llm_unavailable() -> None:
    exc = anthropic.APITimeoutError(request=SimpleNamespace())
    client = _mk_response(exc)
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-unavailable"


def test_authentication_error_is_llm_fatal_no_exception_propagates() -> None:
    exc = anthropic.AuthenticationError(
        message="invalid api key",
        response=SimpleNamespace(headers={}, status_code=401, request=SimpleNamespace()),
        body=None,
    )
    client = _mk_response(exc)
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-fatal"
    assert result.source is None


def test_bad_request_error_is_llm_fatal() -> None:
    exc = anthropic.BadRequestError(
        message="bad request",
        response=SimpleNamespace(headers={}, status_code=400, request=SimpleNamespace()),
        body=None,
    )
    client = _mk_response(exc)
    result = request_llm_rewrite("system", "user", client=client)
    assert result.status == "llm-fatal"


def test_result_is_never_none_on_success_or_failure() -> None:
    for exc in (
        anthropic.RateLimitError(message="x", response=SimpleNamespace(headers={}, status_code=429, request=SimpleNamespace()), body=None),
        anthropic.AuthenticationError(message="x", response=SimpleNamespace(headers={}, status_code=401, request=SimpleNamespace()), body=None),
    ):
        result = request_llm_rewrite("system", "user", client=_mk_response(exc))
        assert isinstance(result, LlmRewriteResult)
