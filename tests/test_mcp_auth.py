"""Unit tests for the AgentDecompile HTTP Basic Auth middleware.

These tests do NOT require PyGhidra, Ghidra, or a running server.
They exercise the ASGI middleware directly by simulating HTTP requests
and inspecting which ASGI events are sent back to the caller.
"""

from __future__ import annotations

import base64

from typing import Any

import pytest

from agentdecompile_cli.mcp_server.auth import (
    CURRENT_AUTH_CONTEXT,
    AuthConfig,
    AuthContext,
    AuthMiddleware,
    get_current_auth_context,
    parse_basic_auth,
    validate_credentials,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _basic_header(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"


def _make_scope(
    headers: dict[str, str] | None = None,
    scope_type: str = "http",
) -> dict[str, Any]:
    raw_headers: list[tuple[bytes, bytes]] = []
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode(), v.encode()))
    return {"type": scope_type, "headers": raw_headers}


class _Recorder:
    """Captures all ASGI events passed to send() and marks inner app as called."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.inner_called: bool = False

    async def send(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def status(self) -> int | None:
        for e in self.events:
            if e.get("type") == "http.response.start":
                return e.get("status")
        return None


async def _passthrough(scope: Any, receive: Any, send: Any) -> None:
    """Minimal inner ASGI app that returns 200."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok", "more_body": False})


async def _inner_with_auth_check(scope: Any, receive: Any, send: Any) -> None:
    """Inner ASGI app that records the current auth context."""
    ctx = get_current_auth_context()
    _inner_with_auth_check.last_ctx = ctx  # type: ignore[attr-defined]
    await _passthrough(scope, receive, send)


_inner_with_auth_check.last_ctx = None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# parse_basic_auth tests
# ---------------------------------------------------------------------------


class TestParseBasicAuth:
    def test_valid(self) -> None:
        user, pwd = parse_basic_auth(_basic_header("alice", "s3cret"))
        assert user == "alice"
        assert pwd == "s3cret"

    def test_password_with_colon(self) -> None:
        user, pwd = parse_basic_auth(_basic_header("bob", "pass:word:extra"))
        assert user == "bob"
        assert pwd == "pass:word:extra"

    def test_empty_password(self) -> None:
        user, pwd = parse_basic_auth(_basic_header("admin", ""))
        assert user == "admin"
        assert pwd == ""

    def test_not_basic(self) -> None:
        with pytest.raises(ValueError, match="Not a Basic"):
            parse_basic_auth("Bearer token123")

    def test_bad_base64(self) -> None:
        with pytest.raises(ValueError):
            parse_basic_auth("Basic !!!notbase64!!!")

    def test_no_colon(self) -> None:
        encoded = base64.b64encode(b"nocolon").decode()
        with pytest.raises(ValueError, match="must contain"):
            parse_basic_auth(f"Basic {encoded}")


# ---------------------------------------------------------------------------
# validate_credentials tests
# ---------------------------------------------------------------------------


class TestValidateCredentials:
    def _config(self, **kwargs: Any) -> AuthConfig:
        defaults = {
            "default_server_host": "ghidra.example.com",
            "default_username": "OldRepublicDevs",
            "default_password": "revanlives",
        }
        defaults.update(kwargs)
        return AuthConfig(**defaults)  # pyright: ignore[reportArgumentType]

    def test_correct_creds_default_server(self) -> None:
        cfg = self._config()
        assert validate_credentials("OldRepublicDevs", "revanlives", cfg, None) is True

    def test_wrong_password(self) -> None:
        cfg = self._config()
        assert validate_credentials("OldRepublicDevs", "wrongpass", cfg, None) is False

    def test_wrong_username(self) -> None:
        cfg = self._config()
        assert validate_credentials("eve", "revanlives", cfg, None) is False

    def test_empty_username(self) -> None:
        cfg = self._config()
        assert validate_credentials("", "revanlives", cfg, None) is False

    def test_correct_creds_explicit_matching_host(self) -> None:
        cfg = self._config()
        assert validate_credentials("OldRepublicDevs", "revanlives", cfg, "ghidra.example.com") is True

    def test_case_insensitive_host_match(self) -> None:
        cfg = self._config()
        assert validate_credentials("OldRepublicDevs", "revanlives", cfg, "GHIDRA.EXAMPLE.COM") is True

    def test_different_server_accepts_any_non_empty_creds(self) -> None:
        cfg = self._config()
        assert validate_credentials("any_user", "any_pass", cfg, "other.server.local") is True

    def test_different_server_rejects_empty_username(self) -> None:
        cfg = self._config()
        assert validate_credentials("", "any_pass", cfg, "other.server.local") is False


# ---------------------------------------------------------------------------
# AuthMiddleware ASGI tests
# ---------------------------------------------------------------------------


class TestAuthMiddleware:
    def _middleware(self, **cfg_kwargs: Any) -> AuthMiddleware:
        cfg = AuthConfig(**cfg_kwargs)
        return AuthMiddleware(_passthrough, cfg)

    # --- No auth required (anonymous mode) ---

    @pytest.mark.asyncio
    async def test_anonymous_passthrough_no_config(self) -> None:
        """When no credentials are configured and no X-Ghidra-Server-Host, pass through."""
        mw = AuthMiddleware(_passthrough, AuthConfig())
        rec = _Recorder()
        await mw(_make_scope(), None, rec.send)
        assert rec.status() == 200

    @pytest.mark.asyncio
    async def test_anonymous_passthrough_require_auth_false(self) -> None:
        mw = self._middleware(require_auth=False)
        rec = _Recorder()
        await mw(_make_scope(), None, rec.send)
        assert rec.status() == 200

    # --- Auth required: missing header → 401 ---

    @pytest.mark.asyncio
    async def test_401_when_username_configured_no_header(self) -> None:
        mw = self._middleware(default_username="user", default_password="pass")
        rec = _Recorder()
        await mw(_make_scope(), None, rec.send)
        assert rec.status() == 401
        all_headers: dict[bytes, bytes] = {}
        for ev in rec.events:
            for k, v in ev.get("headers") or []:
                all_headers[k] = v
        assert b"www-authenticate" in all_headers

    @pytest.mark.asyncio
    async def test_401_when_require_auth_explicit(self) -> None:
        mw = self._middleware(require_auth=True)
        rec = _Recorder()
        await mw(_make_scope(), None, rec.send)
        assert rec.status() == 401

    @pytest.mark.asyncio
    async def test_401_when_x_ghidra_server_host_present(self) -> None:
        """X-Ghidra-Server-Host alone triggers auth even with no startup config."""
        mw = AuthMiddleware(_passthrough, AuthConfig())
        scope = _make_scope({"X-Ghidra-Server-Host": "ghidra.server.local"})
        rec = _Recorder()
        await mw(scope, None, rec.send)
        assert rec.status() == 401

    # --- Auth required: wrong creds → 401 ---

    @pytest.mark.asyncio
    async def test_401_wrong_credentials(self) -> None:
        mw = self._middleware(
            default_username="admin",
            default_password="secret",
        )
        scope = _make_scope({"Authorization": _basic_header("admin", "wrongpass")})
        rec = _Recorder()
        await mw(scope, None, rec.send)
        assert rec.status() == 401

    @pytest.mark.asyncio
    async def test_401_malformed_basic_header(self) -> None:
        mw = self._middleware(default_username="user", default_password="pass")
        scope = _make_scope({"Authorization": "Basic !!!"})
        rec = _Recorder()
        await mw(scope, None, rec.send)
        assert rec.status() == 401

    @pytest.mark.asyncio
    async def test_401_non_basic_scheme(self) -> None:
        mw = self._middleware(default_username="user", default_password="pass")
        scope = _make_scope({"Authorization": "Bearer sometoken"})
        rec = _Recorder()
        await mw(scope, None, rec.send)
        assert rec.status() == 401

    # --- Auth required: correct creds → 200 + context set ---

    @pytest.mark.asyncio
    async def test_200_correct_credentials(self) -> None:
        mw = self._middleware(
            default_server_host="ghidra.example.com",
            default_username="OldRepublicDevs",
            default_password="revanlives",
        )
        scope = _make_scope({"Authorization": _basic_header("OldRepublicDevs", "revanlives")})
        rec = _Recorder()
        await mw(scope, None, rec.send)
        assert rec.status() == 200

    @pytest.mark.asyncio
    async def test_auth_context_propagated(self) -> None:
        """Verify CURRENT_AUTH_CONTEXT is set inside the inner ASGI app."""
        _inner_with_auth_check.last_ctx = None

        cfg = AuthConfig(
            default_server_host="ghidra.example.com",
            default_username="OldRepublicDevs",
            default_password="revanlives",
            default_repository="Odyssey",
        )
        mw = AuthMiddleware(_inner_with_auth_check, cfg)
        scope = _make_scope({"Authorization": _basic_header("OldRepublicDevs", "revanlives")})
        rec = _Recorder()
        await mw(scope, None, rec.send)

        ctx: AuthContext | None = _inner_with_auth_check.last_ctx
        assert ctx is not None
        assert ctx.username == "OldRepublicDevs"
        assert ctx.password == "revanlives"
        assert ctx.server_host == "ghidra.example.com"
        assert ctx.repository == "Odyssey"

    @pytest.mark.asyncio
    async def test_x_ghidra_headers_stored_in_context(self) -> None:
        """X-Ghidra-* headers override defaults in AuthContext."""
        _inner_with_auth_check.last_ctx = None

        cfg = AuthConfig(
            default_server_host="default.host",
            default_username="user",
            default_password="pass",
            default_repository="DefaultRepo",
        )
        mw = AuthMiddleware(_inner_with_auth_check, cfg)
        scope = _make_scope(
            {
                "Authorization": _basic_header("user", "other_pass"),
                "X-Ghidra-Server-Host": "other.host",
                "X-Ghidra-Server-Port": "13200",
                "X-Ghidra-Repository": "OtherRepo",
            }
        )
        rec = _Recorder()
        await mw(scope, None, rec.send)

        # Different server: any creds accepted
        assert rec.status() == 200
        ctx: AuthContext | None = _inner_with_auth_check.last_ctx
        assert ctx is not None
        assert ctx.server_host == "other.host"
        assert ctx.server_port == 13200
        assert ctx.repository == "OtherRepo"

    @pytest.mark.asyncio
    async def test_context_cleared_after_request(self) -> None:
        """CURRENT_AUTH_CONTEXT must be reset after each request."""
        cfg = AuthConfig(default_username="u", default_password="p")
        mw = AuthMiddleware(_passthrough, cfg)
        scope = _make_scope({"Authorization": _basic_header("u", "p")})
        rec = _Recorder()
        await mw(scope, None, rec.send)
        # After the request, context should reset to default (None)
        assert CURRENT_AUTH_CONTEXT.get() is None

    # --- Non-HTTP scopes pass through ---

    @pytest.mark.asyncio
    async def test_lifespan_scope_passes_through(self) -> None:
        """Lifespan and other non-HTTP scopes should never be auth-checked."""
        called: list[bool] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            called.append(True)

        mw2 = AuthMiddleware(inner, AuthConfig(require_auth=True))
        await mw2({"type": "lifespan", "headers": []}, None, None)
        assert called  # inner was called

    # --- WWW-Authenticate header present in 401 response ---

    @pytest.mark.asyncio
    async def test_401_includes_www_authenticate_header(self) -> None:
        mw = self._middleware(default_username="u", default_password="p")
        rec = _Recorder()
        await mw(_make_scope(), None, rec.send)
        start_events = [e for e in rec.events if e.get("type") == "http.response.start"]
        assert start_events
        headers_dict: dict[bytes, bytes] = dict(start_events[0].get("headers", []))
        assert b"www-authenticate" in headers_dict
        assert b"AgentDecompile" in headers_dict[b"www-authenticate"]
