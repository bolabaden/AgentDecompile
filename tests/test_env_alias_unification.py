from __future__ import annotations

from agentdecompile_cli.env_compat import sync_agentdecompile_env_aliases


def test_sync_aliases_canonical_wins_when_both_set() -> None:
    env = {
        "AGENT_DECOMPILE_MCP_SERVER_URL": "http://canonical:8080/mcp",
        "AGENTDECOMPILE_MCP_SERVER_URL": "http://legacy:8080/mcp",
    }
    sync_agentdecompile_env_aliases(env)
    assert env["AGENT_DECOMPILE_MCP_SERVER_URL"] == "http://canonical:8080/mcp"
    assert env["AGENTDECOMPILE_MCP_SERVER_URL"] == "http://canonical:8080/mcp"


def test_sync_aliases_backfills_missing_compact_alias() -> None:
    env = {
        "AGENT_DECOMPILE_PROFILE_DIR": "C:/tmp/profile",
    }
    sync_agentdecompile_env_aliases(env)
    assert env["AGENT_DECOMPILE_PROFILE_DIR"] == "C:/tmp/profile"
    assert env["AGENTDECOMPILE_PROFILE_DIR"] == "C:/tmp/profile"


def test_sync_aliases_backfills_missing_canonical_alias() -> None:
    env = {
        "AGENTDECOMPILE_SESSION_GRACE_PERIOD": "42",
    }
    sync_agentdecompile_env_aliases(env)
    assert env["AGENTDECOMPILE_SESSION_GRACE_PERIOD"] == "42"
    assert env["AGENT_DECOMPILE_SESSION_GRACE_PERIOD"] == "42"
