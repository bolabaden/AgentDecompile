from agentdecompile_cli.mcp_server.providers.project import _shared_key_auth_config


def test_shared_key_auth_requires_username_and_existing_key(tmp_path):
    key = tmp_path / "identity"
    key.write_text("test key material")

    assert _shared_key_auth_config("analyst", {
        "AGENT_DECOMPILE_GHIDRA_SERVER_KEYFILE": str(key),
    }) == (str(key), True)
    assert _shared_key_auth_config("", {
        "AGENT_DECOMPILE_GHIDRA_SERVER_KEYFILE": str(key),
    }) == (str(key), False)
    assert _shared_key_auth_config("analyst", {
        "AGENT_DECOMPILE_GHIDRA_SERVER_KEYFILE": str(tmp_path / "missing"),
    })[1] is False


def test_shared_key_auth_accepts_compatibility_environment_name(tmp_path):
    key = tmp_path / "identity"
    key.write_text("test key material")
    assert _shared_key_auth_config("analyst", {
        "AGENTDECOMPILE_GHIDRA_SERVER_KEYFILE": str(key),
    }) == (str(key), True)
