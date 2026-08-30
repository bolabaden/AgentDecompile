from __future__ import annotations

from types import SimpleNamespace

import pytest

import agentdecompile_cli.mcp_server.program_metadata as program_metadata
import agentdecompile_cli.mcp_server.prompt_providers as prompt_providers


def _patch_session(monkeypatch: pytest.MonkeyPatch, fake_session: SimpleNamespace) -> None:
    monkeypatch.setattr(program_metadata.SESSION_CONTEXTS, "get_or_create", lambda _session_id: fake_session)
    monkeypatch.setattr(program_metadata, "is_shared_server_handle", lambda _handle: False)


@pytest.mark.unit
def test_get_prompt_renders_analysis_target() -> None:
    result = prompt_providers.get_prompt(
        "re-scout-broad-sweep",
        {"analysis_target": "save/load serialization"},
    )

    assert len(result.messages) == 1
    text = result.messages[0].content.text
    assert "save/load serialization" in text
    assert "{analysis_target}" not in text
    assert "untrusted evidence" in text
    assert "continuation ledger" in text
    assert "Do NOT summarise or truncate" not in text


@pytest.mark.unit
def test_get_prompt_substitutes_active_program_from_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "local", "path": "/tmp/proj.gpr"},
        open_programs={"/prog/sample.exe": SimpleNamespace()},
        active_program_key="/prog/sample.exe",
        project_binaries=[],
    )
    _patch_session(monkeypatch, fake_session)

    result = prompt_providers.get_prompt(
        "re-scout-broad-sweep",
        {"analysis_target": "combat system"},
        session_id="session-1",
    )

    text = result.messages[0].content.text
    assert "/prog/sample.exe" in text
    assert "(current project)" not in text


@pytest.mark.unit
def test_get_prompt_uses_placeholder_without_session_programs() -> None:
    result = prompt_providers.get_prompt(
        "re-scout-broad-sweep",
        {"analysis_target": "dialog engine", "program_path": ""},
    )

    text = result.messages[0].content.text
    assert "(current project)" in text


@pytest.mark.unit
def test_get_prompt_unknown_name_raises() -> None:
    with pytest.raises(ValueError, match="Unknown prompt"):
        prompt_providers.get_prompt("not-a-prompt", {"analysis_target": "x"})


@pytest.mark.unit
def test_get_prompt_missing_required_argument_raises() -> None:
    with pytest.raises(ValueError, match="Missing required prompt argument: analysis_target"):
        prompt_providers.get_prompt("re-scout-broad-sweep", {})


@pytest.mark.unit
def test_list_prompts_advertises_nine_prompts() -> None:
    prompts = prompt_providers.list_prompts()
    assert len(prompts) == 9
    assert {prompt.name for prompt in prompts} == {
        "re-scout-broad-sweep",
        "re-diver-deep-dive",
        "re-bottom-up-analyst",
        "re-top-down-analyst",
        "re-data-architect",
        "re-exhaustive-librarian",
        "re-bridge-builder",
        "re-convergence-orchestrator",
        "re-iterative-verifier",
    }


@pytest.mark.unit
@pytest.mark.parametrize("name", [prompt["name"] for prompt in prompt_providers._PROMPTS])
def test_workflow_prompts_use_bounded_evidence_contracts(name: str) -> None:
    prompt_def = prompt_providers._find_prompt_definition(name)
    assert prompt_def is not None
    arguments = {
        item["name"]: "fixture"
        for item in prompt_def["arguments"]
        if item.get("required")
    }

    text = prompt_providers.get_prompt(name, arguments).messages[0].content.text

    assert "untrusted evidence" in text
    assert "continuation ledger" in text
    assert "Do NOT" not in text
    assert "Be EXHAUSTIVE" not in text
    assert "CRITICAL:" not in text
    assert "EVERYTHING" not in text
    assert "BROAD SWEEP" not in text
    assert "DEEP DIVE" not in text
    assert "INDEPENDENTLY" not in text
    assert "verbatim" not in text.lower()
    assert "nicknamed" not in text.lower()
