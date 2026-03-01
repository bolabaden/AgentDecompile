from __future__ import annotations

import pytest

from agentdecompile_cli.registry import ToolRegistry


pytestmark = pytest.mark.unit


def test_parse_arguments_supports_applescript_style_payload() -> None:
    registry = ToolRegistry()

    raw_arguments = {
        "appleScript": (
            "tell AgentDecompile to get references "
            "with program path '/tmp/test.bin' "
            "and target 'main' "
            "and include ref context true "
            "and include data refs false "
            "and limit 5"
        )
    }

    parsed = registry.parse_arguments(raw_arguments, "get-references")

    assert parsed["programPath"] == "/tmp/test.bin"
    assert parsed["target"] == "main"
    assert parsed["includeRefContext"] is True
    assert parsed["includeDataRefs"] is False
    assert parsed["limit"] == 5


def test_parse_arguments_supports_natural_language_kv_forms() -> None:
    registry = ToolRegistry()

    raw_arguments = {
        "naturalLanguage": (
            "mode = list; pattern: \"http\"; program_path is '/tmp/a.bin'; "
            "start index to 2; max count as 10"
        )
    }

    parsed = registry.parse_arguments(raw_arguments, "manage-strings")

    assert parsed["mode"] == "list"
    assert parsed["pattern"] == "http"
    assert parsed["programPath"] == "/tmp/a.bin"
    assert parsed["startIndex"] == 2
    assert parsed["maxCount"] == 10


def test_explicit_arguments_override_natural_language_values() -> None:
    registry = ToolRegistry()

    raw_arguments = {
        "programPath": "/tmp/explicit.bin",
        "target": "explicit_target",
        "appleScript": "program path '/tmp/from-script.bin' and target 'from_script' and limit 20",
    }

    parsed = registry.parse_arguments(raw_arguments, "get-references")

    assert parsed["programPath"] == "/tmp/explicit.bin"
    assert parsed["target"] == "explicit_target"
    assert parsed["limit"] == 20


def test_non_natural_language_keys_do_not_trigger_nl_parsing() -> None:
    registry = ToolRegistry()

    raw_arguments = {
        "note": "with program path '/tmp/nope.bin' and target 'main'",
    }

    parsed = registry.parse_arguments(raw_arguments, "get-references")

    # no structured params inferred from unrelated key
    assert "programPath" not in parsed
    assert "target" not in parsed
    assert parsed["note"] == "with program path '/tmp/nope.bin' and target 'main'"
