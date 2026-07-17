"""Unit tests for autonomous policy wiring into the plugin pipeline."""

from __future__ import annotations

from typing import Any

import pytest

from agentdecompile_recovery.plugin_pipeline import PluginPipeline, PluginResult
from agentdecompile_recovery.source_plugins import SourceCandidateGeneratorPlugin

pytestmark = pytest.mark.unit


class _StubPlugin:
    id = "source-candidate-objdiff"
    name = "Stub Objdiff"
    description = "test stub"

    def __init__(self, difference_count: int) -> None:
        self.difference_count = difference_count
        self.calls = 0

    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        self.calls += 1
        return (
            PluginResult(
                self.id,
                self.name,
                "failure",
                1,
                error=f"best differences={self.difference_count}",
                data={"differenceCount": self.difference_count, "status": "matched"},
            ),
            context,
        )


class _CountingGenerator(SourceCandidateGeneratorPlugin):
    def execute(self, context: dict[str, Any]) -> tuple[PluginResult, dict[str, Any]]:
        return (
            PluginResult(
                self.id,
                self.name,
                "success",
                1,
                data={"candidateIndex": int(context.get("sourceCandidateIndex") or 0)},
            ),
            context,
        )


def test_pipeline_stops_on_reject_near_miss_without_burning_retries() -> None:
    events: list[dict[str, Any]] = []
    stub = _StubPlugin(difference_count=3)
    pipeline = PluginPipeline(max_retries=8, event_handler=events.append)
    pipeline.register(_CountingGenerator(), stub)

    result = pipeline.run_pipeline(
        prompt_path="fn",
        prompt_content="",
        function_name="fn",
        target_object_path="",
        asm="",
        config={},
        initial_context={
            "sourceCandidateIndex": 0,
            "autonomyBudget": {"maxAttemptsPerFunction": 2, "maxFunctions": 1},
        },
    )

    assert result.success is False
    assert stub.calls == 2
    assert any(event.get("type") == "autonomy-stop" for event in events)
    stop = next(event for event in events if event.get("type") == "autonomy-stop")
    assert stop["action"] == "reject-near-miss"
    policy_events = [event for event in events if event.get("type") == "autonomous-policy"]
    assert policy_events
    assert policy_events[-1]["action"] == "reject-near-miss"


def test_pipeline_bumps_candidate_index_for_retry_actions() -> None:
    events: list[dict[str, Any]] = []
    stub = _StubPlugin(difference_count=12)
    generator = _CountingGenerator()
    pipeline = PluginPipeline(max_retries=3, event_handler=events.append)
    pipeline.register(generator, stub)

    result = pipeline.run_pipeline(
        prompt_path="fn",
        prompt_content="",
        function_name="fn",
        target_object_path="",
        asm="",
        config={},
        initial_context={
            "sourceCandidateIndex": 0,
            "compilerProfiles": ["clang"],
            "autonomyBudget": {"maxAttemptsPerFunction": 3, "maxFunctions": 1},
        },
    )

    assert result.success is False
    assert stub.calls == 3
    # After first failure policy should bump index before second attempt.
    assert any(
        event.get("type") == "autonomous-policy" and event.get("action") == "try-next-generated-candidate"
        for event in events
    )


def test_generator_prepare_retry_respects_autonomy_stop() -> None:
    plugin = SourceCandidateGeneratorPlugin()
    updated = plugin.prepare_retry(
        {"sourceCandidateIndex": 1, "autonomyStop": True, "autonomousPolicy": {"action": "reject-near-miss"}},
        [],
    )
    assert updated["sourceCandidateIndex"] == 1
