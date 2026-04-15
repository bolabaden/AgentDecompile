## Plan: E2E Cancelled Timeout Repro

Add a real subprocess-backed E2E stress suite that starts agentdecompile-server from pytest fixture setup, imports a deterministic multi-binary stress corpus built from repo-local fixtures, drives a deliberately expensive multi-program search/decompile path until the client surfaces the cancelled/timeout failure, and emits both Python cProfile artifacts and JVM JFR recordings so the hot path can be attributed precisely.

**Steps**
1. Phase 1: Harden the live-server fixture layer in tests/conftest.py and tests/e2e_project_lifecycle_helpers.py so one session-scoped background server is started before the E2E profiling module runs, with deterministic artifact directories, stderr/stdout log capture, and shutdown cleanup. Prefer a normal subprocess fixture over a visible GUI terminal because it is CI-safe and already matches the repo’s live E2E pattern.
2. Add a dedicated profiling-aware server fixture in tests/conftest.py that extends local_live_server_pool/local_group_server with per-run environment variables for AGENTDECOMPILE_PROFILE_DIR, AGENTDECOMPILE_PROFILE_ANALYZER, and JVM flight recording startup options. The fixture should write artifacts into a temp run directory containing server logs, .prof files, profile summaries, and .jfr output.
3. Phase 2: Create a deterministic stress corpus fixture, likely in tests/conftest.py plus tests/helpers.py, that copies or generates many repo-local binaries from tests/fixtures/test_x86_64, tests/fixtures/test_arm64, and tests/fixtures/test_fat_binary into an isolated workspace. The fixture should create enough distinct import paths to force multi-program traversal without depending on K1/TSL or any external binaries.
4. Define the stress corpus so it can scale. Recommended shape: a small set of unique seed binaries plus many duplicated paths with unique filenames, imported into one runtime project before the heavy test begins. This keeps the corpus deterministic while making search-everything and any follow-up decompilation span many programs.
5. Phase 3: Add the profile analyzer script at scripts/analyze_profile.py using the provided implementation, then point AGENTDECOMPILE_PROFILE_ANALYZER at it from the profiling-aware fixture so every emitted .prof also gets text and JSON summaries automatically.
6. Expand Python-side profiling coverage around the actual expensive path, not just existing match-function flows. The primary target is src/agentdecompile_cli/mcp_server/providers/search_everything.py around _handle and/or the per-program/per-scope scan loop, because the requested reproduction depends on repeated large-limit searches across many imported binaries. A secondary target is src/agentdecompile_cli/mcp_server/providers/dissect.py or the decompilation/search helper path if the stress test intentionally forces decompilation-heavy scopes.
7. Add lightweight correlation metadata to the profiling capture records: query, scopes, number of target programs, per-scope limits, maxFunctionsScan, maxInstructionsScan, decompileTimeout, and whether the request ended in success, timeout, or cancellation. This makes the .prof and .jfr artifacts comparable without needing to reverse-engineer the request later.
8. Phase 4: Add a new E2E module, likely tests/test_e2e_cancelled_profile.py, that uses the new session-scoped background server fixture and stress corpus fixture. The first test should import/open the predetermined binaries and prime the project state.
9. Add one test whose only purpose is reproduction of the cancelled error end-to-end. Recommended flow: import many duplicated binaries, call search-everything with scopes that force the most expensive traversal, set very large limit/perScopeLimit/maxFunctionsScan/maxInstructionsScan values, and enforce a shorter client-side timeout or cancellation boundary so the client surfaces the cancelled failure while the server is still busy.
10. Keep the reproduction non-mocked. The test should go through real MCP transport using JsonRpcMcpSession or the async MCP client already used by live tests, and it should assert on the real error surface observed by the client plus the corresponding server/profile artifacts.
11. Add a second E2E test that runs the same heavy request without the short client timeout and instead asserts that profiling artifacts were produced. This separates “reproduce the failure” from “collect forensic evidence” so one flake does not hide the other.
12. For the cancelled-error test, decide explicitly whether the failure is induced by transport timeout or task cancellation. Recommended implementation path: use the real async client and cancel the in-flight call from the test after the server has begun the heavy request, because that most closely matches the existing CancelledError routing in src/agentdecompile_cli/executor.py. If transport timeout proves to be the only stable trigger, keep that as the fallback and assert the exact observed error text.
13. Phase 5: Enable JVM profiling via JFR on the subprocess server started by tests. The fixture should launch the server process with a deterministic recording destination and settings that capture CPU/method/thread allocation data for the whole server lifetime or for the stress module lifetime. Keep this subprocess-only to avoid the known Windows JPype crash in the pytest process.
14. Capture auxiliary JVM diagnostics around the failing window as supporting evidence, not as a substitute for JFR. Recommended additions are server stdout/stderr log teeing and optional jcmd thread dumps on timeout only if the environment supports it. JFR remains the primary JVM artifact.
15. Phase 6: Add assertions that the artifact bundle is complete after the profiling test module runs: at least one .prof file, one .analysis.txt, one .analysis.json, one .jfr file, and one server log. The tests should print artifact locations on failure to make investigation direct.
16. Update tests/README.md and, if needed, CONTRIBUTING.md with the new profiling E2E marker/commands, required prerequisites for JFR-capable Java 21, and how to inspect the generated artifacts after a failure.

**Relevant files**
- c:\GitHub\agentdecompile\tests\conftest.py — extend the existing live-server fixtures into a session-scoped profiling-aware subprocess server and a deterministic stress-corpus fixture.
- c:\GitHub\agentdecompile\tests\e2e_project_lifecycle_helpers.py — reuse and likely extend LocalServerPool, LocalServerHandle, build_local_server_env, and wait_for_server for artifact/log-aware subprocess startup.
- c:\GitHub\agentdecompile\tests\helpers.py — reuse tests/fixtures binaries and add helper(s) for generating duplicated corpus entries or import manifests.
- c:\GitHub\agentdecompile\tests\fixtures\test_x86_64 — primary seed binary for deterministic stress duplication.
- c:\GitHub\agentdecompile\tests\fixtures\test_arm64 — optional second seed binary to broaden multi-program coverage.
- c:\GitHub\agentdecompile\tests\fixtures\test_fat_binary — optional third seed binary if multi-arch import behavior is useful for search breadth.
- c:\GitHub\agentdecompile\tests\test_e2e_cancelled_profile.py — new live E2E reproduction and profiling suite.
- c:\GitHub\agentdecompile\src\agentdecompile_cli\mcp_server\profiling.py — existing cProfile capture facility to reuse and possibly extend with richer metadata.
- c:\GitHub\agentdecompile\src\agentdecompile_cli\mcp_server\providers\search_everything.py — primary heavy-path candidate for Python profiling around multi-program scans.
- c:\GitHub\agentdecompile\src\agentdecompile_cli\mcp_server\providers\dissect.py — secondary heavy-path candidate when decompilation participates in the stress request.
- c:\GitHub\agentdecompile\src\agentdecompile_cli\executor.py — reference point for the current CancelledError routing the test is expected to surface.
- c:\GitHub\agentdecompile\scripts\analyze_profile.py — add the provided analyzer here and wire it through AGENTDECOMPILE_PROFILE_ANALYZER.
- c:\GitHub\agentdecompile\tests\README.md — document how to run the new profiling/cancellation suite and where artifacts land.

**Verification**
1. Run the new E2E module directly with uv run pytest tests/test_e2e_cancelled_profile.py -v --timeout=300 -s and confirm the server is started from conftest fixture setup rather than manually.
2. Verify the reproduction test triggers the real cancelled or timeout-facing error without monkeypatching and that the assertion matches the observed transport/error text.
3. Verify the stress corpus actually imported multiple binaries by asserting project file/program counts through real MCP calls before the heavy search runs.
4. Verify the heavy request uses large limit/perScopeLimit/maxFunctionsScan/maxInstructionsScan values and spans more than one imported program.
5. Verify at least one Python profile artifact is emitted and that scripts/analyze_profile.py produced both .analysis.txt and .analysis.json outputs for it.
6. Verify one JVM .jfr artifact exists for the subprocess server and is non-empty after the test run.
7. Run the analyzer manually against one emitted .prof file to confirm the summaries are readable outside pytest.
8. If the first attempt does not reliably cancel, increase corpus size or expensive scopes before changing the assertion strategy; the goal is to reproduce the real behavior, not to simulate it.

**Decisions**
- Included: repo-local deterministic binaries created by duplication/generation from existing fixture binaries rather than K1/TSL or external downloads.
- Included: subprocess-only server startup from pytest fixtures so Windows avoids in-process JPype startup.
- Included: JFR as the Java-side profiling artifact.
- Recommended implementation detail: treat a background subprocess fixture as the practical test equivalent of a background terminal; only switch to spawning a visible shell window if there is a hard requirement for interactive console behavior.
- Excluded: mocking, monkeypatch-based cancellation, and dependence on external sample binaries not present in the repo.
- Excluded unless needed after initial run: separate jcmd/jstack collectors beyond optional timeout-triggered diagnostics.

**Further Considerations**
1. The most reliable cancellation trigger may be client-side cancellation of a real async MCP call rather than a raw HTTP timeout. Recommended first attempt: explicit async cancellation because it aligns with existing CancelledError routing.
2. The existing tests/fixtures binaries may still be too small individually. Recommended mitigation: duplicate enough imports and include expensive scopes that perform decompilation or broad instruction scans so the request cost scales with program count.
3. If profiling only search_everything is insufficient, add a second profiling wrapper around the exact decompile/search helper invoked by the chosen scopes so Python-side and JFR hotspots can be correlated more directly.
