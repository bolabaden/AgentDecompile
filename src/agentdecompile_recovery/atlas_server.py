"""JSON API and browser UI for interactive decomp-atlas prompt authoring.

Ports the upstream decomp-atlas-server: the API surface (loadProject,
buildPrompt, savePrompt) as plain, testable handler functions plus a thin
stdlib `http.server` wrapper (no new dependency; the upstream used Hono), and
a browser UI. The upstream UI is a built React app; there's no Node/React
toolchain in this Python repo to build that bundle from, so `_ATLAS_UI_HTML`
below is a single self-contained HTML+vanilla-JS page (no build step) that
talks to the same three JSON endpoints and offers the same actions: pick a
function, generate its prompt, edit it, save it. Same capability, a plainer
implementation -- see run_report.py's HTML report for the same approach.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .craft_prompt import strip_trailing_asm_lines
from .decomp_function_corpus import DecompFunctionCorpus
from .decomp_indexer import load_existing_index
from .map_file import parse_map_file, resolve_object_path
from .prompt_builder import create_decompile_prompt


@dataclass
class AtlasServerState:
    project_root: Path
    prompts_dir: Path
    platform: str
    map_file_path: Path | None = None
    corpus: DecompFunctionCorpus | None = field(default=None, repr=False)
    symbol_map: dict[str, str] | None = field(default=None, repr=False)


def handle_load_project(state: AtlasServerState) -> tuple[dict[str, Any], int]:
    dump, _content_hashes = load_existing_index(state.project_root)
    if dump is None:
        index_path = state.project_root / "decomp-function-index.json"
        return {"error": f"decomp function index not found at {index_path}"}, 404

    state.corpus = DecompFunctionCorpus.from_dump(dump)
    if not state.platform or state.platform == "unknown":
        state.platform = dump.platform

    if state.map_file_path is not None:
        try:
            map_content = state.map_file_path.read_text(encoding="utf-8")
        except OSError:
            return {"error": f"map file not found at {state.map_file_path}"}, 404
        state.symbol_map = parse_map_file(map_content)

    return {
        "data": {
            "platform": dump.platform,
            "functions": [
                {
                    "id": fn.id,
                    "name": fn.name,
                    "asmCode": fn.asm_code,
                    "asmModulePath": fn.asm_module_path,
                    "callsFunctions": fn.calls_functions,
                    "cCode": fn.c_code,
                    "cModulePath": fn.c_module_path,
                }
                for fn in dump.functions
            ],
        },
        "platform": state.platform,
    }, 200


def handle_build_prompt(state: AtlasServerState, function_id: str) -> tuple[dict[str, Any], int]:
    if state.corpus is None:
        return {"error": "Project not loaded. Call /api/loadProject first."}, 400

    try:
        prompt = create_decompile_prompt(
            corpus=state.corpus,
            function_id=function_id,
            platform=state.platform,
            project_root=state.project_root,
        )
    except ValueError as exc:
        return {"error": str(exc)}, 400

    return {"prompt": prompt}, 200


def handle_save_prompt(
    state: AtlasServerState,
    *,
    function_name: str,
    prompt_content: str,
    asm: str,
) -> tuple[dict[str, Any], int]:
    prompt_dir = state.prompts_dir / function_name
    prompt_dir.mkdir(parents=True, exist_ok=True)

    (prompt_dir / "prompt.md").write_text(prompt_content, encoding="utf-8")

    target_object_path = "OBJECT_FILE_NOT_FOUND"
    if state.symbol_map is not None:
        resolved = resolve_object_path(function_name, state.project_root, state.symbol_map)
        if resolved is not None:
            target_object_path = str(resolved)

    settings_yaml = (
        f'functionName: "{function_name}"\n'
        f'targetObjectPath: "{target_object_path}"\n'
        f"asm: |\n" + "\n".join(f"  {line}" for line in strip_trailing_asm_lines(asm).split("\n")) + "\n"
    )
    (prompt_dir / "settings.yaml").write_text(settings_yaml, encoding="utf-8")

    return {"success": True, "path": str(prompt_dir)}, 200


def make_request_handler(state: AtlasServerState) -> type[BaseHTTPRequestHandler]:
    routes = {
        "/api/loadProject": lambda body: handle_load_project(state),
        "/api/buildPrompt": lambda body: handle_build_prompt(state, body.get("functionId", "")),
        "/api/savePrompt": lambda body: handle_save_prompt(
            state,
            function_name=body.get("functionName", ""),
            prompt_content=body.get("promptContent", ""),
            asm=body.get("asm", ""),
        ),
    }

    class AtlasRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming contract.
            body = atlas_ui_html("/api").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming contract.
            handler = routes.get(self.path)
            if handler is None:
                self._respond({"error": "not found"}, 404)
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw_body or b"{}")
            except json.JSONDecodeError:
                self._respond({"error": "invalid JSON body"}, 400)
                return
            payload, status = handler(body)
            self._respond(payload, status)

        def _respond(self, payload: dict[str, Any], status: int) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature.
            pass  # Quiet by default; callers can subclass for logging.

    return AtlasRequestHandler


def atlas_ui_fragment(api_root: str = "/api") -> str:
    """Atlas controls only — embeddable in the workbench stage."""
    root = api_root.rstrip("/") or "/api"
    return _ATLAS_UI_FRAGMENT.replace("__API_ROOT__", root)


def atlas_ui_html(api_root: str = "/api") -> str:
    """Full Atlas page using the workbench chrome."""
    root = api_root.rstrip("/") or "/api"
    return _ATLAS_UI_HTML.replace("__API_ROOT__", root).replace("__ATLAS_BODY__", atlas_ui_fragment(root))


_ATLAS_UI_FRAGMENT = """
<div class="wb-atlas" data-atlas-root="__API_ROOT__">
  <ul id="function-list" class="wb-atlas-list"></ul>
  <div class="wb-atlas-main">
    <div>
      <strong id="current-name">Select a function</strong>
      <button type="button" id="build-btn" class="wb-btn" disabled>Build prompt</button>
      <button type="button" id="save-btn" class="wb-btn" disabled>Save prompt</button>
    </div>
    <textarea id="prompt-text" placeholder="Prompt will appear here after Build prompt."></textarea>
    <div id="status" class="wb-hint"></div>
  </div>
</div>
<script>
(function () {
  const root = document.querySelector("[data-atlas-root]") && document.querySelector("[data-atlas-root]").getAttribute("data-atlas-root") || "__API_ROOT__";
  let currentFunction = null;
  let currentAsm = "";
  function setStatus(text) {
    const node = document.getElementById("status");
    if (node) node.textContent = text;
  }
  async function api(path, body) {
    const res = await fetch(root + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }
  async function loadProject() {
    setStatus("Loading project...");
    const { data } = await api("/loadProject", {});
    const list = document.getElementById("function-list");
    if (!list) return;
    list.innerHTML = "";
    for (const fn of data.functions) {
      const li = document.createElement("li");
      li.textContent = fn.name + (fn.cCode ? " (decompiled)" : "");
      if (fn.cCode) li.className = "decompiled";
      li.onclick = function () { selectFunction(fn, li); };
      list.appendChild(li);
    }
    setStatus("Loaded " + data.functions.length + " functions.");
  }
  function selectFunction(fn, li) {
    currentFunction = fn;
    currentAsm = fn.asmCode;
    document.querySelectorAll(".wb-atlas-list li").forEach(function (node) { node.classList.remove("on"); });
    if (li) li.classList.add("on");
    document.getElementById("current-name").textContent = fn.name;
    document.getElementById("build-btn").disabled = false;
    document.getElementById("prompt-text").value = "";
  }
  const buildBtn = document.getElementById("build-btn");
  const saveBtn = document.getElementById("save-btn");
  if (buildBtn) buildBtn.onclick = async function () {
    if (!currentFunction) return;
    setStatus("Building prompt...");
    const { prompt } = await api("/buildPrompt", { functionId: currentFunction.id });
    document.getElementById("prompt-text").value = prompt;
    if (saveBtn) saveBtn.disabled = false;
    setStatus("Prompt built.");
  };
  if (saveBtn) saveBtn.onclick = async function () {
    if (!currentFunction) return;
    setStatus("Saving prompt...");
    const promptContent = document.getElementById("prompt-text").value;
    const { path } = await api("/savePrompt", {
      functionName: currentFunction.name,
      promptContent: promptContent,
      asm: currentAsm
    });
    setStatus("Saved to " + path);
  };
  loadProject().catch(function (err) {
    setStatus(err.message || String(err));
    var list = document.getElementById("function-list");
    if (list) {
      list.textContent = "";
      var li = document.createElement("li");
      li.className = "wb-hint";
      li.textContent = err.message || String(err);
      list.appendChild(li);
    }
    if (buildBtn) buildBtn.disabled = true;
    if (saveBtn) saveBtn.disabled = true;
  });
})();
</script>
"""


_ATLAS_UI_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Decomp Atlas</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23121a28'/%3E%3Cpath d='M8 8h16v4H8zm0 6h10v12H8z' fill='%237cc8ff'/%3E%3C/svg%3E">
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
<link rel="stylesheet" href="/dashboard/static/workbench.css">
</head>
<body class="workbench-page">
<div id="page-context" hidden data-page="atlas" data-atlas-api="__API_ROOT__"></div>
<header class="wb-toolbar">
  <div class="wb-brand">
    <span class="wb-mark" aria-hidden="true">AD</span>
    <div>
      <strong>AgentDecompile</strong>
      <span class="wb-claim">Atlas prompt authoring on the same 8080 chrome.</span>
    </div>
  </div>
  <div class="wb-toolbar-actions">
    <a class="wb-link" href="/dashboard?tool=prompt">Workbench</a>
    <a class="wb-link" href="/docs">Swagger</a>
    <a class="wb-link" href="/report">Report</a>
  </div>
</header>
<main class="wb-stage">__ATLAS_BODY__</main>
<div id="action-dock" hidden>
  <div class="action-dock-bar">
    <button type="button" class="action-toggle" aria-expanded="false">Jobs</button>
    <span id="job-pulse" class="chip">no jobs</span>
  </div>
  <div class="action-dock-panel" hidden>
    <div class="action-contextual" id="action-contextual"></div>
    <form id="action-form" hidden></form>
    <div id="action-jobs" class="action-jobs"></div>
  </div>
</div>
<script src="/dashboard/static/dashboard.js" defer></script>
<script src="/dashboard/static/actions.js" defer></script>
</body>
</html>
"""


def serve_atlas(state: AtlasServerState, *, host: str = "127.0.0.1", port: int = 3000) -> ThreadingHTTPServer:
    """Build (but do not run) the atlas API server. Call `.serve_forever()` on the result."""
    handler_cls = make_request_handler(state)
    return ThreadingHTTPServer((host, port), handler_cls)
