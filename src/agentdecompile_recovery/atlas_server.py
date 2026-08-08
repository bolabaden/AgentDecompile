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
            body = _ATLAS_UI_HTML.encode("utf-8")
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


_ATLAS_UI_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Decomp Atlas</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; display: flex; height: 100vh; color: #1a1a1a; }
  #sidebar { width: 320px; border-right: 1px solid #ddd; overflow-y: auto; padding: 0.5rem; }
  #main { flex: 1; padding: 1rem; display: flex; flex-direction: column; }
  li { list-style: none; padding: 0.35rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.85rem; }
  li:hover { background: #f0f0f0; }
  li.decompiled { color: #0a7c33; }
  ul { padding: 0; margin: 0; }
  textarea { flex: 1; font-family: ui-monospace, monospace; font-size: 0.85rem; margin-top: 0.5rem; }
  button { margin-right: 0.5rem; }
  #status { color: #666; font-size: 0.85rem; margin-top: 0.5rem; }
</style>
</head>
<body>
<div id="sidebar"><ul id="function-list"></ul></div>
<div id="main">
  <div>
    <strong id="current-name">Select a function</strong>
    <button id="build-btn" disabled>Build prompt</button>
    <button id="save-btn" disabled>Save prompt</button>
  </div>
  <textarea id="prompt-text" placeholder="Prompt will appear here after Build prompt."></textarea>
  <div id="status"></div>
</div>
<script>
let currentFunction = null;
let currentAsm = "";

function setStatus(text) { document.getElementById("status").textContent = text; }

async function api(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function loadProject() {
  setStatus("Loading project...");
  const { data } = await api("/api/loadProject", {});
  const list = document.getElementById("function-list");
  list.innerHTML = "";
  for (const fn of data.functions) {
    const li = document.createElement("li");
    li.textContent = fn.name + (fn.cCode ? " (decompiled)" : "");
    if (fn.cCode) li.className = "decompiled";
    li.onclick = () => selectFunction(fn);
    list.appendChild(li);
  }
  setStatus(`Loaded ${data.functions.length} functions.`);
}

function selectFunction(fn) {
  currentFunction = fn;
  currentAsm = fn.asmCode;
  document.getElementById("current-name").textContent = fn.name;
  document.getElementById("build-btn").disabled = false;
  document.getElementById("prompt-text").value = "";
}

document.getElementById("build-btn").onclick = async () => {
  if (!currentFunction) return;
  setStatus("Building prompt...");
  const { prompt } = await api("/api/buildPrompt", { functionId: currentFunction.id });
  document.getElementById("prompt-text").value = prompt;
  document.getElementById("save-btn").disabled = false;
  setStatus("Prompt built.");
};

document.getElementById("save-btn").onclick = async () => {
  if (!currentFunction) return;
  setStatus("Saving prompt...");
  const promptContent = document.getElementById("prompt-text").value;
  const { path } = await api("/api/savePrompt", {
    functionName: currentFunction.name,
    promptContent,
    asm: currentAsm,
  });
  setStatus(`Saved to ${path}`);
};

loadProject().catch((err) => setStatus("Error: " + err.message));
</script>
</body>
</html>
"""


def serve_atlas(state: AtlasServerState, *, host: str = "127.0.0.1", port: int = 3000) -> ThreadingHTTPServer:
    """Build (but do not run) the atlas API server. Call `.serve_forever()` on the result."""
    handler_cls = make_request_handler(state)
    return ThreadingHTTPServer((host, port), handler_cls)
