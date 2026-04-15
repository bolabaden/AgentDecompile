"""AgentDecompile Web UI server.

Provides a browser-native interface over AgentDecompile's local embedded backend
by default, with optional passthrough to an existing MCP HTTP endpoint.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import threading
import time

from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
import uvicorn

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agentdecompile_cli.executor import normalize_backend_url
from agentdecompile_cli.local_backend import LocalToolBackend
from agentdecompile_cli.mcp_server import prompt_providers
from agentdecompile_cli.mcp_server.server import _build_tool_reference_payload

logger = logging.getLogger(__name__)

DEFAULT_WEBUI_HOST = "127.0.0.1"
DEFAULT_WEBUI_PORT = 8002
WEBUI_HOST_ENV_VARS: tuple[str, ...] = (
    "AGENT_DECOMPILE_WEBUI_HOST",
    "AGENTDECOMPILE_WEBUI_HOST",
)
WEBUI_PORT_ENV_VARS: tuple[str, ...] = (
    "AGENT_DECOMPILE_WEBUI_PORT",
    "AGENTDECOMPILE_WEBUI_PORT",
)
WEBUI_BACKEND_URL_ENV_VARS: tuple[str, ...] = (
    "AGENT_DECOMPILE_WEBUI_BACKEND_URL",
    "AGENTDECOMPILE_WEBUI_BACKEND_URL",
)
WEBUI_ENABLED_ENV_VARS: tuple[str, ...] = (
    "AGENT_DECOMPILE_WEBUI_ENABLED",
    "AGENTDECOMPILE_WEBUI_ENABLED",
    "AGENT_DECOMPILE_WEBUI",
    "AGENTDECOMPILE_WEBUI",
)
_REPO_DOC_ROOT = "https://github.com/bolabaden/AgentDecompile/blob/master"
_GHIDRA_API_ROOT = "https://ghidra.re/ghidra_docs/api"
_JAVA_API_ROOT = "https://docs.oracle.com/en/java/javase/21/docs/api"
_FALSY_VALUES = {"0", "false", "no", "off"}


def _env_str(keys: tuple[str, ...], default: str) -> str:
    for key in keys:
        value = (os.environ.get(key) or "").strip()
        if value:
            return value
    return default


def _env_int(keys: tuple[str, ...], default: int) -> int:
    for key in keys:
        value = (os.environ.get(key) or "").strip()
        if not value:
            continue
        try:
            parsed = int(value)
        except ValueError:
            continue
        if parsed > 0:
            return parsed
    return default


def _webui_enabled() -> bool:
    for key in WEBUI_ENABLED_ENV_VARS:
        value = (os.environ.get(key) or "").strip().lower()
        if not value:
            continue
        return value not in _FALSY_VALUES
    return True


def _asset_dir() -> Path:
    return Path(__file__).with_name("webui_assets")


def _serialize_prompt_messages() -> list[dict[str, Any]]:
    prompt_defs = getattr(prompt_providers, "_PROMPTS", [])
    serialized: list[dict[str, Any]] = []
    for prompt_def in prompt_defs:
        serialized.append(
            {
                "name": prompt_def["name"],
                "title": prompt_def.get("title") or prompt_def["name"],
                "description": prompt_def.get("description", ""),
                "arguments": list(prompt_def.get("arguments", [])),
                "messages": list(prompt_def.get("messages", [])),
            }
        )
    return serialized


def _safe_json_loads(text: str) -> Any | None:
    try:
        return json.loads(text)
    except Exception:
        return None


def _tool_response_payload(result: dict[str, Any]) -> dict[str, Any]:
    content = result.get("content") if isinstance(result, dict) else []
    text_parts = [part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"]
    parsed: Any = None
    if len(text_parts) == 1:
        parsed = _safe_json_loads(text_parts[0])
    return {
        "isError": bool(result.get("isError")) if isinstance(result, dict) else False,
        "content": content,
        "text": "\n\n".join(part for part in text_parts if part),
        "parsed": parsed,
    }


def _docs_hub() -> dict[str, Any]:
    return {
        "internal": [
            {
                "title": "README",
                "url": f"{_REPO_DOC_ROOT}/README.md",
                "description": "Project overview, runtime surfaces, environment variables, and entry points.",
            },
            {
                "title": "USAGE",
                "url": f"{_REPO_DOC_ROOT}/USAGE.md",
                "description": "CLI, server, and HTTP usage patterns with validated examples.",
            },
            {
                "title": "MCP Usage",
                "url": f"{_REPO_DOC_ROOT}/docs/MCP_AGENTDECOMPILE_USAGE.md",
                "description": "MCP transport notes, profiles, and client integration guidance.",
            },
            {
                "title": "PyGhidra API Reference",
                "url": f"{_REPO_DOC_ROOT}/docs/PyGhidra_API_Reference.md",
                "description": "Reference map for PyGhidra, GhidraScript, and embedded automation APIs.",
            },
            {
                "title": "Shared Project CLI",
                "url": f"{_REPO_DOC_ROOT}/docs/SharedProjectCLI.md",
                "description": "Shared-project checkout, sync, and repository workflow details.",
            },
        ],
        "ghidra": [
            {
                "title": "Ghidra API Root",
                "url": f"{_GHIDRA_API_ROOT}/index.html",
                "description": "Top-level Ghidra Java API documentation.",
            },
            {
                "title": "GhidraScript",
                "url": f"{_GHIDRA_API_ROOT}/ghidra/app/script/GhidraScript.html",
                "description": "Core scripting surface exposed through execute-script and PyGhidra helpers.",
            },
            {
                "title": "FlatProgramAPI",
                "url": f"{_GHIDRA_API_ROOT}/ghidra/program/flatapi/FlatProgramAPI.html",
                "description": "Convenience program automation APIs commonly mirrored by tool providers.",
            },
            {
                "title": "Program",
                "url": f"{_GHIDRA_API_ROOT}/ghidra/program/model/listing/Program.html",
                "description": "Program-level listing and metadata object used throughout the backend.",
            },
            {
                "title": "PluginTool",
                "url": f"{_GHIDRA_API_ROOT}/ghidra/framework/plugintool/PluginTool.html",
                "description": "Primary tool/window abstraction for Ghidra UI integration.",
            },
            {
                "title": "TaskMonitor",
                "url": f"{_GHIDRA_API_ROOT}/ghidra/util/task/TaskMonitor.html",
                "description": "Cancellation and progress model used by scripts, analysis, and long-running actions.",
            },
        ],
        "swing": [
            {
                "title": "DialogComponentProvider",
                "url": f"{_GHIDRA_API_ROOT}/docking/DialogComponentProvider.html",
                "description": "Ghidra docking dialog base class for modal and modeless tool windows.",
            },
            {
                "title": "ComponentProvider",
                "url": f"{_GHIDRA_API_ROOT}/docking/ComponentProvider.html",
                "description": "Dockable provider surface for panes and persistent tool components.",
            },
            {
                "title": "DockingAction",
                "url": f"{_GHIDRA_API_ROOT}/docking/action/DockingAction.html",
                "description": "Action wiring used by Ghidra menu, toolbar, and popup integrations.",
            },
            {
                "title": "JFrame",
                "url": f"{_JAVA_API_ROOT}/java.desktop/javax/swing/JFrame.html",
                "description": "Top-level Swing window class for desktop integrations.",
            },
            {
                "title": "JDialog",
                "url": f"{_JAVA_API_ROOT}/java.desktop/javax/swing/JDialog.html",
                "description": "Swing dialog window documentation for modal interaction patterns.",
            },
            {
                "title": "JSplitPane",
                "url": f"{_JAVA_API_ROOT}/java.desktop/javax/swing/JSplitPane.html",
                "description": "Split-view container used by multi-pane tooling layouts.",
            },
            {
                "title": "JTable",
                "url": f"{_JAVA_API_ROOT}/java.desktop/javax/swing/JTable.html",
                "description": "Table widget for symbol, function, and analysis result explorers.",
            },
            {
                "title": "JTree",
                "url": f"{_JAVA_API_ROOT}/java.desktop/javax/swing/JTree.html",
                "description": "Tree widget for project hierarchy, namespaces, and call graph browsing.",
            },
            {
                "title": "SwingWorker",
                "url": f"{_JAVA_API_ROOT}/java.desktop/javax/swing/SwingWorker.html",
                "description": "Background task model for non-blocking desktop UI integrations.",
            },
        ],
    }


class WebUiBackend(Protocol):
    async def list_tools(self) -> list[dict[str, Any]]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...

    async def list_prompts(self) -> list[dict[str, Any]]: ...

    async def list_resources(self) -> list[dict[str, Any]]: ...

    async def read_resource(self, uri: str) -> dict[str, Any]: ...

    async def get_open_programs(self) -> dict[str, Any]: ...

    async def close(self) -> None: ...


@dataclass(slots=True)
class WebUiConfig:
    host: str = DEFAULT_WEBUI_HOST
    port: int = DEFAULT_WEBUI_PORT
    backend_url: str | None = None
    project_path: str | None = None
    project_name: str = "agentdecompile"
    force_analysis: bool = False
    verbose: bool = False

    @property
    def backend_mode(self) -> str:
        return "remote-mcp" if self.backend_url else "embedded-local"


class EmbeddedLocalBackend:
    def __init__(self, config: WebUiConfig) -> None:
        self._backend = LocalToolBackend(
            project_path=config.project_path,
            project_name=config.project_name,
            force_analysis=config.force_analysis,
            verbose=config.verbose,
        )

    async def list_tools(self) -> list[dict[str, Any]]:
        return await self._backend.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self._backend.call_tool(name, arguments)

    async def list_prompts(self) -> list[dict[str, Any]]:
        return await self._backend.list_prompts()

    async def list_resources(self) -> list[dict[str, Any]]:
        return await self._backend.list_resources()

    async def read_resource(self, uri: str) -> dict[str, Any]:
        return await self._backend.read_resource(uri)

    async def get_open_programs(self) -> dict[str, Any]:
        return self._backend.get_open_programs()

    async def close(self) -> None:
        self._backend.close()


class RemoteMcpBackend:
    def __init__(self, backend_url: str) -> None:
        self._backend_url = normalize_backend_url(backend_url)
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0))
        self._session_id: str | None = None
        self._initialized = False
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["mcp-session-id"] = self._session_id
        return headers

    def _capture_session(self, response: httpx.Response) -> None:
        session_id = (response.headers.get("mcp-session-id") or "").strip()
        if session_id:
            self._session_id = session_id

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        response = await self._client.post(
            self._backend_url,
            json={
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "roots": {"listChanged": True},
                        "sampling": {},
                        "elicitation": {"form": {}, "url": {}},
                    },
                    "clientInfo": {"name": "AgentDecompile Web UI", "version": "1.0.0"},
                },
            },
            headers=self._headers(),
        )
        response.raise_for_status()
        self._capture_session(response)
        payload = response.json()
        if payload.get("error"):
            raise RuntimeError(str(payload["error"]))
        await self._client.post(
            self._backend_url,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=self._headers(),
        )
        self._initialized = True

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        await self._ensure_initialized()
        response = await self._client.post(
            self._backend_url,
            json={"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params},
            headers=self._headers(),
        )
        response.raise_for_status()
        self._capture_session(response)
        payload = response.json()
        if payload.get("error"):
            raise RuntimeError(str(payload["error"]))
        return payload.get("result", {})

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self._rpc("tools/list", {})
        return list(result.get("tools", []))

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await self._rpc("tools/call", {"name": name, "arguments": arguments})
        return {
            "content": list(result.get("content", [])),
            "isError": bool(result.get("isError", False)),
        }

    async def list_prompts(self) -> list[dict[str, Any]]:
        result = await self._rpc("prompts/list", {})
        return list(result.get("prompts", []))

    async def list_resources(self) -> list[dict[str, Any]]:
        result = await self._rpc("resources/list", {})
        return list(result.get("resources", []))

    async def read_resource(self, uri: str) -> dict[str, Any]:
        result = await self._rpc("resources/read", {"uri": uri})
        contents = list(result.get("contents", []))
        raw = "\n\n".join(str(item.get("text", "")) for item in contents if item.get("text"))
        return {"uri": uri, "contents": contents, "raw": raw, "parsed": _safe_json_loads(raw)}

    async def get_open_programs(self) -> dict[str, Any]:
        return {}

    async def close(self) -> None:
        await self._client.aclose()


class WebUiSidecar:
    def __init__(self, config: WebUiConfig) -> None:
        self._config = config
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._startup_error: Exception | None = None

    @property
    def url(self) -> str:
        return f"http://{self._config.host}:{self._config.port}/"

    def start(self) -> bool:
        if self._thread is not None:
            return True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((self._config.host, self._config.port))
            except OSError:
                logger.warning("agentdecompile-webui sidecar skipped host=%s port=%s reason=port-unavailable", self._config.host, self._config.port)
                return False

        app = create_app(self._config)
        uvicorn_config = uvicorn.Config(
            app,
            host=self._config.host,
            port=self._config.port,
            log_level="debug" if self._config.verbose else "warning",
            access_log=False,
        )
        self._server = uvicorn.Server(uvicorn_config)
        self._thread = threading.Thread(target=self._run, name="agentdecompile-webui", daemon=True)
        self._thread.start()
        if not self._wait_until_listening(timeout_seconds=5.0):
            if self._startup_error is not None:
                logger.exception("agentdecompile-webui sidecar failed to start", exc_info=self._startup_error)
            else:
                logger.warning("agentdecompile-webui sidecar failed to start host=%s port=%s reason=startup-timeout", self._config.host, self._config.port)
            self.stop()
            return False
        logger.info("agentdecompile-webui sidecar started url=%s backend_mode=%s", self.url, self._config.backend_mode)
        return True

    def _run(self) -> None:
        if self._server is None:
            return
        try:
            self._server.run()
        except Exception as exc:
            self._startup_error = exc
            raise

    def _wait_until_listening(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._thread is not None and not self._thread.is_alive():
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.1)
                if probe.connect_ex((self._config.host, self._config.port)) == 0:
                    return True
        return False

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None
        self._server = None


def launch_webui_sidecar(backend_url: str, *, verbose: bool = False) -> WebUiSidecar | None:
    if not _webui_enabled():
        logger.info("agentdecompile-webui sidecar disabled by environment")
        return None

    config = WebUiConfig(
        host=_env_str(WEBUI_HOST_ENV_VARS, DEFAULT_WEBUI_HOST),
        port=_env_int(WEBUI_PORT_ENV_VARS, DEFAULT_WEBUI_PORT),
        backend_url=backend_url,
        verbose=verbose,
    )
    sidecar = WebUiSidecar(config)
    return sidecar if sidecar.start() else None


class ToolCallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ResourceReadRequest(BaseModel):
    uri: str


class PromptRenderRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class _FormatDict(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return ""


def _prompt_render_args(prompt_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    rendered = dict(arguments or {})
    keywords = (rendered.get("search_keywords") or "").strip()
    rendered.setdefault("program_path", "(current project)")
    rendered.setdefault("source_program_path", rendered.get("program_path", "(current project)"))
    rendered.setdefault("target_program_path", "(target binary)")
    rendered.setdefault("analysis_target", "reverse engineering target")
    rendered.setdefault("prior_function_list", "")
    rendered.setdefault("max_iterations", rendered.get("max_iterations") or 3)
    rendered.setdefault("category_path", f"/RE_Analysis/{str(rendered['analysis_target']).replace(' ', '')}")
    rendered.setdefault("bookmark_category", str(rendered["analysis_target"]).replace(" ", ""))
    rendered.setdefault(
        "keyword_clause",
        f" using these keywords: {keywords}" if keywords else "",
    )
    if prompt_name == "re-bridge-builder":
        rendered.setdefault("source_program_path", rendered.get("source_program_path") or "(source binary)")
        rendered.setdefault("target_program_path", rendered.get("target_program_path") or "(target binary)")
    return rendered


def create_app(config: WebUiConfig, backend: WebUiBackend | None = None) -> FastAPI:
    assets = _asset_dir()
    app_state: dict[str, Any] = {"backend": backend, "config": config}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if app_state["backend"] is None:
            app_state["backend"] = RemoteMcpBackend(config.backend_url) if config.backend_url else EmbeddedLocalBackend(config)
        try:
            yield
        finally:
            backend_obj = app_state.get("backend")
            if backend_obj is not None:
                await backend_obj.close()

    app = FastAPI(
        title="AgentDecompile Web UI",
        version="1.0.0",
        description="Browser-native frontend for AgentDecompile tool, prompt, resource, and documentation workflows.",
        lifespan=lifespan,
    )
    app.mount("/assets", StaticFiles(directory=assets), name="assets")

    def _backend() -> WebUiBackend:
        backend_obj = app_state.get("backend")
        if backend_obj is None:
            raise HTTPException(status_code=503, detail="Web UI backend is not initialized")
        return backend_obj

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "agentdecompile-webui",
            "backendMode": config.backend_mode,
            "port": config.port,
        }

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(assets / "index.html")

    @app.get("/api/meta")
    async def meta() -> dict[str, Any]:
        live_tools = await _backend().list_tools()
        return {
            "application": {
                "name": "AgentDecompile Web UI",
                "backendMode": config.backend_mode,
                "backendUrl": config.backend_url,
                "host": config.host,
                "port": config.port,
            },
            "live": {
                "advertisedToolCount": len(live_tools),
                "openPrograms": await _backend().get_open_programs(),
            },
            "reference": _build_tool_reference_payload(),
            "prompts": _serialize_prompt_messages(),
            "docs": _docs_hub(),
            "api": {
                "health": "/health",
                "toolReference": "/api/tool-reference",
                "tools": "/api/tools",
                "toolCall": "/api/tools/call",
                "prompts": "/api/prompts",
                "resources": "/api/resources",
                "resourceRead": "/api/resources/read",
                "docsHub": "/api/docs-hub",
            },
        }

    @app.get("/api/tool-reference")
    async def tool_reference() -> dict[str, Any]:
        return _build_tool_reference_payload()

    @app.get("/api/tools")
    async def tools() -> dict[str, Any]:
        return {"tools": await _backend().list_tools()}

    @app.post("/api/tools/call")
    async def call_tool(request: ToolCallRequest) -> dict[str, Any]:
        try:
            result = await _backend().call_tool(request.name, dict(request.arguments or {}))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"tool": request.name, **_tool_response_payload(result)}

    @app.get("/api/prompts")
    async def prompts() -> dict[str, Any]:
        return {
            "prompts": await _backend().list_prompts(),
            "definitions": _serialize_prompt_messages(),
        }

    @app.post("/api/prompts/render")
    async def render_prompt(request: PromptRenderRequest) -> dict[str, Any]:
        prompt_defs = {prompt["name"]: prompt for prompt in _serialize_prompt_messages()}
        prompt_def = prompt_defs.get(request.name)
        if prompt_def is None:
            raise HTTPException(status_code=404, detail=f"Unknown prompt: {request.name}")
        render_args = _prompt_render_args(request.name, dict(request.arguments or {}))
        messages = []
        for message in prompt_def.get("messages", []):
            text = str(message.get("text", "")).format_map(_FormatDict(render_args))
            messages.append({"role": message.get("role", "user"), "text": text})
        return {
            "name": request.name,
            "arguments": render_args,
            "messages": messages,
        }

    @app.get("/api/resources")
    async def resources() -> dict[str, Any]:
        return {"resources": await _backend().list_resources()}

    @app.post("/api/resources/read")
    async def read_resource(request: ResourceReadRequest) -> dict[str, Any]:
        try:
            return await _backend().read_resource(request.uri)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/docs-hub")
    async def docs_hub() -> dict[str, Any]:
        return _docs_hub()

    return app


def _build_config_from_args(args: argparse.Namespace) -> WebUiConfig:
    backend_url = args.backend_url or _env_str(WEBUI_BACKEND_URL_ENV_VARS, "") or None
    if backend_url:
        backend_url = normalize_backend_url(backend_url)
    return WebUiConfig(
        host=args.host or _env_str(WEBUI_HOST_ENV_VARS, DEFAULT_WEBUI_HOST),
        port=args.port or _env_int(WEBUI_PORT_ENV_VARS, DEFAULT_WEBUI_PORT),
        backend_url=backend_url,
        project_path=str(args.project_path) if args.project_path else None,
        project_name=args.project_name,
        force_analysis=bool(args.force_analysis),
        verbose=bool(args.verbose),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentDecompile browser UI for tools, prompts, resources, and documentation.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", type=str, default=None, help="Web UI bind host")
    parser.add_argument("--port", type=int, default=None, help="Web UI bind port (default: AGENT_DECOMPILE_WEBUI_PORT or 8002)")
    parser.add_argument("--backend-url", type=str, default=None, help="Optional remote MCP HTTP backend URL; when omitted the web UI runs an embedded local backend")
    parser.add_argument("--project-path", type=Path, default=None, help="Embedded local backend project path")
    parser.add_argument("--project-name", type=str, default="agentdecompile", help="Embedded local backend project name")
    parser.add_argument("--force-analysis", action="store_true", default=False, help="Force analysis when the embedded local backend imports binaries")
    parser.add_argument("--verbose", action="store_true", default=False, help="Enable verbose logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    config = _build_config_from_args(args)
    app = create_app(config)
    logger.info("agentdecompile-webui starting host=%s port=%s backend_mode=%s", config.host, config.port, config.backend_mode)
    uvicorn.run(app, host=config.host, port=config.port, log_level="debug" if args.verbose else "info")


if __name__ == "__main__":
    main()