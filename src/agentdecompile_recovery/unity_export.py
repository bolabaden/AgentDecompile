"""Drive AssetRipper headlessly to reconstruct a Unity project tree.

AssetRipper's GUI build doubles as a local HTTP service (``--headless --port N``)
whose routes -- ``/LoadFolder``, ``/LoadFile``, ``/Export/UnityProject`` -- are the
only supported way to script it: there is no batch CLI that both loads a player
and writes an ``ExportedProject``. This module is the Python port of a
PowerShell driver that was proven against a shipped title, and it exists to
defend three concrete failure modes that cost real runs:

* **Leaked processes.** A failure between launch and export used to leave an
  AssetRipper holding the port, so the next run silently talked to a stale
  instance loaded with the *previous* game. Termination happens in ``finally``.
* **Racing the server.** POSTing before the listener is up fails with a bare
  connection refused. Readiness is gated on ``GET /openapi.json`` returning 200,
  not merely on the TCP port opening.
* **Mid-export death.** AssetRipper loads the whole asset graph into memory
  before writing anything; on a 15 GiB title that ended in an
  ``OutOfMemoryException`` partway through, leaving a plausible-looking but
  scene-less output tree. The staged plan from
  :func:`~agentdecompile_recovery.unity_probe.build_unity_plan` shrinks the
  input, and an early process exit is detected, classified, and reported rather
  than mistaken for success.

Success is not "the command returned". It is
``ExportedProject/ProjectSettings/ProjectVersion.txt`` existing on disk -- the
first file Unity itself requires to open the result -- and that check is what the
receipt reports.

Standard library only: adding an HTTP client dependency for four form POSTs
would be a permanent cost for a temporary convenience.
"""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from pathlib import Path
from typing import Any

from .tools import ToolchainError
from .unity_assets import find_unity_data_dir

# AssetRipper answers a successful form POST with a 302 back to its own UI.
# urllib treats that as an error once redirects are disabled, so the codes that
# mean "accepted" have to be enumerated rather than inferred.
_ACCEPTED_STATUS = frozenset({200, 201, 204, 301, 302, 303, 307, 308})

# Substrings that mean the process died for lack of memory rather than for a
# bug in the input. Mixed .NET and OS-level spellings: the managed exception
# when AssetRipper notices, the allocator abort when it does not, and the Linux
# OOM killer's own wording when the kernel decides first.
_OOM_MARKERS = (
    "outofmemoryexception",
    "out of memory",
    "insufficient memory",
    "bad_alloc",
    "cannot allocate memory",
    "killed process",
    "oom-killer",
)

# SIGKILL. The Linux OOM killer's signature, and indistinguishable from a manual
# `kill -9` -- so it is reported as a *suspected* memory failure, never asserted.
_SIGKILL_RETURNCODE = -9

# 128+9: the same SIGKILL as reported by a shell (`$?`) or a container runtime
# rather than by `Popen.returncode`. Accepted because misclassifying an OOM kill
# as an ordinary failure sends the whole diagnosis down the wrong path, while a
# false positive only over-states a value already named "suspected".
_SHELL_SIGKILL_RETURNCODE = 137

_STARTUP_TIMEOUT = 120.0
_LOG_TAIL_BYTES = 8192

_SCHEMA = "agentdecompile.unity-export.v1"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib from replaying a POST as a GET against AssetRipper's UI.

    Following the 302 would re-enter the web UI, which on some builds re-runs
    work or returns a 404 that masks an otherwise successful export.
    """

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def pick_free_port() -> int:
    """Ask the OS for a currently-unused loopback port.

    Bind-then-release races anything else on the host that binds in the same
    instant; that is acceptable because the alternative -- a hardcoded default
    port -- collides deterministically with a leaked AssetRipper from an earlier
    run, which is the failure this avoids.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _split_base_url(base_url: str) -> tuple[str, int]:
    parts = urllib.parse.urlsplit(base_url)
    return parts.hostname or "127.0.0.1", int(parts.port or 80)


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_assetripper(base_url: str, *, timeout: float) -> bool:
    """Block until AssetRipper's HTTP API answers, or ``timeout`` elapses.

    The readiness signal is ``GET /openapi.json`` returning 200, not an open TCP
    port: the listener accepts connections before the routes are mapped, so a
    port-only check hands back a server that 404s the very next request.
    """

    host, port = _split_base_url(base_url)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _tcp_open(host, port, 0.4):
            try:
                with urllib.request.urlopen(f"{base_url}/openapi.json", timeout=10) as response:
                    if int(response.status) == 200:
                        return True
            except (urllib.error.URLError, OSError):
                pass
        time.sleep(0.3)
    return False


def _form_post(url: str, fields: dict[str, str], *, timeout: float) -> int:
    """POST ``application/x-www-form-urlencoded`` and return the status code.

    ``quote`` (not ``quote_plus``) matches the escaping the proven PowerShell
    driver used, so paths containing spaces travel as ``%20`` exactly as they did
    in the runs this port is derived from.
    """

    body = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote).encode("ascii")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        if exc.code in _ACCEPTED_STATUS:
            return int(exc.code)
        raise


def find_exported_project(output_dir: Path) -> Path | None:
    """Locate the ``ExportedProject`` tree AssetRipper nests under its output.

    AssetRipper writes ``<dest>/ExportedProject`` alongside ``AuxiliaryFiles``,
    but ``CreateSubfolder`` and version differences add a level, so the direct
    child is checked first and a bounded search follows. A destination that is
    itself a Unity project (``Assets`` + ``ProjectSettings``) is accepted last.
    """

    direct = output_dir / "ExportedProject"
    if direct.is_dir():
        return direct
    if output_dir.is_dir():
        for depth in ("*/ExportedProject", "*/*/ExportedProject"):
            for candidate in sorted(output_dir.glob(depth)):
                if candidate.is_dir():
                    return candidate
    if (output_dir / "Assets").is_dir() and (output_dir / "ProjectSettings").is_dir():
        return output_dir
    return None


def project_version_file(exported_project: Path) -> Path:
    """The file whose presence is this stage's success signal."""

    return exported_project / "ProjectSettings" / "ProjectVersion.txt"


def _tail(path: Path, limit: int = _LOG_TAIL_BYTES) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read().decode("utf-8", "replace").strip()
    except OSError:
        return ""


def looks_like_memory_failure(text: str, returncode: int | None = None) -> bool:
    """Classify a dead AssetRipper as a memory failure from its own output.

    Pure string inspection so the classification can be unit-tested against
    captured logs without running anything.
    """

    lowered = text.lower()
    if any(marker in lowered for marker in _OOM_MARKERS):
        return True
    return returncode in {_SIGKILL_RETURNCODE, _SHELL_SIGKILL_RETURNCODE}


def _stop_process(process: subprocess.Popen[bytes] | None, *, grace: float = 0.0) -> tuple[int | None, bool]:
    """Terminate, then kill. Returns ``(returncode, exited_on_its_own)``.

    The second value matters: our own ``terminate()`` leaves a non-zero exit code
    (``-15``) that is indistinguishable from a crash unless we record that the
    process was still alive when we asked it to stop. Reporting that as an early
    death would mask the actual error.

    ``grace`` covers the case that motivates all of this: a server that dies
    mid-request has not been reaped by the time the client sees the dropped
    connection, so an immediate ``poll()`` reports it alive and its real exit
    code -- the OOM evidence -- is lost. Callers pass a grace only when something
    already went wrong, so a healthy run never waits.

    Never raises; this runs on the failure path too.
    """

    if process is None:
        return None, False
    if process.poll() is None and grace > 0:
        try:
            process.wait(timeout=grace)
        except (subprocess.TimeoutExpired, OSError):
            pass
    if process.poll() is not None:
        return process.returncode, True
    try:
        process.terminate()
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            pass
    except OSError:
        pass
    return process.returncode, False


def _load_route(load_path: Path) -> str:
    """``/LoadFile`` for a single player executable, ``/LoadFolder`` otherwise."""

    return "/LoadFile" if load_path.is_file() else "/LoadFolder"


def _staged_containers(plan: dict[str, Any] | None) -> list[str]:
    export = (plan or {}).get("export") or {}
    included = export.get("includedContainers") or []
    return [str(name) for name in included]


def export_unity_project(
    install_root: Path,
    output_dir: Path,
    *,
    assetripper_cli: Path | None,
    plan: dict[str, Any] | None = None,
    staging_dir: Path | None = None,
    port: int | None = None,
    load_timeout: float = 7200,
    export_timeout: float = 7200,
    startup_timeout: float = _STARTUP_TIMEOUT,
) -> dict[str, Any]:
    """Export a shipped Unity player to an ``ExportedProject`` tree.

    When ``plan["export"]["mode"] == "staged"`` the plan's included containers are
    symlinked into a staging tree and AssetRipper is pointed at that instead of
    the real install: identical routes, a fraction of the asset graph, and the
    difference between finishing and dying of memory exhaustion on a large title.

    Everything this writes lives under ``output_dir``: AssetRipper's destination
    at ``output_dir/assetripper``, the staging tree at ``output_dir/_staging``,
    and process logs beside them. The staging tree is deliberately *not* nested
    inside the destination, because headless AssetRipper clears a non-empty
    destination without asking and would delete the tree it is reading from.
    """

    started = time.monotonic()
    install_root = install_root.resolve()
    output_dir = output_dir.resolve()

    if assetripper_cli is None:
        raise ToolchainError(
            "assetripper-missing",
            detail="no AssetRipper binary found (set AGENTDECOMPILE_ASSETRIPPER_CLI or install under target/assetripper)",
        )
    assetripper_cli = Path(assetripper_cli).expanduser().resolve()
    if not assetripper_cli.is_file():
        raise ToolchainError("assetripper-missing", detail=f"not a file: {assetripper_cli}")

    if not install_root.exists():
        return {
            "schema": _SCHEMA,
            "status": "error",
            "reason": f"install root does not exist: {install_root}",
            "installRoot": str(install_root),
            "claimBoundary": "nothing was exported; this receipt describes a rejected input, not a failed export",
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    export_dest = output_dir / "assetripper"
    export_dest.mkdir(parents=True, exist_ok=True)
    stdout_log = output_dir / "assetripper.stdout.log"
    stderr_log = output_dir / "assetripper.stderr.log"

    mode = str(((plan or {}).get("export") or {}).get("mode") or "full")
    staged_containers: list[str] = []
    staging: dict[str, Any] | None = None
    load_path = install_root

    if mode == "staged":
        from .unity_probe import stage_export_tree  # deferred: unity_probe imports tools

        data_dir = find_unity_data_dir(install_root) if install_root.is_dir() else None
        if data_dir is None:
            return {
                "schema": _SCHEMA,
                "status": "error",
                "reason": "staged export requested but no *_Data directory was found under the install root",
                "mode": mode,
                "installRoot": str(install_root),
                "claimBoundary": "nothing was exported; a staged plan cannot be applied to a non-standard player layout",
            }
        staged_containers = _staged_containers(plan)
        staging_root = (staging_dir or (output_dir / "_staging")).resolve()
        staging = stage_export_tree(data_dir, staging_root, staged_containers)
        load_path = staging_root

    port = port or pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    route = _load_route(load_path)

    process: subprocess.Popen[bytes] | None = None
    load_seconds = 0.0
    export_seconds = 0.0
    load_status: int | None = None
    export_status: int | None = None
    failure: str | None = None

    try:
        with stdout_log.open("wb") as out_handle, stderr_log.open("wb") as err_handle:
            process = subprocess.Popen(
                [str(assetripper_cli), "--headless", "--port", str(port)],
                stdout=out_handle,
                stderr=err_handle,
            )

        if not wait_for_assetripper(base_url, timeout=startup_timeout):
            failure = (
                f"AssetRipper did not answer GET {base_url}/openapi.json within {startup_timeout:.0f}s"
            )
        else:
            phase_started = time.monotonic()
            try:
                load_status = _form_post(
                    f"{base_url}{route}",
                    {"Path": str(load_path)},
                    timeout=load_timeout,
                )
            except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
                failure = f"POST {route} failed: {exc}"
            finally:
                load_seconds = time.monotonic() - phase_started

            if failure is None:
                phase_started = time.monotonic()
                try:
                    export_status = _form_post(
                        f"{base_url}/Export/UnityProject",
                        {"Path": str(export_dest)},
                        timeout=export_timeout,
                    )
                except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
                    failure = f"POST /Export/UnityProject failed: {exc}"
                finally:
                    export_seconds = time.monotonic() - phase_started
    finally:
        returncode, exited_on_its_own = _stop_process(process, grace=5.0 if failure else 0.0)

    stderr_tail = _tail(stderr_log)
    stdout_tail = _tail(stdout_log)
    combined = f"{stdout_tail}\n{stderr_tail}"

    exported_project = find_exported_project(export_dest)
    version_file = project_version_file(exported_project) if exported_project else None
    has_project_version = bool(version_file and version_file.is_file())

    # Only a process that was already gone when we went to stop it died on its
    # own; anything else carries our terminate()'s exit code and says nothing.
    died_early = exited_on_its_own and returncode not in (None, 0) and not has_project_version
    memory_suspected = died_early and looks_like_memory_failure(combined, returncode)

    if has_project_version and failure is None:
        status = "complete"
        reason = None
    else:
        status = "error"
        if memory_suspected:
            reason = (
                "AssetRipper died before finishing the export and its output indicates memory "
                f"exhaustion (exit {returncode}); re-run with a staged plan or a smaller memory "
                "budget so fewer containers are loaded at once"
            )
        elif died_early:
            reason = f"AssetRipper exited early with code {returncode} before writing ProjectVersion.txt"
        elif failure is not None:
            reason = failure
        else:
            reason = (
                "export returned without writing ExportedProject/ProjectSettings/ProjectVersion.txt; "
                "the output tree is not an openable Unity project"
            )

    receipt: dict[str, Any] = {
        "schema": _SCHEMA,
        "status": status,
        "reason": reason,
        "mode": mode,
        "installRoot": str(install_root),
        "loadPath": str(load_path),
        "loadRoute": route,
        "outputDir": str(output_dir),
        "exportDir": str(export_dest),
        "exportedProject": str(exported_project) if exported_project else None,
        "projectVersionFile": str(version_file) if version_file else None,
        "hasProjectVersion": has_project_version,
        "stagedContainers": staged_containers,
        "stagedContainerCount": len(staged_containers),
        "stagingDir": staging["stagingDir"] if staging else None,
        "stagingLinkCount": staging["linkCount"] if staging else 0,
        "port": port,
        "assetRipper": str(assetripper_cli),
        "loadStatus": load_status,
        "exportStatus": export_status,
        # Null when we stopped a healthy server ourselves: the exit code would be
        # our own SIGTERM and reads as a crash to anyone scanning the receipt.
        "exitCode": returncode if exited_on_its_own else None,
        "exitedOnItsOwn": exited_on_its_own,
        "diedEarly": died_early,
        "memoryFailureSuspected": memory_suspected,
        "loadSeconds": round(load_seconds, 3),
        "exportSeconds": round(export_seconds, 3),
        "elapsedSeconds": round(time.monotonic() - started, 3),
        "stdoutLog": str(stdout_log),
        "stderrLog": str(stderr_log),
        "stderrTail": stderr_tail[-2000:],
        "claimBoundary": (
            "ProjectVersion.txt proves AssetRipper wrote a project skeleton -- not that the project "
            "opens, compiles, or that its scenes are complete; a staged export additionally omits "
            "every container outside stagedContainers, whose assets remain unresolved references"
        ),
    }
    return receipt
