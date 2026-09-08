"""Create, ingest, and report Ghidra BSim databases.

Wraps ``support/bsim`` (createdatabase, generatesigs, listexes, listfuncs,
getexecount, getmetadata). A PostgreSQL datadir with only initdb templates is
reported as having no BSim database — the failure mode in issue 169.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

DEFAULT_TEMPLATE = "medium_nosize"
RECEIPT_NAME = "agentdecompile-bsim-ingest.json"
_TEMPLATE_OIDS = frozenset({"1", "4", "5"})
_MD5_RE = re.compile(r"\b([0-9a-fA-F]{32})\b")
_ADDR_RE = re.compile(r"\b(0x[0-9a-fA-F]+)\b")
_PORT_RE = re.compile(r"^\s*port\s*=\s*(\d+)", re.MULTILINE)


def _strip_sslmode_query(url: str) -> str:
    """Ghidra's bsim CLI treats '?' as a flag, so sslmode cannot live in the URL."""
    raw = (url or "").strip()
    if "?sslmode=" in raw:
        return raw.split("?sslmode=", 1)[0]
    if "&sslmode=" in raw:
        return raw.replace("&sslmode=disable", "").replace("&sslmode=require", "")
    return raw


def _bsim_cli_error(stdout: str, stderr: str) -> bool:
    blob = f"{stdout}\n{stderr}"
    return "ERROR " in blob or "SQL error" in blob


def find_bsim_launcher(install_dir: str | Path | None = None) -> Path | None:
    root = Path(install_dir or os.environ.get("GHIDRA_INSTALL_DIR") or "").expanduser()
    if not root.is_dir():
        return None
    for name in ("bsim", "bsim.bat"):
        cand = root / "support" / name
        if cand.is_file():
            return cand
    return None


def classify_datadir(datadir: str | Path) -> dict[str, Any]:
    """Inspect a BSimControl PostgreSQL data directory without querying BSim."""
    path = Path(datadir).expanduser()
    if not path.exists():
        return {
            "ok": True,
            "state": "missing_datadir",
            "summary": "datadir does not exist",
            "datadir": str(path),
        }
    if not path.is_dir():
        return {
            "ok": True,
            "state": "not_a_datadir",
            "summary": "path is not a directory",
            "datadir": str(path),
        }
    pg_version = path / "PG_VERSION"
    if not pg_version.is_file():
        return {
            "ok": True,
            "state": "no_postgres",
            "summary": "datadir has no BSim database (not a PostgreSQL cluster)",
            "datadir": str(path),
        }
    version = pg_version.read_text(encoding="utf-8", errors="replace").strip()
    base = path / "base"
    oids: list[str] = []
    if base.is_dir():
        oids = sorted(child.name for child in base.iterdir() if child.is_dir() and child.name.isdigit())
    extras = [oid for oid in oids if oid not in _TEMPLATE_OIDS]
    port = _read_port(path / "postgresql.conf")
    if not extras:
        return {
            "ok": True,
            "state": "no_bsim_database",
            "summary": "datadir has no BSim database",
            "datadir": str(path),
            "pg_version": version,
            "cluster_oids": oids,
            "port": port,
        }
    return {
        "ok": True,
        "state": "cluster_has_extra_databases",
        "summary": "PostgreSQL cluster has databases beyond initdb templates",
        "datadir": str(path),
        "pg_version": version,
        "cluster_oids": oids,
        "extra_oids": extras,
        "port": port,
    }


def default_bsim_url(*, datadir: str | Path | None = None, name: str = "") -> str:
    env = (os.environ.get("AGENT_DECOMPILE_BSIM_URL") or "").strip()
    if env:
        return env
    db = (name or os.environ.get("AGENT_DECOMPILE_BSIM_NAME") or "bsim").strip() or "bsim"
    port = 5432
    if datadir:
        classified = classify_datadir(datadir)
        if classified.get("port"):
            port = int(classified["port"])
    return f"postgresql://127.0.0.1:{port}/{db}"


def ghidra_url_for_program(repository: str, program: str, *, ghidra_url: str = "") -> str:
    prog = (program or "").strip().lstrip("/")
    base = (ghidra_url or "").strip().rstrip("/")
    if base:
        if not prog or prog in base.split("/") or base.endswith("/" + prog):
            return base
        if base.startswith("ghidra://"):
            return f"{base}/{prog}"
        if "?" in base:
            return f"{base}/{prog}" if not base.endswith("/") else f"{base}{prog}"
        return f"{base}?/{prog}"
    path = Path(repository).expanduser().resolve()
    if prog:
        return f"ghidra:{path}?/{prog}"
    return f"ghidra:{path}"


def createdatabase(
    bsim_url: str,
    *,
    template: str = DEFAULT_TEMPLATE,
    name: str = "",
    owner: str = "",
    description: str = "",
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    url = _strip_sslmode_query((bsim_url or "").strip())
    if not url:
        return {"ok": False, "error": "bsim URL is required"}
    argv = ["createdatabase", url, template or DEFAULT_TEMPLATE]
    if name:
        argv.extend(["--name", name])
    if owner:
        argv.extend(["--owner", owner])
    if description:
        argv.extend(["--description", description])
    ran = _run(argv, runner=runner)
    out = (ran.get("stdout") or "") + (ran.get("stderr") or "")
    if (ran["returncode"] or _bsim_cli_error(ran.get("stdout") or "", ran.get("stderr") or "")) and url.startswith("postgresql://") and "does not support SSL" in out:
        fallback = Path(os.environ.get("AGENT_DECOMPILE_CORPUS_WORK_DIR") or "/tmp") / "bsim-file" / (name or "bsim")
        fallback.parent.mkdir(parents=True, exist_ok=True)
        file_url = f"file:{fallback}"
        retry = createdatabase(file_url, template=template, name=name, owner=owner, description=description, runner=runner)
        retry["fallbackFrom"] = url
        retry["fallbackReason"] = "PostgreSQL BSim URL failed (server does not support SSL). Used a file database."
        return retry
    if ran["returncode"] or _bsim_cli_error(ran.get("stdout") or "", ran.get("stderr") or ""):
        return {"ok": False, "error": ran["stderr"] or ran["stdout"] or "createdatabase failed", **ran, "bsimUrl": url}
    return {"ok": True, "action": "bsim-createdatabase", "bsimUrl": url, "template": template or DEFAULT_TEMPLATE, **ran}


def report(
    *,
    datadir: str | Path | None = None,
    bsim_url: str = "",
    name: str = "",
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    cluster = classify_datadir(datadir) if datadir else None
    url = _strip_sslmode_query(
        (bsim_url or "").strip()
        or (default_bsim_url(datadir=datadir, name=name) if datadir or name else "")
    )
    if cluster and cluster.get("state") in {"missing_datadir", "not_a_datadir", "no_postgres", "no_bsim_database"}:
        return {
            "ok": True,
            "action": "bsim-report",
            "state": cluster["state"],
            "summary": cluster["summary"],
            "executables": 0,
            "functions": None,
            "exes": [],
            "cluster": cluster,
            "bsimUrl": url or None,
        }
    if not url:
        return {
            "ok": False,
            "error": "bsim URL or datadir is required",
            "cluster": cluster,
        }
    meta = _run(["getmetadata", url], runner=runner)
    count = _run(["getexecount", url], runner=runner)
    listed = _run(["listexes", url], runner=runner)
    if meta["returncode"] and count["returncode"]:
        err = meta["stderr"] or count["stderr"] or listed["stderr"] or "BSim did not answer"
        state = "no_bsim_database"
        if cluster and cluster.get("state") == "cluster_has_extra_databases":
            state = "database_unreachable"
        return {
            "ok": True,
            "action": "bsim-report",
            "state": state,
            "summary": "datadir has no BSim database" if state == "no_bsim_database" else err,
            "executables": 0,
            "functions": None,
            "exes": [],
            "error": err,
            "cluster": cluster,
            "bsimUrl": url,
        }
    exes = parse_listexes(listed.get("stdout") or "")
    n = _parse_count(count.get("stdout") or "")
    if n is None:
        n = len(exes)
    funcs = None
    if exes:
        # Cheap total: one listfuncs pass is expensive; leave None unless getexecount-only.
        funcs = None
    if n == 0:
        state = "empty_database"
        summary = "database exists but is empty"
    else:
        state = "populated"
        summary = f"database holds {n} executables"
    return {
        "ok": True,
        "action": "bsim-report",
        "state": state,
        "summary": summary,
        "executables": n,
        "functions": funcs,
        "exes": exes,
        "cluster": cluster,
        "bsimUrl": url,
        "metadata": (meta.get("stdout") or "").strip() or None,
    }


def ingest(
    repository: str,
    *,
    bsim_url: str = "",
    datadir: str | Path | None = None,
    name: str = "",
    programs: list[str] | None = None,
    ghidra_url: str = "",
    receipt: str | Path | None = None,
    force: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    list_programs: Callable[[str], list[str]] | None = None,
) -> dict[str, Any]:
    repo = (repository or "").strip()
    if not repo:
        return {"ok": False, "error": "repository or Ghidra project path is required"}
    url = _strip_sslmode_query((bsim_url or "").strip() or default_bsim_url(datadir=datadir, name=name))
    names = list(programs or [])
    if not names:
        names = _discover_programs(repo, list_programs=list_programs)
    if not names:
        return {"ok": False, "error": "no programs found in repository", "repository": repo}
    dest = Path(receipt) if receipt else Path(datadir or repo) / RECEIPT_NAME
    prior = _read_receipt(dest)
    already = {
        str(item.get("name") or "")
        for item in (report(bsim_url=url, datadir=datadir, name=name, runner=runner).get("exes") or [])
        if item.get("name")
    }
    results: list[dict[str, Any]] = []
    for prog in names:
        if not force and (prog in already or (prior.get(prog) or {}).get("status") == "committed"):
            results.append({"name": prog, "status": "skipped", "reason": "already ingested"})
            continue
        gurl = ghidra_url_for_program(repo, prog, ghidra_url=ghidra_url)
        ran = _run(["generatesigs", gurl, "--bsim", url], runner=runner)
        row = {
            "name": prog,
            "ghidraUrl": gurl,
            "status": "committed" if ran["returncode"] == 0 else "failed",
            "returncode": ran["returncode"],
            "stdout": (ran.get("stdout") or "")[-2000:],
            "stderr": (ran.get("stderr") or "")[-2000:],
        }
        if ran["returncode"]:
            row["error"] = ran.get("stderr") or ran.get("stdout") or "generatesigs failed"
        results.append(row)
        prior[prog] = {"status": row["status"], "error": row.get("error")}
        _write_receipt(dest, prior)
    failed = [row for row in results if row["status"] == "failed"]
    return {
        "ok": not failed,
        "action": "bsim-ingest",
        "bsimUrl": url,
        "repository": repo,
        "receipt": str(dest),
        "programs": len(names),
        "committed": sum(1 for row in results if row["status"] == "committed"),
        "skipped": sum(1 for row in results if row["status"] == "skipped"),
        "failed": len(failed),
        "results": results,
    }


def list_program_functions(
    program: str,
    *,
    bsim_url: str = "",
    datadir: str | Path | None = None,
    name: str = "",
    offset: int = 0,
    limit: int | str = "all",
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    from agentdecompile_recovery.corpus.dashboard.common import page_window

    url = (bsim_url or "").strip() or default_bsim_url(datadir=datadir, name=name)
    if not program:
        return {"ok": False, "error": "program name is required", "results": [], "total": 0}
    ran = _run(["listfuncs", url, "--name", program], runner=runner)
    if ran["returncode"]:
        return {
            "ok": False,
            "error": ran.get("stderr") or ran.get("stdout") or "listfuncs failed",
            "results": [],
            "total": 0,
            "source": "bsim",
            "bsimUrl": url,
        }
    rows = parse_listfuncs(ran.get("stdout") or "")
    start, cap = page_window(offset, limit)
    page = rows if cap is None else rows[start : start + cap]
    return {
        "ok": True,
        "source": "bsim",
        "program": program,
        "bsimUrl": url,
        "results": page,
        "total": len(rows),
        "offset": start,
        "limit": "all" if cap is None else cap,
        "hasMore": cap is not None and start + len(page) < len(rows),
    }


def parse_listexes(text: str) -> list[dict[str, Any]]:
    exes: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.lower().startswith(("usage:", "note:", "global ")):
            continue
        md5 = _MD5_RE.search(line)
        name = _exe_name(line)
        if name and (md5 or "executable" in line.lower() or current is None):
            if current and current.get("name"):
                exes.append(current)
            current = {"name": name, "md5": md5.group(1).lower() if md5 else None}
            arch = _kv(line, "arch") or _kv(line, "architecture")
            if arch:
                current["arch"] = arch
            continue
        if current is None:
            continue
        if md5 and not current.get("md5"):
            current["md5"] = md5.group(1).lower()
        for key in ("arch", "architecture", "compiler", "language"):
            val = _kv(line, key)
            if val:
                current["arch" if key in {"arch", "architecture", "language"} else key] = val
    if current and current.get("name"):
        exes.append(current)
    # Dedup by name+md5
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in exes:
        key = (str(item.get("name") or ""), str(item.get("md5") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def parse_listfuncs(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        addr_m = _ADDR_RE.search(line)
        if not addr_m:
            continue
        addr = addr_m.group(1)
        if addr in seen:
            continue
        seen.add(addr)
        name = line.replace(addr, "").strip()
        name = re.sub(r"^[\-|:]+", "", name).strip() or f"FUN_{addr[2:]}"
        try:
            address = int(addr, 16)
        except ValueError:
            address = 0
        rows.append({
            "addr": addr.lower() if addr.startswith("0x") else addr,
            "address": address,
            "name": name.split()[0] if name else f"FUN_{addr[2:]}",
            "size": 0,
            "logicalId": None,
            "decomp": "none",
            "validate": "none",
        })
    return rows


def _discover_programs(repository: str, *, list_programs: Callable[[str], list[str]] | None) -> list[str]:
    if list_programs is not None:
        return [name for name in list_programs(repository) if name]
    from agentdecompile_recovery.corpus.ghidra_project import inspect_locator

    info = inspect_locator(repository)
    names: list[str] = []
    for item in info.get("programs") or []:
        if isinstance(item, str) and item:
            names.append(item)
        elif isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


def _read_port(conf: Path) -> int | None:
    if not conf.is_file():
        return None
    try:
        text = conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    hit = _PORT_RE.search(text)
    return int(hit.group(1)) if hit else None


def _run(
    argv: list[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None,
    timeout: int = 3600,
) -> dict[str, Any]:
    if runner is None:
        launcher = find_bsim_launcher()
        if launcher is None:
            return {
                "returncode": 127,
                "stdout": "",
                "stderr": "Ghidra support/bsim not found (set GHIDRA_INSTALL_DIR)",
                "argv": argv,
            }

        def runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            env = os.environ.copy()
            env.setdefault("PGSSLMODE", "disable")
            env.setdefault("PGSSLROOTCERT", "")
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False, env=env, **kwargs
            )

        cmd = [str(launcher), *argv]
    else:
        cmd = ["bsim", *argv]
    try:
        proc = runner(cmd)
    except subprocess.TimeoutExpired as exc:
        return {"returncode": 124, "stdout": exc.stdout or "", "stderr": "bsim timed out", "argv": argv}
    return {
        "returncode": int(proc.returncode),
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "argv": argv,
    }


def _parse_count(text: str) -> int | None:
    nums = re.findall(r"\b(\d+)\b", text or "")
    if not nums:
        return None
    return int(nums[-1])


def _exe_name(line: str) -> str | None:
    for prefix in ("executable:", "name:", "exe:"):
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip().strip('"')
    parts = line.split()
    if parts and not parts[0].lower() in {"md5", "arch", "compiler", "count"}:
        if "." in parts[0] or parts[0].endswith((".exe", ".ipa", ".app", ".xbe")):
            return parts[0]
        if re.match(r"^[A-Za-z][\w.\-]+$", parts[0]) and not _MD5_RE.fullmatch(parts[0]):
            return parts[0]
    return None


def _kv(line: str, key: str) -> str | None:
    m = re.search(rf"{key}\s*[:=]\s*(\S+)", line, flags=re.IGNORECASE)
    return m.group(1) if m else None


def _read_receipt(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(payload, dict) and isinstance(payload.get("programs"), dict):
        return dict(payload["programs"])
    return payload if isinstance(payload, dict) else {}


def _write_receipt(path: Path, programs: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"programs": programs}, indent=2) + "\n", encoding="utf-8")
