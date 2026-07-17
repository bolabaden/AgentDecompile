"""Target-fingerprint-keyed registry for acquisition bundles.

The registry is the backbone of implicit acquisition UX: build a bundle once and
every consumer (recover, agentdecompile queries, the stdio MCP service, and
prompt-context) can rediscover it from the target it belongs to, without a user
having to remember a bundle path or export an environment variable.

The registry stores pointers, never copies of bundle data.  It records where a
bundle lives keyed by its target fingerprint so lookups are O(1) and stable.
Registry entries are advisory acquisition evidence only; compile and objdiff
gates remain the acceptance boundary.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .acquisition_bundle import target_fingerprint

REGISTRY_SCHEMA = "agentdecompile.acquisition-registry.v1"
REGISTRY_ENV = "AGENTDECOMPILE_ACQUISITION_HOME"
CLAIM_BOUNDARY = "registry entries are advisory acquisition evidence only; compile and objdiff gates remain required."


def registry_root(repo_root: Path | None = None) -> Path:
    """Resolve the registry root, honoring AGENTDECOMPILE_ACQUISITION_HOME first."""

    override = os.environ.get(REGISTRY_ENV)
    if override:
        return Path(override).expanduser().resolve()
    base = (repo_root or Path.cwd()).resolve()
    return base / ".agentdecompile" / "acquisition"


def index_path(repo_root: Path | None = None) -> Path:
    return registry_root(repo_root) / "index.json"


def load_index(repo_root: Path | None = None) -> dict[str, Any]:
    path = index_path(repo_root)
    if not path.exists():
        return {"schema": REGISTRY_SCHEMA, "bundles": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"acquisition registry index is corrupt at {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("bundles"), list):
        raise ValueError(f"acquisition registry index is corrupt at {path}")
    payload.setdefault("schema", REGISTRY_SCHEMA)
    return payload


def register_bundle(
    *,
    bundle_dir: Path,
    manifest: dict[str, Any],
    repo_root: Path | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    """Record a bundle location keyed by its target fingerprint.

    The newest entry for a fingerprint wins on lookup, so re-registering an
    updated bundle transparently supersedes the old one.
    """

    fingerprint = str(manifest.get("targetFingerprint") or "")
    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    if not fingerprint or not (target.get("sha256") or target.get("stableId")):
        raise ValueError(
            "refusing to register acquisition bundle without a real target fingerprint "
            "(non-empty targetFingerprint plus stableId or sha256)"
        )
    entry = {
        "targetFingerprint": fingerprint,
        "bundleDir": str(bundle_dir.resolve()),
        "target": manifest.get("target") or {},
        "entityCount": manifest.get("entityCount"),
        "conflictCount": manifest.get("conflictCount"),
        "registeredAt": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "claimBoundary": CLAIM_BOUNDARY,
    }
    index = load_index(repo_root)
    # Corrupt/empty loads must not be used as a write base that wipes history.
    if not isinstance(index.get("bundles"), list):
        raise ValueError("acquisition registry index is corrupt; refusing to overwrite")
    bundles = [row for row in index.get("bundles", []) if row.get("bundleDir") != entry["bundleDir"]]
    bundles.append(entry)
    index["bundles"] = bundles
    index["schema"] = REGISTRY_SCHEMA
    path = index_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return entry


def _valid_bundle_dir(value: Any) -> Path | None:
    if not value:
        return None
    candidate = Path(str(value))
    return candidate if (candidate / "manifest.json").exists() else None


def find_bundle(
    *,
    target: dict[str, Any] | None = None,
    fingerprint: str | None = None,
    repo_root: Path | None = None,
) -> Path | None:
    """Return the newest registered bundle dir for a target fingerprint."""

    wanted = fingerprint or (target_fingerprint(target) if target is not None else None)
    if not wanted:
        return None
    try:
        index = load_index(repo_root)
    except ValueError:
        return None
    for row in reversed(index.get("bundles", [])):
        if row.get("targetFingerprint") != wanted:
            continue
        bundle_dir = _valid_bundle_dir(row.get("bundleDir"))
        if bundle_dir is not None:
            return bundle_dir
    return None


def latest_bundle(repo_root: Path | None = None) -> Path | None:
    """Return the most recently registered bundle whose data still exists."""

    try:
        index = load_index(repo_root)
    except ValueError:
        return None
    for row in reversed(index.get("bundles", [])):
        bundle_dir = _valid_bundle_dir(row.get("bundleDir"))
        if bundle_dir is not None:
            return bundle_dir
    return None


def list_bundles(repo_root: Path | None = None) -> list[dict[str, Any]]:
    try:
        index = load_index(repo_root)
    except ValueError:
        return []
    rows: list[dict[str, Any]] = []
    for row in index.get("bundles", []):
        entry = dict(row)
        entry["available"] = _valid_bundle_dir(row.get("bundleDir")) is not None
        rows.append(entry)
    return rows


def resolve_bundle(
    *,
    explicit: Path | None = None,
    target: dict[str, Any] | None = None,
    repo_root: Path | None = None,
    allow_latest: bool = False,
) -> Path | None:
    """Implicit bundle resolution used by every consumer.

    Precedence: an explicit path, then the registry entry for the target, then
    (only when allowed and unambiguous) the single most recent bundle.
    """

    if explicit is not None and (explicit / "manifest.json").exists():
        return explicit
    if explicit is not None and (explicit / "acquisition-bundle" / "manifest.json").exists():
        return explicit / "acquisition-bundle"
    resolved = find_bundle(target=target, repo_root=repo_root)
    if resolved is not None:
        return resolved
    if allow_latest:
        return latest_bundle(repo_root)
    return None
