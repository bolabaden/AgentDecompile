"""Durable state and event logging for resumable pipelines."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique per-writer tmp name -- concurrent writers to the same destination
    # (e.g. rewrite_queue.py's campaign process + worker session) must not
    # share one intermediate file, or one writer's in-progress .tmp can be
    # replaced out from under another mid-write.
    tmp = path.with_suffix(f"{path.suffix}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def config_fingerprint(data: dict[str, Any]) -> str:
    payload = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RunState:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.state_path = run_dir / "state.json"
        self.events_path = run_dir / "events.jsonl"
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        if self.state_path.exists():
            return read_json(self.state_path)
        return {
            "schema": "agentdecompile.recover.state.v1",
            "createdAt": now(),
            "updatedAt": now(),
            "stages": {},
        }

    def save(self) -> None:
        self.data["updatedAt"] = now()
        atomic_write_json(self.state_path, self.data)

    def event(self, name: str, **payload: Any) -> dict[str, Any]:
        row = {"time": now(), "event": name, **payload}
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        return row

    def stage_receipt(self, name: str) -> dict[str, Any]:
        return self.data.setdefault("stages", {}).setdefault(name, {})
