#!/usr/bin/env python3
"""Validate Agent Skills frontmatter against https://agentskills.io/specification."""

from __future__ import annotations

import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOTS = (
    ROOT / ".agents" / "skills",
    ROOT / "skills",
    ROOT / ".cursor" / "skills",
    ROOT / ".claude" / "skills",
)
CANONICAL_ROOTS = (ROOT / ".agents" / "skills", ROOT / "skills")


def _frontmatter(text: str) -> tuple[dict[str, object], str] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    block = text[4:end]
    data: dict[str, object] = {}
    current_map: str | None = None
    for raw in block.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if raw.startswith("  ") and current_map:
            key, _, val = raw.strip().partition(":")
            nested = data.setdefault(current_map, {})
            if isinstance(nested, dict):
                nested[key.strip()] = val.strip().strip('"').strip("'")
            continue
        current_map = None
        key, _, val = raw.partition(":")
        key = key.strip()
        val = val.strip()
        if not val:
            current_map = key
            data[key] = {}
            continue
        data[key] = val.strip('"').strip("'")
    return data, text[end + 4 :]


def validate_skill(path: Path, *, require_match_dir: bool) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    parsed = _frontmatter(text)
    if parsed is None:
        return [f"{path}: missing YAML frontmatter"]
    meta, _body = parsed
    name = str(meta.get("name") or "")
    desc = str(meta.get("description") or "")
    if not name:
        errors.append(f"{path}: name is required")
    elif not NAME_RE.fullmatch(name) or len(name) > 64:
        errors.append(f"{path}: invalid name {name!r}")
    elif require_match_dir and path.parent.name != name:
        errors.append(f"{path}: name {name!r} != directory {path.parent.name!r}")
    if not desc:
        errors.append(f"{path}: description is required")
    elif len(desc) > 1024:
        errors.append(f"{path}: description is {len(desc)} chars (max 1024)")
    elif not desc.lower().startswith("use this skill when"):
        errors.append(
            f"{path}: description must start with 'Use this skill when' "
            "(https://agentskills.io/skill-creation/optimizing-descriptions)"
        )
    compat = meta.get("compatibility")
    if compat is not None and not (1 <= len(str(compat)) <= 500):
        errors.append(f"{path}: compatibility must be 1–500 characters")
    extra = set(meta) - {
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "allowed-tools",
    }
    if extra:
        errors.append(f"{path}: non-spec frontmatter keys {sorted(extra)}")
    metadata = meta.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        errors.append(f"{path}: metadata must be a string map")
    elif isinstance(metadata, dict):
        for key, val in metadata.items():
            if not isinstance(val, str):
                errors.append(f"{path}: metadata.{key} must be a string")
    return errors


def main() -> int:
    errors: list[str] = []
    found = 0
    for root in SKILL_ROOTS:
        if not root.is_dir():
            continue
        for skill in sorted(root.glob("*/SKILL.md")):
            found += 1
            errors.extend(validate_skill(skill, require_match_dir=True))
            if root in CANONICAL_ROOTS:
                evals = skill.parent / "evals" / "evals.json"
                triggers = skill.parent / "evals" / "triggers.json"
                if not evals.is_file():
                    errors.append(f"{evals}: missing (https://agentskills.io/skill-creation/evaluating-skills)")
                if not triggers.is_file():
                    errors.append(f"{triggers}: missing (https://agentskills.io/skill-creation/optimizing-descriptions)")
    if not found:
        print("no SKILL.md files found", file=sys.stderr)
        return 2
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"ok: {found} skills match https://agentskills.io/specification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
