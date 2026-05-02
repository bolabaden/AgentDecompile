from __future__ import annotations

from collections.abc import MutableMapping

CANONICAL_PREFIX = "AGENT_DECOMPILE_"
COMPACT_PREFIX = "AGENTDECOMPILE_"


def _to_canonical(key: str) -> str:
    if key.startswith(COMPACT_PREFIX):
        return CANONICAL_PREFIX + key[len(COMPACT_PREFIX) :]
    return key


def _to_compact(key: str) -> str:
    if key.startswith(CANONICAL_PREFIX):
        return COMPACT_PREFIX + key[len(CANONICAL_PREFIX) :]
    return key


def sync_agentdecompile_env_aliases(env: MutableMapping[str, str] | None = None) -> int:
    """Mirror AGENT_DECOMPILE_* and AGENTDECOMPILE_* keys to the same value.

    Precedence rule when both are set: AGENT_DECOMPILE_* wins if non-empty.
    """
    target = env if env is not None else __import__("os").environ

    changed = 0
    keys = [k for k in list(target.keys()) if k.startswith(CANONICAL_PREFIX) or k.startswith(COMPACT_PREFIX)]
    seen: set[str] = set()

    for key in keys:
        canonical = _to_canonical(key)
        compact = _to_compact(canonical)
        if canonical in seen:
            continue
        seen.add(canonical)

        canonical_value = target.get(canonical)
        compact_value = target.get(compact)

        if isinstance(canonical_value, str) and canonical_value.strip():
            resolved = canonical_value
        elif isinstance(compact_value, str) and compact_value.strip():
            resolved = compact_value
        elif canonical_value is not None:
            resolved = canonical_value
        elif compact_value is not None:
            resolved = compact_value
        else:
            continue

        if target.get(canonical) != resolved:
            target[canonical] = resolved
            changed += 1
        if target.get(compact) != resolved:
            target[compact] = resolved
            changed += 1

    return changed
