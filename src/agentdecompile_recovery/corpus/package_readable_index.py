"""Write the top-level README and VS Code workspace for a readable-source tree.

Kept separate from the generator so the index can be regenerated after a
partial rebuild without re-emitting function bodies. *root* is required.
"""

from __future__ import annotations

import json
from pathlib import Path

README = """# Readable decompiled source

Binaries laid out under original source paths where those are known, with
struct/union/enum layouts in `include/types.h` per binary.

## Open it

```bash
code readable.code-workspace
```

## What each authority tier means

| tier | meaning |
|---|---|
| `verified-byte-exact` | recompiled and matched the shipped bytes. Proof. |
| `advisory-ghidra` | Ghidra decompilation. Readable, **not** verified against anything. |

Every function states its tier in its own header comment, and `MANIFEST.json`
in each binary directory records it machine-readably. The two are never merged
into a single "recovered" number.

## What this is not

These files are **not expected to compile**. Class declarations were never
recovered — only struct layouts.

## Per binary

"""


def _manifest_counts(directory: Path, manifest: dict) -> dict:
    functions = manifest.get("functions")
    if isinstance(functions, list):
        verified = sum(1 for f in functions if (f.get("authority") or "") == "verified-byte-exact")
        advisory = sum(1 for f in functions if (f.get("authority") or "") == "advisory-ghidra")
        return {
            "functions_written": int(manifest.get("functions_written") or len(functions)),
            "verified_byte_exact": int(manifest.get("verified_byte_exact") or verified),
            "advisory_ghidra": int(manifest.get("advisory_ghidra") or advisory),
            "types_exported": int(manifest.get("types_exported") or 0),
            "files": int(manifest.get("files") or len({f.get("source_file") for f in functions})),
        }
    return {
        "functions_written": int(manifest.get("functions_written") or 0),
        "verified_byte_exact": int(manifest.get("verified_byte_exact") or 0),
        "advisory_ghidra": int(manifest.get("advisory_ghidra") or 0),
        "types_exported": int(manifest.get("types_exported") or 0),
        "files": int(manifest.get("files") or 0),
    }


def write_index(root: Path | str) -> dict:
    """Regenerate README + workspace file under *root* (required)."""
    dest = Path(root)
    if not dest.exists():
        raise FileNotFoundError(dest)
    rows, folders = [], []
    for directory in sorted(p for p in dest.iterdir() if p.is_dir()):
        mf = directory / "MANIFEST.json"
        if not mf.exists():
            continue
        counts = _manifest_counts(directory, json.loads(mf.read_text(encoding="utf-8")))
        rows.append(
            f"| `{directory.name}` | {counts['functions_written']:,} | "
            f"{counts['verified_byte_exact']:,} | {counts['advisory_ghidra']:,} | "
            f"{counts['types_exported']:,} | {counts['files']:,} |"
        )
        folders.append({"name": directory.name, "path": directory.name})

    text = README + (
        "| binary | functions | verified byte-exact | advisory | types | files |\n"
        "|---|---:|---:|---:|---:|---:|\n" + "\n".join(rows) + "\n"
    )
    (dest / "README.md").write_text(text, encoding="utf-8")
    workspace = dest / "readable.code-workspace"
    workspace.write_text(
        json.dumps(
            {
                "folders": folders,
                "settings": {
                    "C_Cpp.errorSquiggles": "disabled",
                    "C_Cpp.intelliSenseEngine": "default",
                    "files.associations": {"*.c": "cpp"},
                    "search.exclude": {"**/MANIFEST.json": True},
                },
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    return {"binaries": len(rows), "readme": str(dest / "README.md"), "workspace": str(workspace)}
