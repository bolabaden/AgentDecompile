"""Discover and load prompts from a prompts directory.

Ports the upstream prompt-loader: each prompt lives in its own folder with a
`prompt.md` (content) and `settings.yaml` (functionName/targetObjectPath/asm
metadata). This is the loader for that folder convention specifically --
decomp_atlas.py separately scans a `case.yaml` convention for its own
(retrieval-only) purpose; the two are independent, not competing.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class PromptLoadError(Exception):
    def __init__(self, prompt_path: str, message: str) -> None:
        super().__init__(f"Error loading prompt '{prompt_path}': {message}")
        self.prompt_path = prompt_path
        self.reason = message


@dataclass
class PromptInfo:
    path: str
    content: str
    function_name: str
    target_object_path: str
    asm: str


def _parse_settings_yaml(text: str) -> dict[str, str]:
    """Parse the minimal subset of YAML settings.yaml actually uses.

    Same minimal-parser approach as decomp_atlas.parse_simple_case_yaml:
    flat `key: value` pairs plus a `key: |` block-scalar for multi-line
    values (used here for `asm`). Good enough for a hand-authored settings
    file; not a general YAML parser.
    """
    values: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        if not raw_line or raw_line[0].isspace() or ":" not in raw_line:
            i += 1
            continue
        key, _, rest = raw_line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest == "|":
            block_lines: list[str] = []
            i += 1
            while i < len(lines) and (lines[i].startswith("  ") or lines[i].strip() == ""):
                block_lines.append(lines[i][2:] if lines[i].startswith("  ") else "")
                i += 1
            values[key] = "\n".join(block_lines).rstrip("\n")
            continue
        if rest.startswith(("'", '"')) and rest.endswith(("'", '"')) and len(rest) >= 2:
            rest = rest[1:-1]
        values[key] = rest
        i += 1
    return values


def _load_prompt_from_dir(prompts_dir: Path, dir_name: str) -> PromptInfo:
    prompt_dir = prompts_dir / dir_name
    prompt_md_path = prompt_dir / "prompt.md"
    settings_path = prompt_dir / "settings.yaml"

    if not prompt_md_path.is_file():
        raise PromptLoadError(dir_name, "Missing prompt.md file")
    if not settings_path.is_file():
        raise PromptLoadError(dir_name, "Missing settings.yaml file")

    content = prompt_md_path.read_text(encoding="utf-8")

    try:
        settings = _parse_settings_yaml(settings_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PromptLoadError(dir_name, f"Invalid settings.yaml: {exc}") from exc

    function_name = settings.get("functionName")
    target_object_path = settings.get("targetObjectPath")
    asm = settings.get("asm", "")
    if not function_name:
        raise PromptLoadError(dir_name, "settings.yaml missing functionName")
    if not target_object_path:
        raise PromptLoadError(dir_name, "settings.yaml missing targetObjectPath")

    target_path = Path(target_object_path)
    if not target_path.is_file():
        raise PromptLoadError(dir_name, f"Target object file not found: {target_object_path}")

    try:
        completed = subprocess.run(
            ["nm", str(target_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PromptLoadError(dir_name, f"Failed to run nm on object file: {exc}") from exc

    symbols = {
        fields[-1]
        for line in completed.stdout.splitlines()
        if (fields := line.strip().split())
    }
    # Mach-O (and some other ABIs) prefix C symbols with '_'. Accept both.
    if function_name not in symbols and f"_{function_name}" not in symbols:
        raise PromptLoadError(
            dir_name, f"Function '{function_name}' not found in object file: {target_object_path}"
        )

    return PromptInfo(
        path=dir_name,
        content=content,
        function_name=function_name,
        target_object_path=target_object_path,
        asm=asm,
    )


def load_prompts(prompts_dir: Path) -> tuple[list[PromptInfo], list[PromptLoadError]]:
    """Load all prompts from a directory.

    Each subdirectory of `prompts_dir` must contain `prompt.md` and
    `settings.yaml`. Directories that fail to load are reported as errors
    rather than aborting the whole scan.
    """
    prompt_dirs = sorted(p.name for p in prompts_dir.iterdir() if p.is_dir())

    prompts: list[PromptInfo] = []
    errors: list[PromptLoadError] = []

    for dir_name in prompt_dirs:
        try:
            prompts.append(_load_prompt_from_dir(prompts_dir, dir_name))
        except PromptLoadError as exc:
            errors.append(exc)

    return prompts, errors
