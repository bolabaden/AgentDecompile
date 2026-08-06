"""GNU ld map file parser.

Extracts a mapping from function (symbol) names to their containing object
file paths (and, separately, to ROM/linked addresses) by scanning `.text`
section headers and the symbol entries that follow them. Used to resolve
which object file a decomp-permuter/objdiff target lives in for GNU-ld-based
build systems (map paths are relative to the linker's working directory,
which may differ from the project root).
"""

from __future__ import annotations

import re
from pathlib import Path

_SECTION_HEADER_RE = re.compile(r"^\s*\.text\s+0x[\da-f]+\s+0x[\da-f]+\s+(\S+\.o)", re.IGNORECASE)
_SYMBOL_RE = re.compile(r"^\s+0x[\da-f]+\s+(\S+)$")
_SYMBOL_WITH_ADDR_RE = re.compile(r"^\s+0x([\da-f]+)\s+(\S+)$")
_ALIAS_RE = re.compile(r"^\s+0x([\da-f]+)\s+\S+\s*=\s*(\S+)")
_NON_MATCHING_SUFFIX_RE = re.compile(r"\.NON_MATCHING$")


def parse_map_file(content: str) -> dict[str, str]:
    """Parse a GNU ld map file and return a map of symbol name -> relative .o path."""
    result: dict[str, str] = {}
    current_object_file: str | None = None

    for line in content.split("\n"):
        section_match = _SECTION_HEADER_RE.match(line)
        if section_match:
            current_object_file = section_match.group(1)
            continue

        if current_object_file is not None:
            symbol_match = _SYMBOL_RE.match(line)
            if symbol_match:
                symbol_name = _NON_MATCHING_SUFFIX_RE.sub("", symbol_match.group(1))
                result[symbol_name] = current_object_file
            else:
                current_object_file = None

    return result


def resolve_object_path(function_name: str, project_root: Path, symbol_map: dict[str, str]) -> Path | None:
    """Resolve a function name to an absolute object file path using the symbol map."""
    relative_path = symbol_map.get(function_name)
    if not relative_path:
        return None

    direct_path = project_root / relative_path
    if direct_path.is_file():
        return direct_path

    file_name = Path(relative_path).name
    build_dir = project_root / "build"
    if build_dir.is_dir():
        match = next(build_dir.glob(f"**/{file_name}"), None)
        if match is not None:
            return match

    return None


def parse_map_file_addresses(content: str) -> dict[str, int]:
    """Parse a GNU ld map file and return a map of symbol name -> ROM address.

    Extracts addresses from two sources:
    1. Standard `.text` section symbol entries (authoritative -- linked addresses).
    2. Linker-script alias definitions of the form `0x{addr} FUN_xxx = HumanName`
       (fallback for symbols not found in `.text` sections).

    `.text` section entries take priority when a symbol appears in both.
    """
    result: dict[str, int] = {}
    in_text_section = False

    for line in content.split("\n"):
        section_match = _SECTION_HEADER_RE.match(line)
        if section_match:
            in_text_section = True
            continue

        if in_text_section:
            symbol_match = _SYMBOL_WITH_ADDR_RE.match(line)
            if symbol_match:
                address = int(symbol_match.group(1), 16)
                raw_name = symbol_match.group(2)
                name = _NON_MATCHING_SUFFIX_RE.sub("", raw_name)
                # Don't let .NON_MATCHING aliases overwrite the original symbol's address.
                if raw_name == name or name not in result:
                    result[name] = address
            else:
                in_text_section = False

        alias_match = _ALIAS_RE.match(line)
        if alias_match:
            address = int(alias_match.group(1), 16)
            name = alias_match.group(2)
            if name not in result:
                result[name] = address

    return result


def resolve_object_path_from_source_file(c_module_path: str, project_root: Path) -> Path | None:
    """Resolve a C source file path to an absolute object file path.

    Fallback for when a function name isn't in the symbol map (e.g. static
    functions the linker doesn't export). Tries replacing .c -> .o and
    looking for the file directly or under build/.
    """
    obj_relative_path = re.sub(r"\.c$", ".o", c_module_path)

    direct_path = project_root / obj_relative_path
    if direct_path.is_file():
        return direct_path

    file_name = Path(obj_relative_path).name
    build_dir = project_root / "build"
    if build_dir.is_dir():
        match = next(build_dir.glob(f"**/{file_name}"), None)
        if match is not None:
            return match

    return None
