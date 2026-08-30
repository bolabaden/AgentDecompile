"""Tests for ELF toolchain identification: .comment, mangling, and stripped flag."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentdecompile_recovery.inventory import (
    BinaryView,
    elf_comment_strings,
    elf_common_inventory,
    elf_inventory,
    elf_toolchain_from_mangling,
)
from agentdecompile_recovery.targets import TargetIdentity

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "elf"
SAMPLE_ELF = FIXTURES / "sample_i386.elf"

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target(path: Path) -> TargetIdentity:
    return TargetIdentity(
        input_path=path,
        binary_path=path,
        format="elf",
        architecture_hint="x86-64",
        sha256="",
        size=0,
        stable_id="test",
    )


def _fake_sections(comment_data: bytes | None = None) -> list[dict[str, Any]]:
    """Return a minimal sections list, optionally including a .comment section."""
    sections: list[dict[str, Any]] = [
        {
            "index": 0,
            "name": ".text",
            "type": 1,
            "flags": 6,
            "address": 0x1000,
            "offset": 0x100,
            "size": 0x200,
            "link": 0,
            "entrySize": 0,
            "alloc": True,
            "executable": True,
            "writable": False,
        },
    ]
    if comment_data is not None:
        sections.append(
            {
                "index": 1,
                "name": ".comment",
                "type": 1,
                "flags": 0,
                "address": 0,
                "offset": 0,       # caller must place data at offset 0 in view
                "size": len(comment_data),
                "link": 0,
                "entrySize": 0,
                "alloc": False,
                "executable": False,
                "writable": False,
            }
        )
    return sections


def _view_with(data: bytes, tmp_path: Path) -> BinaryView:
    p = tmp_path / "blob.bin"
    p.write_bytes(data)
    return BinaryView(p, data)


def _symbols(names: list[str], table: str = ".dynsym") -> list[dict[str, Any]]:
    return [{"name": n, "value": 0x1000, "size": 4, "bind": 1, "type": 2, "sectionIndex": 1, "table": table} for n in names]


# ---------------------------------------------------------------------------
# elf_comment_strings
# ---------------------------------------------------------------------------

class TestElfCommentStrings:
    def test_no_comment_section(self, tmp_path: Path) -> None:
        view = _view_with(b"\x00" * 16, tmp_path)
        sections: list[dict[str, Any]] = []
        assert elf_comment_strings(view, sections) == []

    def test_reads_single_producer_string(self, tmp_path: Path) -> None:
        comment = b"GCC: (GNU) 9.4.0\x00"
        view = _view_with(comment, tmp_path)
        sections = _fake_sections(comment)
        result = elf_comment_strings(view, sections)
        assert result == ["GCC: (GNU) 9.4.0"]

    def test_reads_multiple_producer_strings(self, tmp_path: Path) -> None:
        comment = b"GCC: (GNU) 4.9.3\x00clang version 14.0.0\x00"
        view = _view_with(comment, tmp_path)
        sections = _fake_sections(comment)
        result = elf_comment_strings(view, sections)
        assert "GCC: (GNU) 4.9.3" in result
        assert "clang version 14.0.0" in result

    def test_empty_comment_section_returns_empty_list(self, tmp_path: Path) -> None:
        view = _view_with(b"\x00" * 16, tmp_path)
        # section with size=0
        sections: list[dict[str, Any]] = [
            {"name": ".comment", "offset": 0, "size": 0}
        ]
        assert elf_comment_strings(view, sections) == []

    def test_all_null_bytes_returns_empty_list(self, tmp_path: Path) -> None:
        comment = b"\x00\x00\x00"
        view = _view_with(comment, tmp_path)
        sections = _fake_sections(comment)
        assert elf_comment_strings(view, sections) == []


# ---------------------------------------------------------------------------
# elf_toolchain_from_mangling
# ---------------------------------------------------------------------------

class TestElfToolchainFromMangling:
    def test_no_symbols(self) -> None:
        result = elf_toolchain_from_mangling([])
        assert result["stdlib"] == "unknown"
        assert result["evidence"] is None

    def test_empty_symbol_names_are_unknown(self) -> None:
        syms = [{"name": ""}, {"name": "main"}, {"name": "printf"}]
        result = elf_toolchain_from_mangling(syms)
        assert result["stdlib"] == "unknown"
        assert result["evidence"] is None

    def test_libcxx_detected(self) -> None:
        syms = [{"name": "_ZNSt3__112basic_stringIcENSaIcEEC1Ev"}]
        result = elf_toolchain_from_mangling(syms)
        assert result["stdlib"] == "libc++"
        assert result["evidence"] is not None
        assert "_ZNSt3__1" in result["evidence"]

    def test_libstdcxx_detected(self) -> None:
        syms = [{"name": "_ZNSt8ios_baseD1Ev"}]
        result = elf_toolchain_from_mangling(syms)
        assert result["stdlib"] == "libstdc++"
        assert result["evidence"] is not None
        assert "_ZNSt" in result["evidence"]

    def test_libstdcxx_not_confused_with_libcxx(self) -> None:
        # _ZNSt3__1 is the distinguishing libc++ marker; plain _ZNSt is libstdc++
        syms = [{"name": "_ZNSt3__16vectorIiNS_9allocatorIiEEEC1Ev"}]
        result = elf_toolchain_from_mangling(syms)
        assert result["stdlib"] == "libc++"

    def test_contradictory_mangling_is_unknown(self) -> None:
        syms = [
            {"name": "_ZNSt3__112basic_stringIcENSaIcEEC1Ev"},
            {"name": "_ZNSt8ios_baseD1Ev"},
        ]
        result = elf_toolchain_from_mangling(syms)
        assert result["stdlib"] == "unknown"
        assert result["evidence"] is None
        assert "note" in result

    def test_returns_first_matching_evidence(self) -> None:
        first_libcxx = "_ZNSt3__112basic_stringIcENSaIcEEC1Ev"
        syms = [{"name": first_libcxx}, {"name": "_ZNSt3__16vectorIiNS_9allocatorIiEEEC1Ev"}]
        result = elf_toolchain_from_mangling(syms)
        assert result["evidence"] == first_libcxx


# ---------------------------------------------------------------------------
# elf_common_inventory — stripped flag
# ---------------------------------------------------------------------------

class TestElfCommonInventoryStripped:
    def _make_inv(
        self,
        tmp_path: Path,
        symbol_names: list[str],
        *,
        has_symtab: bool,
        comment: bytes = b"",
    ) -> dict[str, Any]:
        """Build a minimal inventory result via elf_common_inventory."""
        target = _make_target(tmp_path / "fake.elf")
        view = _view_with(comment or b"\x00" * 16, tmp_path)
        sections = _fake_sections(comment if comment else None)
        if has_symtab:
            sections.append(
                {
                    "index": len(sections),
                    "name": ".symtab",
                    "type": 2,
                    "flags": 0,
                    "address": 0,
                    "offset": 0,
                    "size": 24,
                    "link": 0,
                    "entrySize": 24,
                    "alloc": False,
                    "executable": False,
                    "writable": False,
                }
            )
        syms: list[dict[str, Any]] = _symbols(symbol_names, table=".dynsym")
        if has_symtab:
            syms += _symbols(symbol_names, table=".symtab")
        return elf_common_inventory(target, view, 2, 0x3E, 0, sections, syms)

    def test_not_stripped_when_symtab_present(self, tmp_path: Path) -> None:
        inv = self._make_inv(tmp_path, ["_start"], has_symtab=True)
        assert inv["toolchain"]["stripped"] is False
        assert inv["summary"]["stripped"] is False

    def test_stripped_when_no_symtab(self, tmp_path: Path) -> None:
        inv = self._make_inv(tmp_path, [], has_symtab=False)
        assert inv["toolchain"]["stripped"] is True
        assert inv["summary"]["stripped"] is True

    def test_stripped_elf_mangling_is_unknown(self, tmp_path: Path) -> None:
        inv = self._make_inv(tmp_path, [], has_symtab=False)
        assert inv["toolchain"]["mangling"]["stdlib"] == "unknown"


# ---------------------------------------------------------------------------
# Integration: elf_inventory result shape and toolchain block
# ---------------------------------------------------------------------------

class TestElfInventoryToolchainBlock:
    def test_real_sample_has_toolchain_block(self) -> None:
        p = SAMPLE_ELF
        t = _make_target(p)
        view = BinaryView(p, p.read_bytes())
        inv = elf_inventory(t, view)
        assert "toolchain" in inv
        tc = inv["toolchain"]
        assert "commentStrings" in tc
        assert "mangling" in tc
        assert "stripped" in tc
        assert isinstance(tc["stripped"], bool)
        assert isinstance(tc["commentStrings"], list)
        assert tc["mangling"]["stdlib"] in {"libc++", "libstdc++", "unknown"}

    def test_real_sample_summary_has_stripped(self) -> None:
        p = SAMPLE_ELF
        t = _make_target(p)
        view = BinaryView(p, p.read_bytes())
        inv = elf_inventory(t, view)
        assert "stripped" in inv["summary"]
        assert isinstance(inv["summary"]["stripped"], bool)

    def test_libcxx_elf_identified(self, tmp_path: Path) -> None:
        """elf_common_inventory on Clang/libc++ symbols reports libc++."""
        target = _make_target(tmp_path / "fake.elf")
        view = _view_with(b"clang version 14.0.0\x00", tmp_path)
        comment_data = b"clang version 14.0.0\x00"
        sections = _fake_sections(comment_data)
        sections.append({"index": len(sections), "name": ".symtab", "type": 2, "flags": 0, "address": 0, "offset": 0, "size": 24, "link": 0, "entrySize": 24, "alloc": False, "executable": False, "writable": False})
        syms = _symbols(["_ZNSt3__112basic_stringIcENSaIcEEC1Ev", "_ZNSt3__16vectorIiNS_9allocatorIiEEEC1Ev"], table=".dynsym")
        syms += _symbols(["_ZNSt3__112basic_stringIcENSaIcEEC1Ev"], table=".symtab")
        inv = elf_common_inventory(target, view, 2, 0x3E, 0, sections, syms)
        tc = inv["toolchain"]
        assert tc["mangling"]["stdlib"] == "libc++"
        assert "clang version" in tc["commentStrings"][0]
        assert tc["stripped"] is False

    def test_libstdcxx_elf_identified(self, tmp_path: Path) -> None:
        """elf_common_inventory on GCC/libstdc++ symbols reports libstdc++."""
        target = _make_target(tmp_path / "fake.elf")
        comment_data = b"GCC: (GNU) 9.4.0\x00"
        view = _view_with(comment_data, tmp_path)
        sections = _fake_sections(comment_data)
        sections.append({"index": len(sections), "name": ".symtab", "type": 2, "flags": 0, "address": 0, "offset": 0, "size": 24, "link": 0, "entrySize": 24, "alloc": False, "executable": False, "writable": False})
        syms = _symbols(["_ZNSt8ios_baseD1Ev", "_ZNSt6localeD1Ev"], table=".dynsym")
        syms += _symbols(["_ZNSt8ios_baseD1Ev"], table=".symtab")
        inv = elf_common_inventory(target, view, 2, 0x3E, 0, sections, syms)
        tc = inv["toolchain"]
        assert tc["mangling"]["stdlib"] == "libstdc++"
        assert "GCC: (GNU) 9.4.0" in tc["commentStrings"]
        assert tc["stripped"] is False

    def test_stripped_elf_with_no_symbols_or_comment(self, tmp_path: Path) -> None:
        """Stripped ELF: no .symtab, no .comment, no mangled names -> all unknown."""
        target = _make_target(tmp_path / "fake.elf")
        view = _view_with(b"\x00" * 8, tmp_path)
        sections = _fake_sections(None)
        inv = elf_common_inventory(target, view, 3, 0x3E, 0, sections, [])
        tc = inv["toolchain"]
        assert tc["stripped"] is True
        assert tc["commentStrings"] == []
        assert tc["mangling"]["stdlib"] == "unknown"
        assert inv["summary"]["stripped"] is True
