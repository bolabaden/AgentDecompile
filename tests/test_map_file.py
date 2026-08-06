"""Tests for map_file.py, ported from the upstream GNU ld map-file parser spec."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.map_file import (
    parse_map_file,
    parse_map_file_addresses,
    resolve_object_path_from_source_file,
)

pytestmark = pytest.mark.unit


def test_parses_sa3_style_map_with_arm_symbols():
    map_content = """
 .text          0x0809947c     0x22f4 asm/character_select.o
                0x0809947c                Task_809947C
                0x0809b758                TaskDestructor_CharacterSelect

 .text          0x0809b770      0x1a0 asm/ings_ings_ings.o
                0x0809b770                CreateIngsIngsIngs
"""
    result = parse_map_file(map_content)

    assert result.get("Task_809947C") == "asm/character_select.o"
    assert result.get("TaskDestructor_CharacterSelect") == "asm/character_select.o"
    assert result.get("CreateIngsIngsIngs") == "asm/ings_ings_ings.o"


def test_parses_af_style_map_with_non_matching_suffixes():
    map_content = """
 .text          0x80060e60      0x3f0 build/src/ac_depart.o
                0x80060e60                ac_depart_init
                0x80060fc0                ac_depart_init.NON_MATCHING
                0x80061180                ac_depart_cleanup
"""
    result = parse_map_file(map_content)

    assert result.get("ac_depart_init") == "build/src/ac_depart.o"
    assert result.get("ac_depart_cleanup") == "build/src/ac_depart.o"


def test_handles_multiple_object_files_across_sections():
    map_content = """
 .text          0x08000000      0x100 asm/main.o
                0x08000000                main_func

 .data          0x08100000      0x200 asm/main.o
                0x08100000                main_data

 .text          0x08001000      0x200 asm/utils.o
                0x08001000                util_func
"""
    result = parse_map_file(map_content)

    assert result.get("main_func") == "asm/main.o"
    assert result.get("util_func") == "asm/utils.o"
    assert "main_data" not in result


def test_returns_none_for_symbols_not_in_the_map():
    map_content = """
 .text          0x08000000      0x100 asm/main.o
                0x08000000                main_func
"""
    result = parse_map_file(map_content)

    assert result.get("nonexistent_func") is None


def test_parse_map_file_handles_empty_input():
    assert parse_map_file("") == {}


def test_stops_associating_symbols_after_a_non_symbol_line():
    map_content = """
 .text          0x08000000      0x100 asm/first.o
                0x08000000                first_func
 *fill*         0x08000100       0x10
                0x08000110                stray_symbol
 .text          0x08000200      0x100 asm/second.o
                0x08000200                second_func
"""
    result = parse_map_file(map_content)

    assert result.get("first_func") == "asm/first.o"
    assert "stray_symbol" not in result
    assert result.get("second_func") == "asm/second.o"


def test_extracts_addresses_from_text_section_symbols():
    map_content = """
 .text          0x08000000      0x100 asm/main.o
                0x08000000                main_func
                0x08000040                second_func

 .text          0x08001000      0x200 asm/utils.o
                0x08001000                util_func
"""
    result = parse_map_file_addresses(map_content)

    assert result.get("main_func") == 0x08000000
    assert result.get("second_func") == 0x08000040
    assert result.get("util_func") == 0x08001000


def test_extracts_addresses_from_alias_definitions():
    map_content = """
                0x08045734                        FUN_08045734 = GameUpdate
                0x0803b074                        FUN_0803b074 = UpdateEntities
"""
    result = parse_map_file_addresses(map_content)

    assert result.get("GameUpdate") == 0x08045734
    assert result.get("UpdateEntities") == 0x0803B074


def test_prefers_text_section_addresses_over_aliases():
    map_content = """
                0x08999999                        FUN_08999999 = GameUpdate

 .text          0x08045700      0x100 src/code.o
                0x08045734                GameUpdate
"""
    result = parse_map_file_addresses(map_content)

    assert result.get("GameUpdate") == 0x08045734


def test_strips_non_matching_suffix_from_addresses():
    map_content = """
 .text          0x80060e60      0x3f0 build/src/ac_depart.o
                0x80060e60                ac_depart_init
                0x80060fc0                ac_depart_init.NON_MATCHING
"""
    result = parse_map_file_addresses(map_content)

    assert result.get("ac_depart_init") == 0x80060E60


def test_parse_map_file_addresses_handles_empty_input():
    assert parse_map_file_addresses("") == {}


def test_ignores_non_text_sections_for_addresses():
    map_content = """
 .data          0x08100000      0x200 asm/main.o
                0x08100000                main_data

 .text          0x08000000      0x100 asm/main.o
                0x08000000                main_func
"""
    result = parse_map_file_addresses(map_content)

    assert "main_data" not in result
    assert result.get("main_func") == 0x08000000


def test_resolve_object_path_from_source_file_same_directory(tmp_path: Path):
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "core.o").write_text("")

    result = resolve_object_path_from_source_file("src/core.c", tmp_path)

    assert result == tmp_path / "src" / "core.o"


def test_resolve_object_path_from_source_file_under_build_dir(tmp_path: Path):
    (tmp_path / "build" / "src").mkdir(parents=True)
    (tmp_path / "build" / "src" / "core.o").write_text("")

    result = resolve_object_path_from_source_file("src/core.c", tmp_path)

    assert result == tmp_path / "build" / "src" / "core.o"


def test_resolve_object_path_from_source_file_returns_none_when_missing(tmp_path: Path):
    result = resolve_object_path_from_source_file("src/missing.c", tmp_path)

    assert result is None
