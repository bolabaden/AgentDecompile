"""Advisory symbol provenance from ELF DWARF debug info and PE exports/PDB."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from .reconstruct_enrich import analysis_binary_from_work_dir
from .state import atomic_write_json, now

SCHEMA = "agentdecompile.symbol-provenance.v1"
CLAIM_BOUNDARY = (
    "symbol provenance is advisory naming evidence only; "
    "objdiff-verified-semantic accepts under verified/ remain the proof ladder numerator"
)


def _elf_has_dwarf(path: Path) -> bool:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return False
    with path.open("rb") as fh:
        if fh.read(4) != b"\x7fELF":
            return False
        fh.seek(0)
        elf = ELFFile(fh)
        return elf.has_dwarf_info()


def _extract_dwarf_function_names(path: Path) -> list[dict[str, Any]]:
    from elftools.elf.elffile import ELFFile

    rows: list[dict[str, Any]] = []
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            return rows
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            top = cu.get_top_DIE()
            if top is None:
                continue
            for die in top.iter_children():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                low_pc_attr = die.attributes.get("DW_AT_low_pc")
                if name_attr is None or low_pc_attr is None:
                    continue
                try:
                    name = name_attr.value.decode("utf-8", errors="replace") if isinstance(name_attr.value, bytes) else str(name_attr.value)
                    address = int(low_pc_attr.value)
                except (AttributeError, TypeError, ValueError):
                    continue
                if not name.strip():
                    continue
                rows.append(
                    {
                        "address": address,
                        "addressHex": f"0x{address:x}",
                        "name": name.strip(),
                        "source": "dwarf",
                        "authorityClass": "symbol-provenance",
                    }
                )
    rows.sort(key=lambda row: int(row["address"]))
    return rows


def ingest_symbol_provenance(work_dir: Path, *, binary_path: Path | None = None) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    binary = binary_path or analysis_binary_from_work_dir(work_dir)
    out_path = work_dir / "facts" / "symbol-provenance.json"

    if binary is None or not binary.is_file():
        receipt = {
            "schema": SCHEMA,
            "status": "skipped:no-binary",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "symbolCount": 0,
            "symbols": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }
        atomic_write_json(out_path, receipt)
        return receipt

    if binary.suffix.lower() in {".exe", ".dll"} or _looks_like_pe(binary):
        symbols = _extract_pe_symbols(binary)
        if symbols:
            receipt = {
                "schema": SCHEMA,
                "status": "complete",
                "writtenAt": now(),
                "workDir": str(work_dir),
                "binaryPath": str(binary),
                "symbolCount": len(symbols),
                "symbols": symbols[:2000],
                "source": "pdb" if any(row.get("source") == "pdb" for row in symbols) else "pe-export",
                "claimBoundary": CLAIM_BOUNDARY,
            }
            atomic_write_json(out_path, receipt)
            return receipt
        receipt = {
            "schema": SCHEMA,
            "status": "skipped:no-symbols",
            "reason": "pe-no-export-or-pdb",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "binaryPath": str(binary),
            "symbolCount": 0,
            "symbols": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }
        atomic_write_json(out_path, receipt)
        return receipt

    try:
        if not _elf_has_dwarf(binary):
            raise ValueError("no dwarf")
        symbols = _extract_dwarf_function_names(binary)
    except (OSError, ValueError, ImportError) as exc:
        receipt = {
            "schema": SCHEMA,
            "status": "skipped:no-symbols",
            "reason": str(exc),
            "writtenAt": now(),
            "workDir": str(work_dir),
            "binaryPath": str(binary),
            "symbolCount": 0,
            "symbols": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }
        atomic_write_json(out_path, receipt)
        return receipt

    receipt = {
        "schema": SCHEMA,
        "status": "complete" if symbols else "skipped:no-symbols",
        "writtenAt": now(),
        "workDir": str(work_dir),
        "binaryPath": str(binary),
        "symbolCount": len(symbols),
        "symbols": symbols[:2000],
        "claimBoundary": CLAIM_BOUNDARY,
    }
    atomic_write_json(out_path, receipt)
    return receipt


def _looks_like_pe(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def _read_cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _rva_to_offset(pe: bytes, rva: int) -> int | None:
    if len(pe) < 0x40:
        return None
    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe_offset + 0x18 > len(pe):
        return None
    magic = struct.unpack_from("<H", pe, pe_offset + 24)[0]
    if magic == 0x10B:
        num_sections = struct.unpack_from("<H", pe, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from("<H", pe, pe_offset + 20)[0]
        section_table = pe_offset + 24 + opt_header_size
        for index in range(num_sections):
            base = section_table + index * 40
            if base + 40 > len(pe):
                break
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, base + 8)
            if virtual_addr <= rva < virtual_addr + max(virtual_size, raw_size):
                return raw_ptr + (rva - virtual_addr)
    return None


def _extract_pe_export_symbols(path: Path) -> list[dict[str, Any]]:
    try:
        pe = path.read_bytes()
    except OSError:
        return []
    if len(pe) < 0x40 or pe[:2] != b"MZ":
        return []
    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe_offset + 0x80 > len(pe):
        return []
    export_rva = struct.unpack_from("<I", pe, pe_offset + 24 + 96)[0]
    if export_rva == 0:
        return []
    export_offset = _rva_to_offset(pe, export_rva)
    if export_offset is None or export_offset + 40 > len(pe):
        return []
    (
        _characteristics,
        _time_date_stamp,
        _major,
        _minor,
        _name_rva,
        ord_base,
        addr_count,
        name_count,
        addr_table_rva,
        name_ptr_rva,
        ord_table_rva,
    ) = struct.unpack_from("<IIHHIIIIII", pe, export_offset)
    rows: list[dict[str, Any]] = []
    name_table = _rva_to_offset(pe, name_ptr_rva)
    addr_table = _rva_to_offset(pe, addr_table_rva)
    ord_table = _rva_to_offset(pe, ord_table_rva)
    if name_table is None or addr_table is None or ord_table is None:
        return rows
    for index in range(min(int(name_count), 5000)):
        name_rva_offset = name_table + index * 4
        ord_offset = ord_table + index * 2
        if name_rva_offset + 4 > len(pe) or ord_offset + 2 > len(pe):
            break
        name_rva = struct.unpack_from("<I", pe, name_rva_offset)[0]
        ordinal = struct.unpack_from("<H", pe, ord_offset)[0]
        name_offset = _rva_to_offset(pe, name_rva)
        if name_offset is None:
            continue
        name = _read_cstring(pe, name_offset).strip()
        if not name:
            continue
        func_rva_offset = addr_table + ordinal * 4
        if func_rva_offset + 4 > len(pe):
            continue
        func_rva = struct.unpack_from("<I", pe, func_rva_offset)[0]
        if func_rva == 0:
            continue
        rows.append(
            {
                "address": func_rva,
                "addressHex": f"0x{func_rva:x}",
                "name": name,
                "source": "pe-export",
                "authorityClass": "symbol-provenance",
                "ordinal": int(ord_base) + int(ordinal),
            }
        )
    rows.sort(key=lambda row: int(row["address"]))
    return rows


def _extract_pdb_symbols_via_llvm_pdbutil(binary: Path) -> list[dict[str, Any]]:
    tool = shutil.which("llvm-pdbutil")
    if tool is None:
        return []
    pdb_candidates = [
        binary.with_suffix(".pdb"),
        binary.with_name(binary.stem + ".pdb"),
    ]
    pdb_path = next((candidate for candidate in pdb_candidates if candidate.is_file()), None)
    if pdb_path is None:
        return []
    try:
        proc = subprocess.run(
            [tool, "export", "-summary", str(pdb_path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        if "@" not in line or "F " not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[-1]
        addr_token = next((token for token in parts if token.startswith("0x")), "")
        if not name or not addr_token:
            continue
        try:
            address = int(addr_token, 16)
        except ValueError:
            continue
        rows.append(
            {
                "address": address,
                "addressHex": f"0x{address:x}",
                "name": name,
                "source": "pdb",
                "authorityClass": "symbol-provenance",
            }
        )
    return rows


def _extract_pe_symbols(path: Path) -> list[dict[str, Any]]:
    pdb_rows = _extract_pdb_symbols_via_llvm_pdbutil(path)
    if pdb_rows:
        return pdb_rows
    return _extract_pe_export_symbols(path)


def load_symbol_provenance_names(work_dir: Path) -> dict[str, str]:
    """Return entry-hex -> name map from provenance receipt."""

    path = work_dir.resolve() / "facts" / "symbol-provenance.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    names: dict[str, str] = {}
    for row in payload.get("symbols") or []:
        if not isinstance(row, dict):
            continue
        entry_hex = str(row.get("addressHex") or "").lower().replace("0x", "").zfill(8)[-8:]
        name = str(row.get("name") or "").strip()
        if entry_hex and name:
            names[entry_hex] = name
    return names
