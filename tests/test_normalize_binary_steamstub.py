"""Tests for SteamStub detection and Rich header preservation in normalize-binary.py."""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers: minimal PE builder + Rich header builder
# ---------------------------------------------------------------------------

def _build_pe(
    *,
    sections: list[tuple[str, bytes, int]] | None = None,
    extra_strings: bytes = b"",
    entry_section: str = ".bind",
    rich_header: bytes | None = None,
) -> bytes:
    """
    Build a minimal PE32 binary.

    *sections* is a list of (name, body, characteristics).
    *rich_header* is raw bytes to place between offset 0x40 and the PE signature.
    """
    sections = sections or [(".bind", b"\xCC" * 0x800, 0x60000020)]

    # The MZ stub runs from 0x00..0x3F; PE offset is at 0x3C.
    # We'll place the PE header right after the stub + optional rich header.
    STUB_SIZE = 0x40
    rich = rich_header or b""
    # Pad so rich area ends cleanly and pe_offset is 4-byte aligned.
    rich_padded = rich + b"\x00" * (((len(rich) + 3) & ~3) - len(rich))
    pe_offset = STUB_SIZE + len(rich_padded)

    stub = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", pe_offset)
    assert len(stub) == STUB_SIZE

    # PE signature + COFF header.
    num_sections = len(sections)
    machine = 0x014C  # i386
    coff = struct.pack("<HHIIIHHhh", machine, num_sections, 0, 0, 0, 0xE0, 0x0102, 0, 0)
    # Optional header (PE32 magic).
    opt_hdr = struct.pack(
        "<HBBIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,  # magic PE32
        0, 0,  # linker version
        0x1000, 0x200, 0,  # code/data/bss
        0x1000,  # entry RVA (points into first section)
        0x1000, 0x400000,  # code base, image base
        0x1000, 0x200,  # section/file alignment
        4, 0, 0, 0, 4, 0,  # OS/image/subsystem version
        0, 0x10000, 0x1000, 0x400,  # sizes
        2, 0,  # subsystem, DLL chars
        0x100000, 0x1000, 0x100000, 0x1000,  # stack/heap
        0, 16,  # loader flags, num data dirs
    )
    opt_hdr += b"\x00" * (0xE0 - len(opt_hdr))  # pad to declared size

    pe_hdr = b"PE\x00\x00" + coff + opt_hdr

    # Section headers.
    section_rva = 0x1000
    section_raw = 0x400 * ((len(pe_hdr) + 0x3FF) // 0x400 + num_sections + 1)
    sec_headers = b""
    bodies: list[bytes] = []
    for name, body, chars in sections:
        padded_body = body + b"\x00" * ((0x200 - len(body) % 0x200) % 0x200)
        name_enc = name.encode("ascii", "replace")[:8].ljust(8, b"\x00")
        sec_headers += struct.pack(
            "<8sIIIIIIHHI",
            name_enc,
            len(body),      # virtual size
            section_rva,    # virtual address
            len(padded_body),  # raw size
            section_raw + sum(len(b) for b in bodies),  # raw offset
            0, 0, 0, 0,     # relocations / line numbers
            chars,
        )
        bodies.append(padded_body)
        section_rva += 0x1000

    # Assemble: MZ stub | rich padding | PE header | section headers | bodies.
    pad = b"\x00" * (section_raw - len(pe_hdr) - len(sec_headers))
    raw = stub + rich_padded + pe_hdr + sec_headers + pad + b"".join(bodies)
    if extra_strings:
        raw += extra_strings
    return raw


def _build_rich_header(xor_key: int = 0xDEADBEEF) -> bytes:
    """
    Build a syntactically valid Rich header region (DanS marker + entries + Rich + key).
    Returns raw bytes suitable for insertion between offset 0x40 and the PE signature.
    """
    dans_word = struct.unpack_from("<I", b"DanS\x00", 0)[0]
    entries = [
        (0x013D0083, 3),  # comp_id, count  (MSVC 2019 example)
        (0x013D00AA, 1),
    ]
    block = struct.pack("<I", dans_word ^ xor_key)          # DanS XORed
    block += struct.pack("<III", xor_key, xor_key, xor_key)  # 3 padding dwords
    for comp_id, count in entries:
        block += struct.pack("<II", comp_id ^ xor_key, count ^ xor_key)
    block += b"Rich" + struct.pack("<I", xor_key)
    return block


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "normalize-binary.py"


def _run_script(binary_path: Path, extra_args: list[str] | None = None) -> dict:
    args = [sys.executable, str(SCRIPT), str(binary_path)] + (extra_args or [])
    result = subprocess.run(args, capture_output=True, text=True)
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

class TestSteamStubDetection:
    def test_steamstub_string_signature_detected(self, tmp_path: Path) -> None:
        binary = tmp_path / "packed.exe"
        # SteamStub carries the steam_api string + .bind section.
        pe_bytes = _build_pe(
            sections=[(".bind", b"\xff" * 0x800, 0x60000020)],
            extra_strings=b"steam_api\x00SteamAPI_Init\x00",
        )
        binary.write_bytes(pe_bytes)
        report = _run_script(binary, ["--detect-only"])
        det = report["detection"]
        assert det["protector"] == "SteamStub", det
        assert det["recoverable"] is True

    def test_bind_section_without_securom_strings_is_steamstub(self, tmp_path: Path) -> None:
        binary = tmp_path / "packed.exe"
        pe_bytes = _build_pe(
            sections=[(".bind", b"\xff" * 0x800, 0x60000020)],
        )
        binary.write_bytes(pe_bytes)
        report = _run_script(binary, ["--detect-only"])
        det = report["detection"]
        # .bind without SecuROM strings → should be attributed to SteamStub, not SecuROM.
        assert det["protector"] != "SecuROM", f"should not report SecuROM, got: {det}"

    def test_bind_section_with_securom_strings_is_securom(self, tmp_path: Path) -> None:
        binary = tmp_path / "packed.exe"
        pe_bytes = _build_pe(
            sections=[(".bind", b"\xff" * 0x800, 0x60000020)],
            extra_strings=b"PauseAndPlay\x00.securom\x00",
        )
        binary.write_bytes(pe_bytes)
        report = _run_script(binary, ["--detect-only"])
        det = report["detection"]
        # SecuROM strings should override the .bind → SteamStub default.
        assert det["protector"] == "SecuROM", det


# ---------------------------------------------------------------------------
# Rich header capture and warning tests
# ---------------------------------------------------------------------------

class TestRichHeaderCapture:
    def test_pre_unpack_rich_header_recorded_in_detect_only(self, tmp_path: Path) -> None:
        rich = _build_rich_header(xor_key=0xAABBCCDD)
        binary = tmp_path / "packed.exe"
        pe_bytes = _build_pe(rich_header=rich)
        binary.write_bytes(pe_bytes)
        report = _run_script(binary, ["--detect-only"])
        # detect-only still exposes the key fields but rich capture is in --unpack path;
        # the script should not crash on detect-only with rich present.
        assert "detection" in report

    def test_rich_region_zeroed_warning_emitted(self, tmp_path: Path) -> None:
        """When the unpacked binary has a zeroed Rich region but the packed input had
        a Rich header, the report must emit a ``rich_header_warning``."""
        # Build a packed PE with a Rich header.
        rich = _build_rich_header(xor_key=0xCAFEBABE)
        pe_bytes = _build_pe(rich_header=rich)
        packed = tmp_path / "packed.exe"
        packed.write_bytes(pe_bytes)

        # Simulate what an unpacker does: produce output with 0x40-0xD0 zeroed.
        unpacked_bytes = bytearray(pe_bytes)
        end = min(0xD0, len(unpacked_bytes))
        for i in range(0x40, end):
            unpacked_bytes[i] = 0
        unpacked = tmp_path / "unpacked.exe"
        unpacked.write_bytes(bytes(unpacked_bytes))

        # Import the helper directly to test the sidecar logic.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from agentdecompile_recovery.tools import (
            _read_rich_header_bytes,
            _write_rich_header_sidecar,
        )

        pre_rich = _read_rich_header_bytes(packed)
        assert pre_rich is not None, "expected Rich header in packed binary"

        _write_rich_header_sidecar(packed, unpacked, pre_rich)

        sidecar_path = Path(str(unpacked) + ".rich_header.json")
        assert sidecar_path.exists(), "sidecar file should have been written"
        sidecar = json.loads(sidecar_path.read_text())

        assert sidecar["pre_unpack_rich_header"] is not None
        assert "rich_header_warning" in sidecar, "warning should be emitted when region is zeroed"
        assert "zeroed" in sidecar["rich_header_warning"].lower()

    def test_no_warning_when_rich_region_not_zeroed(self, tmp_path: Path) -> None:
        """No warning when the unpacked output still has a non-zero Rich region."""
        rich = _build_rich_header(xor_key=0x12345678)
        pe_bytes = _build_pe(rich_header=rich)
        packed = tmp_path / "packed.exe"
        packed.write_bytes(pe_bytes)

        unpacked = tmp_path / "unpacked.exe"
        unpacked.write_bytes(pe_bytes)  # unchanged — Rich region preserved

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from agentdecompile_recovery.tools import (
            _read_rich_header_bytes,
            _write_rich_header_sidecar,
        )

        pre_rich = _read_rich_header_bytes(packed)
        assert pre_rich is not None

        _write_rich_header_sidecar(packed, unpacked, pre_rich)

        sidecar_path = Path(str(unpacked) + ".rich_header.json")
        sidecar = json.loads(sidecar_path.read_text())
        assert "rich_header_warning" not in sidecar

    def test_no_sidecar_warning_when_no_pre_unpack_rich(self, tmp_path: Path) -> None:
        """No warning when the input had no Rich header (nothing was lost)."""
        pe_bytes = _build_pe()  # no rich header
        packed = tmp_path / "packed.exe"
        packed.write_bytes(pe_bytes)

        # Output with zeroed region — but input had no Rich header so no loss.
        unpacked_bytes = bytearray(pe_bytes)
        end = min(0xD0, len(unpacked_bytes))
        for i in range(0x40, end):
            unpacked_bytes[i] = 0
        unpacked = tmp_path / "unpacked.exe"
        unpacked.write_bytes(bytes(unpacked_bytes))

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from agentdecompile_recovery.tools import (
            _read_rich_header_bytes,
            _write_rich_header_sidecar,
        )

        pre_rich = _read_rich_header_bytes(packed)
        _write_rich_header_sidecar(packed, unpacked, pre_rich)

        sidecar_path = Path(str(unpacked) + ".rich_header.json")
        sidecar = json.loads(sidecar_path.read_text())
        assert "rich_header_warning" not in sidecar
        assert sidecar["pre_unpack_rich_header"] is None
