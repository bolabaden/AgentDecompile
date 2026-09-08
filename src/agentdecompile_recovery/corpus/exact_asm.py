"""Generate guaranteed byte-exact C for functions the normal path cannot recover.

Two-tier emitter with verification:

  tier A  readable ``__asm`` mnemonics       (tried first, verified)
  tier B  ``__asm _emit 0x..`` byte stream   (always byte-exact)

Paths are required. There is no product-binary or compile-script default.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile

from .extract import slugify
from .store import connect


def disassemble(data: bytes, bits: int = 32) -> list[tuple[int, bytes, str]]:
    """Return [(offset, bytes, intel_text)] using objdump on a raw blob."""
    try:
        with tempfile.TemporaryDirectory() as td:
            raw = pathlib.Path(td) / "b.bin"
            raw.write_bytes(data)
            arch = "i386" if bits == 32 else "i386:x86-64"
            out = subprocess.run(
                ["objdump", "-D", "-b", "binary", "-m", arch, "-M", "intel", str(raw)],
                capture_output=True,
                text=True,
            ).stdout
    except OSError:
        return []
    rows = []
    for line in out.splitlines():
        if ":\t" not in line:
            continue
        head, _, rest = line.partition(":\t")
        try:
            off = int(head.strip(), 16)
        except ValueError:
            continue
        parts = rest.split("\t")
        hexb = parts[0].strip()
        text = parts[1].strip() if len(parts) > 1 else ""
        try:
            bs = bytes.fromhex(hexb.replace(" ", ""))
        except ValueError:
            continue
        rows.append((off, bs, text))
    return rows


def emit_tier_b(name: str, data: bytes, bits: int = 32) -> str:
    """Byte-stream form. Always exact; annotated with the disassembly when available."""
    lines = [
        "/*",
        f" * {name} — byte-exact recovery via explicit encoding.",
        " *",
        " * Emitted as a byte stream rather than mnemonics because the assembler",
        " * does not reproduce this function's original encodings (x87 encoding",
        " * ambiguity and/or explicit fwait). Disassembly is shown for reference;",
        " * the bytes are authoritative.",
        " *",
    ]
    for off, bs, text in disassemble(data, bits):
        if off >= len(data):
            break
        lines.append(f" *   {off:04x}: {bs.hex():<20} {text}")
    lines += [" */", f'extern "C" __declspec(naked) void {name}(void)', "{", "    __asm {"]
    for off, bs, text in disassemble(data, bits):
        if off >= len(data):
            break
        for b in bs:
            lines.append(f"        _emit 0x{b:02x}")
        lines[-1] += f"    // {off:04x} {text}" if text else ""
    emitted = sum(len(bs) for off, bs, _ in disassemble(data, bits) if off < len(data))
    for b in data[emitted:]:
        lines.append(f"        _emit 0x{b:02x}")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def emit_tier_a(name: str, data: bytes, bits: int = 32) -> str | None:
    """Readable mnemonic form. Returns None if it cannot be expressed."""
    rows = disassemble(data, bits)
    if not rows:
        return None
    body = []
    for off, bs, text in rows:
        if off >= len(data):
            break
        if not text or "(bad)" in text:
            return None
        if any(t in text for t in ("PTR ds:", "rip+", "#", "<")):
            return None
        body.append(
            "        "
            + text.replace("DWORD PTR", "dword ptr")
            .replace("WORD PTR", "word ptr")
            .replace("BYTE PTR", "byte ptr")
            .replace("QWORD PTR", "qword ptr")
            .replace("0x", "0")
        )
    lines = [
        "/*",
        f" * {name} — byte-exact recovery (mnemonic form, verified).",
        " */",
        f'extern "C" __declspec(naked) void {name}(void)',
        "{",
        "    __asm {",
        *body,
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def compile_and_extract(
    src: str,
    name: str,
    *,
    compile_script: pathlib.Path | str | None = None,
) -> bytes | None:
    """Compile a candidate and pull back the function's .text bytes."""
    script = pathlib.Path(compile_script) if compile_script else None
    if script is None or not script.exists():
        return None
    with tempfile.TemporaryDirectory() as td:
        tdp = pathlib.Path(td)
        cpp, obj, binf = tdp / "f.cpp", tdp / "f.obj", tdp / "f.bin"
        cpp.write_text(src)
        subprocess.run([str(script), str(cpp), str(obj)], capture_output=True, text=True)
        if not obj.exists():
            return None
        subprocess.run(
            ["objcopy", "-O", "binary", "--only-section=.text", str(obj), str(binf)],
            capture_output=True,
        )
        return binf.read_bytes() if binf.exists() else None


def generate(
    name: str,
    data: bytes,
    bits: int = 32,
    verify: bool = True,
    *,
    compile_script: pathlib.Path | str | None = None,
) -> tuple[str, str]:
    """Return (source, tier). Prefers readable output, guarantees exactness."""
    if verify and shutil.which("wine") and compile_script:
        a = emit_tier_a(name, data, bits)
        if a:
            got = compile_and_extract(a, name, compile_script=compile_script)
            if got is not None and got[: len(data)] == data:
                return a, "A (mnemonic, verified byte-exact)"
        b = emit_tier_b(name, data, bits)
        got = compile_and_extract(b, name, compile_script=compile_script)
        if got is not None and got[: len(data)] == data:
            return b, "B (byte stream, verified byte-exact)"
        return b, "B (byte stream, UNVERIFIED — compiler unavailable or failed)"
    return emit_tier_b(name, data, bits), "B (byte stream, not verified)"


def bytes_from_store(
    store_path: pathlib.Path | str,
    repo_path: str,
    addr: int,
    *,
    raw_path: pathlib.Path | str,
    mapper=None,
) -> bytes:
    """Pull function bytes from *raw_path* using the store size at *addr*."""
    from .exact_universal import mapper_for

    con = connect(store_path)
    row = con.execute(
        "SELECT f.size, b.slug FROM func f JOIN binary b ON b.id=f.binary_id "
        "WHERE b.repo_path=? AND f.addr=?",
        (repo_path, addr),
    ).fetchone()
    if row is None:
        raise ValueError(f"no such function: {repo_path} @ {addr:#x}")
    raw = pathlib.Path(raw_path).read_bytes()
    va2off = mapper or mapper_for(raw)[0]
    if va2off is None:
        raise ValueError(f"no image mapper for {raw_path}")
    off = va2off(addr)
    if off is None or off + row["size"] > len(raw):
        raise ValueError(f"address {addr:#x} not in {raw_path}")
    return raw[off : off + row["size"]]


def write_source(
    dest: pathlib.Path | str,
    name: str,
    data: bytes,
    *,
    bits: int = 32,
    verify: bool = False,
    compile_script: pathlib.Path | str | None = None,
) -> dict:
    src, tier = generate(name, data, bits, verify=verify, compile_script=compile_script)
    path = pathlib.Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(src)
    return {"out": str(path), "tier": tier, "name": name, "size": len(data), "slug": slugify(name)}
