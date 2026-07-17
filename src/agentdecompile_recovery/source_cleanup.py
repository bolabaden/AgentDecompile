"""Proof-preserving source cleanup helpers."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


def portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)


def propose_source_cleanup(
    *,
    source_path: Path,
    out_dir: Path,
    function_fact: dict[str, Any] | None = None,
    verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write a cleaned candidate plus receipt, promoting only with preserved proof."""

    source = source_path.read_text(encoding="utf-8")
    cleaned, replacements, output_suffix = clean_source(source, source_path, function_fact or {})
    formatted, formatting = format_source_text(cleaned, output_suffix)
    lint = lint_source_text(formatted, output_suffix, formatting)
    out_dir.mkdir(parents=True, exist_ok=True)
    cleaned_path = out_dir / f"{source_path.stem}{output_suffix}"
    receipt_path = out_dir / "source-cleanup-receipt.json"
    cleaned_path.write_text(formatted, encoding="utf-8")
    source_hash = sha256_text(source)
    cleaned_hash = sha256_text(formatted)
    proof = verification or {}
    preserved = bool(proof.get("proofPreserved")) and proof.get("verificationTier") and proof.get("acceptanceGate")
    receipt = {
        "schema": "agentdecompile.source-cleanup-receipt.v1",
        "status": "proof-preserved" if preserved else "proposed-unverified",
        "source": portable_path(source_path),
        "cleanedSource": portable_path(cleaned_path),
        "sourceSha256": source_hash,
        "cleanedSourceSha256": cleaned_hash,
        "changed": source_hash != cleaned_hash,
        "replacements": replacements,
        "formatting": formatting,
        "lint": lint,
        "cleanupKind": "masm-byte-emission-to-naked-c" if output_suffix == ".c" and source_path.suffix.lower() == ".asm" else "text-symbol-cleanup",
        "verificationTier": proof.get("verificationTier"),
        "acceptanceGate": proof.get("acceptanceGate"),
        "claimBoundary": "cleaned source is exportable only when verification proof is preserved for the cleaned artifact",
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {**receipt, "receipt": portable_path(receipt_path)}


def cleanup_recovered_source_package(*, package_dir: Path, out_dir: Path) -> dict[str, Any]:
    manifest_path = package_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cleaned_package = out_dir
    functions_dir = cleaned_package / "functions"
    if cleaned_package.exists():
        shutil.rmtree(cleaned_package)
    functions_dir.mkdir(parents=True, exist_ok=True)

    functions: list[dict[str, Any]] = []
    cleanup_rows: list[dict[str, Any]] = []
    converted_to_c = 0
    changed = 0
    formatted_count = 0
    lint_ok = 0
    for item in manifest.get("functions", []):
        if not isinstance(item, dict):
            continue
        source = resolve_package_path(package_dir, item.get("source"))
        metadata = resolve_package_path(package_dir, item.get("metadata"))
        if not source.exists() or not metadata.exists():
            continue
        meta = json.loads(metadata.read_text(encoding="utf-8"))
        cleanup_dir = functions_dir / source.stem
        cleanup = propose_source_cleanup(source_path=source, out_dir=cleanup_dir, function_fact=meta.get("functionFact") if isinstance(meta.get("functionFact"), dict) else meta)
        cleaned_source = Path(str(cleanup["cleanedSource"]))
        cleaned_meta = dict(meta)
        cleaned_meta["source"] = str(cleaned_source)
        cleaned_meta["packagedSource"] = str(cleaned_source)
        cleaned_meta["cleanup"] = cleanup
        if source.suffix.lower() in {".asm", ".s"} and cleaned_source.suffix.lower() == ".c":
            converted_to_c += 1
            cleaned_meta["sourceLanguage"] = "c"
            cleaned_meta["sourceQuality"] = "inline-asm-c"
            cleaned_meta["sourceOrigin"] = "automatic cleanup from pure MASM byte-emission candidate to MSVC naked C _emit source"
            hints = cleaned_meta.get("compilerProfileHints") if isinstance(cleaned_meta.get("compilerProfileHints"), dict) else {}
            cleaned_meta["compilerProfileHints"] = {
                **hints,
                "compiler": "msvc",
                "language": "c",
                "reason": "cleaned MSVC naked C _emit source preserves byte-emission candidate bytes",
            }
        if cleanup.get("changed"):
            changed += 1
        formatting = cleanup.get("formatting") if isinstance(cleanup.get("formatting"), dict) else {}
        if formatting.get("status") == "formatted":
            formatted_count += 1
        lint = cleanup.get("lint") if isinstance(cleanup.get("lint"), dict) else {}
        if lint.get("status") == "ok":
            lint_ok += 1
        target_slice = cleaned_meta.get("targetSlice")
        if isinstance(target_slice, dict):
            copied_slice = copy_slice_to_package(package_dir, target_slice, functions_dir / f"{source.stem}.target.bin")
            if copied_slice is not None:
                cleaned_meta["targetSlice"] = {**target_slice, "packagedBytesPath": str(copied_slice)}
        cleaned_metadata = functions_dir / f"{source.stem}.json"
        cleaned_metadata.write_text(json.dumps(cleaned_meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        functions.append(
            {
                "name": cleaned_meta.get("name") or item.get("name"),
                "address": cleaned_meta.get("address") or item.get("address"),
                "status": cleaned_meta.get("status") or item.get("status"),
                "source": str(cleaned_source),
                "sourceLanguage": cleaned_meta.get("sourceLanguage"),
                "sourceQuality": cleaned_meta.get("sourceQuality"),
                "metadata": str(cleaned_metadata),
                "targetSlice": cleaned_meta.get("targetSlice"),
            }
        )
        cleanup_rows.append(cleanup)

    cleaned_manifest = {
        "schema": "agentdecompile.cleaned-source-package.v1",
        "status": "complete",
        "sourcePackage": portable_path(package_dir),
        "packageDir": portable_path(cleaned_package),
        "functionsDir": portable_path(functions_dir),
        "functionCount": len(functions),
        "changed": changed,
        "convertedToC": converted_to_c,
        "formatted": formatted_count,
        "lintOk": lint_ok,
        "lintFailed": len(functions) - lint_ok,
        "functions": functions,
        "cleanups": cleanup_rows,
        "claimBoundary": "cleaned package sources remain candidates until the cleaned package passes compiler/object/objdiff verification",
    }
    (cleaned_package / "manifest.json").write_text(json.dumps(cleaned_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return cleaned_manifest


def resolve_package_path(package_dir: Path, value: Any) -> Path:
    """Resolve package-relative paths under ``package_dir`` only.

    Absolute paths short-circuit. Relative paths never resolve against CWD.
    """

    path = Path(str(value))
    if path.is_absolute():
        return path
    return package_dir / path


def copy_slice_to_package(package_dir: Path, target_slice: dict[str, Any], destination: Path) -> Path | None:
    source_value = target_slice.get("packagedBytesPath") or target_slice.get("bytesPath")
    if not source_value:
        return None
    source = resolve_package_path(package_dir, source_value)
    if not source.exists():
        return None
    shutil.copy2(source, destination)
    return destination


def clean_source(source: str, source_path: Path, fact: dict[str, Any]) -> tuple[str, list[dict[str, str]], str]:
    suffix = source_path.suffix.lower()
    if suffix in {".asm", ".s"}:
        converted = convert_masm_byte_emission_to_c(source, fact)
        if converted is not None:
            return converted["source"], converted["replacements"], ".c"
    cleaned, replacements = clean_source_text(source, fact)
    return cleaned, replacements, source_path.suffix or ".c"


def clean_source_text(source: str, fact: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    replacements: list[dict[str, str]] = []
    cleaned = source
    locals_ = fact.get("locals") if isinstance(fact.get("locals"), list) else []
    for item in locals_:
        if not isinstance(item, dict):
            continue
        name = sanitize_identifier(item.get("name"))
        slot = sanitize_identifier(item.get("slot") or item.get("originalName"))
        if not name or not slot or name == slot:
            continue
        pattern = re.compile(rf"\b{re.escape(slot)}\b")
        if not pattern.search(cleaned):
            continue
        cleaned = pattern.sub(name, cleaned)
        replacements.append({"from": slot, "to": name, "reason": "agentdecompile-local-name"})
    constants = fact.get("constants") if isinstance(fact.get("constants"), list) else []
    for item in constants:
        if not isinstance(item, dict):
            continue
        name = sanitize_identifier(item.get("name"))
        value = str(item.get("value") or "").strip()
        if not name or not value:
            continue
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(value)}(?![A-Za-z0-9_])")
        if not pattern.search(cleaned):
            continue
        cleaned = pattern.sub(name, cleaned)
        replacements.append({"from": value, "to": name, "reason": "agentdecompile-named-constant"})
    return cleaned, replacements


def format_source_text(source: str, suffix: str) -> tuple[str, dict[str, Any]]:
    if suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
        return source, {
            "schema": "agentdecompile.source-formatting.v1",
            "status": "skipped",
            "reason": "unsupported-source-suffix",
            "tool": "clang-format",
        }
    tool = shutil.which("clang-format")
    if not tool:
        return source, {
            "schema": "agentdecompile.source-formatting.v1",
            "status": "unavailable",
            "tool": "clang-format",
            "reason": "clang-format not found on PATH",
        }
    style = "{BasedOnStyle: LLVM, ColumnLimit: 100}"
    try:
        proc = subprocess.run(
            [tool, f"--style={style}"],
            input=source,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return source, {
            "schema": "agentdecompile.source-formatting.v1",
            "status": "failed",
            "tool": tool,
            "reason": "clang-format timed out",
        }
    if proc.returncode != 0:
        return source, {
            "schema": "agentdecompile.source-formatting.v1",
            "status": "failed",
            "tool": tool,
            "returnCode": proc.returncode,
            "stderr": proc.stderr[-2000:],
        }
    formatted = ensure_final_newline(proc.stdout)
    return formatted, {
        "schema": "agentdecompile.source-formatting.v1",
        "status": "formatted",
        "tool": tool,
        "style": style,
        "changed": formatted != source,
        "sourceSha256BeforeFormat": sha256_text(source),
        "sourceSha256AfterFormat": sha256_text(formatted),
        "claimBoundary": "formatting is source hygiene only; byte/source parity must be reverified after formatting",
    }


def lint_source_text(source: str, suffix: str, formatting: dict[str, Any]) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()
    for index, line in enumerate(lines, start=1):
        if line.rstrip(" \t") != line:
            issues.append({"line": index, "kind": "trailing-whitespace"})
        if "\t" in line:
            issues.append({"line": index, "kind": "tab-character"})
        if len(line) > 120:
            issues.append({"line": index, "kind": "line-too-long", "length": len(line)})
    if source and not source.endswith("\n"):
        issues.append({"kind": "missing-final-newline"})
    idempotence = clang_format_idempotence(source, suffix) if formatting.get("status") == "formatted" else {"status": "not-run"}
    if idempotence.get("status") not in {"ok", "not-run"}:
        issues.append({"kind": "formatter-not-idempotent", "status": idempotence.get("status")})
    return {
        "schema": "agentdecompile.source-lint.v1",
        "status": "ok" if not issues else "failed",
        "checks": ["final-newline", "no-trailing-whitespace", "no-tabs", "line-length-120", "clang-format-idempotent"],
        "issueCount": len(issues),
        "issues": issues[:50],
        "issuesTruncated": len(issues) > 50,
        "formatterIdempotence": idempotence,
        "claimBoundary": "lint success is source hygiene only; it is not semantic decompilation proof",
    }


def clang_format_idempotence(source: str, suffix: str) -> dict[str, Any]:
    if suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
        return {"status": "not-run", "reason": "unsupported-source-suffix"}
    tool = shutil.which("clang-format")
    if not tool:
        return {"status": "not-run", "reason": "clang-format unavailable"}
    style = "{BasedOnStyle: LLVM, ColumnLimit: 100}"
    try:
        proc = subprocess.run(
            [tool, f"--style={style}"],
            input=source,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "clang-format timed out"}
    if proc.returncode != 0:
        return {"status": "failed", "returnCode": proc.returncode, "stderr": proc.stderr[-1000:]}
    reformatted = ensure_final_newline(proc.stdout)
    return {
        "status": "ok" if reformatted == source else "changed-on-second-pass",
        "tool": tool,
        "style": style,
        "sha256": sha256_text(reformatted),
    }


def ensure_final_newline(source: str) -> str:
    return source if source.endswith("\n") else source + "\n"


def convert_masm_byte_emission_to_c(source: str, fact: dict[str, Any]) -> dict[str, Any] | None:
    lines = source.splitlines()
    symbol = masm_symbol(lines) or gas_symbol(lines)
    if not symbol:
        return None
    bytes_ = masm_db_bytes(lines) or gas_byte_values(lines)
    if not bytes_:
        return None
    if has_non_byte_emission(lines):
        return None
    c_name = c_identifier_for_symbol(symbol, fact)
    if not c_name:
        return None
    emit_lines = [f"        _emit 0x{value:02x}" for value in bytes_]
    c_source = "\n".join(
        [
            "/* Automatically converted from a pure MASM byte-emission candidate.",
            " * This is still a byte-authoritative cleanup artifact, not high-level semantic C.",
            " * Export requires the cleaned C to pass the same compiler/object comparison gate.",
            " */",
            f"__declspec(naked) void {c_name}(void)",
            "{",
            "    __asm {",
            *emit_lines,
            "    }",
            "}",
            "",
        ]
    )
    return {
        "source": c_source,
        "replacements": [
            {
                "from": symbol,
                "to": c_name,
                "reason": "masm-byte-emission-to-msvc-naked-c",
            }
        ],
    }


def masm_symbol(lines: list[str]) -> str | None:
    for line in lines:
        match = re.match(r"^\s*PUBLIC\s+([A-Za-z_.$?@][A-Za-z0-9_.$?@]*)\s*$", line, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    for line in lines:
        match = re.match(r"^\s*([A-Za-z_.$?@][A-Za-z0-9_.$?@]*)\s+PROC\b", line, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def masm_db_bytes(lines: list[str]) -> list[int]:
    values: list[int] = []
    for line in lines:
        content = line.split(";", 1)[0].strip()
        if not re.match(r"^DB\b", content, flags=re.IGNORECASE):
            continue
        for token in content[2:].split(","):
            byte = parse_masm_byte(token.strip())
            if byte is None:
                return []
            values.append(byte)
    return values


def parse_masm_byte(token: str) -> int | None:
    if not token:
        return None
    text = token.lower()
    try:
        if text.endswith("h"):
            value = int(text[:-1], 16)
        elif text.startswith("0x"):
            value = int(text, 16)
        else:
            value = int(text, 10)
    except ValueError:
        return None
    if 0 <= value <= 0xFF:
        return value
    return None


def gas_symbol(lines: list[str]) -> str | None:
    for line in lines:
        match = re.match(r"^\s*\.globl\s+([A-Za-z_.$?@][A-Za-z0-9_.$?@]*)\s*$", line)
        if match:
            return match.group(1)
    for line in lines:
        match = re.match(r"^\s*([A-Za-z_.$?@][A-Za-z0-9_.$?@]*):\s*$", line)
        if match:
            return match.group(1)
    return None


def gas_byte_values(lines: list[str]) -> list[int]:
    values: list[int] = []
    for line in lines:
        content = line.split(";", 1)[0].strip()
        if not content.startswith(".byte"):
            continue
        for token in content[5:].split(","):
            byte = parse_masm_byte(token.strip())
            if byte is None:
                return []
            values.append(byte)
    return values


def has_non_byte_emission(lines: list[str]) -> bool:
    if any(re.search(r"\bPROC\b", line, flags=re.IGNORECASE) for line in lines):
        return has_non_byte_emission_in_masm_proc(lines)
    return has_non_byte_emission_in_gas_function(lines)


def has_non_byte_emission_in_masm_proc(lines: list[str]) -> bool:
    in_proc = False
    for line in lines:
        content = line.split(";", 1)[0].strip()
        if not content:
            continue
        if re.search(r"\bPROC\b", content, flags=re.IGNORECASE):
            in_proc = True
            continue
        if re.search(r"\bENDP\b", content, flags=re.IGNORECASE):
            in_proc = False
            continue
        if not in_proc:
            continue
        if re.match(r"^DB\b", content, flags=re.IGNORECASE):
            continue
        return True
    return False


def has_non_byte_emission_in_gas_function(lines: list[str]) -> bool:
    in_function = False
    for line in lines:
        content = line.split(";", 1)[0].strip()
        if not content:
            continue
        if content.startswith(("/*", "*", "*/")):
            continue
        if re.match(r"^[A-Za-z_.$?@][A-Za-z0-9_.$?@]*:\s*$", content):
            in_function = True
            continue
        if not in_function:
            if content.startswith((".text", ".globl", ".type")):
                continue
            return True
        if content.startswith(".byte"):
            continue
        if content.startswith((".size", ".section")):
            continue
        return True
    return False


def c_identifier_for_symbol(symbol: str, fact: dict[str, Any]) -> str | None:
    preferred = sanitize_identifier(fact.get("name"))
    if preferred:
        return preferred
    name = symbol
    if name.startswith("_"):
        name = name[1:]
    name = name.split("@", 1)[0]
    name = re.sub(r"\W+", "_", name).strip("_")
    return sanitize_identifier(name)


def sanitize_identifier(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text):
        return None
    return text


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
