"""Emit C from HighFunction / ClangTokenGroup / p-code facts.

Live Ghidra fills :class:`HighFacts`. Tests and the knowledge-db path build
the same structure from a token stream so Python never regex-rewrites printed
C as the semantic layer. Names, templates, destructors, fields, conventions,
and Ghidra pseudo-ops are rewritten from token / p-code metadata before C
leaves this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .normalize_pipeline import NormalizeMode


class TokenKind(str, Enum):
    IDENT = "ident"
    TYPE = "type"
    FIELD = "field"
    OP = "op"
    SYNTAX = "syntax"
    COMMENT = "comment"
    SPACE = "space"
    OTHER = "other"


@dataclass
class TokenFact:
    kind: TokenKind
    text: str
    symbol: str | None = None
    datatype: str | None = None
    field_offset: str | None = None
    calling_convention: str | None = None


@dataclass
class PcodeFact:
    op: str
    out_bytes: int | None = None
    in_bytes: list[int] = field(default_factory=list)
    offset: int | None = None


@dataclass
class HighFacts:
    name: str = ""
    calling_convention: str | None = None
    return_type: str = "void"
    tokens: list[TokenFact] = field(default_factory=list)
    pcode: list[PcodeFact] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    source: str = "tokens"


def _c_name(name: str) -> str:
    return re.sub(r"[^A-Za-z_0-9]", "_", name)


# Identifier glued to `<...>` (Ghidra templates). `i < n` stays two tokens
# because of the spaces. Qualified `A::B` / `A::~A` stay one token.
_COMPLEX = re.compile(
    r"(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*"
    r"(?:<[-A-Za-z0-9_:*\s,]+>)?"
    r"(?:::~?[A-Za-z_]\w*)*"
)
_OPERATOR = re.compile(r"(::)?operator\s*([^\s(]+)")
_QUAL_OPERATOR = re.compile(r"(?:[A-Za-z_]\w*::)+operator\s*([^\s(]+)")
_FIELD_ANON = re.compile(r"field\d+_0x([0-9a-fA-F]+)")
_BARE_DTOR = re.compile(r"~([A-Za-z_]\w*)")
_PSEUDO = re.compile(r"\b(?:CONCAT|SUB|SEXT|ZEXT)\d+\b")
_SPACE = re.compile(r"\s+")
_COMMENT_LINE = re.compile(r"//[^\n]*")
_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_TYPE_HINTS = {
    "int", "void", "char", "short", "long", "float", "double",
    "unsigned", "signed", "const", "struct", "enum", "typedef",
}


def facts_from_tokens(code: str) -> HighFacts:
    """Lexer → token facts. Spelling metadata only; no invented layout."""
    tokens: list[TokenFact] = []
    i = 0
    n = len(code or "")
    saw_thiscall = False
    while i < n:
        if code.startswith("//", i):
            m = _COMMENT_LINE.match(code, i)
            tokens.append(TokenFact(TokenKind.COMMENT, m.group(0) if m else code[i:]))
            i = m.end() if m else n
            continue
        if code.startswith("/*", i):
            m = _COMMENT_BLOCK.match(code, i)
            tokens.append(TokenFact(TokenKind.COMMENT, m.group(0) if m else code[i:]))
            i = m.end() if m else n
            continue
        m = _SPACE.match(code, i)
        if m:
            tokens.append(TokenFact(TokenKind.SPACE, m.group(0)))
            i = m.end()
            continue
        m = _QUAL_OPERATOR.match(code, i) or _OPERATOR.match(code, i)
        if m:
            tokens.append(TokenFact(TokenKind.IDENT, m.group(0), symbol=m.group(0)))
            i = m.end()
            continue
        if code[i] == "~" and (not tokens or tokens[-1].text in "(,;{ \t\n"):
            m = _BARE_DTOR.match(code, i)
            if m:
                tokens.append(TokenFact(TokenKind.IDENT, m.group(0), symbol=m.group(0)))
                i = m.end()
                continue
        m = _COMPLEX.match(code, i)
        if m:
            text = m.group(0)
            if text == "__thiscall":
                saw_thiscall = True
            kind = TokenKind.TYPE if text in _TYPE_HINTS else TokenKind.IDENT
            if _FIELD_ANON.fullmatch(text):
                kind = TokenKind.FIELD
            tokens.append(TokenFact(kind, text, symbol=text))
            i = m.end()
            continue
        tokens.append(
            TokenFact(TokenKind.SYNTAX if code[i] in "(){};,.*&[]=<>!~+-/" else TokenKind.OTHER, code[i])
        )
        i += 1
    facts = HighFacts(tokens=tokens, source="tokens")
    if saw_thiscall:
        facts.calling_convention = "__thiscall"
    return facts


def emit_from_facts(facts: HighFacts, *, mode: NormalizeMode | str) -> str:
    from .normalize_pipeline import NormalizeMode

    resolved = NormalizeMode(mode)
    out: list[str] = []
    i = 0
    tokens = facts.tokens
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind is TokenKind.COMMENT:
            if tok.text.lstrip().startswith("WARNING:"):
                i += 1
                continue
            out.append(tok.text)
            i += 1
            continue
        if tok.kind in (TokenKind.IDENT, TokenKind.TYPE, TokenKind.FIELD):
            if _PSEUDO.fullmatch(tok.text) and resolved is NormalizeMode.SEMANTIC:
                expr, nxt = _emit_pseudo_call(tokens, i, resolved)
                out.append(expr)
                i = nxt
                continue
            if tok.text == "__thiscall" and resolved is NormalizeMode.SEMANTIC:
                out.append("__thiscall")
                i += 1
                continue
            out.append(_emit_ident(tok, facts))
            i += 1
            continue
        out.append(tok.text)
        i += 1
    text = "".join(out)
    text = re.sub(r"^WARNING:.*$", "", text, flags=re.M)
    if resolved is NormalizeMode.COMPILE_ONLY:
        text = _thiscall_to_fastcall(text)
    return text


def _emit_ident(tok: TokenFact, facts: HighFacts) -> str:
    raw = tok.symbol or tok.text
    if tok.kind is TokenKind.FIELD or _FIELD_ANON.fullmatch(raw):
        off = tok.field_offset
        if not off:
            m = _FIELD_ANON.fullmatch(raw)
            off = m.group(1) if m else None
        if off and off in facts.fields:
            return facts.fields[off]
        if off:
            return f"field_{off}"
    if raw.startswith("operator") or "operator" in raw:
        m = _OPERATOR.search(raw)
        if m:
            slug = re.sub(r"[^A-Za-z0-9]+", "_", m.group(2)).strip("_") or "op"
            prefix = m.group(1) or ""
            rest = raw[: m.start()] + f"{prefix}operator_{slug}"
            return _c_name(rest) if "::" in rest else rest
    if raw.startswith("~"):
        return _c_name(raw)
    if "::" in raw or "<" in raw:
        flattened = raw
        while True:
            nxt = re.sub(
                r"([A-Za-z_]\w*)<([-A-Za-z0-9_:*\s,]+)>",
                lambda m: f"{m.group(1)}_{re.sub(r'[^A-Za-z0-9]+', '_', m.group(2)).strip('_')}",
                flattened,
            )
            if nxt == flattened:
                break
            flattened = nxt
        return _c_name(flattened)
    return tok.text


def _thiscall_to_fastcall(text: str) -> str:
    """Compile-only ABI proxy. Semantic mode never adds edx_unused."""
    key = "__thiscall"
    for _ in range(32):
        idx = text.find(key)
        if idx < 0:
            return text
        paren = text.find("(", idx)
        if paren < 0:
            return text[:idx] + "__fastcall" + text[idx + len(key):]
        end = _match_paren(text, paren)
        if end < 0:
            return text[:idx] + "__fastcall" + text[idx + len(key):]
        params = text[paren + 1 : end].strip()
        parts = [p.strip() for p in params.split(",")] if params else []
        if not parts:
            text = text[:idx] + "__fastcall" + text[idx + len(key):]
            continue
        if any("edx_unused" in p for p in parts):
            text = text[:idx] + "__fastcall" + text[idx + len(key):]
            continue
        new_params = ", ".join([parts[0], "int edx_unused"] + parts[1:])
        text = (
            text[:idx]
            + "__fastcall"
            + text[idx + len(key) : paren + 1]
            + new_params
            + text[end:]
        )
    return text.replace("__thiscall", "__fastcall")


def _match_paren(text: str, paren: int) -> int:
    depth = 0
    for i in range(paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _emit_pseudo_call(tokens: list[TokenFact], i: int, mode: Any) -> tuple[str, int]:
    name = tokens[i].text
    j = i + 1
    while j < len(tokens) and tokens[j].kind is TokenKind.SPACE:
        j += 1
    if j >= len(tokens) or tokens[j].text != "(":
        return name, i + 1
    depth = 0
    end = j
    while end < len(tokens):
        if tokens[end].text == "(":
            depth += 1
        elif tokens[end].text == ")":
            depth -= 1
            if depth == 0:
                break
        end += 1
    args_text = "".join(t.text for t in tokens[j + 1 : end])
    args = [a.strip() for a in args_text.split(",") if a.strip()]
    return _expand_pseudo(name, args), end + 1


def _expand_pseudo(name: str, args: list[str]) -> str:
    """C for a Ghidra CONCAT/SUB/ZEXT/SEXT op. Widths come from the op name."""
    if not args:
        return name
    if name.startswith("CONCAT") and len(name) >= 8:
        try:
            x, y = int(name[6]), int(name[7])
        except ValueError:
            return f"{name}({', '.join(args)})"
        a = args[0] if args else "0"
        b = args[1] if len(args) > 1 else "0"
        return (
            f"(({_uint_of(x + y)})(({_uint_of(x)})({a}) << {y * 8}) | "
            f"(({_uint_of(y)})({b})))"
        )
    if name.startswith("SUB") and len(name) >= 5:
        a = args[0]
        off = args[1] if len(args) > 1 else "0"
        return f"(({_uint_of(1)})(({_uint_of(8)})({a}) >> (({off})*8)))"
    if name.startswith("ZEXT") and args:
        return f"(({_uint_of(4)})({args[0]}))"
    if name.startswith("SEXT") and args:
        return f"((int)({args[0]}))"
    return f"{name}({', '.join(args)})"


def _uint_of(nbytes: int) -> str:
    return {
        1: "unsigned char",
        2: "unsigned short",
        3: "unsigned int",
        4: "unsigned int",
        8: "unsigned __int64",
    }.get(nbytes, "unsigned int")


def collect_high_facts(program, function, decompiler, monitor=None) -> HighFacts:
    """Live Ghidra: HighFunction + ClangTokenGroup + p-code + datatypes.

    Returns token facts so emit does not regex the pretty-printer string.
    """
    timeout = 30
    result = decompiler.decompileFunction(function, timeout, monitor)
    if result is None or not result.decompileCompleted():
        raise RuntimeError("decompile did not complete")
    hf = result.getHighFunction()
    markup = result.getCCodeMarkup()
    tokens = _tokens_from_clang_group(markup)
    pcode = _pcode_from_high(hf)
    fields = _fields_from_program(program)
    conv = None
    try:
        spec = function.getCallingConvention()
        conv = spec.getName() if spec is not None else function.getCallingConventionName()
    except Exception:
        conv = None
    ret = "void"
    try:
        sig = function.getSignature()
        if sig is not None and sig.getReturnType() is not None:
            ret = str(sig.getReturnType().getName())
    except Exception:
        pass
    return HighFacts(
        name=str(function.getName()),
        calling_convention=str(conv) if conv else None,
        return_type=ret,
        tokens=tokens,
        pcode=pcode,
        fields=fields,
        source="ghidra",
    )


def _tokens_from_clang_group(group) -> list[TokenFact]:
    tokens: list[TokenFact] = []
    if group is None:
        return tokens
    try:
        iterator = group.tokenIterator(True)
    except Exception:
        return _walk_clang(group, tokens)
    while iterator.hasNext():
        tok = iterator.next()
        tokens.append(_clang_token_fact(tok))
    return tokens or _walk_clang(group, tokens)


def _walk_clang(node, tokens: list[TokenFact]) -> list[TokenFact]:
    try:
        n = node.numChildren()
    except Exception:
        tokens.append(_clang_token_fact(node))
        return tokens
    if n == 0:
        tokens.append(_clang_token_fact(node))
        return tokens
    for i in range(n):
        _walk_clang(node.Child(i), tokens)
    return tokens


def _clang_token_fact(tok) -> TokenFact:
    text = str(tok)
    if hasattr(tok, "getText"):
        try:
            text = str(tok.getText())
        except Exception:
            text = str(tok)
    kind = TokenKind.OTHER
    symbol = None
    datatype = None
    field_offset = None
    try:
        name = type(tok).__name__
        if "Comment" in name:
            kind = TokenKind.COMMENT
        elif "Type" in name:
            kind = TokenKind.TYPE
        elif "Field" in name or "Member" in name:
            kind = TokenKind.FIELD
        elif "Syntax" in name:
            kind = TokenKind.SYNTAX
        elif "Variable" in name or "FuncName" in name:
            kind = TokenKind.IDENT
    except Exception:
        pass
    try:
        hs = tok.getHighSymbol() if hasattr(tok, "getHighSymbol") else None
        if hs is not None:
            symbol = str(hs.getName())
            dt = hs.getDataType()
            if dt is not None:
                datatype = str(dt.getName())
    except Exception:
        pass
    try:
        if hasattr(tok, "getHighVariable"):
            hv = tok.getHighVariable()
            if hv is not None and hv.getDataType() is not None:
                datatype = str(hv.getDataType().getName())
    except Exception:
        pass
    return TokenFact(kind, text, symbol=symbol, datatype=datatype, field_offset=field_offset)


def _pcode_from_high(hf) -> list[PcodeFact]:
    ops: list[PcodeFact] = []
    if hf is None:
        return ops
    try:
        blocks = hf.getPcodeOps()
    except Exception:
        return ops
    while blocks.hasNext():
        op = blocks.next()
        try:
            opc = str(op.getMnemonic())
        except Exception:
            continue
        if opc not in {"PIECE", "SUBPIECE", "INT_ZEXT", "INT_SEXT", "CALLIND", "MULTIEQUAL"}:
            continue
        in_bytes = []
        try:
            for i in range(op.getNumInputs()):
                vn = op.getInput(i)
                if vn is not None and vn.getSize():
                    in_bytes.append(int(vn.getSize()))
        except Exception:
            pass
        out_bytes = None
        try:
            out = op.getOutput()
            if out is not None:
                out_bytes = int(out.getSize())
        except Exception:
            pass
        offset = None
        if opc == "SUBPIECE" and op.getNumInputs() > 1:
            try:
                offset = int(op.getInput(1).getOffset())
            except Exception:
                offset = None
        ops.append(PcodeFact(opc, out_bytes=out_bytes, in_bytes=in_bytes, offset=offset))
    return ops


def _fields_from_program(program) -> dict[str, str]:
    fields: dict[str, str] = {}
    try:
        dtm = program.getDataTypeManager()
        it = dtm.getAllStructures()
        while it.hasNext():
            st = it.next()
            for comp in st.getComponents():
                name = str(comp.getFieldName() or "")
                if name:
                    fields[format(int(comp.getOffset()), "x")] = name
    except Exception:
        return fields
    return fields
