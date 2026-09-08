"""Single test for recovered source vs machine-code shim.

Ported from kotorxid `kx/realc.py`. Nothing else may re-derive this test.
Real C, compile success, and byte-accuracy are three separate properties.
"""

from __future__ import annotations

import re

SHIM_RE = re.compile(
    r"""
      \bnaked\b
    | (?<!\w)__asm(?:__)?\b
    | \basm\b(?=\s*(?:(?:volatile|goto|inline|__volatile__|__inline__)\s*)*\()
    | \b_emit\b
    | \.byte\b
    | \b(?:KOTOR_NAKED|ASM_NAKED)\b
    | \b(?:KOTOR_ASM_BEGIN|ASM_BEGIN)\b
    | \b(?:KOTOR_ASM_END|ASM_END)\b
    | \b(?:KOTOR_BYTES|ASM_BYTES)\b
    | \bincbin\b
    """,
    re.I | re.X,
)

SYMBOL_ALIAS_RE = re.compile(r'''(?<!\w)(?:__asm__?|asm)\s*\(\s*"(?:\\.|[^"\\])*"\s*\)''')
_RAW_STRING = re.compile(r'(?:u8|u|U|L)?R"([^ ()\\\t\r\n]{0,16})\(')
_CONTROL_PREFIX = re.compile(r'\b(?:if|for|while|switch|return|co_return|else|do|case|goto)\b')


def _mask_non_code(source: str, *, literals: bool = True) -> str:
    """Preserve positions while hiding comments and optionally quoted literals."""
    output: list[str] = []
    copied = 0
    index = 0
    while index < len(source):
        start = index
        comment = False
        if source.startswith('//', index):
            end = source.find('\n', index + 2)
            index = len(source) if end < 0 else end
            comment = True
        elif source.startswith('/*', index):
            end = source.find('*/', index + 2)
            index = len(source) if end < 0 else end + 2
            comment = True
        elif (raw := _RAW_STRING.match(source, index)) is not None:
            delimiter = ')' + raw.group(1) + '"'
            end = source.find(delimiter, raw.end())
            index = len(source) if end < 0 else end + len(delimiter)
        elif source[index] in {'"', "'"}:
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == '\\':
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            index = min(index, len(source))
        else:
            index += 1
            continue
        if comment or literals:
            output.extend((source[copied:start], re.sub(r'[^\n]', ' ', source[start:index])))
            copied = index
    if not output:
        return source
    output.append(source[copied:])
    return ''.join(output)


def _strip_symbol_aliases(source: str) -> str:
    # C/C++ performs backslash-newline splicing before recognizing comments.
    source = re.sub(r'\\\r?\n', '', source)
    commented = _mask_non_code(source, literals=False)
    code = _mask_non_code(source)
    output: list[str] = []
    copied = 0
    for match in SYMBOL_ALIAS_RE.finditer(commented):
        # Ignore matches inside a quoted literal, which remains in commented.
        if not code[match.start():match.start()+3].strip():
            continue
        boundary = max(code.rfind(token, 0, match.start()) for token in ';{}')
        prefix = code[boundary + 1:match.start()].strip()
        prefix = re.sub(r'(?m)^[ \t]*#.*$', '', prefix).strip()
        head = prefix.split('(', 1)[0]
        # A symbol label follows a declaration (type/storage plus declarator).
        # A standalone/basic asm statement, or one after if/while/etc., must
        # not disappear merely because it takes a single string argument.
        declaration = len(re.findall(r'\b[A-Za-z_]\w*\b', head)) >= 2
        if declaration and not _CONTROL_PREFIX.search(prefix) and '=' not in prefix:
            output.extend((code[copied:match.start()], ' ' * (match.end() - match.start())))
            copied = match.end()
    if not output:
        return code
    output.append(code[copied:])
    return ''.join(output)


def is_real_c(source: str | None) -> bool:
    return not SHIM_RE.search(_strip_symbol_aliases(source or ""))


def shim_reason(source: str | None) -> str | None:
    match = SHIM_RE.search(_strip_symbol_aliases(source or ""))
    return match.group(0) if match else None


def is_machine_code_shim(text: str | None) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    return not is_real_c(body)


def is_recovered_source(text: str | None) -> bool:
    body = (text or "").strip()
    if not body:
        return False
    return is_real_c(body)
