"""Compatibility imports for the canonical recovered-source classifier.

Source, compilation and byte verification remain separate claims. Add new
machine-code constructs to ``source_claims`` so all recovery callers agree.
"""

from .source_claims import (
    SHIM_RE,
    SYMBOL_ALIAS_RE,
    _strip_symbol_aliases,
    is_real_c,
    shim_reason,
)

__all__ = ['SHIM_RE', 'SYMBOL_ALIAS_RE', 'is_real_c', 'shim_reason']
