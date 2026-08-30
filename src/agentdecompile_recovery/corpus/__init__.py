"""Corpus-wide semantic decompilation — AgentDecompile’s main recovery pipeline."""

from .contract import PIPELINE_STAGES, PRIORITIES, SCHEMA
from .ghidra_sanitize import sanitize_body
from .naming import NAME_TIERS, choose_name, is_placeholder_name, resolve_members
from .registry import BinaryEntry, CorpusManifest, add_binary, load_corpus, save_corpus
from .source_claims import is_machine_code_shim, is_recovered_source, is_real_c

__all__ = [
    "PIPELINE_STAGES",
    "PRIORITIES",
    "SCHEMA",
    "NAME_TIERS",
    "BinaryEntry",
    "CorpusManifest",
    "add_binary",
    "choose_name",
    "is_machine_code_shim",
    "is_placeholder_name",
    "is_recovered_source",
    "load_corpus",
    "resolve_members",
    "sanitize_body",
    "save_corpus",
]
