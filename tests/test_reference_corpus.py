"""Unit tests for reference C/C++ corpus parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.reference_corpus import (
    build_corpus,
    parse_header_text,
    unmatched_rtti_classes,
    write_corpus,
)

pytestmark = pytest.mark.unit

SAMPLE_HEADER = """
#ifndef C_AREA_H
#define C_AREA_H

class CExoBase;

class CExampleArea : public CExoBase {
public:
    CExampleArea();
    virtual ~CExampleArea();
    void LoadArea(int nId);
    int GetWidth() const;
    CExoString m_sName;
    int m_nWidth;
private:
    void *m_pInternal;
};

#endif
"""


def test_parse_header_yields_class_methods_fields() -> None:
    classes, err = parse_header_text(SAMPLE_HEADER, relative_path="game/clientcore/include/CExampleArea.h")
    assert err is None
    assert len(classes) == 1
    cls = classes[0]
    assert cls.name == "CExampleArea"
    assert "CExoBase" in cls.base_classes
    assert "LoadArea" in cls.methods
    assert "GetWidth" in cls.methods
    field_names = {f.name for f in cls.fields}
    assert "m_nWidth" in field_names or "m_sName" in field_names


def test_malformed_header_isolated(tmp_path: Path) -> None:
    root = tmp_path / "CODE" / "game"
    root.mkdir(parents=True)
    good = root / "good.h"
    good.write_text(SAMPLE_HEADER, encoding="utf-8")
    bad = root / "bad.h"
    bad.write_text("class Broken { public: void x(", encoding="utf-8")
    corpus = build_corpus(tmp_path)
    assert "CExampleArea" in corpus.classes
    digest1 = corpus.content_digest
    good.write_text(SAMPLE_HEADER + "\n// touch\n", encoding="utf-8")
    corpus2 = build_corpus(tmp_path)
    assert corpus2.content_digest != digest1


def test_write_corpus_receipt(tmp_path: Path) -> None:
    root = tmp_path / "ref" / "CODE" / "libsource"
    root.mkdir(parents=True)
    (root / "CExampleApp.h").write_text(
        "class CExampleApp { public: void Init(); int m_nFlag; };\n",
        encoding="utf-8",
    )
    (root / "exampleapp.cpp").write_text("// stub\n", encoding="utf-8")
    corpus = build_corpus(tmp_path / "ref")
    out = write_corpus(corpus, tmp_path / "out")
    assert out.exists()
    assert (tmp_path / "out" / "reference-corpus-receipt.json").exists()
    assert unmatched_rtti_classes(corpus, ["CExampleApp", "MissingClass"]) == ["MissingClass"]
