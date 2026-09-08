from __future__ import annotations

import sqlite3

from agentdecompile_recovery.corpus.match import status_for
from agentdecompile_recovery.corpus.propagate import downgrade_named_conflicts, reclassify_existing


def test_independent_canonical_name_conflict_cannot_be_auto() -> None:
    status = status_for(
        score=0.99,
        margin=0.20,
        pair_class="cross_format",
        content=2,
        canonical_name_conflict=True,
    )
    assert status == "verify"


def test_auto_status_is_unchanged_without_a_name_conflict() -> None:
    status = status_for(
        score=0.99,
        margin=0.20,
        pair_class="cross_format",
        content=2,
    )
    assert status == "auto"


def test_compunit_disagreement_vetoes_auto() -> None:
    assert status_for(0.99, 0.20, "same_platform", 2, compunit=0.0) == "review"


def test_existing_auto_rows_with_conflicting_names_are_downgraded() -> None:
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE func (binary_id INTEGER, addr INTEGER, canon_key TEXT);
        CREATE TABLE match (
            id INTEGER PRIMARY KEY, run TEXT,
            src_binary INTEGER, src_addr INTEGER,
            dst_binary INTEGER, dst_addr INTEGER, status TEXT
        );
        INSERT INTO func VALUES
            (1, 10, 'CSWCCreature::ForceAppearanceUpdate'),
            (2, 20, 'CSWCCreature::ResetAnimationState'),
            (1, 11, 'Same::Method'),
            (2, 21, 'Same::Method'),
            (1, 12, 'Named::Source'),
            (2, 22, NULL);
        INSERT INTO match VALUES
            (1, 'v1', 1, 10, 2, 20, 'auto'),
            (2, 'v1', 1, 11, 2, 21, 'auto'),
            (3, 'v1', 1, 12, 2, 22, 'auto');
        """
    )
    changed = downgrade_named_conflicts(con, "v1")
    assert changed == 1
    assert con.execute("SELECT id, status FROM match ORDER BY id").fetchall() == [
        (1, "verify"),
        (2, "auto"),
        (3, "auto"),
    ]


def test_reclassification_rolls_back_status_when_identity_rebuild_fails() -> None:
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE func (binary_id INTEGER, addr INTEGER, canon_key TEXT);
        CREATE TABLE match (
            id INTEGER PRIMARY KEY, run TEXT,
            src_binary INTEGER, src_addr INTEGER,
            dst_binary INTEGER, dst_addr INTEGER, score REAL, status TEXT, evidence TEXT
        );
        INSERT INTO func VALUES (1, 10, 'C::First'), (2, 20, 'C::Second');
        INSERT INTO match VALUES (1, 'v1', 1, 10, 2, 20, 0.99, 'auto', '{}');
        """
    )
    with pytest.raises(sqlite3.OperationalError):
        reclassify_existing(con, "v1")
    assert con.execute("SELECT status FROM match WHERE id=1").fetchone()[0] == "auto"
