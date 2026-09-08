"""Emit one run-results JSON covering every binary that has recovered_function rows.

Stored source classifications are context, not fresh compilation or comparison
receipts. This export never upgrades them to byte verification.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .store import connect

RECOVERED_FUNCTION_DDL = """
CREATE TABLE IF NOT EXISTS recovered_function (
    program TEXT,
    name TEXT,
    addr INTEGER,
    size INTEGER,
    convention TEXT,
    real_c INTEGER,
    logical_id INTEGER,
    path TEXT,
    evidence TEXT,
    machine_code TEXT
)
"""


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))


def match_source(logical_id: int | None, evidence: str | None) -> str:
    if (evidence or "").startswith("seed-validation-byte-exact:"):
        return "recorded-seed-evidence"
    if logical_id:
        return "recorded-source-with-logical-identity"
    return "recorded-source"


def build(con) -> dict:
    con.executescript(RECOVERED_FUNCTION_DDL)
    rows = con.execute("SELECT program, name, addr, size, convention, real_c, logical_id, path, evidence FROM recovered_function ORDER BY program, addr").fetchall()

    now = time.time()
    results = []
    for row in rows:
        real_c = bool(row["real_c"])
        note = "Byte comparison was not performed by this report. Stored source classification does not establish byte identity."
        results.append(
            {
                "promptPath": f"{row['program']}/{row['name']}",
                "functionName": row["name"],
                "success": False,
                "real_c": real_c,
                "compiled": None,
                "byte_exact": None,
                "provenance": {"path": row["path"], "address": row["addr"], "evidence": row["evidence"], "logical_id": row["logical_id"], "claim": "stored source classification"},
                "totalDurationMs": 0,
                "matchSource": match_source(row["logical_id"], row["evidence"]),
                "setupPhase": {
                    "attemptNumber": 1,
                    "success": True,
                    "durationMs": 0,
                    "startTimestamp": None,
                    "pluginResults": [
                        {
                            "pluginId": "get-context",
                            "pluginName": "Get Context",
                            "status": "success",
                            "durationMs": 0,
                            "output": f"source: {row['program']}",
                            "sections": [],
                        }
                    ],
                },
                "attempts": [
                    {
                        "attemptNumber": 1,
                        "success": False,
                        "durationMs": 0,
                        "startTimestamp": None,
                        "pluginResults": [
                            {
                                "pluginId": "byte-compare",
                                "pluginName": "Byte Compare",
                                "status": "skipped",
                                "durationMs": 0,
                                "output": note,
                                "sections": [],
                            },
                            {
                                "pluginId": "real-c-check",
                                "pluginName": "Real C Check",
                                "status": "skipped",
                                "durationMs": 0,
                                "output": ("recorded as assembly-free; source was not rechecked by this report" if real_c else "not recorded as assembly-free source"),
                                "sections": [],
                            },
                        ],
                    }
                ],
                "postMatchPhase": {
                    "attemptNumber": 1,
                    "success": True,
                    "durationMs": 0,
                    "startTimestamp": None,
                    "pluginResults": [
                        {
                            "pluginId": "identity",
                            "pluginName": "Cross-Build Identity",
                            "status": "success" if row["logical_id"] else "skipped",
                            "durationMs": 0,
                            "output": (f"bound to logical function {row['logical_id']}" if row["logical_id"] else "no logical binding recorded; reason not recorded"),
                            "sections": [],
                        }
                    ],
                },
            }
        )

    n = len(results)
    n_real = sum(1 for r in results if r["real_c"])
    per_binary: dict[str, dict] = {}
    for row in con.execute("SELECT program, COUNT(*) n, SUM(real_c) real FROM recovered_function GROUP BY program"):
        per_binary[row["program"]] = {"functions": row["n"], "real_c": row["real"] or 0}

    return {
        "version": 1,
        "timestamp": _iso(now),
        "config": {
            "promptsDir": "recovered_function",
            "maxRetries": 1,
            "stallThreshold": 1,
            "ttftTimeoutMs": 0,
            "compilerScript": "era-exact compiler per binary",
            "getContextScript": "n/a — aggregated report, not a live pipeline run",
            "target": "unknown",
            "model": "aggregated-corpus-record",
        },
        "results": results,
        "summary": {
            "totalPrompts": n,
            "successfulPrompts": 0,
            "successRate": None,
            "recordedRealC": n_real,
            "verifiedInThisReport": 0,
            "byteExact": None,
            "avgAttempts": 0,
            "totalDurationMs": 0,
            "note": (f"{n} stored source records across {len(per_binary)} binaries. {n_real} are classified as real C. This export did not compile source or compare bytes; historical evidence is retained without promoting its claims."),
            "perBinary": per_binary,
        },
    }


def write_report(store_path: Path | str, dest: Path | str) -> dict:
    """Build the report from *store_path* and write it to *dest* (both required)."""
    con = connect(store_path)
    try:
        dump = build(con)
    finally:
        con.close()
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dump), encoding="utf-8")
    dump["out"] = str(path)
    return dump
