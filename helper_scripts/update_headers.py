#!/usr/bin/env python3
"""Patch selected `kotor_save_load` headers/sources with known struct/list additions.

This helper is intentionally parameterized so you can target a different tree,
choose specific patches, and preview changes without writing.

Examples:
  python helper_scripts/update_headers.py
  python helper_scripts/update_headers.py --base kotor_save_load --only store,encounter-header
  python helper_scripts/update_headers.py --dry-run --verbose
"""

from __future__ import annotations

import argparse
import sys

from dataclasses import dataclass
from pathlib import Path


@dataclass
class PatchResult:
    name: str
    applied: bool
    detail: str


def _replace_once(text: str, old: str, new: str) -> tuple[str, bool]:
    if old not in text:
        return text, False
    return text.replace(old, new, 1), True


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def patch_store_header(base: Path, *, dry_run: bool) -> PatchResult:
    target = base / "csws_store.h"
    if not target.exists():
        return PatchResult("store", False, f"missing file: {target}")

    content = _read(target)
    marker = "    // 4 shop inventory lists"
    if marker not in content:
        return PatchResult("store", False, "marker not found")

    snippet = (
        "    // Inventory management\n"
        "    struct StoreItem {\n"
        "        DWORD m_dwObjectId;\n"
        "        CResRef m_refInventory;\n"
        "        BYTE m_bInfinite;\n"
        "    };\n"
        "    StoreItem* m_pInventory;\n"
        "    DWORD m_nInventoryCount;"
    )

    if snippet in content:
        return PatchResult("store", True, "already present")

    updated = content.replace(marker, f"{snippet}\n{marker}")
    if not dry_run:
        _write(target, updated)
    return PatchResult("store", True, "inserted inventory struct block")


def patch_encounter_header(base: Path, *, dry_run: bool) -> PatchResult:
    target = base / "csws_encounter.h"
    if not target.exists():
        return PatchResult("encounter-header", False, f"missing file: {target}")

    content = _read(target)
    insert_after = "// SpawnPointList"
    if insert_after not in content:
        return PatchResult("encounter-header", False, "insertion marker not found")

    snippet = (
        "    // Geometry polygon (encounter boundary)\n"
        "    struct GeometryPoint {\n"
        "        FLOAT m_fX;\n"
        "        FLOAT m_fY;\n"
        "        FLOAT m_fZ;\n"
        "    };\n"
        "    GeometryPoint* m_pGeometry;\n"
        "    DWORD m_nGeometryCount;\n\n"
        "    // Creature spawn templates\n"
        "    struct EncounterCreature {\n"
        "        CResRef m_refResRef;\n"
        "        FLOAT m_fCR;\n"
        "        BYTE m_bSingleSpawn;\n"
        "    };\n"
        "    EncounterCreature* m_pCreatures;\n"
        "    DWORD m_nCreatureCount;\n\n"
        "    // Spawn points\n"
        "    struct SpawnPoint {\n"
        "        FLOAT m_fX;\n"
        "        FLOAT m_fY;\n"
        "        FLOAT m_fZ;\n"
        "        FLOAT m_fOrientation;\n"
        "    };\n"
        "    SpawnPoint* m_pSpawnPoints;\n"
        "    DWORD m_nSpawnPointCount;\n\n"
        "    // Runtime tracking lists\n"
        "    DWORD* m_pAreaList;\n"
        "    DWORD m_nAreaListSize;\n"
        "    struct SpawnEntry {\n"
        "        CResRef m_refResRef;\n"
        "        FLOAT m_fCR;\n"
        "    };\n"
        "    SpawnEntry* m_pSpawnList;\n"
        "    DWORD m_nSpawnListSize;\n"
    )

    if "GeometryPoint* m_pGeometry;" in content and "SpawnEntry* m_pSpawnList;" in content:
        return PatchResult("encounter-header", True, "already present")

    lines = content.splitlines(keepends=True)
    idx = next((i for i, line in enumerate(lines) if insert_after in line), -1)
    if idx < 0:
        return PatchResult("encounter-header", False, "insertion marker not found in lines")

    lines.insert(idx + 1, snippet + "\n")
    if not dry_run:
        _write(target, "".join(lines))
    return PatchResult("encounter-header", True, "inserted encounter list blocks")


def patch_encounter_cpp(base: Path, *, dry_run: bool) -> PatchResult:
    target = base / "csws_encounter.cpp"
    if not target.exists():
        return PatchResult("encounter-cpp", False, f"missing file: {target}")

    content = _read(target)

    replacements: list[tuple[str, str]] = [
        (
            """    // Geometry polygon (vertex list)\n    {\n        CResList geoList = pGFF->AddList(pStruct, \"Geometry\");\n        // Each element: PointX:FLOAT, PointY:FLOAT, PointZ:FLOAT\n    }""",
            """    // Geometry polygon (encounter boundary vertices)\n    {\n        CResList geoList = pGFF->AddList(pStruct, \"Geometry\");\n        if (m_pGeometry && m_nGeometryCount > 0) {\n            for (DWORD i = 0; i < m_nGeometryCount; i++) {\n                CResStruct pointStruct;\n                pGFF->AddListElement(&pointStruct, geoList, 0);\n                pGFF->WriteFieldFLOAT(&pointStruct, m_pGeometry[i].m_fX, \"X\");\n                pGFF->WriteFieldFLOAT(&pointStruct, m_pGeometry[i].m_fY, \"Y\");\n                pGFF->WriteFieldFLOAT(&pointStruct, m_pGeometry[i].m_fZ, \"Z\");\n            }\n        }\n    }""",
        ),
        (
            """    // Creature template list\n    {\n        CResList creatureList = pGFF->AddList(pStruct, \"CreatureList\");\n        // Each element: ResRef:CResRef, GuaranteedCount:INT, SingleSpawn:BYTE\n    }""",
            """    // Creature template list (spawn templates)\n    {\n        CResList creatureList = pGFF->AddList(pStruct, \"CreatureList\");\n        if (m_pCreatures && m_nCreatureCount > 0) {\n            for (DWORD i = 0; i < m_nCreatureCount; i++) {\n                CResStruct elem;\n                pGFF->AddListElement(&elem, creatureList, 0);\n                pGFF->WriteFieldCResRef(&elem, m_pCreatures[i].m_refResRef, \"ResRef\");\n                pGFF->WriteFieldFLOAT(&elem, m_pCreatures[i].m_fCR, \"CR\");\n                pGFF->WriteFieldBYTE(&elem, m_pCreatures[i].m_bSingleSpawn, \"SingleSpawn\");\n            }\n        }\n    }""",
        ),
        (
            """    // Spawn point list\n    {\n        CResList spawnList = pGFF->AddList(pStruct, \"SpawnPointList\");\n        // Each element: X:FLOAT, Y:FLOAT, Z:FLOAT, Orientation:FLOAT\n    }""",
            """    // Spawn point list (actual spawn locations)\n    {\n        CResList spawnList = pGFF->AddList(pStruct, \"SpawnPointList\");\n        if (m_pSpawnPoints && m_nSpawnPointCount > 0) {\n            for (DWORD i = 0; i < m_nSpawnPointCount; i++) {\n                CResStruct elem;\n                pGFF->AddListElement(&elem, spawnList, 0);\n                pGFF->WriteFieldFLOAT(&elem, m_pSpawnPoints[i].m_fX, \"X\");\n                pGFF->WriteFieldFLOAT(&elem, m_pSpawnPoints[i].m_fY, \"Y\");\n                pGFF->WriteFieldFLOAT(&elem, m_pSpawnPoints[i].m_fZ, \"Z\");\n                pGFF->WriteFieldFLOAT(&elem, m_pSpawnPoints[i].m_fOrientation, \"Orientation\");\n            }\n        }\n    }""",
        ),
        (
            """    // Additional area/spawn tracking lists observed in SaveEncounter\n    {\n        CResList areaList = pGFF->AddList(pStruct, \"AreaList\");\n        (void)areaList;\n        // Element field: AreaObject : DWORD\n    }\n    {\n        CResList spawnResList = pGFF->AddList(pStruct, \"SpawnList\");\n        (void)spawnResList;\n        // Element fields: SpawnResRef : CResRef, SpawnCR : FLOAT\n    }""",
            """    // Runtime tracking lists\n    {\n        CResList areaList = pGFF->AddList(pStruct, \"AreaList\");\n        if (m_pAreaList && m_nAreaListSize > 0) {\n            for (DWORD i = 0; i < m_nAreaListSize; i++) {\n                CResStruct elem;\n                pGFF->AddListElement(&elem, areaList, 0);\n                pGFF->WriteFieldDWORD(&elem, m_pAreaList[i], \"AreaObject\");\n            }\n        }\n    }\n    {\n        CResList spawnResList = pGFF->AddList(pStruct, \"SpawnList\");\n        if (m_pSpawnList && m_nSpawnListSize > 0) {\n            for (DWORD i = 0; i < m_nSpawnListSize; i++) {\n                CResStruct elem;\n                pGFF->AddListElement(&elem, spawnResList, 0);\n                pGFF->WriteFieldCResRef(&elem, m_pSpawnList[i].m_refResRef, \"SpawnResRef\");\n                pGFF->WriteFieldFLOAT(&elem, m_pSpawnList[i].m_fCR, \"SpawnCR\");\n            }\n        }\n    }""",
        ),
    ]

    changed = False
    updated = content
    for old, new in replacements:
        next_text, did_change = _replace_once(updated, old, new)
        updated = next_text
        changed = changed or did_change

    if not changed:
        return PatchResult("encounter-cpp", False, "no known stubs found (possibly already patched)")

    if not dry_run:
        _write(target, updated)
    return PatchResult("encounter-cpp", True, "updated save-list stubs")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Patch known kotor_save_load header/source stubs")
    parser.add_argument(
        "--base",
        type=Path,
        default=Path("kotor_save_load"),
        help="Base directory containing csws_store.h/csws_encounter.h/csws_encounter.cpp",
    )
    parser.add_argument(
        "--only",
        default="store,encounter-header,encounter-cpp",
        help="Comma-separated subset: store,encounter-header,encounter-cpp",
    )
    parser.add_argument("--dry-run", action="store_true", help="Compute and report changes without writing files")
    parser.add_argument("--verbose", action="store_true", help="Print per-patch details")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    base = args.base
    selected = [token.strip() for token in args.only.split(",") if token.strip()]

    handlers = {
        "store": patch_store_header,
        "encounter-header": patch_encounter_header,
        "encounter-cpp": patch_encounter_cpp,
    }

    unknown = [name for name in selected if name not in handlers]
    if unknown:
        print(f"Unknown patch selectors: {', '.join(unknown)}", file=sys.stderr)
        return 2

    results: list[PatchResult] = []
    for name in selected:
        result = handlers[name](base, dry_run=args.dry_run)
        results.append(result)
        if args.verbose:
            status = "PASS" if result.applied else "SKIP"
            print(f"[{status}] {result.name}: {result.detail}")

    if not args.verbose:
        for result in results:
            status = "PASS" if result.applied else "SKIP"
            print(f"[{status}] {result.name}: {result.detail}")

    failures = [r for r in results if ("missing file" in r.detail.lower())]
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
