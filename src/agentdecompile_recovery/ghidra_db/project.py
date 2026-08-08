"""Resolution of a Ghidra project directory to the program databases inside it.

Mirrors the layout written by ``ghidra.framework.store.local.LocalFileSystem``
and ``IndexedLocalFileSystem``, and the file naming in ``db.Database``
(Apache-2.0).

On disk a project called `Odyssey` is::

    Odyssey.gpr                       marker file, may be empty
    Odyssey.rep/
        project.prp                   repository/server coordinates
        idata/                        private (checked-out) items
            ~index.dat                folder index
            00/                       storage subdirectory
                00000000.prp          item metadata: NAME, PARENT, FILE_ID, ...
                ~00000000.db/
                    db.1.gbf          the database, one file per version
        versioned/                    server-side item tree, same shape
        user/

A Ghidra *server repository* is the same item tree with the wrapper stripped off:
the repository directory is itself the filesystem root, so the storage
subdirectories sit directly inside it::

    _odyssey/                         one repository on a Ghidra server
        ~index.dat                    folder index
        userAccess.acl
        00/
            0000000b.prp
            ~0000000b.db/
                db.1.gbf

`IndexedLocalFileSystem.isIndexed` calls a directory holding `~index.dat` a
filesystem root, and that is exactly the difference: in a local project the file
sits in `idata/`, in a server repository it sits at the top. Both shapes are
walked the same way from there.

Two deliberate choices:

*Glob the `.prp` files, do not parse `~index.dat`.* The index is a journalled
cache that Ghidra rebuilds; it can lag the filesystem, and its `~journal.bak`
sibling shows it does. The `.prp` files are the items themselves, so a directory
walk cannot report a program that is not there or miss one that is. Nothing is
lost by ignoring it: each `.prp` carries its own `NAME` and `PARENT`, so an item
knows its folder without the index.

*Search `versioned/` as well as `idata/`.* Ghidra's own test project keeps its
programs only under `versioned/`; looking in `idata/` alone finds nothing there
and would report a perfectly good project as empty. A server repository has
neither, so the repository directory itself is searched -- see
`item_storage_roots`.

Read-only. Nothing here creates, deletes or writes any file, `.lock` files
included: a lock means another process may be *writing*, and since this module
only ever reads, it reads anyway rather than refusing or clearing the lock.
"""

from __future__ import annotations

import re

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from xml.etree import ElementTree

from .program import GhidraProgram

PROJECT_DIR_SUFFIX = ".rep"
PROJECT_FILE_SUFFIX = ".gpr"
PROPERTY_SUFFIX = ".prp"

# LocalFolderItem.DATA_DIR_EXTENSION / LocalFileSystem.HIDDEN_DIR_PREFIX
HIDDEN_DIR_PREFIX = "~"
DATA_DIR_EXTENSION = ".db"

# db.Database.DATABASE_FILE_PREFIX + version + LocalBufferFile.BUFFER_FILE_EXTENSION
DATABASE_FILE_PREFIX = "db."
BUFFER_FILE_EXTENSION = ".gbf"
_DATABASE_FILE_PATTERN = re.compile(r"^db\.(\d+)\.gbf$")

# Item data roots inside a local project, in the order a caller would expect to
# find a program. A server repository has none of these: it is a root itself.
DATA_ROOTS = ("idata", "data", "versioned")

# IndexedLocalFileSystem.INDEX_FILE -- marks the root of an item filesystem.
INDEX_FILE = "~index.dat"

PROGRAM_CONTENT_TYPE = "Program"


class ProjectLayoutError(Exception):
    """Raised when a path is not a readable Ghidra project."""


@dataclass(frozen=True)
class ProgramEntry:
    """One program item in a project, resolved to the file that holds it."""

    name: str
    folder_path: str
    file_id: str | None
    content_type: str
    storage_name: str
    property_file: Path
    database_path: Path
    version: int

    @property
    def project_path(self) -> str:
        """Ghidra's own path form, e.g. `/TSL/k2_win_gog_aspyr_swkotor2.exe`."""

        folder = self.folder_path if self.folder_path.startswith("/") else f"/{self.folder_path}"
        return f"{folder.rstrip('/')}/{self.name}"

    def open(self) -> GhidraProgram:
        """Open the program database this entry points at."""

        return GhidraProgram(self.database_path)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.project_path,
            "fileId": self.file_id,
            "contentType": self.content_type,
            "database": str(self.database_path),
            "version": self.version,
        }


def storage_subdirectory(storage_name: str) -> str:
    """The subdirectory an item is filed under, per `IndexedLocalFileSystem`.

    Ghidra fans items out using the 3rd and 2nd hex digits from the right of the
    8-digit storage name -- `storageName.substring(len - 3, len - 1)` -- so
    `00000000` lives in `00/` and `00000123` in `12/`. Transcribed here for
    callers that need to predict a path; the walk itself globs instead, which
    cannot disagree with the filesystem.
    """

    if len(storage_name) < 3:
        raise ProjectLayoutError(f"storage name {storage_name!r} is too short to place")
    return storage_name[-3:-1]


def is_item_filesystem_root(path: Path | str) -> bool:
    """Whether a directory is itself an item filesystem root.

    `IndexedLocalFileSystem.isIndexed`: a root is a directory holding
    `~index.dat`. A server repository is one; a local `.rep` is not (its roots
    are `idata/` and `versioned/`).
    """

    return (Path(path) / INDEX_FILE).exists()


def item_storage_roots(root: Path) -> list[Path]:
    """Directories whose subdirectories hold `.prp` items, in search order.

    A local project keeps its item trees in `idata/`, `data/` and `versioned/`.
    A server repository *is* an item tree, so its storage subdirectories (`00/`,
    `01/`, ...) sit directly in the repository directory and there is no wrapper
    to look inside. Resolving the root is therefore not enough on its own: the
    walk has to be told the root is also a scan base, or a server repository
    enumerates as empty.
    """

    bases = [root / data_root for data_root in DATA_ROOTS if (root / data_root).is_dir()]
    if is_item_filesystem_root(root):
        bases.append(root)
    return bases


def resolve_project_root(path: Path | str) -> Path:
    """Resolve a `.gpr`, `.rep`, project directory or server repository to its root.

    The `.gpr` file is only a marker -- it is routinely zero bytes -- so it is
    never opened; only its name is used to find the sibling `.rep`.
    """

    candidate = Path(path)

    if candidate.suffix == PROJECT_FILE_SUFFIX:
        repository = candidate.with_suffix(PROJECT_DIR_SUFFIX)
        if not repository.is_dir():
            raise ProjectLayoutError(
                f"{candidate}: no sibling {repository.name} directory; the project "
                "file has no data without it"
            )
        return repository

    if candidate.is_dir():
        if candidate.suffix == PROJECT_DIR_SUFFIX:
            return candidate
        # A bare project directory, or a server repository: accept either shape.
        if any((candidate / root).is_dir() for root in DATA_ROOTS):
            return candidate
        if is_item_filesystem_root(candidate):
            return candidate
        raise ProjectLayoutError(
            f"{candidate}: not a Ghidra project directory or server repository "
            f"(no {'/, '.join(DATA_ROOTS)}/ and no {INDEX_FILE} inside)"
        )

    raise ProjectLayoutError(f"{candidate}: no such project file or directory")


def _read_property_file(path: Path) -> dict[str, str]:
    """Read a `.prp` item file into `{STATE NAME: VALUE}`.

    Malformed XML is reported with the offending path rather than swallowed: a
    `.prp` that will not parse means an item is invisible, and silently skipping
    it would understate the project.

    The parser is the stdlib one (no third-party dependency is available here),
    so entity declarations are refused up front rather than handed to expat: a
    real `.prp` is a flat `FILE_INFO`/`STATE` document with no DTD, and the only
    reason one would carry entities is a billion-laughs expansion.
    """

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ProjectLayoutError(f"{path}: cannot read item property file: {exc}") from exc

    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        raise ProjectLayoutError(f"{path}: item property file declares a DTD or entities; refusing to parse")

    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ProjectLayoutError(f"{path}: not readable as an item property file: {exc}") from exc

    states: dict[str, str] = {}
    for element in root.iter("STATE"):
        name = element.get("NAME")
        if name is not None:
            states[name] = element.get("VALUE", "")
    return states


def _latest_database_file(database_dir: Path) -> tuple[Path, int] | None:
    """Highest-numbered `db.N.gbf` in an item's data directory.

    Ghidra keeps older versions alongside the current one and treats the largest
    N as current (`db.Database.scanFiles`), so picking the first match found
    would read a stale database on any item with history.
    """

    best: tuple[Path, int] | None = None
    if not database_dir.is_dir():
        return None
    for entry in database_dir.iterdir():
        match = _DATABASE_FILE_PATTERN.match(entry.name)
        if match is None or not entry.is_file():
            continue
        version = int(match.group(1))
        if best is None or version > best[1]:
            best = (entry, version)
    return best


def iter_program_entries(
    path: Path | str, *, content_type: str | None = PROGRAM_CONTENT_TYPE
) -> Iterator[ProgramEntry]:
    """Yield every program item in a project, in stable path order.

    Pass `content_type=None` to include non-program items (data type archives
    and the like). Items whose database directory is absent are skipped: those
    are server-side stubs with no bytes checked out locally.
    """

    root = resolve_project_root(path)

    for base in item_storage_roots(root):
        for property_file in sorted(base.glob(f"*/*{PROPERTY_SUFFIX}")):
            if property_file.name.startswith(HIDDEN_DIR_PREFIX):
                continue
            states = _read_property_file(property_file)
            item_type = states.get("CONTENT_TYPE", "")
            if content_type is not None and item_type != content_type:
                continue

            storage_name = property_file.stem
            database_dir = property_file.parent / f"{HIDDEN_DIR_PREFIX}{storage_name}{DATA_DIR_EXTENSION}"
            latest = _latest_database_file(database_dir)
            if latest is None:
                continue

            yield ProgramEntry(
                name=states.get("NAME", storage_name),
                folder_path=states.get("PARENT", "/"),
                file_id=states.get("FILE_ID") or None,
                content_type=item_type,
                storage_name=storage_name,
                property_file=property_file,
                database_path=latest[0],
                version=latest[1],
            )


def list_programs(
    path: Path | str, *, content_type: str | None = PROGRAM_CONTENT_TYPE
) -> list[ProgramEntry]:
    """All program items in a project. An empty project yields an empty list."""

    entries = list(iter_program_entries(path, content_type=content_type))
    entries.sort(key=lambda entry: entry.project_path)
    return entries


def find_program(path: Path | str, name: str) -> ProgramEntry | None:
    """Find one program by full project path (`/TSL/foo.exe`) or by bare name."""

    wanted = name.rstrip("/")
    for entry in list_programs(path):
        if entry.project_path == wanted or entry.name == wanted:
            return entry
    return None


def open_project_program(path: Path | str, name: str) -> GhidraProgram:
    """Open a named program from a project."""

    entry = find_program(path, name)
    if entry is None:
        available = [item.project_path for item in list_programs(path)]
        raise ProjectLayoutError(f"{path}: no program {name!r} (have: {available})")
    return entry.open()
