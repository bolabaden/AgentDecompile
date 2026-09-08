"""Read and write a Ghidra item filesystem (local ``.rep`` or server repository).

Mirrors ``ghidra.framework.store.local.IndexedLocalFileSystem`` /
``IndexedV1LocalFileSystem`` (Apache-2.0). A server repository is the same
item tree as ``versioned/`` inside a ``.rep``: ``~index.dat`` at the root,
storage folders ``00/``…, ``NNNNNNNN.prp``, and ``~NNNNNNNN.db/db.N.gbf``.

Opening that tree does not need a Ghidra server. Serialization writes the
same files Ghidra writes so a checkout can be copied into a local ``.gpr``
or exported back as a repository directory.
"""

from __future__ import annotations

import re
import os
import shutil
import tempfile
import hashlib
import json
import threading
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any, Iterable

from .project import (
    DATA_DIR_EXTENSION,
    HIDDEN_DIR_PREFIX,
    INDEX_FILE,
    PROGRAM_CONTENT_TYPE,
    PROJECT_DIR_SUFFIX,
    PROJECT_FILE_SUFFIX,
    PROPERTY_SUFFIX,
    ProgramEntry,
    ProjectLayoutError,
    find_program,
    is_item_filesystem_root,
    iter_program_entries,
    list_programs,
    resolve_project_root,
    storage_subdirectory,
)

# IndexedLocalFileSystem
INDEX_VERSION_PREFIX = "VERSION="
NEXT_FILE_INDEX_ID_PREFIX = "NEXT-ID:"
MD5_PREFIX = "MD5:"
INDEX_ITEM_INDENT = "  "
INDEX_ITEM_SEPARATOR = ":"
INDEX_IMPLEMENTATION_VERSION = 1  # IndexedV1LocalFileSystem
BAK_INDEX_FILE = "~index.bak"
TMP_INDEX_FILE = "~index.tmp"

# Ghidra's writeIndex calls MessageDigest.digest(line) per line, which resets
# the digest; the trailing MD5 is therefore the empty hash. On-disk repos
# (including _odyssey) store that value. We write the same so Ghidra accepts
# the file, and we do not refuse an index whose MD5 is empty.
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_INDEXED_STORAGE_NAME = re.compile(r"^[0-9a-fA-F]{8}$")

_PRP_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="{content_type}" />
        <STATE NAME="PARENT" TYPE="string" VALUE="{parent}" />
        <STATE NAME="FILE_ID" TYPE="string" VALUE="{file_id}" />
        <STATE NAME="FILE_TYPE" TYPE="int" VALUE="{file_type}" />
        <STATE NAME="NAME" TYPE="string" VALUE="{name}" />
    </BASIC_INFO>
</FILE_INFO>
"""


def store_roots(locator: str | Path) -> list[Path]:
    """Item-filesystem roots under a ``.gpr``, ``.rep``, repo, or repos folder."""
    text = str(locator or "").strip()
    if not text:
        return []
    path = Path(text).expanduser()
    try:
        path = path.resolve()
    except OSError:
        return []
    if not path.exists():
        return []
    if path.suffix.lower() == PROJECT_FILE_SUFFIX or path.suffix.lower() == PROJECT_DIR_SUFFIX:
        try:
            return [resolve_project_root(path)]
        except ProjectLayoutError:
            return []
    if path.is_dir() and is_item_filesystem_root(path):
        return [path]
    kids: list[Path] = []
    if path.is_dir():
        try:
            children = list(path.iterdir())
        except OSError:
            children = []
        for child in sorted(children, key=lambda p: p.name.lower()):
            if child.is_dir() and is_item_filesystem_root(child):
                kids.append(child)
    if kids:
        return kids
    try:
        return [resolve_project_root(path)]
    except ProjectLayoutError:
        return []


def list_store_programs(locator: str | Path) -> list[ProgramEntry]:
    """Every program in a local project or server repository tree."""
    entries: list[ProgramEntry] = []
    seen: set[str] = set()
    for root in store_roots(locator):
        for entry in list_programs(root):
            key = f"{root}:{entry.project_path}"
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
    entries.sort(key=lambda item: item.project_path)
    return entries


def find_store_program(locator: str | Path, name: str) -> ProgramEntry | None:
    wanted = (name or "").rstrip("/")
    if not wanted:
        return None
    for root in store_roots(locator):
        hit = find_program(root, wanted)
        if hit is not None:
            return hit
    bare = wanted.rsplit("/", 1)[-1]
    if bare != wanted:
        for root in store_roots(locator):
            hit = find_program(root, bare)
            if hit is not None:
                return hit
    return None


def write_property_file(
    path: Path,
    *,
    name: str,
    parent: str,
    file_id: str = "",
    content_type: str = PROGRAM_CONTENT_TYPE,
    file_type: int = 0,
) -> Path:
    """Write an ``IndexedPropertyFile`` ``.prp`` (FILE_INFO / STATE XML)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _PRP_TEMPLATE.format(
        content_type=_xml_attr(content_type),
        parent=_xml_attr(parent or "/"),
        file_id=_xml_attr(file_id),
        file_type=int(file_type),
        name=_xml_attr(name),
    )
    path.write_text(payload, encoding="utf-8")
    return path


def read_property_file(path: Path) -> dict[str, str]:
    """Read NAME/PARENT/FILE_ID/CONTENT_TYPE from a ``.prp``."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        raise ProjectLayoutError(f"{path}: item property file declares a DTD or entities")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ProjectLayoutError(f"{path}: not readable as an item property file: {exc}") from exc
    states: dict[str, str] = {}
    for element in root.iter("STATE"):
        key = element.get("NAME")
        if key is not None:
            states[key] = element.get("VALUE", "")
    return states


def format_index_item(storage_name: str, name: str, file_id: str | None = None) -> str:
    """IndexedV1 ``storage:name[:fileId]`` line body."""
    entry = f"{storage_name}{INDEX_ITEM_SEPARATOR}{name}"
    if file_id:
        entry += f"{INDEX_ITEM_SEPARATOR}{file_id}"
    return entry


def write_index_dat(
    root: Path,
    entries: Iterable[ProgramEntry | dict[str, Any]],
    *,
    version: int = INDEX_IMPLEMENTATION_VERSION,
    next_id: int | None = None,
) -> Path:
    """Write a V1 ``~index.dat`` matching ``IndexedV1LocalFileSystem.writeIndex``."""
    items: list[tuple[str, str, str, str]] = []
    max_storage = 0
    for raw in entries:
        if isinstance(raw, ProgramEntry):
            storage = raw.storage_name
            name = raw.name
            folder = raw.folder_path or "/"
            file_id = raw.file_id or ""
        else:
            storage = str(raw.get("storage_name") or raw.get("id") or "")
            name = str(raw.get("name") or "")
            folder = str(raw.get("folder") or raw.get("folder_path") or "/")
            file_id = str(raw.get("file_id") or raw.get("fileId") or "")
        if not storage or not name:
            continue
        if not folder.startswith("/"):
            folder = "/" + folder
        items.append((folder, storage, name, file_id))
        try:
            max_storage = max(max_storage, int(storage, 16))
        except ValueError:
            pass
    folders: dict[str, list[tuple[str, str, str]]] = {}
    for folder, storage, name, file_id in items:
        folders.setdefault(folder, []).append((storage, name, file_id))
    if "/" not in folders:
        folders["/"] = []

    if next_id is None:
        next_id = max_storage + 1

    lines = [f"{INDEX_VERSION_PREFIX}{int(version)}"]
    for folder in _folder_order(folders):
        lines.append(folder)
        for storage, name, file_id in sorted(folders.get(folder) or [], key=lambda row: row[1].lower()):
            lines.append(INDEX_ITEM_INDENT + format_index_item(storage, name, file_id))
    lines.append(f"{NEXT_FILE_INDEX_ID_PREFIX}{next_id:x}")
    lines.append(f"{MD5_PREFIX}{EMPTY_MD5}")

    root.mkdir(parents=True, exist_ok=True)
    target = root / INDEX_FILE
    tmp = root / TMP_INDEX_FILE
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    backup = root / BAK_INDEX_FILE
    if target.exists():
        backup.write_bytes(target.read_bytes())
    tmp.replace(target)
    return target


def rebuild_index(root: Path) -> Path:
    """Rebuild ``~index.dat`` from ``.prp`` items, like ``IndexedV1LocalFileSystem.rebuild``."""
    root = Path(root)
    if not (root / INDEX_FILE).exists() and not any((root / name).is_dir() for name in ("idata", "data", "versioned")):
        write_index_dat(root, [])
    entries = list(iter_program_entries(root, content_type=None))
    return write_index_dat(root, entries)


def item_filesystem_root(path: Path | str) -> Path:
    """Walk up from a ``.prp`` or ``~.db`` path to the ``~index.dat`` root."""
    cur = Path(path)
    if cur.is_file():
        cur = cur.parent
    for candidate in (cur, *cur.parents):
        if is_item_filesystem_root(candidate):
            return candidate
    raise ProjectLayoutError(f"{path}: not inside a Ghidra item filesystem")


def next_storage_name(root: Path) -> str:
    """Next ``IndexedV1`` storage id under ``root`` (8 hex digits)."""
    max_id = -1
    for entry in iter_program_entries(Path(root), content_type=None):
        try:
            max_id = max(max_id, int(entry.storage_name, 16))
        except ValueError:
            continue
    return f"{max_id + 1:08x}"


def copy_program_item(
    entry: ProgramEntry,
    dest_root: Path,
    *,
    storage_name: str | None = None,
    dest_name: str | None = None,
) -> ProgramEntry:
    """Copy one program's ``.prp`` + ``~.db`` tree into an item filesystem root."""
    dest_root = Path(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)
    name = storage_name or entry.storage_name
    item_name = (dest_name or entry.name or Path(entry.property_file).stem).strip()
    indexed_dest = is_item_filesystem_root(dest_root)
    if indexed_dest and not _INDEXED_STORAGE_NAME.match(name):
        name = next_storage_name(dest_root)
    dest_prp = dest_root / storage_subdirectory(name) / f"{name}{PROPERTY_SUFFIX}"
    if dest_prp.exists() and name == entry.storage_name:
        name = next_storage_name(dest_root)
        dest_prp = dest_root / storage_subdirectory(name) / f"{name}{PROPERTY_SUFFIX}"
    dest_dir = dest_prp.parent
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(entry.property_file, dest_prp)
    if dest_name:
        # Keep READ_ONLY and any newer Ghidra properties. Storage IDs live in
        # the destination filename/index, so only the displayed name changes.
        tree = ElementTree.parse(dest_prp)
        basic = tree.getroot().find('BASIC_INFO')
        if basic is None:
            raise ProjectLayoutError(f'{entry.property_file}: missing BASIC_INFO')
        field = next((node for node in basic.findall('STATE') if node.get('NAME') == 'NAME'), None)
        if field is None:
            field = ElementTree.SubElement(basic, 'STATE', {'NAME': 'NAME', 'TYPE': 'string'})
        field.set('VALUE', item_name)
        tree.write(dest_prp, encoding='utf-8', xml_declaration=True)
    dest_db = dest_dir / f"{HIDDEN_DIR_PREFIX}{name}{DATA_DIR_EXTENSION}"
    if dest_db.exists():
        shutil.rmtree(dest_db)
    shutil.copytree(entry.database_dir, dest_db)
    latest = dest_db / entry.database_path.name
    return ProgramEntry(
        name=item_name,
        folder_path=entry.folder_path,
        file_id=entry.file_id,
        content_type=entry.content_type,
        storage_name=name,
        property_file=dest_prp,
        database_path=latest if latest.is_file() else entry.database_path,
        version=entry.version,
    )


def remove_program_item(entry: ProgramEntry) -> Path:
    """Delete one program's ``.prp`` + ``~.db`` tree and rebuild ``~index.dat``."""
    root = item_filesystem_root(entry.property_file)
    if entry.property_file.is_file():
        entry.property_file.unlink()
    db_dir = entry.database_dir
    if db_dir.is_dir():
        shutil.rmtree(db_dir)
    rebuild_index(root)
    return root


def materialize_local_project(source: str | Path, dest_gpr: Path) -> Path:
    """Publish a stable repository snapshot as a new local project.

    The .gpr is the last, exclusive publication step. An interrupted copy is
    never advertised as an openable project, and an existing project is never
    merged or replaced. This preserves repository versions rather than claiming
    to perform a shared-server check-in or Ghidra's current-version copyTo.
    """
    dest_gpr = Path(dest_gpr).absolute()
    dest_rep = dest_gpr.with_suffix(PROJECT_DIR_SUFFIX)
    if dest_gpr.exists() or dest_gpr.is_symlink() or dest_rep.exists() or dest_rep.is_symlink():
        raise FileExistsError(f'{dest_gpr}: destination project already exists')
    entries = list_store_programs(source)
    if not entries:
        raise ProjectLayoutError(f'{source}: no program databases found')
    project_paths = [entry.project_path for entry in entries]
    if len(set(project_paths)) != len(project_paths):
        raise ProjectLayoutError('Several source repositories contain the same project path; select one repository before copying so no program is hidden by another.')
    before = _committed_manifest(entries)
    dest_gpr.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f'.{dest_gpr.stem}-copy-', dir=dest_gpr.parent))
    published_rep = False
    try:
        staged_rep = stage / 'project.rep'
        for sub in ('idata', 'user', 'versioned'):
            (staged_rep / sub).mkdir(parents=True, exist_ok=True)
        versioned = staged_rep / 'versioned'
        write_index_dat(versioned, [])
        copied = [copy_program_item(entry, versioned) for entry in entries]
        write_index_dat(versioned, copied)
        current = list_store_programs(source)
        if _committed_manifest(current) != before:
            raise ProjectLayoutError('Source repository changed during copying; no destination project was published.')
        staged_gpr = stage / 'project.gpr'
        staged_gpr.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<FILE_INFO>\n  <BASIC_INFO>\n    <CREATE_DATE>0</CREATE_DATE>\n  </BASIC_INFO>\n</FILE_INFO>\n', encoding='utf-8')
        # mkdir is exclusive even when another exporter races us. The project
        # marker remains absent until every completed store has been moved.
        dest_rep.mkdir()
        published_rep = True
        for child in staged_rep.iterdir():
            child.rename(dest_rep / child.name)
        os.link(staged_gpr, dest_gpr)  # exclusive; never overwrite a racing .gpr
    except BaseException:
        if published_rep:
            shutil.rmtree(dest_rep)
        raise
    finally:
        shutil.rmtree(stage)
    return dest_gpr


def _committed_manifest(entries: list[ProgramEntry]) -> dict[str, tuple[int, int, int]]:
    """Detect changes to committed databases, versions, and item properties."""
    manifest: dict[str, tuple[int, int, int]] = {}
    for entry in entries:
        for path in (entry.property_file, *entry.database_dir.rglob('*')):
            if not path.is_file() or path.name.endswith(('.ps', '.lock', '.lock~')):
                continue
            stat = path.stat()
            manifest[str(path)] = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    return manifest


_NATIVE_CHECKOUT_LOCK = threading.RLock()


def native_local_checkout(source: str | Path, work_dir: Path) -> tuple[Path, dict[str, Any]]:
    """Reuse one owned native checkout while preserving the source repository."""
    source_path = Path(source).expanduser().resolve()
    source_key = hashlib.sha256(str(source_path).encode()).hexdigest()
    directory = Path(work_dir) / 'native-checkouts' / source_key
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / 'Workspace.gpr'
    receipt_path = directory / 'source.json'
    with _NATIVE_CHECKOUT_LOCK, (directory / '.checkout.lock').open('a+') as lease:
        if os.name == 'nt':
            import msvcrt
            lease.write('0'); lease.flush(); lease.seek(0)
            msvcrt.locking(lease.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lease.fileno(), fcntl.LOCK_EX)
        entries = list_store_programs(source_path)
        if not entries:
            raise ProjectLayoutError(f'{source_path}: no program databases found')
        manifest = _committed_manifest(entries)
        revision = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        if destination.exists():
            try:
                receipt = json.loads(receipt_path.read_text())
            except (OSError, ValueError) as exc:
                raise ProjectLayoutError('Owned native checkout has no source receipt; reconciliation is required before it can be reused.') from exc
            if receipt.get('sourceLocator') != str(source_path) or receipt.get('sourceManifest') != revision:
                raise ProjectLayoutError('Source repository changed after the native checkout was created. Its local annotations are preserved; reconcile the changed source before continuing.')
            return destination, {**receipt, 'reused': True}
        materialize_local_project(source_path, destination)
        # The copy helper verifies its own start/end manifest. This additional
        # check binds the receipt to the snapshot observed before admission.
        if _committed_manifest(list_store_programs(source_path)) != manifest:
            raise ProjectLayoutError('Source changed before native checkout admission; the unbound copy is preserved for inspection and will not be opened.')
        receipt = {'sourceLocator': str(source_path), 'localProjectPath': str(destination), 'sourceManifest': revision, 'sourceFileCount': len(manifest), 'createdAt': time.time(), 'mode': 'owned-local-checkout', 'sourceModified': False, 'analysisRequested': False}
        temporary = receipt_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(receipt, indent=2))
        temporary.replace(receipt_path)
        return destination, {**receipt, 'reused': False}


def materialize_server_repo(source: str | Path, dest_root: Path, *, name: str = "") -> Path:
    """Write a server-repository directory (``~index.dat`` at the top) from a project."""
    dest_root = Path(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)
    stem = name or dest_root.name.lstrip("_") or "repo"
    repo = dest_root if is_item_filesystem_root(dest_root) or dest_root.name.startswith("_") else dest_root / f"_{stem}"
    repo.mkdir(parents=True, exist_ok=True)
    copied = [copy_program_item(entry, repo) for entry in list_store_programs(source)]
    write_index_dat(repo, copied)
    return repo


def _folder_order(folders: dict[str, Any]) -> list[str]:
    names = set(folders)
    names.add("/")
    # Parents before children, then lexical — same walk order as writeIndexFolder.
    return sorted(names, key=lambda path: (path.count("/"), path.lower()))


def _xml_attr(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
