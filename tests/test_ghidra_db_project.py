"""Tests for project layout resolution and `.gzf` unpacking (U7).

Layout is tested against synthetic trees (so the odd shapes -- legacy `data/`,
zero programs, several database versions -- are reachable) *and* against the two
real projects on this machine, because a rule that only holds for a tree we
built ourselves proves nothing about Ghidra's.
"""

from __future__ import annotations

import struct
import zlib

from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.packed import (
    MAGIC_NUMBER,
    PackedFileError,
    extract_database,
    is_packed_file,
    open_packed_database,
    read_packed_header,
)
from agentdecompile_recovery.ghidra_db.project import (
    INDEX_FILE,
    ProjectLayoutError,
    find_program,
    is_item_filesystem_root,
    item_storage_roots,
    iter_program_entries,
    list_programs,
    open_project_program,
    resolve_project_root,
    storage_subdirectory,
)

pytestmark = pytest.mark.unit

ODYSSEY_GPR = Path("/home/brunner56/Odyssey.gpr")
ODYSSEY_REP = Path("/home/brunner56/Odyssey.rep")
GHIDRA_REP = Path("/home/brunner56/Downloads/biodecompwarehouse/projects/agentdecompile.rep")
REAL_GZF = Path("/home/brunner56/Desktop/k1_win_gog_swkotor.exe.gzf")
SERVER_REPO = Path("/run/media/brunner56/MyBook/Downloads/biodecompwarehouse/repos/_odyssey")

_needs_odyssey = pytest.mark.skipif(not ODYSSEY_REP.is_dir(), reason="Odyssey project fixture unavailable")
_needs_ghidra_project = pytest.mark.skipif(not GHIDRA_REP.is_dir(), reason="Ghidra project fixture unavailable")
_needs_real_gzf = pytest.mark.skipif(not REAL_GZF.is_file(), reason="packed .gzf fixture unavailable")
_needs_server_repo = pytest.mark.skipif(
    not SERVER_REPO.is_dir(), reason="Ghidra server repository fixture unavailable"
)


# -- synthetic project builder ----------------------------------------------

_PRP_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="{content_type}" />
        <STATE NAME="PARENT" TYPE="string" VALUE="{parent}" />
        <STATE NAME="FILE_ID" TYPE="string" VALUE="{file_id}" />
        <STATE NAME="FILE_TYPE" TYPE="int" VALUE="0" />
        <STATE NAME="NAME" TYPE="string" VALUE="{name}" />
    </BASIC_INFO>
</FILE_INFO>
"""


def _make_project(
    root: Path,
    *,
    data_root: str = "idata",
    storage_name: str = "00000000",
    name: str = "target.exe",
    parent: str = "/",
    content_type: str = "Program",
    versions: tuple[int, ...] = (1,),
) -> Path:
    """Build a minimal `.rep` tree with one item."""

    repository = root if root.suffix == ".rep" else root.with_suffix(".rep")
    storage = repository / data_root / storage_subdirectory(storage_name)
    storage.mkdir(parents=True, exist_ok=True)
    (storage / f"{storage_name}.prp").write_text(
        _PRP_TEMPLATE.format(content_type=content_type, parent=parent, file_id=f"id-{storage_name}", name=name)
    )
    database = storage / f"~{storage_name}.db"
    database.mkdir(exist_ok=True)
    for version in versions:
        (database / f"db.{version}.gbf").write_bytes(b"")
    return repository


def _make_server_repository(
    root: Path,
    *,
    items: tuple[tuple[str, str, str], ...] = (("0000000b", "game.exe", "/TSL"),),
    content_type: str = "Program",
    versions: tuple[int, ...] = (1,),
) -> Path:
    """Build a minimal Ghidra *server* repository.

    A repository on a server is an item filesystem with no project wrapper: the
    `~index.dat` that marks a root sits at the top, and the storage
    subdirectories are its immediate children. `items` is `(storage_name, name,
    folder)` triples.
    """

    root.mkdir(parents=True, exist_ok=True)
    folders = sorted({folder for _, _, folder in items})
    lines = ["VERSION=1", "/"]
    for folder in folders:
        lines.append(folder)
        for storage_name, name, item_folder in items:
            if item_folder == folder:
                lines.append(f"  {storage_name}:{name}:id-{storage_name}")
    lines += ["NEXT-ID:32", "MD5:d41d8cd98f00b204e9800998ecf8427e", ""]
    (root / INDEX_FILE).write_text("\n".join(lines))

    for storage_name, name, folder in items:
        storage = root / storage_subdirectory(storage_name)
        storage.mkdir(exist_ok=True)
        (storage / f"{storage_name}.prp").write_text(
            _PRP_TEMPLATE.format(
                content_type=content_type, parent=folder, file_id=f"id-{storage_name}", name=name
            )
        )
        database = storage / f"~{storage_name}.db"
        database.mkdir(exist_ok=True)
        for version in versions:
            (database / f"db.{version}.gbf").write_bytes(b"")
    return root


# -- storage arithmetic -----------------------------------------------------


def test_storage_subdirectory_uses_the_third_and_second_digits() -> None:
    """`storageName.substring(len - 3, len - 1)`, per IndexedLocalFileSystem."""

    assert storage_subdirectory("00000000") == "00"
    assert storage_subdirectory("00000123") == "12"
    assert storage_subdirectory("0000abcd") == "bc"


def test_storage_subdirectory_rejects_a_name_it_cannot_place() -> None:
    with pytest.raises(ProjectLayoutError):
        storage_subdirectory("ab")


# -- project resolution -----------------------------------------------------


def test_gpr_resolves_to_its_sibling_rep(tmp_path: Path) -> None:
    project_file = tmp_path / "Sample.gpr"
    project_file.write_bytes(b"")
    repository = _make_project(project_file)

    assert resolve_project_root(project_file) == repository


def test_rep_directory_resolves_to_itself(tmp_path: Path) -> None:
    repository = _make_project(tmp_path / "Sample.gpr")

    assert resolve_project_root(repository) == repository


def test_gpr_without_a_rep_is_an_error(tmp_path: Path) -> None:
    """The `.gpr` is a zero-byte marker; without the `.rep` there is no data."""

    project_file = tmp_path / "Orphan.gpr"
    project_file.write_bytes(b"")

    with pytest.raises(ProjectLayoutError, match="Orphan.rep"):
        resolve_project_root(project_file)


def test_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ProjectLayoutError, match="no such project"):
        resolve_project_root(tmp_path / "absent")


def test_unrelated_directory_is_rejected(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()

    with pytest.raises(ProjectLayoutError, match="not a Ghidra project"):
        resolve_project_root(plain)


# -- program enumeration ----------------------------------------------------


def test_single_program_is_found_with_its_metadata(tmp_path: Path) -> None:
    repository = _make_project(tmp_path / "Sample.gpr", parent="/TSL", name="game.exe")

    entries = list_programs(repository)

    assert len(entries) == 1
    assert entries[0].name == "game.exe"
    assert entries[0].project_path == "/TSL/game.exe"
    assert entries[0].file_id == "id-00000000"
    assert entries[0].database_path.name == "db.1.gbf"


def test_project_with_zero_programs_yields_an_empty_list(tmp_path: Path) -> None:
    repository = tmp_path / "Empty.rep"
    (repository / "idata").mkdir(parents=True)

    assert list_programs(repository) == []


def test_legacy_data_root_is_searched(tmp_path: Path) -> None:
    """Older, non-indexed projects store items under `data/`, not `idata/`."""

    repository = _make_project(tmp_path / "Legacy.gpr", data_root="data")

    assert [entry.name for entry in list_programs(repository)] == ["target.exe"]


def test_versioned_root_is_searched(tmp_path: Path) -> None:
    """Ghidra's own fixture project keeps programs only under `versioned/`."""

    repository = _make_project(tmp_path / "Server.gpr", data_root="versioned")

    assert [entry.name for entry in list_programs(repository)] == ["target.exe"]


def test_highest_database_version_wins(tmp_path: Path) -> None:
    """Older `db.N.gbf` files survive alongside the current one."""

    repository = _make_project(tmp_path / "Sample.gpr", versions=(1, 2, 10))

    entry = list_programs(repository)[0]

    assert entry.database_path.name == "db.10.gbf"
    assert entry.version == 10


def test_item_without_a_database_directory_is_skipped(tmp_path: Path) -> None:
    """A server-side item that was never checked out has no bytes here."""

    repository = _make_project(tmp_path / "Sample.gpr")
    database = repository / "idata" / "00" / "~00000000.db"
    for child in database.iterdir():
        child.unlink()
    database.rmdir()

    assert list_programs(repository) == []


def test_non_program_items_are_filtered_out(tmp_path: Path) -> None:
    repository = _make_project(tmp_path / "Sample.gpr", content_type="Archive", name="types.gdt")

    assert list_programs(repository) == []
    assert [entry.name for entry in list_programs(repository, content_type=None)] == ["types.gdt"]


def test_lock_file_does_not_block_reading(tmp_path: Path) -> None:
    """A lock means someone may be writing; this reader only ever reads."""

    project_file = tmp_path / "Locked.gpr"
    project_file.write_bytes(b"")
    _make_project(project_file)
    lock = tmp_path / "Locked.lock"
    lock.write_text("held")

    assert len(list_programs(project_file)) == 1
    assert lock.is_file()


def test_find_program_accepts_a_path_or_a_bare_name(tmp_path: Path) -> None:
    repository = _make_project(tmp_path / "Sample.gpr", parent="/TSL", name="game.exe")

    assert find_program(repository, "/TSL/game.exe") is not None
    assert find_program(repository, "game.exe") is not None
    assert find_program(repository, "other.exe") is None


def test_opening_an_unknown_program_lists_what_exists(tmp_path: Path) -> None:
    repository = _make_project(tmp_path / "Sample.gpr", parent="/TSL", name="game.exe")

    with pytest.raises(ProjectLayoutError, match="/TSL/game.exe"):
        open_project_program(repository, "missing.exe")


def test_malformed_property_file_is_reported_not_skipped(tmp_path: Path) -> None:
    """A `.prp` that will not parse hides an item; silence would understate the project."""

    repository = _make_project(tmp_path / "Sample.gpr")
    (repository / "idata" / "00" / "00000000.prp").write_text("<FILE_INFO>")

    with pytest.raises(ProjectLayoutError, match="not readable"):
        list_programs(repository)


def test_property_file_declaring_entities_is_refused(tmp_path: Path) -> None:
    """Real `.prp` files have no DTD; entities would only be an expansion attack."""

    repository = _make_project(tmp_path / "Sample.gpr")
    (repository / "idata" / "00" / "00000000.prp").write_text(
        '<!DOCTYPE FILE_INFO [<!ENTITY a "aaa">]><FILE_INFO/>'
    )

    with pytest.raises(ProjectLayoutError, match="DTD or entities"):
        list_programs(repository)


def test_iteration_is_lazy(tmp_path: Path) -> None:
    repository = _make_project(tmp_path / "Sample.gpr")

    entries = iter_program_entries(repository)

    assert next(entries).name == "target.exe"


# -- server repositories ----------------------------------------------------


def test_server_repository_resolves_to_itself(tmp_path: Path) -> None:
    """`IndexedLocalFileSystem.isIndexed`: a directory holding `~index.dat` is a root."""

    repository = _make_server_repository(tmp_path / "_odyssey")

    assert is_item_filesystem_root(repository)
    assert resolve_project_root(repository) == repository


def test_local_project_root_is_not_an_item_filesystem_root(tmp_path: Path) -> None:
    """In a `.rep` the index sits in `idata/`, so the wrapper itself is not a root."""

    repository = _make_project(tmp_path / "Sample.gpr")
    (repository / "idata" / INDEX_FILE).write_text("VERSION=1\n/\n")

    assert not is_item_filesystem_root(repository)
    assert item_storage_roots(repository) == [repository / "idata"]


def test_server_repository_programs_carry_their_folder(tmp_path: Path) -> None:
    """Names repeat across folders, so identity is the folder path plus the name."""

    repository = _make_server_repository(
        tmp_path / "_odyssey",
        items=(
            ("0000002a", "swkotor.exe", "/K1"),
            ("0000000b", "swkotor.exe", "/TSL"),
        ),
    )

    entries = list_programs(repository)

    assert [entry.project_path for entry in entries] == ["/K1/swkotor.exe", "/TSL/swkotor.exe"]
    assert entries[0].database_path == repository / "02/~0000002a.db/db.1.gbf"
    assert entries[1].database_path == repository / "00/~0000000b.db/db.1.gbf"


def test_server_repository_takes_the_highest_database_version(tmp_path: Path) -> None:
    repository = _make_server_repository(tmp_path / "_odyssey", versions=(1, 2, 18))

    entry = list_programs(repository)[0]

    assert entry.version == 18
    assert entry.database_path.name == "db.18.gbf"


def test_server_repository_ignores_version_and_change_files(tmp_path: Path) -> None:
    """A checked-in item keeps `ver.N.gbf` and `change.N.gbf` beside `db.N.gbf`."""

    repository = _make_server_repository(tmp_path / "_odyssey", versions=(1, 18))
    database = repository / "00/~0000000b.db"
    (database / "ver.99.gbf").write_bytes(b"")
    (database / "change.99.gbf").write_bytes(b"")
    (database / "checkout.dat").write_bytes(b"")

    assert list_programs(repository)[0].database_path.name == "db.18.gbf"


# -- real projects ----------------------------------------------------------


@_needs_server_repo
def test_server_repository_lists_every_program_with_its_folder() -> None:
    """The real 24-program `_odyssey` repository, enumerated from its root."""

    entries = list_programs(SERVER_REPO)

    assert len(entries) == 24
    assert [entry.project_path for entry in entries] == [
        "/JE/JadeEmpire.exe",
        "/K1/k1_android_ARM64",
        "/K1/k1_android_ARMEABI",
        "/K1/k1_iOS_KOTOR.ipa",
        "/K1/k1_mac_swkotor.app",
        "/K1/k1_win_amazongames_swkotor.exe",
        "/K1/k1_win_gog_swkotor.exe",
        "/K1/k1_win_gog_swkotor.exe.keep",
        "/K1/k1_xbox_default.xbe",
        "/Other BioWare Engines/Aurora/nwmain.exe",
        "/Other BioWare Engines/Eclipse/DragonAge2.exe",
        "/Other BioWare Engines/Eclipse/daorigins.exe",
        "/TSL/k2_android_libkotor2.so_arm64-v8aandroid",
        "/TSL/k2_android_libkotor2.so_armeabi-v7aandroid",
        "/TSL/k2_android_libkotor2.so_x86_64android",
        "/TSL/k2_android_libkotor2.so_x86android",
        "/TSL/k2_ios_KOTOR_II.ipa",
        "/TSL/k2_linux_swkotor2.elf",
        "/TSL/k2_mac_swkotor2.app",
        "/TSL/k2_win_CD_1.0_swkotor2.exe",
        "/TSL/k2_win_CD_1.0b_swkotor2.exe",
        "/TSL/k2_win_gog_aspyr_swkotor2.exe",
        "/TSL/k2_win_steam_aspyr_swkotor2.exe",
        "/TSL/k2_xbox_default.xbe",
    ]


@_needs_server_repo
def test_server_repository_folders_agree_with_the_index_file() -> None:
    """Globbing `.prp` files must give the folder tree `~index.dat` records.

    The walk deliberately ignores the index, so this is the check that the two
    cannot drift apart unnoticed: every `id:name:fileId` line in the index has to
    match the `PARENT`/`NAME`/`FILE_ID` of the item with that storage name.
    """

    indexed: dict[str, str] = {}
    folder = "/"
    for line in (SERVER_REPO / INDEX_FILE).read_text().splitlines():
        if line.startswith("/"):
            folder = line
        elif line.startswith("  "):
            storage_name, name, file_id = line.strip().split(":")
            indexed[storage_name] = f"{folder.rstrip('/')}/{name}|{file_id}"

    walked = {
        entry.storage_name: f"{entry.project_path}|{entry.file_id}"
        for entry in list_programs(SERVER_REPO)
    }

    assert walked == indexed


@_needs_server_repo
def test_server_repository_current_version_is_the_highest_database_file() -> None:
    """`/TSL/k2_win_gog_aspyr_swkotor2.exe` has 18 versions checked in."""

    entry = find_program(SERVER_REPO, "/TSL/k2_win_gog_aspyr_swkotor2.exe")

    assert entry is not None
    assert entry.database_path == SERVER_REPO / "01/~00000014.db/db.18.gbf"
    assert entry.version == 18
    assert sorted(entry.database_path.parent.glob("ver.*.gbf"))  # older versions kept beside it


@_needs_server_repo
def test_server_repository_program_opens_and_reads_its_metadata() -> None:
    """The 6 MB `/TSL/k2_win_CD_1.0_swkotor2.exe`, opened straight from the repository."""

    entry = find_program(SERVER_REPO, "/TSL/k2_win_CD_1.0_swkotor2.exe")

    assert entry is not None
    with entry.open() as program:
        assert program.image_base == 0x400000
        assert program.language_id == "x86:LE:32:default"
        assert [block.name for block in program.memory_blocks()] == [
            "Headers",
            ".text",
            ".rdata",
            ".data",
            ".rsrc",
        ]


@_needs_odyssey
def test_odyssey_project_resolves_to_the_curated_program() -> None:
    entries = list_programs(ODYSSEY_GPR if ODYSSEY_GPR.is_file() else ODYSSEY_REP)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.project_path == "/TSL/k2_win_gog_aspyr_swkotor2.exe"
    assert entry.database_path == ODYSSEY_REP / "idata/00/~00000000.db/db.1.gbf"
    assert entry.file_id == "a502e2011160668943040900"


@_needs_odyssey
def test_odyssey_entry_opens_as_a_program() -> None:
    entry = find_program(ODYSSEY_REP, "/TSL/k2_win_gog_aspyr_swkotor2.exe")

    assert entry is not None
    with entry.open() as program:
        assert program.image_base == 0x400000
        assert program.program_name == "swkotor2.exe"


@_needs_ghidra_project
def test_ghidra_own_project_lists_both_versioned_programs() -> None:
    entries = list_programs(GHIDRA_REP)

    assert [entry.name for entry in entries] == ["decompile", "sleigh"]
    assert all("versioned" in entry.database_path.parts for entry in entries)


# -- packed .gzf ------------------------------------------------------------


def _java_utf(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def _build_gzf(
    path: Path,
    payload: bytes,
    *,
    item_name: str = "sample.exe",
    content_type: str = "Program",
    magic: int = MAGIC_NUMBER,
    format_version: int = 1,
    entry_name: bytes = b"FOLDER_ITEM",
    declared_length: int | None = None,
    long_block: bool = False,
) -> Path:
    """Write a `.gzf` exactly as `ItemSerializer.outputItem` does.

    Including its quirks: the ZIP is left unfinished (no central directory), and
    the entry's sizes live in a trailing data descriptor rather than the local
    header.
    """

    block = struct.pack(">q", magic) + struct.pack(">i", format_version)
    block += _java_utf(item_name) + _java_utf(content_type)
    block += struct.pack(">i", 0)
    block += struct.pack(">q", len(payload) if declared_length is None else declared_length)

    header = b"\xac\xed\x00\x05"
    header += struct.pack(">Bi", 0x7A, len(block)) if long_block else struct.pack(">BB", 0x77, len(block))

    compressor = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    compressed = compressor.compress(payload) + compressor.flush()

    local = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0x0008, 8, 0, 0, 0, 0, 0, len(entry_name), 0
    )
    descriptor = struct.pack(
        "<4sIII", b"PK\x07\x08", zlib.crc32(payload) & 0xFFFFFFFF, len(compressed), len(payload)
    )

    path.write_bytes(header + block + local + entry_name + compressed + descriptor)
    return path


def test_packed_magic_sits_at_offset_six(tmp_path: Path) -> None:
    packed = _build_gzf(tmp_path / "sample.gzf", b"payload")

    assert struct.unpack(">Q", packed.read_bytes()[6:14])[0] == MAGIC_NUMBER
    assert is_packed_file(packed)


def test_bad_magic_is_not_a_packed_file(tmp_path: Path) -> None:
    packed = _build_gzf(tmp_path / "bad.gzf", b"payload", magic=0x1122334455667788)

    assert not is_packed_file(packed)
    with pytest.raises(PackedFileError, match="bad packed-file magic"):
        read_packed_header(packed)


def test_unrelated_file_is_not_a_packed_file(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a packed database at all")

    assert not is_packed_file(junk)


def test_missing_file_is_not_a_packed_file(tmp_path: Path) -> None:
    assert not is_packed_file(tmp_path / "absent.gzf")


def test_truncated_file_is_not_a_packed_file(tmp_path: Path) -> None:
    stub = tmp_path / "stub.gzf"
    stub.write_bytes(b"\xac\xed\x00\x05")

    assert not is_packed_file(stub)


def test_header_reports_item_metadata(tmp_path: Path) -> None:
    packed = _build_gzf(tmp_path / "sample.gzf", b"x" * 100, item_name="k1.exe")

    header = read_packed_header(packed)

    assert header.item_name == "k1.exe"
    assert header.content_type == "Program"
    assert header.content_length == 100
    assert header.is_database
    assert header.zip_offset > 6


def test_long_block_tag_is_supported(tmp_path: Path) -> None:
    """`ObjectOutputStream` switches to 0x7A once a block exceeds 255 bytes."""

    packed = _build_gzf(tmp_path / "long.gzf", b"payload", long_block=True)

    assert read_packed_header(packed).item_name == "sample.exe"


def test_non_serialization_stream_is_rejected(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.gzf"
    bogus.write_bytes(b"\x00\x00\x00\x00" + b"\x00" * 64)

    with pytest.raises(PackedFileError, match="not a Java serialization stream"):
        read_packed_header(bogus)


def test_unsupported_format_version_is_rejected(tmp_path: Path) -> None:
    packed = _build_gzf(tmp_path / "future.gzf", b"payload", format_version=2)

    with pytest.raises(PackedFileError, match="unsupported packed format version"):
        read_packed_header(packed)


def test_extraction_reproduces_the_payload_byte_for_byte(tmp_path: Path) -> None:
    payload = bytes(range(256)) * 400
    packed = _build_gzf(tmp_path / "sample.gzf", payload)

    extracted = extract_database(packed, tmp_path / "out.gbf")

    assert extracted.read_bytes() == payload


def test_extraction_rejects_a_wrong_entry_name(tmp_path: Path) -> None:
    packed = _build_gzf(tmp_path / "sample.gzf", b"payload", entry_name=b"SOMETHING_ELSE")

    with pytest.raises(PackedFileError, match="FOLDER_ITEM"):
        extract_database(packed, tmp_path / "out.gbf")


def test_extraction_rejects_a_length_mismatch(tmp_path: Path) -> None:
    """The header length is authoritative; disagreement means a corrupt file."""

    target = tmp_path / "out.gbf"
    packed = _build_gzf(tmp_path / "sample.gzf", b"payload" * 10, declared_length=999999)

    with pytest.raises(PackedFileError, match="header declares"):
        extract_database(packed, target)
    assert not target.exists()


def test_packed_file_needs_no_central_directory(tmp_path: Path) -> None:
    """ItemSerializer never calls finish(), so `zipfile` cannot read a real .gzf."""

    import zipfile

    packed = _build_gzf(tmp_path / "sample.gzf", b"payload" * 100)

    with pytest.raises(zipfile.BadZipFile), packed.open("rb") as handle:
        zipfile.ZipFile(handle)
    assert extract_database(packed, tmp_path / "out.gbf").read_bytes() == b"payload" * 100


@_needs_real_gzf
def test_real_gzf_header_matches_its_name() -> None:
    header = read_packed_header(REAL_GZF)

    assert is_packed_file(REAL_GZF)
    assert header.item_name == "k1_win_gog_swkotor.exe"
    assert header.content_type == "Program"
    assert header.is_database
    assert header.content_length > 0


@_needs_real_gzf
def test_real_gzf_unpacks_to_a_readable_buffer_file() -> None:
    """The `FOLDER_ITEM` entry is a `.gbf`, so `BufferFile` reads it unchanged."""

    with open_packed_database(REAL_GZF) as buffer_file:
        assert buffer_file.header.block_size > 0
        assert buffer_file.buffer_count > 0
        assert buffer_file.read_buffer(0)


@_needs_real_gzf
def test_extracted_database_can_be_reused_from_a_workdir(tmp_path: Path) -> None:
    with open_packed_database(REAL_GZF, workdir=tmp_path) as first:
        block_size = first.header.block_size
    extracted = tmp_path / "k1_win_gog_swkotor.exe.gbf"
    assert extracted.is_file()

    stamp = extracted.stat().st_mtime_ns
    with open_packed_database(REAL_GZF, workdir=tmp_path) as second:
        assert second.header.block_size == block_size
    assert extracted.stat().st_mtime_ns == stamp
