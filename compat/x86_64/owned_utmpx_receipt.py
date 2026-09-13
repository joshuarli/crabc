#!/usr/bin/env python3
"""Collect and replay a closed native receipt for the owned utmpx ABI leaf.

Collection runs the established native runner once with already-built static and
dynamic products.  It copies every finite byte input that its sealed links,
symbol inspectors, and raw process streams consume into a ``/workspace``-shaped
receipt.  ``validate-report`` only reads those copied bytes; it never invokes a
compiler, linker, shell, ELF utility, or target executable.

This is component evidence for the eight aliases selected by
``x86-owned-static-runtime``.  It is deliberately not a selection change,
runtime-family completion claim, or public-support promotion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any, Mapping

# This module is the host's trusted reader.  It must never import retained
# receipt source: that would turn a tampered source snapshot into host code.
import owned_posix_product_evidence as retained_link_reader
from loader_debug_abi_evidence import Elf

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-utmpx-receipt/v1"
COMMAND_SCHEMA = "crabc.x86_64-owned-utmpx-command/v1"
SOURCE_MOUNT = "/workspace"
PINNED_IMAGE_ID = "sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
PINNED_IMAGE = "crabc-core-evidence@" + PINNED_IMAGE_ID
IMAGE_MANIFEST = "compat/x86_64/owned_utmpx_image_inputs.json"
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATH = "/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Every external command directly used by the opted-in runner, plus the
# compiler/oracle executables it invokes.  The committed manifest maps these
# command names through ``IMAGE_PATH`` to their physical immutable-image bytes.
IMAGE_COMMANDS = ("bash", "basename", "chmod", "chroot", "cmp", "cp", "dirname", "env", "grep", "mkdir", "mktemp",
                  "mknod", "nm", "python3", "readelf", "realpath", "sha256sum", "timeout", "gcc", "as", "ld", "rustup")
IMAGE_FIXED_PATHS = (
    "/usr/local/bin/crabc-x86_64-musl-gcc", "/opt/musl-1.2.6/lib/libc.so", "/opt/musl-1.2.6/lib/libc.a",
    "/opt/musl-1.2.6/lib/musl-gcc.specs",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/bin/rustc",
    "/opt/rustup/toolchains/nightly-2026-07-24-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld",
)

# These are the eight current source-selected legacy aliases.  ``utmpname`` is
# the weak name-provider body; it is checked in raw symbol evidence but is not
# a ninth selected alias relationship.
ALIASES = (
    ("endutent", "endutxent"),
    ("setutent", "setutxent"),
    ("getutent", "getutxent"),
    ("getutid", "getutxid"),
    ("getutline", "getutxline"),
    ("pututline", "pututxline"),
    ("updwtmp", "updwtmpx"),
    ("utmpxname", "utmpname"),
)
STRONG = ("endutxent", "setutxent", "getutxent", "getutxid", "getutxline", "pututxline", "updwtmpx")
WEAK = ("endutent", "setutent", "getutent", "getutid", "getutline", "pututline", "updwtmp", "utmpname", "utmpxname")
TRUSTED_READER_SOURCES = (
    "compat/x86_64/owned_utmpx_receipt.py",
    "compat/x86_64/owned_posix_product_evidence.py",
    "compat/x86_64/owned_dynamic_receipt.py",
    "compat/x86_64/loader_debug_abi_evidence.py",
)
SOURCES = (
    "libc/src/c_abi/x86_64/owned_utmpx.rs",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
    "include/utmp.h",
    "include/utmpx.h",
    "compat/x86_64/owned_utmpx_probe.c",
    "compat/x86_64/owned_utmpx_header_abi_probe.c",
    "compat/x86_64/owned_utmpx_header_abi_probe.cpp",
    "compat/x86_64/run_owned_utmpx.sh",
    "compat/x86_64/owned_utmpx_receipt.py",
    "compat/x86_64/owned_posix_product_evidence.py",
    "compat/x86_64/owned_dynamic_receipt.py",
    "compat/x86_64/loader_debug_abi_evidence.py",
    "compat/x86_64/owned_utmpx_image_inputs.json",
    "docs/evidence/x86-owned-utmpx.md",
    "compat/upstreams.toml",
    "docker/x86_64-musl-oracle-gcc",
)

# Receipt collection always supplies both product families.  That finite matrix
# makes a record missing static aliases, a dynamic executable, or direct-loader
# observations invalid rather than silently accepting a partial runner mode.
COMMAND_ROLES = frozenset({
    "header-oracle-c", "header-oracle-cxx", "header-oracle-undefined-judge",
    "header-project-c", "header-project-cxx", "header-project-undefined-judge",
    "dynamic-driver-compile", "dependency-audit", "oracle-link",
    "archive-symbols", "archive-symbol-bytes", "archive-symbol-judge", "shared-symbols", "shared-symbol-judge",
    "static-link-static", "static-link-static-pie", "dynamic-link-pie", "dynamic-link-non-pie",
    "sealed-link-static", "sealed-link-static-pie", "sealed-link-pie", "sealed-link-non-pie",
    "executable-symbols-static-static", "executable-symbol-bytes-static-static", "executable-symbol-judge-static-static",
    "executable-symbols-static-static-pie", "executable-symbol-bytes-static-static-pie", "executable-symbol-judge-static-static-pie",
    "executable-symbol-bytes-dynamic-pie", "executable-symbol-bytes-dynamic-non-pie",
    "runtime-oracle-ordinary", "runtime-static-static-ordinary", "runtime-static-static-pie-ordinary",
    "runtime-dynamic-pie-kernel-ordinary", "runtime-dynamic-pie-direct-ordinary",
    "runtime-dynamic-non-pie-kernel-ordinary", "runtime-dynamic-non-pie-direct-ordinary",
    "link-identities",
})
# The established static runner loops over ``static`` and ``static-pie`` and
# writes ``$mode-symbols.txt``.  Command role labels include the product family
# to make their link authority unambiguous, but the retained filenames retain
# the runner's original spelling.
STATIC_EXECUTABLE_SYMBOLS = (
    ("static", "static-symbols.txt"),
    ("static-pie", "static-pie-symbols.txt"),
)
# Final-object filenames and raw ``readelf`` renderings use the command-role
# label, whereas the retained-link reader uses the shorter linkage label.
FINAL_ELF_LABELS = {
    "static": "static-static",
    "static-pie": "static-static-pie",
    "pie": "dynamic-pie",
    "non-pie": "dynamic-non-pie",
}
RUNTIME_ROWS = (
    ("oracle", "oracle-ordinary"),
    ("static", "static-static-ordinary"),
    ("static-pie", "static-static-pie-ordinary"),
    ("pie-kernel", "dynamic-pie-kernel-ordinary"),
    ("pie-direct", "dynamic-pie-direct-ordinary"),
    ("non-pie-kernel", "dynamic-non-pie-kernel-ordinary"),
    ("non-pie-direct", "dynamic-non-pie-direct-ordinary"),
)
# ``RUNTIME_ROWS`` names the output leaves the normal runner writes.  Copy the
# finite set from those rows rather than reconstructing names from link modes,
# which would lose the ordinary-scenario suffix.
RUNNER_STREAM_FILES = tuple(
    stream + "." + suffix
    for label, stream in RUNTIME_ROWS if label != "oracle"
    for suffix in ("stdout", "stderr", "status")
)


class ReceiptError(RuntimeError):
    """The bounded utmpx receipt cannot be reconstructed from retained bytes."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def same(left: Any, right: Any, message: str) -> None:
    # JSON serialization retains scalar type distinctions such as False versus
    # 0, which ordinary Python equality would erase.
    require(json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False), message)


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path, label: str) -> dict[str, Any]:
    regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} is not strict JSON") from error
    require(type(value) is dict, f"{label} must be an object")
    return value


def no_links(root: Path, path: Path, label: str) -> Path:
    """Return an absolute path after rejecting every lexical symlink component."""
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ReceiptError(f"{label} escapes receipt root") from error
    cursor = root
    for component in relative.parts:
        cursor /= component
        try:
            require(not stat.S_ISLNK(cursor.lstat().st_mode), f"{label} traverses a symlink")
        except OSError as error:
            raise ReceiptError(f"{label} is unreadable") from error
    return path


def regular(path: Path, label: str) -> Path:
    try:
        require(stat.S_ISREG(path.lstat().st_mode), f"{label} is not a physical regular file")
    except OSError as error:
        raise ReceiptError(f"{label} is unreadable") from error
    return path


def digest(path: Path) -> str:
    regular(path, "hashed receipt artifact")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def identity(root: Path, path: Path) -> dict[str, Any]:
    path = no_links(root, path, "receipt artifact")
    regular(path, "receipt artifact")
    return {"path": path.relative_to(root).as_posix(), "sha256": digest(path),
            "size": path.stat().st_size, "mode": stat.S_IMODE(path.stat().st_mode)}


def check_identity(root: Path, value: Any, label: str) -> Path:
    require(type(value) is dict and set(value) == {"path", "sha256", "size", "mode"}, f"{label} identity fields drifted")
    relative, expected, size, mode = value["path"], value["sha256"], value["size"], value["mode"]
    require(type(relative) is str and relative and not Path(relative).is_absolute() and ".." not in Path(relative).parts,
            f"{label} identity path is invalid")
    require(type(expected) is str and SHA_RE.fullmatch(expected) is not None, f"{label} identity digest is invalid")
    require(type(size) is int and size >= 0 and type(mode) is int and 0 <= mode <= 0o777, f"{label} identity metadata is invalid")
    path = no_links(root, root / relative, label)
    regular(path, label)
    same(identity(root, path), value, f"{label} differs from retained bytes")
    return path


def tree_identity(root: Path, product: Path) -> dict[str, Any]:
    """Seal a product's complete finite tree, including its one declared alias."""
    product = no_links(root, product, "product")
    try:
        require(stat.S_ISDIR(product.lstat().st_mode), "product is not a physical directory")
    except OSError as error:
        raise ReceiptError("product is unreadable") from error
    entries: dict[str, Any] = {}
    for path in sorted(product.rglob("*")):
        relative = path.relative_to(product).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            entries[relative] = {"kind": "directory", "mode": stat.S_IMODE(mode)}
        elif stat.S_ISREG(mode):
            entries[relative] = {"kind": "file", "mode": stat.S_IMODE(mode), "size": path.stat().st_size,
                                 "sha256": digest(path)}
        elif stat.S_ISLNK(mode):
            entries[relative] = {"kind": "symlink", "target": os.readlink(path)}
        else:
            raise ReceiptError(f"product contains non-file entry: {relative}")
    require(entries, "product tree is empty")
    return entries


def copy_regular(source: Path, destination: Path) -> None:
    regular(source, "collected source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists() and not destination.is_symlink(), "receipt output already exists")
    shutil.copyfile(source, destination, follow_symlinks=False)
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode))


def copy_product(source: Path, destination: Path) -> None:
    require(not destination.exists() and not destination.is_symlink(), "receipt product output already exists")
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)


def source_records(root: Path) -> dict[str, Any]:
    return {name: identity(root, root / name) for name in SOURCES}


def image_file_record(invocation: str) -> dict[str, Any]:
    path = Path(invocation).resolve(strict=True)
    regular(path, "pinned image input")
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode)}


def live_image_manifest() -> dict[str, Any]:
    """Regenerate the finite image tool/oracle identity inside the pinned image."""
    paths = [shutil.which(name, path=IMAGE_PATH) for name in IMAGE_COMMANDS]
    require(all(paths), "pinned image omits a required utmpx command")
    paths.extend(IMAGE_FIXED_PATHS)
    try:
        for name in ("cc1", "collect2", "liblto_plugin.so"):
            paths.append(subprocess.check_output(["/usr/bin/gcc", "-print-prog-name=" + name], text=True).strip())
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError("pinned image GCC support identity is unavailable") from error
    require(all(type(path) is str and path.startswith("/") for path in paths), "pinned image command identity differs")
    return {"schema": "crabc.x86_64-owned-utmpx-image-inputs/v1", "image": PINNED_IMAGE_ID,
            "path": IMAGE_PATH, "files": {path: image_file_record(path) for path in sorted(set(paths))}}


def trusted_image_manifest() -> dict[str, Any]:
    value = read_json(ROOT / IMAGE_MANIFEST, "trusted utmpx image manifest")
    require(type(value) is dict and set(value) == {"schema", "image", "path", "files"}
            and value["schema"] == "crabc.x86_64-owned-utmpx-image-inputs/v1"
            and value["image"] == PINNED_IMAGE_ID and value["path"] == IMAGE_PATH
            and type(value["files"]) is dict and value["files"], "trusted utmpx image manifest differs")
    for invocation, record in value["files"].items():
        require(type(invocation) is str and invocation.startswith("/") and type(record) is dict
                and set(record) == {"path", "sha256", "size", "mode"} and type(record["path"]) is str
                and record["path"].startswith("/") and type(record["sha256"]) is str
                and SHA_RE.fullmatch(record["sha256"]) is not None and type(record["size"]) is int and record["size"] >= 0
                and type(record["mode"]) is int and 0 <= record["mode"] <= 0o777,
                "trusted utmpx image manifest file identity differs")
    return value


def validate_retained_image_manifest(workspace: Path, value: Any) -> dict[str, Any]:
    """Bind a copied manifest to the trusted immutable-image input roster."""
    retained = check_identity(workspace, value, "retained image manifest")
    require(value["path"] == IMAGE_MANIFEST, "retained image manifest path differs")
    manifest = read_json(retained, "retained image manifest")
    same(manifest, trusted_image_manifest(), "retained image manifest differs from trusted immutable image inputs")
    return manifest


def validate_image_tool(program: str, retained: Any, workspace: Path, products: Mapping[str, Path], manifest: Mapping[str, Any]) -> None:
    """Admit a tool only as an exact image input or a copied owned product file."""
    check_identity(workspace, retained, "retained native tool")
    if program.startswith(SOURCE_MOUNT + "/"):
        source = workspace / program[len(SOURCE_MOUNT) + 1:]
        no_links(workspace, source, "retained owned tool")
        require(any(source.is_relative_to(product) for product in products.values()), "retained tool escapes copied owned products")
        require(digest(source) == retained["sha256"] and stat.S_IMODE(source.stat().st_mode) == retained["mode"],
                "retained owned tool differs from its copied product")
        return
    expected = manifest["files"].get(program)
    require(type(expected) is dict, "retained tool is not an allowed pinned-image input")
    require({key: retained[key] for key in ("sha256", "size", "mode")} ==
            {key: expected[key] for key in ("sha256", "size", "mode")},
            "retained image tool bytes differ from trusted manifest")


def collected_program_source(program: str, workspace: Path) -> Path:
    """Map a native source-mounted command path to its copied product bytes."""
    require(type(program) is str and program.startswith(SOURCE_MOUNT + "/"),
            "collected command program is not source mounted")
    source = workspace / program[len(SOURCE_MOUNT) + 1:]
    products = (workspace / ".work/utmpx-receipt/inputs/static",
                workspace / ".work/utmpx-receipt/inputs/dynamic")
    require(any(source.is_relative_to(product) for product in products),
            "collected command program escapes copied owned products")
    no_links(workspace, source, "collected owned command program")
    return regular(source, "collected owned command program")


def local_git_head(root: Path) -> str:
    """Read the trusted checkout's current Git epoch without spawning Git."""
    marker = root / ".git"
    try:
        if marker.is_dir() and not marker.is_symlink():
            gitdir = marker.resolve(strict=True)
        else:
            regular(marker, "trusted checkout Git marker")
            text = marker.read_text(encoding="ascii").strip()
            require(text.startswith("gitdir: "), "trusted checkout Git marker differs")
            gitdir = Path(text[len("gitdir: "):])
            if not gitdir.is_absolute():
                gitdir = marker.parent / gitdir
            gitdir = gitdir.resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise ReceiptError("trusted checkout Git marker is unreadable") from error
    regular(gitdir / "HEAD", "trusted checkout HEAD")
    head = (gitdir / "HEAD").read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", head) is not None:
        return head
    require(head.startswith("ref: "), "trusted checkout HEAD differs")
    reference = head[len("ref: "):]
    require(reference.startswith("refs/") and ".." not in Path(reference).parts, "trusted checkout HEAD reference differs")
    common = gitdir
    common_file = gitdir / "commondir"
    if common_file.exists():
        regular(common_file, "trusted checkout common Git directory")
        suffix = common_file.read_text(encoding="ascii").strip()
        require(suffix and not Path(suffix).is_absolute(), "trusted checkout common Git directory differs")
        common = (gitdir / suffix).resolve(strict=True)
        require(common.is_dir(), "trusted checkout common Git directory differs")
    for base in (gitdir, common):
        loose = base / reference
        if loose.is_file() and not loose.is_symlink():
            value = loose.read_text(encoding="ascii").strip()
            if re.fullmatch(r"[0-9a-f]{40}", value) is not None:
                return value
    packed = common / "packed-refs"
    if packed.is_file() and not packed.is_symlink():
        for row in packed.read_text(encoding="ascii").splitlines():
            if row and not row.startswith(("#", "^")):
                value, name = row.split(" ", 1)
                if name == reference and re.fullmatch(r"[0-9a-f]{40}", value) is not None:
                    return value
    raise ReceiptError("trusted checkout HEAD reference has no object identity")

def git_blob_id(path: Path) -> str:
    """Compute Git's SHA-1 blob identity without invoking Git on host replay."""
    data = regular(path, "Git-sealed source").read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def git_source_tree(root: Path, revision: str) -> dict[str, Any]:
    """Capture the clean index's mode/blob rows for this finite source roster."""
    try:
        raw = subprocess.check_output(["git", "ls-files", "--stage", "-z", "--", *SOURCES], cwd=root)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError("receipt collection cannot read the source index") from error
    entries: dict[str, Any] = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        try:
            metadata, encoded = row.split(b"\t", 1)
            mode, blob, stage = metadata.decode("ascii").split()
            name = os.fsdecode(encoded)
        except (UnicodeDecodeError, ValueError) as error:
            raise ReceiptError("receipt collection source index row is malformed") from error
        require(name in SOURCES and stage == "0" and mode in {"100644", "100755"}
                and re.fullmatch(r"[0-9a-f]{40}", blob) is not None and name not in entries,
                "receipt collection source index differs")
        source = root / name
        require(git_blob_id(source) == blob and stat.S_IMODE(source.stat().st_mode) == (int(mode, 8) & 0o777),
                "receipt collection source bytes differ from the clean Git index")
        entries[name] = {"git_mode": mode, "git_blob": blob}
    require(set(entries) == set(SOURCES), "receipt collection source index omits a retained source")
    return {"revision": revision, "entries": entries}

def validate_selected_source(workspace: Path, sources: Mapping[str, Any], source_tree: Any) -> None:
    require(type(source_tree) is dict and set(source_tree) == {"revision", "entries"}
            and type(source_tree["revision"]) is str and re.fullmatch(r"[0-9a-f]{40}", source_tree["revision"]) is not None
            and source_tree["revision"] == local_git_head(ROOT)
            and type(source_tree["entries"]) is dict and set(source_tree["entries"]) == set(SOURCES),
            "source Git tree record differs")
    require(set(sources) == set(SOURCES), "source roster differs")
    for name, record in sources.items():
        path = check_identity(workspace, record, f"source {name}")
        require(record["path"] == name, f"source record path differs: {name}")
        require(path == workspace / name, f"source record location differs: {name}")
        git_entry = source_tree["entries"][name]
        require(type(git_entry) is dict and set(git_entry) == {"git_mode", "git_blob"}
                and git_entry["git_mode"] in {"100644", "100755"}
                and type(git_entry["git_blob"]) is str and re.fullmatch(r"[0-9a-f]{40}", git_entry["git_blob"]) is not None
                and git_blob_id(path) == git_entry["git_blob"] and record["mode"] == (int(git_entry["git_mode"], 8) & 0o777),
                f"source Git identity differs: {name}")
    # The report and its Git rows are evidence, never an admission authority.
    # Replay compares every finite copied source byte and mode to the trusted
    # local checkout at the exact recorded HEAD; coordinated edits to a report,
    # blob row, source digest, or source mode cannot re-authorize themselves.
    for name in SOURCES:
        trusted = ROOT / name
        git_entry = source_tree["entries"][name]
        regular(trusted, "trusted local source")
        require(git_blob_id(trusted) == git_entry["git_blob"]
                and stat.S_IMODE(trusted.stat().st_mode) == (int(git_entry["git_mode"], 8) & 0o777),
                "trusted local source differs from the recorded Git tree: " + name)
        require(digest(trusted) == digest(workspace / name)
                and stat.S_IMODE(trusted.stat().st_mode) == stat.S_IMODE((workspace / name).stat().st_mode),
                "trusted local source differs from the retained source: " + name)
    owned = (workspace / "libc/src/c_abi/x86_64/owned_utmpx.rs").read_text(encoding="utf-8")
    selector = (workspace / "libc/src/c_abi/x86_64/static_c_abi.rs").read_text(encoding="utf-8")
    require("mod owned_utmpx;" in selector, "static runtime no longer selects owned utmpx")
    for alias, target in ALIASES:
        require(f".weak {alias}" in owned and f".set {alias}, {target}" in owned,
                f"owned utmpx source omits selected alias: {alias}")
    for name in STRONG:
        require(f"pub unsafe extern \"C\" fn {name}" in owned, f"owned utmpx source omits provider: {name}")
    # The private musl name is documented in comments but must not appear in
    # the retained archive or shared export streams (checked below).


def archive_members(data: bytes) -> Iterable[tuple[str, bytes]]:
    """Decode only the ordinary GNU ar layout emitted by the owned product."""
    require(data.startswith(b"!<arch>\n"), "retained archive has no GNU ar header")
    cursor, long_names = 8, b""
    while cursor < len(data):
        header = data[cursor:cursor + 60]
        require(len(header) == 60 and header[58:] == b"`\n", "retained archive member header differs")
        name = header[:16].rstrip()
        try:
            size = int(header[48:58])
        except ValueError as error:
            raise ReceiptError("retained archive member size differs") from error
        start = cursor + 60
        body = data[start:start + size]
        require(len(body) == size, "retained archive member is truncated")
        cursor = start + size + size % 2
        if name == b"//":
            long_names = body
        elif name not in (b"/", b"/SYM64/"):
            if name.startswith(b"/"):
                try:
                    offset = int(name[1:])
                except ValueError as error:
                    raise ReceiptError("retained archive long member differs") from error
                end = long_names.find(b"/\n", offset)
                require(0 <= offset < len(long_names) and end >= 0, "retained archive long member differs")
                name = long_names[offset:end]
            else:
                require(name.endswith(b"/"), "retained archive member naming differs")
                name = name[:-1]
            try:
                yield name.decode("ascii"), body
            except UnicodeDecodeError as error:
                raise ReceiptError("retained archive member name differs") from error
    require(cursor == len(data), "retained archive has trailing bytes")


def elf_from_bytes(data: bytes) -> Elf:
    """Use the established local ELF parser over retained bytes, not a tool."""
    require(data[:7] == b"\x7fELF\x02\x01\x01", "retained symbol artifact is not ELF64 little-endian")
    elf = Elf.__new__(Elf)
    elf.data = data
    try:
        require(elf.unpack("<H", 18)[0] == 62, "retained symbol artifact is not native x86-64")
        elf.elf_type = elf.unpack("<H", 16)[0]
        section_offset = elf.unpack("<Q", 40)[0]
        section_size, section_count = elf.unpack("<HH", 58)
        require(section_size == 64 and section_count > 0, "retained symbol artifact has no section table")
        elf.sections = [elf.unpack("<IIQQQQIIQQ", section_offset + index * section_size)
                        for index in range(section_count)]
    except Exception as error:
        if isinstance(error, ReceiptError):
            raise
        raise ReceiptError("retained symbol artifact ELF layout differs") from error
    return elf


def elf_section_name(elf: Elf, section: tuple[Any, ...]) -> str:
    try:
        strings = elf.sections[elf.unpack("<H", 62)[0]]
        start = strings[4] + section[0]
        end = elf.data.find(b"\0", start, strings[4] + strings[5])
        require(strings[4] <= start <= end < len(elf.data), "retained ELF section name differs")
        return elf.data[start:end].decode("ascii")
    except (IndexError, UnicodeDecodeError, ValueError) as error:
        raise ReceiptError("retained ELF section name differs") from error


def expected_symbol_rows(artifact: Path, logical_path: str, tables: frozenset[str]) -> list[tuple[Any, ...]]:
    """Derive every readelf symbol row from an ELF or each member of an ar."""
    data = regular(artifact, "retained symbol artifact").read_bytes()
    members = ([(f"{logical_path}({name})", elf_from_bytes(body)) for name, body in archive_members(data)]
               if data.startswith(b"!<arch>\n") else [("", elf_from_bytes(data))])
    expected: list[tuple[Any, ...]] = []
    for member, elf in members:
        for index, section in enumerate(elf.sections):
            table = elf_section_name(elf, section)
            if section[1] not in (2, 11) or table not in tables:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, "retained ELF symbol table differs")
            for number in range(section[5] // 24):
                try:
                    row = elf.symbol_row(index, number)
                except Exception as error:
                    raise ReceiptError("retained ELF symbol row differs") from error
                kind = {"0": "NOTYPE", "3": "SECTION", "4": "FILE", "5": "COMMON", "6": "TLS", "10": "IFUNC"}.get(row["type"], row["type"])
                name = row["name"]
                if kind == "SECTION" and not name:
                    name = elf_section_name(elf, elf.sections[row["section"]])
                owner = {0: "UND", 0xfff1: "ABS", 0xfff2: "COM"}.get(row["section"], str(row["section"]))
                expected.append((member, table, number, row["value"], row["size"], kind,
                                 row["binding"], row["visibility"], owner, name))
    return expected


def validate_symbol_byte_stream(stream: Path, artifact: Path, logical_path: str, tables: frozenset[str]) -> None:
    """Require raw readelf output to be an exact rendering of retained bytes."""
    expected = expected_symbol_rows(artifact, logical_path, tables)
    actual: list[tuple[Any, ...]] = []
    member, table = "", ""
    try:
        lines = regular(stream, "retained raw symbol stream").read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReceiptError("retained raw symbol stream is not UTF-8") from error
    for line in lines:
        if line.startswith("File: "):
            member, table = line[6:], ""
        elif line.startswith("Symbol table '"):
            try:
                table = line.split("'", 2)[1]
            except IndexError as error:
                raise ReceiptError("retained raw symbol table heading differs") from error
        elif re.match(r"\s*\d+:", line):
            fields = line.split(maxsplit=7)
            require(len(fields) >= 7 and table in tables, "retained raw symbol row differs")
            try:
                name = fields[7].split("@", 1)[0] if len(fields) == 8 else ""
                actual.append((member, table, int(fields[0][:-1]), int(fields[1], 16),
                               int(fields[2], 0) if fields[2].startswith("0x") else int(fields[2]),
                               *fields[3:7], name))
            except ValueError as error:
                raise ReceiptError("retained raw symbol row differs") from error
        else:
            require(not line.strip() or line.lstrip().startswith("Num:"), "retained raw symbol text differs")
    require(actual == expected, "raw symbols do not describe the retained ELF bytes")

def _nm_symbols(path: Path, label: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in {*STRONG, *WEAK}:
            require(fields[2] not in result, f"{label} duplicates provider: {fields[2]}")
            result[fields[2]] = (fields[0], fields[1])
    return result


def validate_symbol_bytes(workspace: Path, products: Mapping[str, Path] | None = None,
                          links: Mapping[str, Any] | None = None) -> dict[str, Any]:
    raw = workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
    if products is not None:
        # These are the exact archive/shared objects named by the reconstructed
        # command roles. Rehash them before interpreting their raw streams.
        static_archive = products["static"] / "usr/lib/libc.a"
        dynamic_shared = products["dynamic"] / "usr/lib/libc.so"
        digest(static_archive)
        digest(dynamic_shared)
        validate_symbol_byte_stream(raw / "archive-symbol-bytes.txt", static_archive,
                                    SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/static/usr/lib/libc.a", frozenset({".symtab"}))
        validate_symbol_byte_stream(raw / "dynamic-symbols.txt", dynamic_shared,
                                    SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/dynamic/usr/lib/libc.so", frozenset({".dynsym"}))
    archive = _nm_symbols(regular(raw / "archive-symbols.txt", "archive symbols"), "archive symbols")
    for name in STRONG:
        require(name in archive and archive[name][1] == "T", f"archive strong provider differs: {name}")
    for name in WEAK:
        require(name in archive and archive[name][1] == "W", f"archive weak provider differs: {name}")
    require(set(archive) == {*STRONG, *WEAK}, "archive symbol roster differs")
    require("__utmpxname" not in (raw / "archive-symbols.txt").read_text(encoding="utf-8"), "archive leaks internal utmpx name")
    for alias, target in ALIASES:
        require(archive[alias][0] == archive[target][0], f"archive alias address differs: {alias}")

    shared: dict[str, tuple[str, str]] = {}
    for line in regular(raw / "dynamic-symbols.txt", "shared symbols").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[7] in {*STRONG, *WEAK} and fields[6] != "UND":
            name = fields[7]
            require(name not in shared, f"shared symbols duplicate provider: {name}")
            shared[name] = (fields[1], fields[4])
    for name in STRONG:
        require(shared.get(name, (None, None))[1] == "GLOBAL", f"shared strong provider differs: {name}")
    for name in WEAK:
        require(shared.get(name, (None, None))[1] == "WEAK", f"shared weak provider differs: {name}")
    require(set(shared) == {*STRONG, *WEAK}, "shared symbol roster differs")
    require("__utmpxname" not in (raw / "dynamic-symbols.txt").read_text(encoding="utf-8"), "shared library leaks internal utmpx name")
    for alias, target in ALIASES:
        require(shared[alias][0] == shared[target][0], f"shared alias address differs: {alias}")
    executables: dict[str, Any] = {}
    for label, name in STATIC_EXECUTABLE_SYMBOLS:
        symbols = _nm_symbols(regular(raw / name, label + " executable symbols"), label + " executable symbols")
        require(set(symbols) == {*STRONG, *WEAK} and all(binding in {"T", "W"} for _, binding in symbols.values()),
                label + " executable provider roster differs")
        for alias, target in ALIASES:
            require(symbols[alias][0] == symbols[target][0], label + " executable alias address differs: " + alias)
        executable = raw / FINAL_ELF_LABELS[label]
        if products is not None:
            validate_symbol_byte_stream(raw / (FINAL_ELF_LABELS[label] + "-symbol-bytes.txt"), executable,
                                        SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt/" + executable.name,
                                        frozenset({".dynsym", ".symtab"}))
        if links is not None:
            require(type(links.get(label)) is dict and links[label].get("executable_sha256") == digest(executable),
                    label + " symbol stream is not bound to its retained linked ELF")
        executables[label] = {symbol: symbols[symbol][1] for symbol in sorted(symbols)}
    imports: dict[str, Any] = {}
    if products is not None:
        for label in ("pie", "non-pie"):
            executable = raw / FINAL_ELF_LABELS[label]
            validate_symbol_byte_stream(raw / (FINAL_ELF_LABELS[label] + "-symbol-bytes.txt"), executable,
                                        SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt/" + executable.name,
                                        frozenset({".dynsym", ".symtab"}))
            rows = expected_symbol_rows(executable, SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt/" + executable.name,
                                        frozenset({".dynsym"}))
            dynamic_imports: dict[str, tuple[Any, ...]] = {}
            for name in (*STRONG, *WEAK):
                matches = [row for row in rows if row[-1] == name]
                require(len(matches) == 1, label + " dynamic import roster differs: " + name)
                row = matches[0]
                require(row[5:9] == ("FUNC", "GLOBAL", "DEFAULT", "UND"),
                        label + " dynamic import differs: " + name)
                dynamic_imports[name] = row
            if links is not None:
                require(type(links.get(label)) is dict and links[label].get("executable_sha256") == digest(executable),
                        label + " import stream is not bound to its retained linked ELF")
            imports[label] = {name: "GLOBAL DEFAULT UND" for name in (*STRONG, *WEAK)}
    return {"archive": {name: archive[name][1] for name in sorted(archive)},
            "shared": {name: shared[name][1] for name in sorted(shared)}, "executables": executables,
            "dynamic_imports": imports}


def expected_command_program(argv0: str) -> str:
    """Resolve a retained command's executable from the trusted image roster."""
    require(type(argv0) is str and argv0, "retained command has no executable")
    if argv0.startswith(SOURCE_MOUNT + "/"):
        return argv0
    manifest = trusted_image_manifest()
    if Path(argv0).is_absolute():
        require(argv0 in manifest["files"], "retained command executable is not an allowed image input")
        return argv0
    matches = [path for path in manifest["files"] if Path(path).name == argv0]
    require(len(matches) == 1, "retained command executable is not uniquely pinned")
    return matches[0]


def command_records(workspace: Path) -> dict[str, Any]:
    directory = workspace / ".work/utmpx-receipt/owned-utmpx-receipt/commands"
    require(directory.is_dir() and not directory.is_symlink(), "command roster directory is missing")
    names = {entry.name for entry in directory.iterdir()}
    expected = {role + ".json" for role in COMMAND_ROLES}
    require(names == expected, "command roster differs")
    records: dict[str, Any] = {}
    for role in COMMAND_ROLES:
        value = read_json(directory / (role + ".json"), f"command {role}")
        require(set(value) == {"schema", "role", "cwd", "status", "program", "argv"}, f"command {role} fields differ")
        require(value["schema"] == COMMAND_SCHEMA and value["role"] == role and value["status"] == 0,
                f"command {role} status or role differs")
        require(type(value["cwd"]) is str and value["cwd"].startswith(SOURCE_MOUNT) and ".." not in Path(value["cwd"]).parts,
                f"command {role} working directory differs")
        require(type(value["program"]) is str and Path(value["program"]).is_absolute() and ".." not in Path(value["program"]).parts,
                f"command {role} program differs")
        require(type(value["argv"]) is list and value["argv"] and all(type(item) is str for item in value["argv"]),
                f"command {role} argv differs")
        require(value["program"] == expected_command_program(value["argv"][0]),
                f"command {role} program does not match its executable")
        records[role] = value
    raw = SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt"
    require(records["archive-symbols"]["cwd"] == SOURCE_MOUNT and records["archive-symbols"]["argv"] ==
            ["nm", "-g", "--defined-only", SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/static/usr/lib/libc.a"],
            "archive symbol command differs")
    require(records["archive-symbol-bytes"]["cwd"] == SOURCE_MOUNT and records["archive-symbol-bytes"]["argv"] ==
            ["readelf", "--symbols", "--wide", SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/static/usr/lib/libc.a"],
            "archive byte-symbol command differs")
    require(records["shared-symbols"]["cwd"] == SOURCE_MOUNT and records["shared-symbols"]["argv"] ==
            ["readelf", "--dyn-syms", "--wide", SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/dynamic/usr/lib/libc.so"],
            "shared symbol command differs")
    for linkage, executable in (("static-static", "static-static"), ("static-static-pie", "static-static-pie")):
        role = "executable-symbols-" + linkage
        require(records[role]["cwd"] == SOURCE_MOUNT and records[role]["argv"] ==
                ["nm", "-g", "--defined-only", raw + "/" + executable], role + " command differs")
    for linkage, executable in (("static-static", "static-static"), ("static-static-pie", "static-static-pie"),
                                ("dynamic-pie", "dynamic-pie"), ("dynamic-non-pie", "dynamic-non-pie")):
        byte_role = "executable-symbol-bytes-" + linkage
        require(records[byte_role]["cwd"] == SOURCE_MOUNT and records[byte_role]["argv"] ==
                ["readelf", "--symbols", "--wide", raw + "/" + executable], byte_role + " command differs")
    for tree in ("oracle", "project"):
        include = [] if tree == "oracle" else ["-I", SOURCE_MOUNT + "/include"]
        c_object = raw + "/" + tree + "-header-c.o"
        cxx_object = raw + "/" + tree + "-header-cxx.o"
        c_role = "header-" + tree + "-c"
        cxx_role = "header-" + tree + "-cxx"
        judge_role = "header-" + tree + "-undefined-judge"
        require(records[c_role]["cwd"] == SOURCE_MOUNT and records[c_role]["argv"] ==
                ["/usr/local/bin/crabc-x86_64-musl-gcc", "-std=c11", "-D_GNU_SOURCE", "-fno-builtin",
                 *include, "-H", "-c", SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_header_abi_probe.c", "-o", c_object],
                c_role + " command differs")
        require(records[cxx_role]["cwd"] == SOURCE_MOUNT and records[cxx_role]["argv"] ==
                ["/usr/local/bin/crabc-x86_64-musl-gcc", "-x", "c++", "-std=c++17", "-D_GNU_SOURCE",
                 "-fno-builtin", "-nostdinc++", *include, "-c",
                 SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_header_abi_probe.cpp", "-o", cxx_object],
                cxx_role + " command differs")
        require(records[judge_role]["cwd"] == SOURCE_MOUNT and records[judge_role]["argv"] ==
                ["python3", "-B", "-", c_object, cxx_object], judge_role + " command differs")
    for linkage in ("static", "static-pie", "pie", "non-pie"):
        role = "sealed-link-" + linkage
        product = SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/" + ("static" if linkage.startswith("static") else "dynamic")
        executable = raw + "/" + ("static-" + linkage if linkage.startswith("static") else "dynamic-" + linkage)
        receipt = executable + (".receipt.json" if linkage.startswith("static") else ".crabc-link.json")
        require(records[role]["cwd"] == SOURCE_MOUNT and records[role]["argv"] ==
                ["python3", "-B", "-", SOURCE_MOUNT, product, raw + "/workload.o", executable, receipt, linkage],
                role + " command differs")
    # Status and a role count are never enough. The expected operation and
    # exact core argv shape are reconstructed from the role's retained bytes.
    require(records["dynamic-driver-compile"]["argv"][1:] == ["--dynamic-pie", "-std=c11", "-fno-builtin", "-c",
            SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_probe.c", "-o", SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt/workload.o"],
            "installed dynamic compile command differs")
    require(records["oracle-link"]["argv"][1:4] == ["-static", "-fno-pie", "-no-pie"], "oracle link command differs")
    for linkage, role in (("static", "static-link-static"), ("static-pie", "static-link-static-pie")):
        argv = records[role]["argv"]
        require(records[role]["cwd"] == raw and argv[1] == "-" + linkage and "--link-receipt" in argv
                and argv[-2:] == ["-o", raw + "/static-" + linkage], f"{linkage} driver command differs")
    for linkage, role in (("pie", "dynamic-link-pie"), ("non-pie", "dynamic-link-non-pie")):
        argv = records[role]["argv"]
        require(records[role]["cwd"] == SOURCE_MOUNT and argv[1:] == ["--dynamic-" + linkage, raw + "/workload.o", "-o",
                              raw + "/dynamic-" + linkage], f"{linkage} driver command differs")
    runtime_roots = {
        "runtime-oracle-ordinary": raw + "/oracle-root",
        "runtime-static-static-ordinary": raw + "/static-static-root",
        "runtime-static-static-pie-ordinary": raw + "/static-static-pie-root",
        "runtime-dynamic-pie-kernel-ordinary": raw + "/dynamic-pie-root",
        "runtime-dynamic-pie-direct-ordinary": raw + "/dynamic-pie-root",
        "runtime-dynamic-non-pie-kernel-ordinary": raw + "/dynamic-non-pie-root",
        "runtime-dynamic-non-pie-direct-ordinary": raw + "/dynamic-non-pie-root",
    }
    for role, root in runtime_roots.items():
        argv = records[role]["argv"]
        suffix = (["/lib/ld-crabc-x86_64.so.1"] if "-direct-" in role else []) + ["/consumer", "ordinary"]
        require(records[role]["cwd"] == SOURCE_MOUNT and argv[:4] == ["timeout", "20", "env", "-i"]
                and len(argv) == 7 + len(suffix) and argv[4].startswith("PATH=")
                and argv[5:7] == ["chroot", root] and argv[7:] == suffix,
                f"{role} runtime command envelope differs")
    return records


def validate_header_bytes(workspace: Path) -> dict[str, str]:
    """Reconstruct the compiled C/C++ header declarations from retained objects."""
    raw = workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
    expected_names = {*STRONG, *WEAK}
    objects: dict[str, Path] = {}
    for tree in ("oracle", "project"):
        trace = regular(raw / (tree + "-header.trace"), tree + " header trace")
        if tree == "project":
            require((SOURCE_MOUNT + "/include/utmpx.h").encode("utf-8") in trace.read_bytes(),
                    "project header witness did not include the copied utmpx header")
        for language in ("c", "cxx"):
            label = tree + "-" + language
            object_file = regular(raw / (tree + "-header-" + language + ".o"), label + " header object")
            rows = expected_symbol_rows(object_file, SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt/" + object_file.name,
                                        frozenset({".symtab"}))
            undefined = {row[9] for row in rows if row[8] == "UND" and row[9] in expected_names}
            require(undefined == expected_names, label + " header declarations differ")
            objects[label] = object_file
    expected_inputs = {
        SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_header_abi_probe.c": workspace / "compat/x86_64/owned_utmpx_header_abi_probe.c",
        SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_header_abi_probe.cpp": workspace / "compat/x86_64/owned_utmpx_header_abi_probe.cpp",
        **{SOURCE_MOUNT + "/.work/utmpx-receipt/owned-utmpx-receipt/" + path.name: path for path in objects.values()},
    }
    rows: dict[str, str] = {}
    for line in regular(raw / "header-input.sha256", "header input hashes").read_text(encoding="ascii").splitlines():
        fields = line.split(maxsplit=1)
        require(len(fields) == 2 and SHA_RE.fullmatch(fields[0]) is not None and fields[1] not in rows,
                "header input hash row differs")
        rows[fields[1]] = fields[0]
    require(set(rows) == set(expected_inputs) and all(rows[name] == digest(path) for name, path in expected_inputs.items()),
            "header input hashes do not describe retained source and objects")
    return {name: digest(path) for name, path in sorted(objects.items())}


def validate_runtime_bytes(workspace: Path) -> dict[str, str]:
    raw = workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
    oracle = regular(raw / "oracle-ordinary.stdout", "oracle stdout").read_bytes()
    try:
        lines = oracle.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReceiptError("oracle raw semantic stream is not ASCII") from error
    ordinary = ("endutxent", "endutent", "setutxent", "setutent", "getutxent", "getutent")
    query = tuple(name + suffix for name in ("getutxid", "getutid", "getutxline", "getutline", "pututxline", "pututline")
                  for suffix in ("", "-null", "-protected"))
    update = ("updwtmpx", "updwtmpx-null", "updwtmp", "updwtmp-null")
    names = ("utmpname-null", "utmpname-protected", "utmpxname-null", "utmpxname-protected")
    expected = ["aliases=1"]
    expected += [name + r" ptr=0 errno=[0-9]+ input=[0-9a-f]{8}" for name in ordinary]
    expected += [name + r" ptr=0 errno=[0-9]+ input=[0-9a-f]{8}" for name in query]
    expected += [name + r" ptr=0 errno=[0-9]+ input=[0-9a-f]{8}" for name in update]
    expected += [name + r" result=-1 errno=[0-9]+ input=[0-9a-f]{8}" for name in names]
    expected += [r"pututxline-zero ptr=0 errno=0 input=[0-9a-f]{8}", "utmpx-ok"]
    require(len(lines) == len(expected) and all(re.fullmatch(pattern, line) is not None
            for pattern, line in zip(expected, lines)), "oracle raw semantic stream differs")
    result: dict[str, str] = {}
    for label, prefix in RUNTIME_ROWS:
        stdout = regular(raw / (prefix + ".stdout"), label + " stdout").read_bytes()
        require(regular(raw / (prefix + ".stderr"), label + " stderr").read_bytes() == b"", label + " stderr differs")
        require(regular(raw / (prefix + ".status"), label + " status").read_bytes() == b"0\n", label + " status differs")
        require(stdout == oracle, label + " output differs from pinned musl")
        result[label] = hashlib.sha256(stdout).hexdigest()
    return result


def validate_compile_bytes(workspace: Path, dynamic_product: Path, tools: Mapping[str, Any]) -> dict[str, Any]:
    """Bind the one installed-driver object and its real preprocessing inputs."""
    raw = workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
    record = read_json(raw / "compile.json", "installed-driver compile record")
    expected = {"schema", "driver_sha256", "manifest_sha256", "source_sha256", "object_sha256",
                "dependency_audit_command", "dependencies"}
    require(set(record) == expected and record["schema"] == "crabc.x86_64-owned-utmpx-compile/v1",
            "installed-driver compile record differs")
    driver = dynamic_product / "bin/crabc-cc-dynamic"
    manifest = dynamic_product / "share/crabc/manifest.json"
    source = workspace / "compat/x86_64/owned_utmpx_probe.c"
    object_file = raw / "workload.o"
    require(record["driver_sha256"] == digest(driver) and record["manifest_sha256"] == digest(manifest)
            and record["source_sha256"] == digest(source) and record["object_sha256"] == digest(object_file),
            "installed-driver compile identities differ")
    command = record["dependency_audit_command"]
    headers = SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/dynamic/usr/include"
    require(type(command) is list and all(type(item) is str for item in command) and len(command) == 11,
            "installed-driver dependency command differs")
    require(command[1:] == ["-nostdinc", "-isystem", headers, "-std=c11", "-ffreestanding", "-fno-builtin",
                            "-fstack-protector-strong", "-fPIE", "-M", SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_probe.c"],
            "installed-driver dependency command arguments differ")
    programs = tools.get("programs") if type(tools) is dict else None
    require(type(programs) is dict and command[0] in programs, "dependency compiler was not retained as a tool")
    dependencies = record["dependencies"]
    require(type(dependencies) is dict and dependencies, "installed-driver dependency roster differs")
    retained: dict[str, str] = {}
    for native_path, expected_hash in dependencies.items():
        require(type(native_path) is str and native_path.startswith(SOURCE_MOUNT + "/") and type(expected_hash) is str
                and SHA_RE.fullmatch(expected_hash) is not None, "installed-driver dependency identity differs")
        path = workspace / native_path[len(SOURCE_MOUNT) + 1:]
        no_links(workspace, path, "installed-driver dependency")
        require(path == source or path.is_relative_to(dynamic_product / "usr/include"),
                "installed-driver dependency escapes copied headers")
        require(digest(path) == expected_hash, "installed-driver dependency bytes differ")
        retained[native_path] = expected_hash
    require(SOURCE_MOUNT + "/compat/x86_64/owned_utmpx_probe.c" in retained,
            "installed-driver dependency roster omits source")
    return record

STATIC_PREPARATION_SCHEMA = "crabc.x86_64-owned-posix-static-preparation/v1"
DYNAMIC_STATE_PATH = "share/crabc/dynamic-product-state.json"
DYNAMIC_STATE_SCHEMA = "crabc.x86_64-owned-dynamic-materialization/v1"
PREPARATION_PATH = ".work/utmpx-receipt/inputs/static-preparation/preparation.json"
PREPARATION_SOURCE_SEALS = ("source-before.json", "source-after.json")


def _source_epoch(value: Any, label: str) -> dict[str, str]:
    require(type(value) is dict and set(value) == {"revision", "content_sha256"}
            and type(value["revision"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["revision"]) is not None
            and type(value["content_sha256"]) is str and SHA_RE.fullmatch(value["content_sha256"]) is not None,
            label + " source epoch differs")
    return {"revision": value["revision"], "content_sha256": value["content_sha256"]}


def _preparation_tree_identity(root: Path, product: Path) -> dict[str, Any]:
    """Match the static preparer's normalized package tree without running it."""
    observed = tree_identity(root, product)
    normalized: dict[str, Any] = {}
    for name, entry in observed.items():
        require(entry["kind"] != "symlink", "static preparation product has a symlink")
        if entry["kind"] == "directory":
            normalized[name] = {"kind": "directory", "mode": 0o755}
        else:
            normalized[name] = {"kind": "file", "mode": 0o755 if entry["mode"] & 0o111 else 0o644,
                                "sha256": entry["sha256"], "size": entry["size"]}
    return normalized


def selected_product_epoch(preparation: Mapping[str, Any], workspace: Path) -> dict[str, str]:
    """Read the retained static preparation's independently sealed product epoch."""
    require(set(preparation) == {"schema", "status", "work", "source", "source_seals", "pins", "products", "archives", "steps"}
            and preparation["schema"] == STATIC_PREPARATION_SCHEMA and preparation["status"] == "prepared-unqualified"
            and type(preparation["work"]) is str and preparation["work"].startswith(".work/")
            and ".." not in Path(preparation["work"]).parts,
            "static preparation contract differs")
    # The static preparation names the selected product epoch.  It may be an
    # earlier committed source cohort than this collector/reader; the receipt
    # records those identities separately.  Do not replace this join with the
    # collector HEAD: that would reject valid frozen product inputs and blur
    # product provenance with the code that later reads it.
    source = _source_epoch(preparation["source"], "static preparation")
    seals = preparation["source_seals"]
    require(type(seals) is dict and set(seals) == set(PREPARATION_SOURCE_SEALS), "static preparation source seals differ")
    for name in PREPARATION_SOURCE_SEALS:
        recorded = seals[name]
        retained = workspace / ".work/utmpx-receipt/inputs/static-preparation" / name
        actual = identity(workspace, retained)
        require(type(recorded) is dict and set(recorded) == {"path", "sha256", "size"}
                and recorded["path"] == preparation["work"] + "/" + name
                and recorded["sha256"] == actual["sha256"] and recorded["size"] == actual["size"],
                "static preparation source seal differs: " + name)
        same(read_json(retained, "retained static preparation " + name), source,
             "static preparation source seal content differs: " + name)
    return source


def _validate_static_preparation(preparation: Mapping[str, Any], workspace: Path, static: Path) -> dict[str, str]:
    """Join the copied static product to its own source-bound preparation."""
    source = selected_product_epoch(preparation, workspace)
    products = preparation["products"]
    require(type(products) is dict and set(products) == {"primary", "reproduction", "extracted"},
            "static preparation product roster differs")
    primary = products["primary"]
    require(type(primary) is dict and set(primary) == {"path", "manifest", "tree", "producer_tools", "toolchain"}
            and primary["path"] == preparation["work"] + "/products/primary"
            and type(primary["tree"]) is dict and primary["tree"],
            "static preparation primary product differs")
    actual_manifest = identity(workspace, static / "share/crabc/manifest.json")
    manifest = primary["manifest"]
    require(type(manifest) is dict and set(manifest) == {"path", "sha256", "size"}
            and manifest["path"] == primary["path"] + "/share/crabc/manifest.json"
            and manifest["sha256"] == actual_manifest["sha256"] and manifest["size"] == actual_manifest["size"],
            "static preparation primary manifest differs")
    same(primary["tree"], _preparation_tree_identity(workspace, static),
         "static preparation primary tree differs from the copied static product")
    return source

def _validate_dynamic_source_epoch(state: Mapping[str, Any], source: Mapping[str, str]) -> None:
    """Reject a dynamic materialization whose whole-source hash names another cohort."""
    required = {"schema", "status", "source_sha256", "contracts", "payload_files", "runtime_v1_published",
                "campaign_complete", "public_support", "modes", "runtime_profile", "qualification"}
    require(set(state) == required and state["schema"] == DYNAMIC_STATE_SCHEMA
            and state["status"] == "materialized-unqualified"
            and state["source_sha256"] == source["content_sha256"]
            and state["runtime_v1_published"] is False and state["campaign_complete"] is False
            and state["public_support"] is False
            and state["modes"] == ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"]
            and type(state["contracts"]) is dict and type(state["runtime_profile"]) is str
            and type(state["qualification"]) is str,
            "dynamic product source cohort differs from static preparation")


def _validate_dynamic_state(workspace: Path, dynamic: Path, source: Mapping[str, str]) -> dict[str, Any]:
    """Bind the materialized dynamic tree and full source digest to the static epoch."""
    state_path = dynamic / DYNAMIC_STATE_PATH
    state = read_json(state_path, "retained dynamic product state")
    _validate_dynamic_source_epoch(state, source)
    try:
        _manifest, files = retained_link_reader._validate_dynamic_product(dynamic)
    except Exception as error:
        raise ReceiptError("copied dynamic product manifest differs") from error
    require(state["payload_files"] == {name: value for name, value in files.items() if name != DYNAMIC_STATE_PATH},
            "dynamic product state payload binding differs")
    return state


def product_cohort(workspace: Path, products: Mapping[str, Path]) -> dict[str, Any]:
    """Derive the selected static/dynamic source cohort from retained product bytes."""
    preparation_path = workspace / PREPARATION_PATH
    preparation = read_json(preparation_path, "retained static preparation")
    static = products["static"]
    dynamic = products["dynamic"]
    try:
        retained_link_reader._validate_static_product(static)
    except Exception as error:
        raise ReceiptError("copied static product manifest differs") from error
    source = _validate_static_preparation(preparation, workspace, static)
    _validate_dynamic_state(workspace, dynamic, source)
    return {
        "source": source,
        "static_preparation": identity(workspace, preparation_path),
        "static_source_before": identity(workspace, workspace / ".work/utmpx-receipt/inputs/static-preparation/source-before.json"),
        "static_source_after": identity(workspace, workspace / ".work/utmpx-receipt/inputs/static-preparation/source-after.json"),
        "static_manifest": identity(workspace, static / "share/crabc/manifest.json"),
        "dynamic_manifest": identity(workspace, dynamic / "share/crabc/manifest.json"),
        "dynamic_state": identity(workspace, dynamic / DYNAMIC_STATE_PATH),
    }


def _product(workspace: Path, value: Any, family: str) -> Path:
    require(type(value) is dict and set(value) == {"workspace_path", "retained_tree"},
            f"{family} product record differs")
    expected = f".work/utmpx-receipt/inputs/{family}"
    require(value["workspace_path"] == expected, f"{family} product path differs")
    path = workspace / expected
    same(tree_identity(workspace, path), value["retained_tree"], f"{family} retained product bytes differ")
    return path


def project_link_product(linkage: str, product: Path, rebuilt: Mapping[str, Any]) -> dict[str, Any]:
    """Express a byte-reconstructed copied product at its fixed native mount."""
    family = "static" if linkage.startswith("static") else "dynamic"
    require(linkage in {"static", "static-pie", "pie", "non-pie"}, "rebuilt link linkage differs")
    require(type(rebuilt) is dict and rebuilt.get("linkage") == linkage and rebuilt.get("product") == str(product),
            "rebuilt link physical product path differs")
    projected = dict(rebuilt)
    projected["product"] = SOURCE_MOUNT + "/.work/utmpx-receipt/inputs/" + family
    return projected


def rebuild_links(workspace: Path, products: Mapping[str, Path], tools: Mapping[str, Any]) -> dict[str, Any]:
    """Use the existing bounded retained-link parser on each copied receipt."""
    evidence = retained_link_reader
    linker = tools.get("linker")
    require(type(linker) is dict and set(linker) == {"native_path", "retained"}, "linker tool seal differs")
    check_identity(workspace, linker["retained"], "retained linker tool")
    native = linker["native_path"]
    require(type(native) is str and Path(native).name == "ld.lld" and Path(native).is_absolute(), "linker native path differs")
    raw = workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
    workload = raw / "workload.o"
    rebuilt: dict[str, Any] = {}
    for linkage in ("static", "static-pie", "pie", "non-pie"):
        product = products["static" if linkage.startswith("static") else "dynamic"]
        executable = raw / ("static-" + linkage if linkage.startswith("static") else "dynamic-" + linkage)
        receipt = Path(str(executable) + (".receipt.json" if linkage.startswith("static") else ".crabc-link.json"))
        try:
            local = evidence.validate_retained_link(
                workspace, SOURCE_MOUNT, product, workload, executable, receipt, linkage,
                {"path": native, "sha256": linker["retained"]["sha256"]},
            )
            rebuilt[linkage] = project_link_product(linkage, product, local)
        except Exception as error:
            raise ReceiptError(f"{linkage} sealed link cannot be reconstructed") from error
    return rebuilt


def validate_link_identity_bytes(workspace: Path, links: Mapping[str, Any]) -> None:
    raw = workspace / ".work/utmpx-receipt/owned-utmpx-receipt"
    record = read_json(raw / "link-identities.json", "native link identities")
    require(set(record) == {"schema", "expected_linkages", "links"}
            and record["schema"] == "crabc.x86_64-owned-utmpx-link-identities/v1"
            and record["expected_linkages"] == ["non-pie", "pie", "static", "static-pie"],
            "native link identity roster differs")
    same(record["links"], links, "native link identities differ from reconstructed links")

def validate_report(path: Path) -> dict[str, Any]:
    """Reconstruct a receipt exclusively from retained bytes; never execute tools."""
    path = Path(path).absolute()
    root = path.parent
    try:
        require(root.is_dir() and not root.is_symlink(), "receipt report parent is not physical")
    except OSError as error:
        raise ReceiptError("receipt report parent is unreadable") from error
    value = read_json(path, "utmpx receipt report")
    expected = {"schema", "image", "source_tree", "sources", "products", "product_cohort", "tools", "commands", "symbols", "runtime", "links", "projection"}
    require(set(value) == expected and value["schema"] == SCHEMA, "utmpx receipt schema differs")
    require(type(value["image"]) is dict and set(value["image"]) == {"id", "manifest"}
            and value["image"]["id"] == PINNED_IMAGE, "receipt image record differs")
    workspace = root / "workspace"
    no_links(root, workspace, "receipt workspace")
    require(workspace.is_dir(), "receipt workspace is missing")
    validate_retained_image_manifest(workspace, value["image"]["manifest"])
    validate_selected_source(workspace, value["sources"], value["source_tree"])
    require(type(value["products"]) is dict and set(value["products"]) == {"static", "dynamic"}, "product families differ")
    products = {family: _product(workspace, value["products"][family], family) for family in ("static", "dynamic")}
    same(value["product_cohort"], product_cohort(workspace, products),
         "reported selected product cohort is not reconstructed from retained products")
    commands = command_records(workspace)
    same(value["commands"], {role: identity(workspace, workspace / ".work/utmpx-receipt/owned-utmpx-receipt/commands" / (role + ".json"))
                             for role in sorted(COMMAND_ROLES)}, "reported command identities differ")
    require(type(value["tools"]) is dict and set(value["tools"]) == {"linker", "programs"}, "tool roster differs")
    compile_record = read_json(workspace / ".work/utmpx-receipt/owned-utmpx-receipt/compile.json", "installed-driver compile record")
    dependency_tool = compile_record.get("dependency_audit_command", [None])[0]
    linker_record = value["tools"].get("linker")
    require(type(linker_record) is dict and type(linker_record.get("native_path")) is str, "linker tool seal differs")
    expected_programs = {record["program"] for record in commands.values()} | {dependency_tool, linker_record["native_path"]}
    require(type(value["tools"]["programs"]) is dict and set(value["tools"]["programs"]) == expected_programs,
            "retained program roster differs")
    for program, record in value["tools"]["programs"].items():
        require(type(program) is str and type(record) is dict and set(record) == {"native_path", "retained"} and record["native_path"] == program,
                "retained program record differs")
        validate_image_tool(program, record["retained"], workspace, products, trusted_image_manifest())
    compile = validate_compile_bytes(workspace, products["dynamic"], value["tools"])
    require(compile["dependency_audit_command"][0] in value["tools"]["programs"], "dependency compiler tool seal differs")
    require(type(value["links"]) is dict and set(value["links"]) == {"static", "static-pie", "pie", "non-pie"}, "link roster differs")
    links = rebuild_links(workspace, products, value["tools"])
    validate_link_identity_bytes(workspace, links)
    same(value["links"], links, "reported link identities differ")
    symbols = {"headers": validate_header_bytes(workspace), **validate_symbol_bytes(workspace, products, links)}
    same(value["symbols"], symbols, "reported symbol facts differ")
    runtime = validate_runtime_bytes(workspace)
    same(value["runtime"], runtime, "reported runtime facts differ")
    projection = {"selected_aliases": [list(pair) for pair in ALIASES], "component_complete": True,
                  "family_complete": False, "runtime_qualified": False, "public_support": False,
                  "linkages": sorted(links), "runtime_streams": sorted(runtime)}
    same(value["projection"], projection, "reported projection is not reconstructed from retained evidence")
    return value


def _copy_workspace_file(root: Path, workspace: Path, native: Path, source: Path) -> None:
    relative = source.relative_to(root)
    copy_regular(source, workspace / relative)


def _copy_native_file(workspace: Path, native: Path, source: Path) -> None:
    copy_regular(source, workspace / ".work/utmpx-receipt/owned-utmpx-receipt" / source.relative_to(native))


def retain_native_runner_failure(output: Path, stdout: bytes, stderr: bytes, status: int) -> None:
    """Keep raw native diagnostics for a failed fresh collection, never a receipt."""
    require(type(status) is int and status != 0, "native failure status differs")
    output.mkdir(parents=True)
    stdout_path = output / "native-runner.stdout"
    stderr_path = output / "native-runner.stderr"
    status_path = output / "native-runner.status"
    record_path = output / "native-runner-failure.json"
    require(not any(path.exists() or path.is_symlink() for path in (stdout_path, stderr_path, status_path, record_path)),
            "native failure diagnostics already exist")
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    status_path.write_text(str(status) + "\n", encoding="ascii")
    record_path.write_text(json.dumps({
        "schema": "crabc.x86_64-owned-utmpx-native-runner-failure/v1",
        "status": status,
        "stdout": "native-runner.stdout",
        "stderr": "native-runner.stderr",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def clean_source_revision() -> str:
    """Refuse a stale or mixed source tree before native evidence is observed."""
    try:
        status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError("receipt collection cannot seal the source revision") from error
    require(not status and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
            "receipt collection requires a clean committed source tree")
    return revision


def collect(static_preparation: Path, static_product: Path, dynamic_product: Path, output: Path) -> dict[str, Any]:
    """Run the native runner once and retain the closed full static/dynamic matrix."""
    expected_image = trusted_image_manifest()
    same(live_image_manifest(), expected_image, "live native image differs from its immutable utmpx manifest")
    require(ROOT == Path(SOURCE_MOUNT), "native collection requires the pinned /workspace mount")
    output = Path(output).absolute()
    require(output.is_relative_to(ROOT / ".work") and output != ROOT / ".work", "receipt output must be a checkout .work child")
    require(not output.exists() and not output.is_symlink(), "receipt output already exists")
    static_preparation = Path(static_preparation).absolute()
    no_links(ROOT, static_preparation, "static preparation input")
    require(static_preparation.is_relative_to(ROOT / ".work") and static_preparation.name == "preparation.json",
            "static preparation must be a physical checkout .work preparation.json")
    preparation_files = {"preparation.json": static_preparation,
                         **{name: static_preparation.parent / name for name in PREPARATION_SOURCE_SEALS}}
    for name, input_path in preparation_files.items():
        no_links(ROOT, input_path, "static preparation " + name)
        regular(input_path, "static preparation " + name)
    before_preparation = {name: identity(ROOT, input_path) for name, input_path in preparation_files.items()}
    for product, family in ((static_product, "static"), (dynamic_product, "dynamic")):
        product = Path(product).absolute()
        no_links(ROOT, product, family + " input product")
        require(product.is_relative_to(ROOT / ".work") and product.is_dir(), family + " product must be a physical checkout .work directory")
    require(Path(static_product).absolute() != Path(dynamic_product).absolute(), "receipt product inputs must differ")
    revision = clean_source_revision()
    before_sources = source_records(ROOT)
    source_tree = git_source_tree(ROOT, revision)
    before_trees = {"static": tree_identity(ROOT, Path(static_product).absolute()),
                    "dynamic": tree_identity(ROOT, Path(dynamic_product).absolute())}
    workspace = output / "workspace"
    stage = ROOT / ".work/utmpx-receipt"
    require(output != stage and not output.is_relative_to(stage), "receipt output overlaps the native evidence leaf")
    require(not stage.exists() and not stage.is_symlink(), "native receipt evidence leaf already exists")
    try:
        # Native commands see these fixed checkout-relative paths.  The later
        # copy below recreates the same tree below ``workspace`` without
        # rewriting any receipt path or accepting a host path substitution.
        stage.mkdir(parents=True)
        copy_product(Path(static_product).absolute(), stage / "inputs/static")
        copy_product(Path(dynamic_product).absolute(), stage / "inputs/dynamic")
        command = [str(ROOT / "compat/x86_64/run_owned_utmpx.sh"), "--static-sysroot",
                   str(stage / "inputs/static"), str(stage / "inputs/dynamic")]
        environment = {**os.environ, "TMPDIR": str(stage), "CRABC_X86_64_RETAIN_UTMPX_COMMANDS": "1"}
        completed = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode != 0:
            retain_native_runner_failure(output, completed.stdout, completed.stderr, completed.returncode)
            raise ReceiptError("native owned-utmpx runner failed; retained raw diagnostics")
        match = re.search(rb"owned utmpx evidence: (.+)\n", completed.stdout)
        require(match is not None, "native runner did not publish its evidence directory")
        native = Path(match.group(1).decode("utf-8")).absolute()
        no_links(ROOT, native, "native runner evidence")
        require(native == stage / "owned-utmpx-receipt" and native.is_dir(),
                "native runner evidence path differs from retained contract")
        for name in SOURCES:
            copy_regular(ROOT / name, workspace / name)
        for name, input_path in preparation_files.items():
            copy_regular(input_path, workspace / ".work/utmpx-receipt/inputs/static-preparation" / name)
        copy_product(stage / "inputs/static", workspace / ".work/utmpx-receipt/inputs/static")
        copy_product(stage / "inputs/dynamic", workspace / ".work/utmpx-receipt/inputs/dynamic")
        needed = [
            "archive-symbols.txt", "archive-symbol-bytes.txt", "dynamic-symbols.txt", "compile.json", "workload.o", "link-identities.json",
            "header-input.sha256", "oracle-header.trace", "project-header.trace", "oracle-header-c.o", "oracle-header-cxx.o",
            "project-header-c.o", "project-header-cxx.o",
            "oracle", "oracle-ordinary.stdout", "oracle-ordinary.stderr", "oracle-ordinary.status",
            "static-static", "static-static.receipt.json", "static-static.receipt.map", "static-static.receipt.trace", "static-symbols.txt", "static-static-symbol-bytes.txt",
            "static-static-pie", "static-static-pie.receipt.json", "static-static-pie.receipt.map", "static-static-pie.receipt.trace", "static-pie-symbols.txt", "static-static-pie-symbol-bytes.txt",
            "dynamic-pie", "dynamic-pie.crabc-link.json", "dynamic-pie-symbol-bytes.txt",
            "dynamic-non-pie", "dynamic-non-pie.crabc-link.json", "dynamic-non-pie-symbol-bytes.txt",
        ]
        needed.extend(RUNNER_STREAM_FILES)
        for name in needed:
            _copy_native_file(workspace, native, native / name)
        for record in sorted((native / "commands").glob("*.json")):
            _copy_native_file(workspace, native, record)
        require(clean_source_revision() == revision and source_records(ROOT) == before_sources
                and live_image_manifest() == expected_image,
                "source or pinned image changed during native utmpx receipt collection")
        require(tree_identity(ROOT, Path(static_product).absolute()) == before_trees["static"], "static product changed during collection")
        require(tree_identity(ROOT, Path(dynamic_product).absolute()) == before_trees["dynamic"], "dynamic product changed during collection")
        require({name: identity(ROOT, input_path) for name, input_path in preparation_files.items()} == before_preparation,
                "static preparation changed during collection")
        shutil.rmtree(stage)
        commands = command_records(workspace)
        tools: dict[str, Any] = {"programs": {}}
        compile_record = read_json(workspace / ".work/utmpx-receipt/owned-utmpx-receipt/compile.json", "collected compile record")
        nested_compiler = compile_record.get("dependency_audit_command", [None])[0]
        require(type(nested_compiler) is str and Path(nested_compiler).is_absolute(),
                "collected dependency compiler is invalid")
        for program in sorted({record["program"] for record in commands.values()} | {nested_compiler}):
            target = (collected_program_source(program, workspace)
                      if program.startswith(SOURCE_MOUNT + "/") else Path(program).resolve(strict=True))
            require(target.is_file() and not target.is_symlink(), "native command program is not physical")
            retained = workspace / "tools" / hashlib.sha256(program.encode()).hexdigest()
            copy_regular(target, retained)
            tools["programs"][program] = {"native_path": program, "retained": identity(workspace, retained)}
        # The sealed receipts, not a report-only field, identify the actual
        # LLD invocation that each installed driver used.
        receipt_linkers = []
        for name in ("static-static.receipt.json", "static-static-pie.receipt.json",
                     "dynamic-pie.crabc-link.json", "dynamic-non-pie.crabc-link.json"):
            received = read_json(workspace / ".work/utmpx-receipt/owned-utmpx-receipt" / name, "collected link receipt")
            linker = received.get("resolved_linker")
            require(type(linker) is dict and set(linker) == {"path", "sha256"}
                    and type(linker["path"]) is str and Path(linker["path"]).name == "ld.lld"
                    and type(linker["sha256"]) is str and SHA_RE.fullmatch(linker["sha256"]) is not None,
                    "collected link receipt linker differs")
            receipt_linkers.append(linker)
        require(all(linker == receipt_linkers[0] for linker in receipt_linkers),
                "collected link receipts disagree about linker identity")
        linker_path = receipt_linkers[0]["path"]
        if linker_path not in tools["programs"]:
            target = (collected_program_source(linker_path, workspace)
                      if linker_path.startswith(SOURCE_MOUNT + "/") else Path(linker_path).resolve(strict=True))
            require(target.is_file() and not target.is_symlink(), "sealed linker is not physical")
            retained = workspace / "tools" / hashlib.sha256(linker_path.encode()).hexdigest()
            copy_regular(target, retained)
            tools["programs"][linker_path] = {"native_path": linker_path, "retained": identity(workspace, retained)}
        tools["linker"] = tools["programs"][linker_path]
        require(tools["linker"]["retained"]["sha256"] == receipt_linkers[0]["sha256"],
                "sealed linker bytes differ from receipt")
        products = {family: {"workspace_path": f".work/utmpx-receipt/inputs/{family}",
                             "retained_tree": tree_identity(workspace, workspace / f".work/utmpx-receipt/inputs/{family}")}
                    for family in ("static", "dynamic")}
        product_paths = {key: workspace / value["workspace_path"] for key, value in products.items()}
        cohort = product_cohort(workspace, product_paths)
        report = {"schema": SCHEMA, "image": {"id": PINNED_IMAGE, "manifest": identity(workspace, workspace / IMAGE_MANIFEST)},
                  "source_tree": source_tree, "sources": {name: identity(workspace, workspace / name) for name in SOURCES}, "products": products,
                  "product_cohort": cohort, "tools": tools,
                  "commands": {role: identity(workspace, workspace / ".work/utmpx-receipt/owned-utmpx-receipt/commands" / (role + ".json")) for role in sorted(COMMAND_ROLES)},
                  "symbols": {}, "runtime": validate_runtime_bytes(workspace), "links": {}, "projection": {}}
        report["links"] = rebuild_links(workspace, product_paths, tools)
        report["symbols"] = {"headers": validate_header_bytes(workspace),
                             **validate_symbol_bytes(workspace, product_paths, report["links"])}
        report["projection"] = {
            "selected_aliases": [list(pair) for pair in ALIASES], "component_complete": True,
            "family_complete": False, "runtime_qualified": False, "public_support": False,
            "linkages": sorted(report["links"]), "runtime_streams": sorted(report["runtime"]),
        }
        report_path = output / "report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validate_report(report_path)
        return report
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        if not (output / "native-runner-failure.json").is_file():
            shutil.rmtree(output, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    collect_parser = subcommands.add_parser("collect")
    collect_parser.add_argument("--static-preparation", type=Path, required=True)
    collect_parser.add_argument("--static-product", type=Path, required=True)
    collect_parser.add_argument("--dynamic-product", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    image_parser = subcommands.add_parser("image-input-manifest")
    image_parser.add_argument("--output", type=Path)
    validate_parser = subcommands.add_parser("validate-report")
    validate_parser.add_argument("report", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.action == "collect":
            result = collect(arguments.static_preparation, arguments.static_product, arguments.dynamic_product, arguments.output)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif arguments.action == "image-input-manifest":
            result = live_image_manifest()
            if arguments.output is None:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                require(not arguments.output.exists() and not arguments.output.is_symlink(), "image manifest output already exists")
                arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            print(json.dumps(validate_report(arguments.report), indent=2, sort_keys=True))
    except ReceiptError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
