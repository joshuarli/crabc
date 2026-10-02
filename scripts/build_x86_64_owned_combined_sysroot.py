#!/usr/bin/env python3
"""Compose the one installed x86-64 sysroot that owns all selected link modes.

The installed sysroot carries headers, CRT objects, ``libc.a``, shared libc,
the interpreter and its compatibility alias, compiler helpers, the selected
allocator and deterministic link specifications. The static and dynamic
products keep separate producers, so static delivery never depends on dynamic
startup. This owner builds both from the same live source into private staging
and composes them into one regular-file tree. The composition rules are exact:

* Two products installing the same runtime path (headers, CRT objects,
  archives, drivers) must supply identical bytes and mode. In particular
  ``usr/lib/crt1.o`` is the ``ET_EXEC`` entry of both static and dynamic
  non-PIE links, so one object must serve both.
* ``usr/lib/Scrt1.o`` is the dynamic-PIE entry. No static mode links it, so
  the static producer's own copy is recorded as not installed.
* Each product's own manifest moves to ``share/crabc/<product>/manifest.json``.
  Other product metadata keeps its path unless the products disagree, in
  which case both copies move under ``share/crabc/<product>/``.
* Any other disagreement fails closed. No product is preferred.

Composition is not qualification: the combined gate separately compares two
clean builds, packages and extracts one, and runs the product suites.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_static_sysroot_package as shared_package

FORMAT = "crabc-x86-64-owned-sysroot-v1"
TARGET = "x86_64-unknown-linux-musl"
MANIFEST = "share/crabc/manifest.json"
DYNAMIC_STATE = "share/crabc/dynamic-product-state.json"
DYNAMIC_STATE_SCHEMA = "crabc.x86_64-owned-dynamic-materialization/v1"
METADATA_PREFIX = "share/crabc/"
PRODUCTS = ("static", "dynamic")
PRODUCT_BUILDERS = {
    "static": "scripts/build_x86_64_owned_sysroot.py",
    "dynamic": "scripts/build_x86_64_owned_dynamic_sysroot.py",
}
PRODUCT_FORMATS = {
    "static": "crabc-x86-64-owned-static-sysroot-v1",
    "dynamic": "crabc-x86-64-owned-dynamic-sysroot-v1",
}
# Installed modules imported by an installed driver. They are runtime files,
# not relocatable metadata, even though they live below share/crabc/.
DRIVER_MODULES = frozenset({
    "share/crabc/crabc_cc_static.py",
    "share/crabc/owned_dynamic_receipt.py",
    "share/crabc/owned_dynamic_elf.py",
})
# One product owns a runtime path that the other installs but never links.
ENTRY_OWNERS = {"usr/lib/Scrt1.o": "dynamic"}
MODES = ("static-et-exec", "static-pie", "dynamic-pie", "dynamic-non-pie", "dynamic-shared-object")
MAX_ARCHIVE_MEMBERS = shared_package.MAX_ARCHIVE_MEMBER_COUNT


class CompositionError(RuntimeError):
    """The two owned products cannot form one exact installed sysroot."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompositionError(message)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree(root: Path) -> tuple[dict[str, tuple[str, bool]], dict[str, str]]:
    """Return every regular file (hash, executable) and symlink below a root."""

    files: dict[str, tuple[str, bool]] = {}
    links: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        details = path.lstat()
        if stat.S_ISLNK(details.st_mode):
            links[relative] = os.readlink(path)
        elif stat.S_ISREG(details.st_mode):
            files[relative] = (sha256_file(path), bool(details.st_mode & 0o111))
        else:
            require(stat.S_ISDIR(details.st_mode), f"non-regular installed entry: {relative}")
    return files, links


def product_manifest(root: Path, product: str) -> dict:
    try:
        record = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CompositionError(f"{product} product manifest is unreadable") from error
    require(isinstance(record, dict) and record.get("format") == PRODUCT_FORMATS[product]
            and record.get("target") == TARGET, f"{product} product manifest identity differs")
    return record


def require_matching_source_seals(static_manifest: dict, dynamic_state_payload: bytes) -> None:
    """Require the two embedded products to claim the same complete source tree."""

    static_source = static_manifest.get("source_sha256")
    require(isinstance(static_source, str) and len(static_source) == 64
            and all(character in "0123456789abcdef" for character in static_source),
            "static product source seal is missing or invalid")
    try:
        dynamic_state = json.loads(dynamic_state_payload)
    except (ValueError, UnicodeDecodeError) as error:
        raise CompositionError("dynamic product state is invalid") from error
    require(isinstance(dynamic_state, dict) and dynamic_state.get("schema") == DYNAMIC_STATE_SCHEMA,
            "dynamic product state identity differs")
    dynamic_source = dynamic_state.get("source_sha256")
    require(isinstance(dynamic_source, str) and len(dynamic_source) == 64
            and all(character in "0123456789abcdef" for character in dynamic_source),
            "dynamic product source seal is missing or invalid")
    require(static_source == dynamic_source, "static and dynamic product source seals differ")
    # All four entry modes share one allocator and one instrumentation contract.
    for field, default in (("allocator_backend", "accepted-c"), ("build_profile", "release"),
                           ("allocator_lifecycle_test_audit", False)):
        require(static_manifest.get(field, default) == dynamic_state.get(field, default),
                f"static and dynamic product configuration differs: {field}")


def dynamic_state_destination(record: dict) -> str:
    products = record.get("products")
    dynamic = products.get("dynamic") if isinstance(products, dict) else None
    placements = dynamic.get("placements") if isinstance(dynamic, dict) else None
    destination = placements.get(DYNAMIC_STATE) if isinstance(placements, dict) else None
    require(isinstance(destination, str) and destination in record.get("files", {}),
            "combined product does not place dynamic product state")
    return destination


def plan(products: Mapping[str, Path]) -> dict:
    """Decide every installed path from two validated product trees."""

    require(tuple(products) == PRODUCTS, "composition requires the static and dynamic products")
    trees = {name: tree(root) for name, root in products.items()}
    manifests = {name: product_manifest(root, name) for name, root in products.items()}
    try:
        dynamic_state = (products["dynamic"] / DYNAMIC_STATE).read_bytes()
    except OSError as error:
        raise CompositionError("dynamic product state is missing") from error
    require_matching_source_seals(manifests["static"], dynamic_state)
    toolchains = {record.get("toolchain") for record in manifests.values()}
    require(len(toolchains) == 1 and isinstance(next(iter(toolchains)), str),
            "products were built by different Rust toolchains")

    sources: dict[str, tuple[str, str]] = {}  # installed path -> (product, product path)
    placements: dict[str, dict[str, str | None]] = {name: {} for name in PRODUCTS}
    conflicts: list[str] = []

    def install(destination: str, owner: str, origin: str, readers: list[str]) -> None:
        require(destination not in sources, f"two product files claim installed path {destination}")
        sources[destination] = (owner, origin)
        for name in readers:
            placements[name][origin] = destination

    paths = sorted({path for files, _ in trees.values() for path in files})
    for path in paths:
        owners = [name for name in PRODUCTS if path in trees[name][0]]
        relocatable = path.startswith(METADATA_PREFIX) and path not in DRIVER_MODULES
        if path == MANIFEST or (relocatable and len({trees[name][0][path] for name in owners}) > 1):
            for name in owners:
                install(f"{METADATA_PREFIX}{name}/{path[len(METADATA_PREFIX):]}", name, path, [name])
        elif len({trees[name][0][path] for name in owners}) == 1:
            install(path, owners[0], path, owners)
        elif path in ENTRY_OWNERS:
            install(path, ENTRY_OWNERS[path], path, [ENTRY_OWNERS[path]])
            for name in owners:
                placements[name].setdefault(path, None)
        else:
            conflicts.append(path)
    require(not conflicts, "static and dynamic products install different bytes at shared runtime "
            f"paths: {', '.join(conflicts)}")

    links: dict[str, str] = {}
    for name in PRODUCTS:
        for path, target in trees[name][1].items():
            require(links.setdefault(path, target) == target, f"products disagree on symlink {path}")
            require(path not in sources, f"symlink collides with a regular file: {path}")
    for destination in sources:
        parents = PurePosixPath(destination).parents
        require(not any(parent.as_posix() in sources or parent.as_posix() in links for parent in parents),
                f"installed path is also an ancestor: {destination}")
    return {
        "sources": dict(sorted(sources.items())),
        "files": {path: trees[name][0][origin][0] for path, (name, origin) in sorted(sources.items())},
        "executables": sorted(path for path, (name, origin) in sources.items() if trees[name][0][origin][1]),
        "symlinks": dict(sorted(links.items())),
        "placements": {name: dict(sorted(placement.items())) for name, placement in placements.items()},
        "toolchain": next(iter(toolchains)),
    }


def manifest_record(decision: Mapping) -> dict:
    return {
        "schema": 1,
        "format": FORMAT,
        "target": TARGET,
        "toolchain": decision["toolchain"],
        "modes": list(MODES),
        "files": decision["files"],
        "executables": decision["executables"],
        "symlinks": decision["symlinks"],
        "products": {
            name: {"format": PRODUCT_FORMATS[name], "manifest": f"{METADATA_PREFIX}{name}/manifest.json",
                   "placements": decision["placements"][name]}
            for name in PRODUCTS
        },
    }


def compose(products: Mapping[str, Path], output: Path) -> dict:
    """Materialize one composed tree at a fresh private path."""

    decision = plan(products)
    require(not output.exists() and not output.is_symlink(), "composition output already exists")
    output.mkdir()
    for destination, (name, origin) in decision["sources"].items():
        path = output / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((products[name] / origin).read_bytes())
        path.chmod(0o755 if destination in decision["executables"] else 0o644)
    for destination, target in decision["symlinks"].items():
        path = output / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
    record = manifest_record(decision)
    (output / MANIFEST).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / MANIFEST).chmod(0o644)
    validate(output)
    return record


def validate_component_claims(record: dict, embedded_payloads: Mapping[str, bytes | None]) -> None:
    """Require every installed file to be claimed by a placed component file."""

    products = record.get("products")
    require(isinstance(products, dict) and set(products) == set(PRODUCTS),
            "combined package component roster differs")
    require(record.get("schema") == 1 and record.get("target") == TARGET
            and isinstance(record.get("toolchain"), str) and record.get("modes") == list(MODES),
            "combined package identity differs")
    claims: dict[str, str] = {}
    static_manifest: dict | None = None
    for name in PRODUCTS:
        manifest_path = f"{METADATA_PREFIX}{name}/manifest.json"
        component = products[name]
        require(isinstance(component, dict) and set(component) == {"format", "manifest", "placements"}
                and component["format"] == PRODUCT_FORMATS[name]
                and component["manifest"] == manifest_path
                and isinstance(component["placements"], dict),
                f"combined package {name} placement identity differs")
        payload = embedded_payloads.get(manifest_path)
        require(isinstance(payload, bytes), f"combined package {name} manifest is missing")
        try:
            embedded = json.loads(payload)
        except (ValueError, UnicodeDecodeError) as error:
            raise CompositionError(f"combined package {name} manifest is invalid") from error
        require(isinstance(embedded, dict) and embedded.get("schema") == 1
                and embedded.get("format") == PRODUCT_FORMATS[name]
                and embedded.get("target") == TARGET
                and embedded.get("toolchain") == record["toolchain"],
                f"combined package {name} manifest identity differs")
        if name == "static":
            static_manifest = embedded
        installed = embedded.get("installed")
        if name == "static":
            component_files = installed.get("files") if isinstance(installed, dict) else None
        else:
            component_files = embedded.get("files")
        require(isinstance(component_files, dict)
                and all(isinstance(path, str) and isinstance(digest, str)
                        for path, digest in component_files.items()),
                f"combined package {name} file roster differs")
        if name == "dynamic":
            require(DYNAMIC_STATE in component_files,
                    "dynamic product manifest omits its source-bound state")
            require(embedded.get("symlinks") == record["symlinks"],
                    "combined package aliases differ from dynamic component")
        placements = component["placements"]
        require(set(placements) == set(component_files) | {MANIFEST}
                and placements[MANIFEST] == manifest_path,
                f"combined package {name} placement roster differs")
        for origin, digest in {**component_files, MANIFEST: sha256_bytes(payload)}.items():
            destination = placements[origin]
            if destination is None:
                require(name == "static" and origin == "usr/lib/Scrt1.o",
                        f"combined package {name} omits a required placement")
                continue
            require(isinstance(destination, str) and record["files"].get(destination) == digest,
                    f"combined package {name} placement payload differs: {origin}")
            require(destination not in claims or claims[destination] == digest,
                    f"combined package {name} placement conflicts: {origin}")
            claims[destination] = digest
    require(claims == record["files"], "unclaimed package payload")
    state_payload = embedded_payloads.get(dynamic_state_destination(record))
    require(isinstance(state_payload, bytes), "combined package dynamic product state is missing")
    require(static_manifest is not None, "combined package static manifest is missing")
    require_matching_source_seals(static_manifest, state_payload)


def validate(root: Path) -> dict:
    """Require the exact manifested regular-file, mode and symlink roster."""

    try:
        record = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CompositionError("combined manifest is unreadable") from error
    require(isinstance(record, dict) and record.get("schema") == 1 and record.get("format") == FORMAT
            and record.get("target") == TARGET and record.get("modes") == list(MODES),
            "combined manifest identity differs")
    files, links = tree(root)
    manifest_identity = files.pop(MANIFEST, None)
    require(manifest_identity is not None and not manifest_identity[1], "combined manifest is not a plain file")
    require({path: digest for path, (digest, _) in files.items()} == record.get("files"),
            "installed payload differs from the combined manifest")
    require(sorted(path for path, (_, executable) in files.items() if executable) == record.get("executables"),
            "installed executable modes differ from the combined manifest")
    require(links == record.get("symlinks"), "installed symlinks differ from the combined manifest")
    for path, target in links.items():
        resolved = PurePosixPath(path).parent / target
        require("/" not in target and resolved.as_posix() in files, f"symlink escapes the payload: {path}")
    state_destination = dynamic_state_destination(record)
    validate_component_claims(record, {
        **{f"{METADATA_PREFIX}{name}/manifest.json":
           (root / f"{METADATA_PREFIX}{name}/manifest.json").read_bytes() for name in PRODUCTS},
        state_destination: (root / state_destination).read_bytes(),
    })
    return record


def package(root: Path, output: Path) -> None:
    """Write one deterministic USTAR archive of a validated combined tree."""

    record = validate(root)
    require(not output.exists() and not output.is_symlink(), "package output already exists")
    entries = sorted({*record["files"], MANIFEST, *record["symlinks"]})
    with tempfile.TemporaryDirectory(prefix=".combined-package.", dir=output.parent) as temporary:
        staged = Path(temporary) / "sysroot.tar"
        with tarfile.open(staged, "w", format=tarfile.USTAR_FORMAT) as archive:
            for relative in entries:
                entry = tarfile.TarInfo(relative)
                entry.mtime, entry.uid, entry.gid, entry.uname, entry.gname = 1, 0, 0, "", ""
                if relative in record["symlinks"]:
                    entry.type, entry.linkname, entry.mode = tarfile.SYMTYPE, record["symlinks"][relative], 0o777
                    archive.addfile(entry)
                    continue
                payload = (root / relative).read_bytes()
                entry.size = len(payload)
                entry.mode = 0o755 if relative in record["executables"] else 0o644
                archive.addfile(entry, io.BytesIO(payload))
        shared_package.publish_noreplace(staged, output, "combined package output")


def read_validated_package(package_path: Path) -> tuple[dict, dict[str, bytes]]:
    """Read only regular payloads after validating the complete archive contract."""

    require(package_path.is_file() and not package_path.is_symlink(), "combined package is not a regular file")
    with tarfile.open(package_path, "r:") as archive:
        members = archive.getmembers()
        require(len(members) <= MAX_ARCHIVE_MEMBERS, "combined package member safety limit")
        require(sum(max(member.size, 0) for member in members) <= shared_package.MAX_ARCHIVE_TOTAL_BYTES,
                "combined package aggregate size safety limit")
        names = [member.name for member in members]
        require(len(set(names)) == len(names), "duplicate package member")
        for member in members:
            path = PurePosixPath(member.name)
            require(member.name and not path.is_absolute() and ".." not in path.parts
                    and path.as_posix() == member.name, "unsafe package member path")
            require(member.isfile() or member.issym(), "non-regular package member")
        require(MANIFEST in names, "combined package has no manifest")
        manifest_member = archive.getmember(MANIFEST)
        require(manifest_member.isfile(), "combined package manifest is not a regular file")
        try:
            record = json.loads(archive.extractfile(manifest_member).read())
        except (ValueError, UnicodeDecodeError) as error:
            raise CompositionError("combined package manifest is invalid") from error
        require(isinstance(record, dict) and record.get("format") == FORMAT
                and isinstance(record.get("files"), dict) and isinstance(record.get("symlinks"), dict)
                and isinstance(record.get("executables"), list), "wrong combined package contract")
        require(set(names) == {*record["files"], MANIFEST, *record["symlinks"]},
                "combined package roster differs from its manifest")
        for path, target in record["symlinks"].items():
            require(isinstance(target, str) and "/" not in target
                    and (PurePosixPath(path).parent / target).as_posix() in record["files"],
                    "unsafe package alias target")
        payloads: dict[str, bytes] = {}
        for member in members:
            if member.name in record["symlinks"]:
                require(member.issym() and member.linkname == record["symlinks"][member.name],
                        "combined package alias differs")
                continue
            require(member.isfile(), "combined package payload replaced by a link")
            require(member.mode == (0o755 if member.name in record["executables"] else 0o644),
                    "combined package member mode differs")
            payload = archive.extractfile(member).read()
            if member.name != MANIFEST:
                require(sha256_bytes(payload) == record["files"][member.name], "combined package payload differs")
            payloads[member.name] = payload
    validate_component_claims(record, payloads)
    return record, payloads


def extract(package_path: Path, output: Path) -> None:
    """Validate every member before writing an installed tree."""

    require(not output.exists() and not output.is_symlink(), "extraction output already exists")
    record, payloads = read_validated_package(package_path)
    with tempfile.TemporaryDirectory(prefix=".combined-extraction.", dir=output.parent) as temporary:
        staged = Path(temporary) / "sysroot"
        staged.mkdir()
        for relative, payload in payloads.items():
            path = staged / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(0o755 if relative in record["executables"] else 0o644)
        for relative, target in record["symlinks"].items():
            (staged / relative).parent.mkdir(parents=True, exist_ok=True)
            (staged / relative).symlink_to(target)
        validate(staged)
        shared_package.publish_noreplace(staged, output, "combined extraction output")


def compare(first: Path, second: Path) -> None:
    """Two independent clean builds must match over the declared file set."""

    first_record, second_record = validate(first), validate(second)
    require((first / MANIFEST).read_bytes() == (second / MANIFEST).read_bytes(),
            "independent combined builds have different manifests")
    for relative in first_record["files"]:
        require((first / relative).read_bytes() == (second / relative).read_bytes(),
                f"independent combined builds differ at {relative}")
    require(first_record == second_record, "independent combined builds differ")


def build(output: Path) -> dict:
    """Build both products privately from live source, then compose one tree."""

    output = output.absolute()
    require(output.resolve() == output and output.is_relative_to(ROOT / ".work"),
            "combined output must be a physical path below checkout .work")
    require(not output.exists() and not output.is_symlink(), "combined output already exists")
    stage = output.parent / (output.name + ".build")
    require(not stage.exists() and not stage.is_symlink(), "combined build state already exists")
    # The native container writes as root; keep retained product logs and
    # staging readable by the host user who reviews the evidence.
    stage.mkdir(parents=True, mode=0o755)
    products = {name: stage / name for name in PRODUCTS}
    for name, builder in PRODUCT_BUILDERS.items():
        with (stage / f"{name}.log").open("xb") as log:
            completed = subprocess.run([sys.executable, "-B", str(ROOT / builder), "--output", str(products[name])],
                                       cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False)
        require(completed.returncode == 0, f"{name} product build failed; log: {stage / (name + '.log')}")
    composed = stage / "installed"
    record = compose(products, composed)
    shared_package.publish_noreplace(composed, output, "combined sysroot output")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build").add_argument("output", type=Path)
    for name in ("package", "extract", "compare"):
        command = commands.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("output", type=Path)
    commands.add_parser("validate").add_argument("root", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "build":
            build(arguments.output)
        elif arguments.command == "package":
            package(arguments.source, arguments.output)
        elif arguments.command == "extract":
            extract(arguments.source, arguments.output)
        elif arguments.command == "compare":
            compare(arguments.source, arguments.output)
        else:
            validate(arguments.root)
    except (CompositionError, shared_package.PackageError, OSError, tarfile.TarError) as error:
        print(f"owned combined sysroot: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
