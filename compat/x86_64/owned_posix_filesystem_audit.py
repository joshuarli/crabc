#!/usr/bin/env python3
"""Closed product and receipt audit for the owned POSIX filesystem workload.

The shell matrix intentionally keeps compilation, linking, ELF inspection, and
chroot execution visible.  This module owns the part that is easy to weaken by
accident: it validates an installed product's complete payload and then binds a
consumer receipt to the one workload object, the exact selected runtime inputs,
and the linker trace that resolved them.  It is standard-library-only so its
negative fixtures can exercise the same checks without building a runtime.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping


STATIC_FORMAT = "crabc-x86-64-owned-static-sysroot-v1"
DYNAMIC_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
STATIC_RECEIPT_FORMAT = "crabc-x86-64-sealed-static-driver-v1"
TARGET = "x86_64-unknown-linux-musl"
DYNAMIC_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
MANIFEST_RELATIVE = Path("share/crabc/manifest.json")


class AuditError(RuntimeError):
    """A product, receipt, or resolved-link boundary departed from the contract."""


def fail(message: str) -> None:
    raise AuditError(message)


def digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def require_regular(path: Path, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"{label} is unreadable: {error}")
    if path.is_symlink() or not stat.S_ISREG(mode):
        fail(f"{label} is not a regular file: {path}")
    return path


def require_directory(path: Path, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"{label} is unreadable: {error}")
    if path.is_symlink() or not stat.S_ISDIR(mode):
        fail(f"{label} is not a physical directory: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        fail(f"{label} cannot be resolved: {error}")


def require_resolved_regular(path: Path, label: str) -> Path:
    require_regular(path, label)
    try:
        return path.resolve(strict=True)
    except OSError as error:
        fail(f"{label} cannot be resolved: {error}")


def read_object(path: Path, label: str) -> dict[str, Any]:
    require_regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"{label} is not valid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} is not a JSON object")
    return value


def checked_files(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        fail(f"{label} lacks payload hashes")
    files: dict[str, str] = {}
    for relative, expected in value.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            fail(f"{label} has a malformed payload record")
        candidate = Path(relative)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or relative == MANIFEST_RELATIVE.as_posix()
        ):
            fail(f"{label} has an unsafe payload path: {relative}")
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            fail(f"{label} has an invalid payload hash: {relative}")
        files[relative] = expected
    return files


def validate_payload(
    root: Path,
    files: Mapping[str, str],
    expected_symlinks: Mapping[str, str],
    label: str,
) -> None:
    """Require that every installed payload name and hash is closed by a manifest."""

    observed_files: set[str] = set()
    observed_symlinks: dict[str, str] = {}
    for artifact in sorted(root.rglob("*")):
        relative = artifact.relative_to(root).as_posix()
        try:
            mode = artifact.lstat().st_mode
        except OSError as error:
            fail(f"{label} payload is unreadable: {relative}: {error}")
        if stat.S_ISLNK(mode):
            try:
                observed_symlinks[relative] = artifact.readlink().as_posix()
            except OSError as error:
                fail(f"{label} symlink is unreadable: {relative}: {error}")
        elif stat.S_ISDIR(mode):
            continue
        elif stat.S_ISREG(mode):
            if relative != MANIFEST_RELATIVE.as_posix():
                observed_files.add(relative)
        else:
            fail(f"{label} has a non-regular payload entry: {relative}")

    if observed_files != set(files):
        missing = sorted(set(files) - observed_files)
        unexpected = sorted(observed_files - set(files))
        detail = missing[0] if missing else unexpected[0]
        fail(f"{label} payload roster drifted: {detail}")
    if observed_symlinks != dict(expected_symlinks):
        fail(f"{label} symlink roster drifted")
    for relative, expected in files.items():
        artifact = root / relative
        require_regular(artifact, f"{label} payload")
        if digest(artifact) != expected:
            fail(f"{label} payload hash drifted: {relative}")


def validate_static_product(product: Path) -> Path:
    """Validate the complete static product before its receipt is trusted."""

    root = require_directory(product, "static product")
    manifest_path = root / MANIFEST_RELATIVE
    manifest = read_object(manifest_path, "static manifest")
    if manifest.get("schema") != 1 or manifest.get("format") != STATIC_FORMAT:
        fail("static manifest schema or format drifted")
    if manifest.get("target") != TARGET:
        fail("static manifest target drifted")
    installed = manifest.get("installed")
    if not isinstance(installed, dict):
        fail("static manifest lacks installed payload")
    expected_installed = {
        "headers": "usr/include",
        "crt_objects": [
            "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/rcrt1.o",
            "usr/lib/crti.o", "usr/lib/crtn.o",
        ],
        "static_libc": "usr/lib/libc.a",
        "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
        "sealed_static_driver": "bin/crabc-cc",
    }
    for field, expected in expected_installed.items():
        if installed.get(field) != expected:
            fail(f"static manifest installed {field} drifted")
    driver = manifest.get("sealed_static_driver")
    if not isinstance(driver, dict) or driver.get("format") != STATIC_RECEIPT_FORMAT:
        fail("static manifest sealed driver drifted")
    files = checked_files(installed.get("files"), "static manifest")
    validate_payload(root, files, {}, "static product")
    require_directory(root / "usr/include", "static product headers")
    require_directory(root / "usr/lib", "static product libraries")
    for relative in (*expected_installed["crt_objects"], expected_installed["static_libc"],
                     expected_installed["bounded_compiler_helpers"], expected_installed["sealed_static_driver"]):
        require_regular(root / relative, f"static product required input {relative}")
    return root


def validate_dynamic_product(product: Path) -> Path:
    """Validate the exact supplied dynamic payload before linking or running it."""

    root = require_directory(product, "dynamic product")
    manifest_path = root / MANIFEST_RELATIVE
    manifest = read_object(manifest_path, "dynamic manifest")
    if manifest.get("schema") != 1 or manifest.get("format") != DYNAMIC_FORMAT:
        fail("dynamic manifest schema or format drifted")
    if manifest.get("target") != TARGET:
        fail("dynamic manifest target drifted")
    expected_symlinks = {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}
    if manifest.get("symlinks") != expected_symlinks:
        fail("dynamic manifest symlink contract drifted")
    files = checked_files(manifest.get("files"), "dynamic manifest")
    validate_payload(root, files, expected_symlinks, "dynamic product")
    require_directory(root / "usr/include", "dynamic product headers")
    require_directory(root / "usr/lib", "dynamic product libraries")
    require_directory(root / "lib", "dynamic product loaders")
    for relative in (
        "bin/crabc-cc-dynamic", "usr/lib/libc.so", "usr/lib/crt1.o",
        "usr/lib/Scrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o",
        "usr/lib/crabc-dynamic-attach.o", "usr/lib/libcrabc-builtins.a",
        "lib/ld-crabc-x86_64.so.1",
    ):
        require_regular(root / relative, f"dynamic product required input {relative}")
    return root


def require_linker(record: object, label: str) -> Path:
    if not isinstance(record, dict):
        fail(f"{label} lacks resolved linker identity")
    path_text = record.get("path")
    expected_hash = record.get("sha256")
    if not isinstance(path_text, str) or not isinstance(expected_hash, str):
        fail(f"{label} has malformed linker identity")
    linker = require_resolved_regular(Path(path_text), f"{label} resolved linker")
    if linker.name != "ld.lld" or digest(linker) != expected_hash:
        fail(f"{label} linker identity drifted")
    return linker


def require_record(receipt: Mapping[str, Any], field: str, expected: object, label: str) -> None:
    if receipt.get(field) != expected:
        fail(f"{label} {field} drifted")


def require_sidecar(
    receipt: Mapping[str, Any],
    field: str,
    sidecar: Path,
    expected_path: str,
    label: str,
) -> None:
    sidecar = require_resolved_regular(sidecar, f"{label} {field} sidecar")
    require_record(
        receipt,
        field,
        {"path": expected_path, "sha256": digest(sidecar)},
        label,
    )


def archive_trace_category(line: str, archive: Path, category: str) -> str | None:
    archive_text = str(archive)
    if line == archive_text:
        return category
    if (
        line.startswith(archive_text + "(")
        and line.endswith(")")
        and line[len(archive_text) + 1:-1]
    ):
        return category
    return None


def require_trace_order(
    trace: object,
    *,
    entry: Path,
    attach: Path | None,
    prologue: Path,
    application: Path,
    libc: Path,
    builtins: Path,
    epilogue: Path,
    label: str,
) -> None:
    """Check every resolved input without inventing an archive-member contract.

    LLD can show an archive as a whole or as one or more selected members.  The
    fixed source/object/runtime order is meaningful; member spelling is not.
    """

    if not isinstance(trace, list) or not all(isinstance(line, str) for line in trace):
        fail(f"{label} link_trace is malformed")
    expected_order = ["entry"]
    if attach is not None:
        expected_order.append("attach")
    expected_order.extend(["prologue", "application", "libc", "builtins", "epilogue"])
    order = {name: index for index, name in enumerate(expected_order)}
    fixed = {"entry", "attach", "prologue", "application", "epilogue"}
    seen: dict[str, int] = {name: 0 for name in expected_order}
    previous = -1
    for line in trace:
        if line == str(entry):
            category = "entry"
        elif attach is not None and line == str(attach):
            category = "attach"
        elif line == str(prologue):
            category = "prologue"
        elif line == str(application):
            category = "application"
        elif line == str(epilogue):
            category = "epilogue"
        else:
            category = archive_trace_category(line, libc, "libc")
            if category is None:
                category = archive_trace_category(line, builtins, "builtins")
            if category is None:
                fail(f"{label} link trace escaped the exact input set: {line}")
        if order[category] < previous:
            fail(f"{label} link trace reordered fixed inputs")
        previous = order[category]
        seen[category] += 1
    if any(seen[name] != 1 for name in fixed if name in seen):
        fail(f"{label} link trace omitted or duplicated a fixed input")
    if not seen["libc"]:
        fail(f"{label} link trace omitted the selected libc input")
    # The fixed driver always names the builtins archive and its receipt binds
    # that exact file, but LLD need not extract or print a member when this
    # particular workload uses no compiler helper. Do not invent extraction as
    # a workload contract; if it is printed, the path and order above remain
    # closed to the one installed archive.


def reject_ambient_static_map(map_path: Path) -> None:
    map_text = map_path.read_text(encoding="utf-8", errors="replace")
    for pattern in (
        r"/opt/musl-", r"/usr/lib/(gcc|clang)", r"/lib/ld-",
        r"crt(begin|end)", r"lib(gcc|ssp|atomic)", r"compiler-rt", r"libc\.so",
    ):
        if re.search(pattern, map_text, flags=re.IGNORECASE):
            fail(f"static link map contains an ambient target runtime input: {pattern}")


def audit_static_receipt(
    product: Path,
    mode: str,
    application: Path,
    candidate: Path,
    receipt_path: Path,
) -> None:
    """Bind a static consumer to its product manifest and exact one-object link."""

    root = validate_static_product(product)
    application = require_resolved_regular(application, "static workload object")
    candidate = require_resolved_regular(candidate, "static consumer")
    receipt_path = require_resolved_regular(receipt_path, "static receipt")
    receipt = read_object(receipt_path, "static receipt")
    expected_modes = {
        "static": ("static-et-exec", "ET_EXEC", "crt1.o", False),
        "static-pie": ("static-pie", "ET_DYN", "rcrt1.o", True),
    }
    try:
        mode_id, elf_type, crt_name, pie = expected_modes[mode]
    except KeyError:
        fail(f"unknown static mode: {mode}")
    require_record(receipt, "schema", 1, "static receipt")
    require_record(receipt, "format", STATIC_RECEIPT_FORMAT, "static receipt")
    require_record(receipt, "target", TARGET, "static receipt")
    require_record(
        receipt,
        "mode",
        {"id": mode_id, "elf_type": elf_type, "crt_object": crt_name, "interpreter": "absent"},
        "static receipt",
    )
    require_linker(receipt.get("resolved_linker"), "static receipt")
    library = root / "usr/lib"
    expected_runtime = [
        ("crt-entry", library / crt_name),
        ("crt-prologue", library / "crti.o"),
        ("libc", library / "libc.a"),
        ("builtins", library / "libcrabc-builtins.a"),
        ("crt-epilogue", library / "crtn.o"),
    ]
    expected_records = [
        {"role": role, "path": str(path.relative_to(root)), "sha256": digest(path)}
        for role, path in expected_runtime
    ]
    expected_records.append(
        {"role": "application", "path": str(application), "sha256": digest(application)}
    )
    require_record(receipt, "input_receipts", expected_records, "static receipt")
    expected_contract = [
        "ld.lld", "-static", *(["-pie"] if pie else []), "--no-dynamic-linker",
        "--no-undefined", "--gc-sections", "-z", "relro", "-z", "now", "-e",
        "_start", str(library / crt_name), str(library / "crti.o"),
        "<application-objects>", str(library / "libc.a"),
        str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", "<output>",
    ]
    require_record(receipt, "owned_link_contract", expected_contract, "static receipt")
    require_record(
        receipt,
        "output",
        {"path": str(candidate), "sha256": digest(candidate)},
        "static receipt",
    )
    map_path = receipt_path.with_suffix(".map")
    trace_path = receipt_path.with_suffix(".trace")
    require_sidecar(receipt, "map", map_path, map_path.name, "static receipt")
    require_sidecar(receipt, "trace", trace_path, trace_path.name, "static receipt")
    require_trace_order(
        trace_path.read_text(encoding="utf-8", errors="replace").splitlines(),
        entry=library / crt_name,
        attach=None,
        prologue=library / "crti.o",
        application=application,
        libc=library / "libc.a",
        builtins=library / "libcrabc-builtins.a",
        epilogue=library / "crtn.o",
        label="static receipt",
    )
    reject_ambient_static_map(map_path)


def audit_dynamic_receipt(
    product: Path,
    mode: str,
    application: Path,
    candidate: Path,
    receipt_path: Path,
) -> None:
    """Bind a dynamic consumer to one installed payload and one workload object."""

    root = validate_dynamic_product(product)
    application = require_resolved_regular(application, "dynamic workload object")
    candidate = require_resolved_regular(candidate, "dynamic consumer")
    receipt_path = require_resolved_regular(receipt_path, "dynamic receipt")
    receipt = read_object(receipt_path, "dynamic receipt")
    expected_modes = {"pie": ("pie", "Scrt1.o"), "non-pie": ("exec", "crt1.o")}
    try:
        receipt_mode, crt_name = expected_modes[mode]
    except KeyError:
        fail(f"unknown dynamic mode: {mode}")
    require_record(receipt, "schema", 1, "dynamic receipt")
    require_record(receipt, "format", DYNAMIC_FORMAT, "dynamic receipt")
    require_record(receipt, "mode", receipt_mode, "dynamic receipt")
    require_record(receipt, "binding", "now", "dynamic receipt")
    require_record(receipt, "runtime_imports", [], "dynamic receipt")
    require_record(receipt, "application_dsos", {}, "dynamic receipt")
    require_record(receipt, "application_runpath", "/usr/lib", "dynamic receipt")
    linker = require_linker(receipt.get("resolved_linker"), "dynamic receipt")
    library = root / "usr/lib"
    entry = library / crt_name
    attach = library / "crabc-dynamic-attach.o"
    prologue = library / "crti.o"
    libc = library / "libc.so"
    builtins = library / "libcrabc-builtins.a"
    epilogue = library / "crtn.o"
    runtime = [prologue, libc, epilogue, entry, attach]
    expected_records = [
        {"path": str(path), "sha256": digest(path)} for path in runtime
    ] + [{"path": str(application), "sha256": digest(application)},
         {"path": str(builtins), "sha256": digest(builtins)}]
    require_record(receipt, "input_receipts", expected_records, "dynamic receipt")
    expected_runtime = sorted(path.relative_to(root).as_posix() for path in [*runtime, builtins])
    require_record(receipt, "owned_runtime_inputs", expected_runtime, "dynamic receipt")
    manifest_path = root / MANIFEST_RELATIVE
    require_record(receipt, "manifest_sha256", digest(manifest_path), "dynamic receipt")
    require_record(receipt, "output_path", str(candidate), "dynamic receipt")
    require_record(receipt, "output_sha256", digest(candidate), "dynamic receipt")
    expected_command = [
        str(linker), *(["-pie"] if mode == "pie" else []), "--hash-style=sysv", "-z",
        "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
        "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
        "--dynamic-linker", DYNAMIC_INTERPRETER, str(entry), str(attach), str(prologue),
        str(application), str(libc), str(builtins), str(epilogue), "-o", str(candidate),
    ]
    require_record(receipt, "link_command", expected_command, "dynamic receipt")
    require_trace_order(
        receipt.get("link_trace"),
        entry=entry,
        attach=attach,
        prologue=prologue,
        application=application,
        libc=libc,
        builtins=builtins,
        epilogue=epilogue,
        label="dynamic receipt",
    )


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-static-product", "validate-dynamic-product"):
        command = commands.add_parser(name)
        command.add_argument("product", type=Path)
    for name in ("audit-static", "audit-dynamic"):
        command = commands.add_parser(name)
        command.add_argument("product", type=Path)
        command.add_argument("mode")
        command.add_argument("application", type=Path)
        command.add_argument("candidate", type=Path)
        command.add_argument("receipt", type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    parsed = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        if parsed.command == "validate-static-product":
            validate_static_product(parsed.product)
        elif parsed.command == "validate-dynamic-product":
            validate_dynamic_product(parsed.product)
        elif parsed.command == "audit-static":
            audit_static_receipt(
                parsed.product, parsed.mode, parsed.application, parsed.candidate, parsed.receipt
            )
        else:
            audit_dynamic_receipt(
                parsed.product, parsed.mode, parsed.application, parsed.candidate, parsed.receipt
            )
    except AuditError as error:
        print(f"owned POSIX filesystem audit: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
