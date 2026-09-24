#!/usr/bin/env python3
"""Produce one full six-cell installed clock/calendar component receipt.

Run this leaf only inside the pinned native x86-64 image.  It consumes supplied,
already-qualified static and dynamic products; it never builds or mutates them.
Each candidate cell gets a fresh chroot root containing a byte-bound copy of the
product (for dynamic entries), the linked object consumer, and sealed TZif
fixtures copied from the pinned image before the first execution.

The separate host-side ``fetch-tzif-archives`` operation only retains the fixed
IANA archives (hash-checked) and their unverified detached signatures below
the checkout's ``.work`` tree for the containerized TZif preparation.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Iterable
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_calendar_component_receipt as receipt
import owned_posix_family_execution as family
import owned_posix_product_evidence as products


class RunnerError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise RunnerError(message)


def physical_directory(path: Path, description: str) -> Path:
    path = Path(os.path.abspath(path))
    if not path.is_dir() or path.is_symlink():
        fail(f"{description} is not a physical directory: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            fail(f"{description} traverses a symlink: {path}")
    return path


def under_work(path: Path, description: str) -> Path:
    path = physical_directory(path, description)
    if not path.is_relative_to(ROOT / ".work"):
        fail(f"{description} escapes checkout .work: {path}")
    return path


def under_work_file(path: Path, description: str) -> Path:
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(ROOT / ".work"):
        fail(f"{description} escapes checkout .work: {path}")
    if not path.is_file() or path.is_symlink():
        fail(f"{description} is not a physical regular file: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            fail(f"{description} traverses a symlink: {path}")
    return path


def fresh_work_directory(path: Path, description: str) -> Path:
    path = Path(os.path.abspath(path))
    if not path.parent.is_relative_to(ROOT / ".work") or path.exists() or path.is_symlink():
        fail(f"{description} must be a fresh checkout .work directory: {path}")
    physical_directory(path.parent, f"{description} parent")
    return path


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        fail(f"refuses to replace retained artifact: {path}")
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def identity(path: Path) -> dict[str, object]:
    return receipt.identity(ROOT, path)


def capture(work: Path, label: str, argv: list[str], *, stdin: bytes | None = None,
            environment: dict[str, str] | None = None, permitted: Iterable[int] = (0,), cwd: Path = ROOT) -> int:
    """Run once and retain exact argv, streams, and shell-compatible status."""
    cwd = physical_directory(cwd, f"{label} command cwd")
    if not cwd.is_relative_to(ROOT):
        fail(f"{label} command cwd escapes checkout: {cwd}")
    write_json(work / f"{label}.argv.json", argv)
    write_json(work / f"{label}.cwd.json", receipt.mounted(ROOT, cwd))
    completed = subprocess.run(argv, cwd=cwd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, check=False, timeout=60)
    status = completed.returncode if completed.returncode >= 0 else 128 - completed.returncode
    (work / f"{label}.stdout").write_bytes(completed.stdout)
    (work / f"{label}.stderr").write_bytes(completed.stderr)
    (work / f"{label}.status").write_text(f"{status}\n", encoding="ascii")
    if status not in set(permitted):
        fail(f"{label} exited {status}")
    return status


def validate_link_script() -> bytes:
    return b'''import json\nfrom pathlib import Path\nimport sys\nroot, product, workload, executable, link_receipt, linkage = map(Path, sys.argv[1:])\nsys.path.insert(0, str(root / "compat/x86_64"))\nfrom owned_posix_product_evidence import validate_link\nprint(json.dumps(validate_link(product, workload, executable, link_receipt, str(linkage)), sort_keys=True, separators=(",", ":")))\n'''


def record_commands(work: Path) -> dict[str, dict[str, dict[str, object]]]:
    commands: dict[str, dict[str, dict[str, object]]] = {}
    for argv in sorted(work.glob("*.argv.json")):
        label = argv.name.removesuffix(".argv.json")
        commands[label] = {field: identity(work / f"{label}.{suffix}")
                           for field, suffix in (("argv", "argv.json"), ("cwd", "cwd.json"), ("stdout", "stdout"),
                                                 ("stderr", "stderr"), ("status", "status"))}
    return commands


def stage_zoneinfo(work: Path, tzif_input: Path) -> dict[str, object]:
    tzif_input = under_work(tzif_input, "calendar TZif input")
    manifest = receipt.identity(ROOT, tzif_input / "manifest.json")
    input_fixtures = receipt.check_tzif_input(ROOT, tzif_input, manifest)
    staged: dict[str, object] = {}
    for name, _destination in receipt.TZIF_FIXTURES:
        source = tzif_input / receipt.TZIF_INPUT_PATHS[name]
        destination = work / "zoneinfo-source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)
        os.chmod(destination, 0o644)
        staged[name] = {"input": input_fixtures[name], "staged": identity(destination)}
    return {"input_root": tzif_input.relative_to(ROOT).as_posix(), "input_manifest": manifest, "staged": staged}


def copy_real_zone_fixtures(work: Path, root: Path, *, missing_lord_howe: bool = False) -> None:
    for name, destination in receipt.TZIF_FIXTURES:
        if missing_lord_howe and name == "Australia/Lord_Howe":
            continue
        target = root / destination.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work / "zoneinfo-source" / name, target)
        os.chmod(target, 0o644)


def private_fixture(root: Path, action: str) -> None:
    if action in {"calendar", "calendar-malformed"}:
        path = root / "fixture/calendar-private.tzif"
    elif action.startswith("tzif"):
        path = root / "fixture/tzif-private.tzif"
    elif action == "getdate":
        path = root / "templates/mask"
    else:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    os.chmod(path, 0o644)


def copy_root(work: Path, root: Path, dynamic: Path | None, executable: Path, role: str, action: str,
              audit: Path) -> None:
    if dynamic is not None:
        shutil.copytree(dynamic, root, symlinks=True, copy_function=shutil.copy2)
        write_json(audit / "product-copy.json", family.snapshot(root))
    else:
        root.mkdir(parents=True)
    shutil.copy2(executable, root / f"consumer-{role}")
    os.chmod(root / f"consumer-{role}", stat.S_IMODE(executable.stat().st_mode))
    copy_real_zone_fixtures(work, root, missing_lord_howe=action == "calendar-real-zones-missing-lord-howe")
    private_fixture(root, action)


def root_audit(root: Path, audit: Path, point: str) -> None:
    write_json(audit / f"{point}.json", family.snapshot(root))


def write_seal(work: Path, name: str, value: object) -> None:
    write_json(work / f"{name}.json", value)


def mode_for_cell(cell: str) -> str:
    if cell == "static-et-exec":
        return "static"
    if cell == "static-pie":
        return "static-pie"
    if cell.startswith("dynamic-pie"):
        return "dynamic-pie"
    return "dynamic-non-pie"


def checked_archive(path: Path, name: str) -> Path:
    path = under_work_file(path, f"{name} archive")
    expected = receipt.TZDATA_ARCHIVES[name]["sha256"]
    if receipt.digest(path) != expected:
        fail(f"{name} archive hash differs from the tracked IANA pin")
    return path


def checked_signature(path: Path, name: str) -> Path:
    path = under_work_file(path, f"{name} detached signature")
    if path.stat().st_size == 0:
        fail(f"{name} detached signature is empty")
    return path


def extract_regular_archive(archive: Path, destination: Path, description: str) -> None:
    """Extract only physical, relative regular files and directories."""
    try:
        with tarfile.open(archive, "r:gz") as stream:
            members = stream.getmembers()
            for member in members:
                parts = Path(member.name).parts
                if member.name.startswith("/") or not parts or any(part in {"", ".", ".."} for part in parts):
                    fail(f"{description} archive has unsafe member: {member.name}")
                if not (member.isdir() or member.isfile()):
                    fail(f"{description} archive has non-regular member: {member.name}")
            stream.extractall(destination, members=members)
    except (OSError, tarfile.TarError) as error:
        raise RunnerError(f"{description} archive cannot be extracted") from error


def readable_tree(path: Path) -> None:
    for entry in path.rglob("*"):
        if entry.is_symlink():
            fail(f"calendar TZif preparation retained a symlink: {entry}")
        if entry.is_dir():
            os.chmod(entry, 0o755)
        elif entry.is_file():
            os.chmod(entry, 0o755 if entry.name == "zic" else 0o644)
        else:
            fail(f"calendar TZif preparation retained a special file: {entry}")


def prepare_tzif_input(args: argparse.Namespace) -> int:
    if args.image_id != receipt.PINNED_IMAGE_ID:
        fail("calendar TZif preparation requires the immutable pinned core image ID")
    if os.uname().sysname != "Linux" or os.uname().machine not in {"x86_64", "amd64"}:
        fail("calendar TZif preparation requires native Linux/x86-64 and refuses emulation")
    output = fresh_work_directory(args.output, "calendar TZif input output")
    tzcode = checked_archive(args.tzcode_archive, "tzcode")
    tzdata = checked_archive(args.tzdata_archive, "tzdata")
    tzcode_signature = checked_signature(args.tzcode_signature, "tzcode")
    tzdata_signature = checked_signature(args.tzdata_signature, "tzdata")
    for tool in ("make", "cc"):
        if shutil.which(tool) is None:
            fail(f"calendar TZif preparation requires {tool}")
    output.mkdir(mode=0o755)
    try:
        archives = output / "archives"
        archives.mkdir()
        copied_archives = {
            "tzcode": (tzcode, tzcode_signature, "tzcode2025b.tar.gz"),
            "tzdata": (tzdata, tzdata_signature, "tzdata2025b.tar.gz"),
        }
        for _name, (archive, signature, filename) in copied_archives.items():
            shutil.copy2(archive, archives / filename)
            shutil.copy2(signature, archives / f"{filename}.asc")
            os.chmod(archives / filename, 0o644)
            os.chmod(archives / f"{filename}.asc", 0o644)
        build = output / "build"
        tzdb_root = build / "tzdb"
        tzdb_root.mkdir(parents=True)
        # IANA's matching source archives form one build tree: `make zic`
        # reads the data release's `version` and region files beside tzcode.
        extract_regular_archive(archives / "tzcode2025b.tar.gz", tzdb_root, "tzcode")
        extract_regular_archive(archives / "tzdata2025b.tar.gz", tzdb_root, "tzdata")
        version = (tzdb_root / "version")
        if not version.is_file() or version.read_text(encoding="ascii").strip() != receipt.TZDATA_VERSION:
            fail("tzdata archive version differs from the tracked fixture release")
        make_path = shutil.which("make")
        compiler_path = shutil.which("cc")
        assert make_path is not None and compiler_path is not None
        compiler_path = str(Path(compiler_path).resolve(strict=True))
        capture(output, "build-zic", [make_path, "-C", str(tzdb_root), f"CC={compiler_path}", "zic"])
        zic = tzdb_root / "zic"
        if not zic.is_file() or zic.is_symlink() or not (zic.stat().st_mode & 0o111):
            fail("tzcode build did not produce an executable zic")
        intermediate = build / "zoneinfo"
        capture(output, "derive-zoneinfo", [str(zic), "-d", str(intermediate),
                                              str(tzdb_root / "northamerica"), str(tzdb_root / "europe"),
                                              str(tzdb_root / "australasia")])
        fixture = output / "fixture"
        fixture.mkdir()
        for name, _destination in receipt.TZIF_FIXTURES:
            source = intermediate / name if name != "localtime" else intermediate / "America/New_York"
            if not source.is_file() or source.is_symlink():
                fail(f"zic did not derive required timezone fixture: {name}")
            target = fixture / name if name != "localtime" else fixture / "localtime"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target, follow_symlinks=False)
            os.chmod(target, 0o644)
            observed = {"sha256": receipt.digest(target), "size": target.stat().st_size}
            if observed != receipt.TZIF_EXPECTED_FIXTURES[name]:
                fail(f"zic derived {name} bytes differ from the tracked IANA fixture pin")
        readable_tree(output)
        archives_record: dict[str, object] = {}
        for name, expected in receipt.TZDATA_ARCHIVES.items():
            filename = f"{name}2025b.tar.gz"
            archives_record[name] = {
                "url": expected["url"], "sha256": expected["sha256"], "signature_url": expected["signature_url"],
                "signature_verification": "retained-unverified", "archive": identity(archives / filename),
                "signature": identity(archives / f"{filename}.asc"),
            }
        manifest = {
            "schema": receipt.TZIF_INPUT_SCHEMA, "image_id": args.image_id, "version": receipt.TZDATA_VERSION,
            "archives": archives_record,
            "tools": {"compiler": receipt.recorded_tool_identity(ROOT, Path(compiler_path), "calendar TZif compiler"),
                      "make": receipt.recorded_tool_identity(ROOT, Path(make_path), "calendar TZif make"),
                      "zic": identity(zic)},
            "recipe": {"make_target": "zic", "zic_sources": ["northamerica", "europe", "australasia"],
                       "localtime_source": "America/New_York"},
            "commands": record_commands(output),
            "fixtures": {name: identity(fixture / name if name != "localtime" else fixture / "localtime")
                         for name, _destination in receipt.TZIF_FIXTURES},
        }
        write_json(output / "manifest.json", manifest)
        print(f"owned calendar TZif input: PASS (fixed IANA {receipt.TZDATA_VERSION}; input: {output})")
        return 0
    finally:
        readable_tree(output)


def fetch_tzif_archives(args: argparse.Namespace) -> int:
    """Retain the fixed IANA archive pair without replacing an existing byte.

    Archive bytes must equal the tracked SHA-256 pins before they are
    published. Detached signatures have no tracked digest; like the prepared
    manifest they remain ``retained-unverified`` and need only be nonempty.
    """
    output = Path(os.path.abspath(args.output))
    if not output.is_relative_to(ROOT / ".work"):
        fail(f"calendar TZif archive directory escapes checkout .work: {output}")
    output.mkdir(parents=True, exist_ok=True)
    physical_directory(output, "calendar TZif archive directory")
    for name, pin in receipt.TZDATA_ARCHIVES.items():
        filename = f"{name}{receipt.TZDATA_VERSION}.tar.gz"
        for url, target, expected in ((pin["url"], output / filename, pin["sha256"]),
                                      (pin["signature_url"], output / f"{filename}.asc", None)):
            if not target.exists() and not target.is_symlink():
                try:
                    with urllib.request.urlopen(url, timeout=60) as response:
                        data = response.read()
                except OSError as error:
                    raise RunnerError(f"cannot fetch fixed IANA input {url}") from error
                partial = target.with_name(target.name + ".partial")
                partial.write_bytes(data)
                if expected is not None and receipt.digest(partial) != expected:
                    partial.unlink()
                    fail(f"fetched {name} archive hash differs from the tracked IANA pin")
                os.replace(partial, target)
                os.chmod(target, 0o644)
            if expected is not None:
                checked_archive(target, name)
            else:
                checked_signature(target, name)
    print(f"owned calendar TZif archives: {output}")
    return 0


def prepare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-sysroot", type=Path, required=True)
    parser.add_argument("--dynamic-sysroot", type=Path, required=True)
    parser.add_argument("--tzif-input", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    return parser


def collect_component(args: argparse.Namespace) -> int:
    if args.image_id != receipt.PINNED_IMAGE_ID:
        fail("calendar receipt requires the immutable pinned core image ID")
    if os.uname().sysname != "Linux" or os.uname().machine not in {"x86_64", "amd64"}:
        fail("calendar receipt requires native Linux/x86-64 and refuses emulation")
    temporary = os.environ.get("TMPDIR")
    if not temporary:
        fail("calendar receipt requires checkout-local TMPDIR")
    tempdir = under_work(Path(temporary), "TMPDIR")
    static_product = under_work(args.static_sysroot, "static supplied product")
    dynamic_product = under_work(args.dynamic_sysroot, "dynamic supplied product")
    if not (dynamic_product / "bin/crabc-cc-dynamic").is_file() or not (static_product / "bin/crabc-cc").is_file():
        fail("calendar receipt supplied product lacks an installed compiler driver")
    for tool in ("chroot",):
        if shutil.which(tool) is None:
            fail(f"calendar receipt requires {tool}")
    work = Path(tempfile.mkdtemp(prefix="owned-calendar-products.", dir=tempdir))
    os.chmod(work, 0o755)
    print(f"owned calendar products evidence: {work}")
    try:
        tools = receipt.tool_roster(ROOT, static_product, dynamic_product)
        plan = receipt.command_plan(ROOT, work, static_product, dynamic_product, tools)
        zoneinfo = stage_zoneinfo(work, args.tzif_input)
        before_seal = receipt.source_product_seal(ROOT, static_product, dynamic_product)
        write_seal(work, "source-product-before", before_seal)
        write_seal(work, "tools-before", tools)

        role_objects: dict[str, Path] = {}
        for role, _source, _defines, _comparison in receipt.ROLE_SPECS:
            capture(work, f"header-{role}", plan[f"header-{role}"])
            capture(work, f"compile-{role}", plan[f"compile-{role}"])
            role_objects[role] = work / "objects" / f"{role}.o"
        for role in receipt.role_map():
            if role == receipt.EXTRA_ROLE:
                continue
            output = work / "oracle" / role
            output.parent.mkdir(parents=True, exist_ok=True)
            capture(work, f"oracle-link-{role}", plan[f"oracle-link-{role}"])

        links: dict[str, dict[str, object]] = {}
        for mode, product, linkage in (("static", static_product, "static"), ("static-pie", static_product, "static-pie"),
                                       ("dynamic-pie", dynamic_product, "pie"), ("dynamic-non-pie", dynamic_product, "non-pie")):
            for role in receipt.role_map():
                executable = work / "executables" / mode / role
                executable.parent.mkdir(parents=True, exist_ok=True)
                capture(work, f"{mode}-link-{role}", plan[f"{mode}-link-{role}"], cwd=executable.parent)
                link_receipt = executable.with_name(executable.name + ".crabc-link.json")
                validate_label = f"{mode}-validate-{role}"
                capture(work, validate_label, plan[validate_label], stdin=validate_link_script())
                retained = work / "links" / f"{mode}-{role}.json"
                retained.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(work / f"{validate_label}.stdout", retained)
                links[f"{mode}/{role}"] = identity(retained)

        clean_environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
        roots: dict[str, object] = {}
        action_roles = {name: role for name, role, _arguments, _classification in receipt.action_specs()}
        classifications = {name: classification for name, _role, _arguments, classification in receipt.action_specs()}
        # The two input-validation guards retain their container-boundary
        # capability status before the shell directly execs chroot.
        (work / "capability").mkdir()
        # Each musl action has its own sealed chroot root.  The raw oracle
        # command names the root and all candidates below compare to it only
        # where the source contract calls it a differential.
        for action, role, _arguments, classification in receipt.action_specs():
            if classification in {"candidate-only", "tzif-specification"}:
                continue
            oracle_root = work / "oracle-roots" / action
            copy_root(work, oracle_root, None, work / "oracle" / role, role, action, work / "oracle-audits" / action)
            permitted = (0, 139) if classification == "musl-fault-correction" else \
                (1,) if classification == "fixture-required" else (0,)
            capture(work, f"oracle-{action}", plan[f"oracle-{action}"], environment=clean_environment, permitted=permitted)
        for cell in receipt.EXECUTION_CELLS:
            mode = mode_for_cell(cell)
            dynamic = dynamic_product if cell.startswith("dynamic") else None
            for action, role, _arguments, classification in receipt.action_specs():
                if classification == "musl-defect":
                    continue
                executable = work / "executables" / mode / role
                root = work / "roots" / cell / action
                audit = work / "root-audits" / f"{cell}-{action}"
                audit.mkdir(parents=True, exist_ok=True)
                copy_root(work, root, dynamic, executable, role, action, audit)
                root_audit(root, audit, "before")
                permitted = (1,) if classification == "fixture-required" else (0,)
                capture(work, f"candidate-{cell}-{action}", plan[f"candidate-{cell}-{action}"], environment=clean_environment,
                        permitted=permitted)
                root_audit(root, audit, "after")
                record: dict[str, object] = {
                    "before": identity(audit / "before.json"), "after": identity(audit / "after.json"),
                    "product-copy": identity(audit / "product-copy.json") if dynamic is not None else None,
                    "capability": None,
                }
                if classifications[action] == "differential-capability-absent":
                    record["capability"] = identity(work / "capability" / f"{cell}-{action}.status")
                roots[f"{cell}/{action}"] = record

        after_tools = receipt.tool_roster(ROOT, static_product, dynamic_product)
        write_seal(work, "tools-after", after_tools)
        after_seal = receipt.source_product_seal(ROOT, static_product, dynamic_product)
        write_seal(work, "source-product-after", after_seal)
        if before_seal != after_seal or tools != after_tools:
            fail("calendar receipt source, supplied product, or tool changed during execution")
        objects = {role: {"source": specification["source"], "defines": list(specification["defines"]),
                          "object": identity(role_objects[role])}
                   for role, specification in receipt.role_map().items()}
        record = {
            "schema": receipt.SCHEMA, "source_mount": receipt.SOURCE_MOUNT, "image_id": args.image_id,
            "execution_mode": receipt.FULL_MODE, "scope": list(receipt.SCOPE), "rows": [list(row) for row in receipt.ROWS],
            "sources": before_seal["sources"], "objects": objects,
            "products": {"static": static_product.relative_to(ROOT).as_posix(), "dynamic": dynamic_product.relative_to(ROOT).as_posix()},
            "seals": {name: identity(work / f"{name}.json") for name in
                      ("source-product-before", "source-product-after", "tools-before", "tools-after")},
            "fixtures": zoneinfo, "commands": record_commands(work), "links": links, "execution_roots": roots,
            "family_completion": False, "promotion_ready": False, "public_support": False,
        }
        report = work / "owned-calendar-products.json"
        write_json(report, record)
        receipt.validate_report(ROOT, report, require_static=True)
        print(f"owned calendar products: PASS (bounded full-six installed clock/calendar component; evidence: {work})")
        return 0
    finally:
        # Evidence remains mode-readable even after an interrupted command.
        for path in work.rglob("*"):
            if path.is_file() and not path.is_symlink():
                os.chmod(path, stat.S_IMODE(path.stat().st_mode) | 0o444)


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "fetch-tzif-archives":
            parser = argparse.ArgumentParser(description="Retain the fixed IANA calendar archive pair.")
            parser.add_argument("--output", type=Path, required=True)
            raise SystemExit(fetch_tzif_archives(parser.parse_args(sys.argv[2:])))
        if len(sys.argv) > 1 and sys.argv[1] == "prepare-tzif-input":
            parser = argparse.ArgumentParser(description="Prepare the fixed test-only calendar TZif input.")
            parser.add_argument("--output", type=Path, required=True)
            parser.add_argument("--tzcode-archive", type=Path, required=True)
            parser.add_argument("--tzcode-signature", type=Path, required=True)
            parser.add_argument("--tzdata-archive", type=Path, required=True)
            parser.add_argument("--tzdata-signature", type=Path, required=True)
            parser.add_argument("--image-id", required=True)
            raise SystemExit(prepare_tzif_input(parser.parse_args(sys.argv[2:])))
        raise SystemExit(collect_component(prepare_parser().parse_args()))
    except (RunnerError, receipt.CalendarReceiptError, OSError, subprocess.TimeoutExpired) as error:
        print(f"owned calendar products: {error}", file=sys.stderr)
        raise SystemExit(1)
