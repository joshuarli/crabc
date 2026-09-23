#!/usr/bin/env python3
"""Reconstruct the bounded installed clock/calendar component receipt.

This is intentionally a receipt reader for ``run_owned_calendar_component.py``.
It makes the selected installed C objects, their six entry cells, their private
TZif roots, and their raw observations reconstructable. A valid report remains
a non-promoting component input: it does not complete the larger text/math/
locale/stdio family or public native support.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_posix_family_execution as family
import owned_posix_product_evidence as products

SCHEMA = "crabc.x86_64-owned-calendar-products/v1"
SOURCE_MOUNT = "/workspace"
PINNED_IMAGE_ID = "sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d"
SCOPE = ("time.clock-calendar",)
FULL_MODE = "full-six-mode"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
EXECUTION_CELLS = (
    "static-et-exec", "static-pie", "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
HEADERS = (
    "errno.h", "locale.h", "pthread.h", "stdio.h", "stdlib.h", "string.h", "time.h",
    "unistd.h", "sys/time.h", "sys/timex.h", "features.h", "bits/alltypes.h",
)
SOURCE_PATHS = {
    "calendar-differential": "compat/x86_64/owned_calendar_probe.c",
    "calendar-malformed-tzif": "compat/x86_64/owned_calendar_probe.c",
    "calendar-real-zones": "compat/x86_64/owned_calendar_real_zone_probe.c",
    "tzif-specification": "compat/x86_64/owned_timezone_tzif_probe.c",
    "strptime": "compat/x86_64/owned_strptime_probe.c",
    "getdate": "compat/x86_64/owned_getdate_probe.c",
    "legacy-clock-control": "compat/x86_64/owned_legacy_time_probe.c",
    "clock-adjtime-rejected": "compat/x86_64/libc_clock_adjtime_probe.c",
    "runner": "compat/x86_64/run_owned_calendar_component.py",
    "reader": "compat/x86_64/owned_calendar_component_receipt.py",
}
ROLE_SPECS = (
    ("calendar-differential", SOURCE_PATHS["calendar-differential"], (), "musl-differential"),
    ("calendar-malformed-tzif", SOURCE_PATHS["calendar-malformed-tzif"],
     ("-DCRABC_OWNED_CALENDAR",), "candidate-only"),
    ("calendar-real-zones", SOURCE_PATHS["calendar-real-zones"], (), "real-zone-transitions"),
    ("tzif-specification", SOURCE_PATHS["tzif-specification"], (), "tzif-specification"),
    ("strptime", SOURCE_PATHS["strptime"], (), "musl-differential-with-known-corrections"),
    ("getdate", SOURCE_PATHS["getdate"], (), "musl-differential"),
    ("legacy-clock-control", SOURCE_PATHS["legacy-clock-control"], (), "safe-clock-controls"),
    ("clock-adjtime-rejected", SOURCE_PATHS["clock-adjtime-rejected"], (), "rejected-clock-ids"),
)
ROWS = (
    ("calendar-posix-tz-format", "calendar-differential"),
    ("calendar-tzif-specification", "tzif-specification"),
    ("calendar-strptime", "strptime"),
    ("calendar-getdate-global", "getdate"),
    ("calendar-clock-adjustment-safe", "legacy-clock-control"),
)
# This separately compiled candidate-only object is support for the calendar
# row, never a sixth capability row.
EXTRA_ROLE = "calendar-malformed-tzif"
TZIF_FIXTURES = (
    ("America/New_York", "/usr/share/zoneinfo/America/New_York"),
    ("Europe/Berlin", "/usr/share/zoneinfo/Europe/Berlin"),
    ("Australia/Lord_Howe", "/usr/share/zoneinfo/Australia/Lord_Howe"),
    ("localtime", "/etc/localtime"),
)
TZIF_INPUT_SCHEMA = "crabc.x86_64-owned-calendar-tzif-input/v1"
TZDATA_VERSION = "2025b"
TZDATA_ARCHIVES = {
    "tzcode": {
        "url": "https://data.iana.org/time-zones/releases/tzcode2025b.tar.gz",
        "sha256": "05f8fedb3525ee70d49c87d3fae78a8a0dbae4fe87aa565c65cda9948ae135ec",
        "signature_url": "https://data.iana.org/time-zones/releases/tzcode2025b.tar.gz.asc",
    },
    "tzdata": {
        "url": "https://data.iana.org/time-zones/releases/tzdata2025b.tar.gz",
        "sha256": "11810413345fc7805017e27ea9fa4885fd74cd61b2911711ad038f5d28d71474",
        "signature_url": "https://data.iana.org/time-zones/releases/tzdata2025b.tar.gz.asc",
    },
}
TZIF_INPUT_PATHS = {name: f"fixture/{name}" for name, _destination in TZIF_FIXTURES if name != "localtime"}
TZIF_INPUT_PATHS["localtime"] = "fixture/localtime"
TZIF_EXPECTED_FIXTURES = {
    "America/New_York": {"sha256": "d7f2206b3a45989fc9ad63d558922532fa7352280d5f87176bf1db79cb1d1fa9", "size": 1744},
    "Europe/Berlin": {"sha256": "a7fd9932d785d4d690900b834c3563c1810c1cf2e01711bcc0926af6c0767cb7", "size": 705},
    "Australia/Lord_Howe": {"sha256": "f368bd25659c0293d02bb79ec7dac7d5b73a92dffafce14b4dd2ffb8ba11aada", "size": 692},
    "localtime": {"sha256": "d7f2206b3a45989fc9ad63d558922532fa7352280d5f87176bf1db79cb1d1fa9", "size": 1744},
}
REAL_ZONE_SUCCESS_STDOUT = b"owned-calendar-real-zones: New_York Berlin Lord_Howe localtime\n"
REAL_ZONE_MISSING_LORD_HOWE_STDERR = b"owned-calendar-real-zones: fixture assertion failed: Lord_Howe-January\n"
PRIVATE_FIXTURES = ("/fixture/calendar-private.tzif", "/fixture/tzif-private.tzif", "/templates/mask")
CAPABILITY_STATUS_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
CAP_SYS_TIME_BIT = 25
CLOCK_CONTROL_SCENARIOS = (
    "adjustment-query", "adjustment-guards", "settimeofday-null", "settimeofday-guards",
    "adjustment-seccomp",
)
SECCOMP_DENIED_SYSCALLS = ("adjtimex", "clock_adjtime", "settimeofday", "clock_settime")
TZIF_SPECIFICATION_STDOUT = (
    b"1 offset=3600 timezone=-3600 dst=0 name=ONE\n"
    b"2 offset=-18000 timezone=18000 dst=0 name=ONE\n"
    b"3 offset=10800 timezone=-10800 dst=0 name=XXX\n"
    b"4 offset=7200 timezone=-3600 dst=1 name=ONE\n"
    b"5 offset=7200 timezone=-3600 dst=1 name=ONE\n"
    b"6 offset=3600 timezone=-3600 dst=0 name=ONE\n"
)
TZIF_MUSL_DEFECT_STDOUT = (
    b"1 offset=0 timezone=0 dst=0 name=\n"
    b"2 offset=0 timezone=0 dst=0 name=\n"
    b"3 offset=0 timezone=-10800 dst=0 name=ONE\n"
    b"4 offset=3600 timezone=-3600 dst=0 name=TWO\n"
    b"5 offset=3600 timezone=-3600 dst=0 name=TWO\n"
    b"6 offset=3600 timezone=0 dst=0 name=ONE\n"
)
# `owned-strptime.md` records these fixed delimiter boundaries separately from
# the pinned-musl guard-page fault.
STRPTIME_DELIMITERS_STDOUT = (
    b"0 end=3 isdst=0\n1 end=3 isdst=1\n2 end=7 isdst=-1\n"
    b"3 end=7 isdst=-1\n4 end=7 isdst=-1\n5 end=7 isdst=-1\n"
)


class CalendarReceiptError(RuntimeError):
    """A retained installed calendar component cannot be reconstructed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CalendarReceiptError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path, description: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_pairs)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise CalendarReceiptError(f"{description} is not valid JSON: {path}") from error


def physical_directory(path: Path, description: str) -> Path:
    try:
        result = Path(os.path.abspath(path))
        require(result.exists() and not result.is_symlink() and result.is_dir(),
                f"{description} is not a physical directory: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise CalendarReceiptError(f"{description} is unreadable: {path}") from error


def physical_file(path: Path, description: str) -> Path:
    try:
        result = Path(os.path.abspath(path))
        require(result.exists() and not result.is_symlink() and stat.S_ISREG(result.lstat().st_mode),
                f"{description} is not a physical regular file: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise CalendarReceiptError(f"{description} is unreadable: {path}") from error


def digest(path: Path) -> str:
    path = physical_file(path, "hashed artifact")
    value = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def checkout_path(root: Path, value: object, description: str, *, directory: bool = False) -> Path:
    require(isinstance(value, str) and value, f"{description} has no checkout-relative path")
    relative = Path(value)
    require(not relative.is_absolute() and relative.parts and all(part not in {"", ".", ".."} for part in relative.parts),
            f"{description} has an unsafe checkout-relative path")
    path = root / relative
    return physical_directory(path, description) if directory else physical_file(path, description)


def identity(root: Path, path: Path) -> dict[str, object]:
    path = physical_file(path, "receipt artifact")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise CalendarReceiptError(f"receipt artifact escapes checkout: {path}") from error
    return {"path": relative, "sha256": digest(path), "size": path.stat().st_size}


def assert_identity(root: Path, value: object, description: str, *, expected: Path | None = None) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{description} identity fields differ")
    path = checkout_path(root, value["path"], description)
    if expected is not None:
        require(path == physical_file(expected, description), f"{description} path differs")
    require(value == identity(root, path), f"{description} identity differs from physical artifact")
    return path


def mounted(root: Path, path: Path) -> str:
    try:
        return str(Path(SOURCE_MOUNT) / path.relative_to(root))
    except ValueError as error:
        raise CalendarReceiptError(f"command path escapes checkout: {path}") from error


def recorded_tool_identity(root: Path, path: Path, description: str) -> dict[str, object]:
    path = physical_file(path.resolve(strict=True), description)
    record: dict[str, object] = {"path": str(path), "sha256": digest(path), "size": path.stat().st_size}
    if path.is_relative_to(root):
        record["path"] = mounted(root, path)
    return record


def recorded_command_identity(path: Path, description: str) -> dict[str, object]:
    """Bind a command spelling as well as the physical multi-call payload.

    The core image deliberately uses multi-call executables for ``sh`` and
    ``chroot``.  Invoking their resolved payload directly loses argv[0]'s
    selected applet, so evidence records the executable spelling and hashes
    the physical target independently.
    """
    target = physical_file(path.resolve(strict=True), description)
    return {"path": str(path), "resolved_path": str(target), "sha256": digest(target), "size": target.stat().st_size}


def tracked_source_identity(root: Path, relative: str) -> dict[str, object]:
    path = checkout_path(root, relative, "calendar receipt source")
    return {**identity(root, path), "mode": stat.S_IMODE(path.stat().st_mode)}


def source_product_seal(root: Path, static_product: Path, dynamic_product: Path) -> dict[str, object]:
    root = physical_directory(root, "checkout root")
    static_product = checkout_path(root, static_product.relative_to(root).as_posix(), "static calendar product", directory=True)
    dynamic_product = checkout_path(root, dynamic_product.relative_to(root).as_posix(), "dynamic calendar product", directory=True)
    try:
        static_manifest, _ = products._validate_static_product(static_product)
        dynamic_manifest, _ = products._validate_dynamic_product(dynamic_product)
    except products.ProductEvidenceError as error:
        raise CalendarReceiptError(f"calendar product validation failed: {error}") from error
    return {
        "sources": {name: tracked_source_identity(root, path) for name, path in SOURCE_PATHS.items()},
        "static": {"path": static_product.relative_to(root).as_posix(), "manifest": identity(root, static_manifest),
                   "tree": family.snapshot(static_product)},
        "dynamic": {"path": dynamic_product.relative_to(root).as_posix(), "manifest": identity(root, dynamic_manifest),
                    "tree": family.snapshot(dynamic_product)},
    }


def tool_roster(root: Path, static_product: Path, dynamic_product: Path) -> dict[str, object]:
    helper = physical_file(dynamic_product / "share/crabc/crabc_cc_static.py", "dynamic compiler helper")
    spec = importlib.util.spec_from_file_location("owned_calendar_component_tools", helper)
    require(spec is not None and spec.loader is not None, "cannot load dynamic compiler helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        return {
            "oracle": recorded_tool_identity(root, Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl compiler"),
            "static_driver": recorded_tool_identity(root, static_product / "bin/crabc-cc", "static compiler driver"),
            "dynamic_driver": recorded_tool_identity(root, dynamic_product / "bin/crabc-cc-dynamic", "dynamic compiler driver"),
            "compiler": recorded_tool_identity(root, Path(module.compiler()), "resolved compiler"),
            "linker": recorded_tool_identity(root, Path(module.linker(dynamic_product)), "resolved linker"),
            "shell": recorded_command_identity(Path("/bin/sh"), "capability-proof shell"),
            "chroot": recorded_command_identity(Path("/usr/sbin/chroot"), "chroot control command"),
        }
    finally:
        sys.modules.pop(spec.name, None)


def role_map() -> dict[str, dict[str, object]]:
    result = {name: {"source": source, "defines": defines, "comparison": comparison}
              for name, source, defines, comparison in ROLE_SPECS}
    require(len(result) == len(ROLE_SPECS), "calendar object roles duplicate")
    return result


def classify_tzif_streams(candidate: bytes, musl_observation: bytes) -> str:
    """Accept RFC/POSIX output while retaining pinned-musl output separately."""
    require(musl_observation == TZIF_MUSL_DEFECT_STDOUT, "pinned-musl TZif defect transcript differs")
    if candidate == musl_observation:
        raise CalendarReceiptError("TZif candidate matches pinned-musl defect instead of specification")
    require(candidate == TZIF_SPECIFICATION_STDOUT, "TZif candidate differs from specification transcript")
    return "candidate-matches-specification"


def header_trace_paths(stderr: bytes) -> tuple[str, ...]:
    try:
        lines = stderr.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CalendarReceiptError("installed header trace is not UTF-8") from error
    paths = tuple(line.lstrip(" .") for line in lines if line.lstrip(" .").startswith("/"))
    require(paths, "installed header trace has no parsed include paths")
    return paths


def check_elf_rel(path: Path) -> None:
    data = path.read_bytes()
    require(len(data) >= 20 and data[:7] == b"\x7fELF\x02\x01\x01" and data[16:18] == b"\x01\x00" and
            data[18:20] == b">\x00", "installed-header calendar workload is not an x86-64 ELF relocatable object")


def parse_argv(raw: bytes, label: str) -> list[str]:
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicate_pairs)
    except (ValueError, json.JSONDecodeError) as error:
        raise CalendarReceiptError(f"{label} retained argv is invalid JSON") from error
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label} retained argv is not a string list")
    return value


def artifact_bytes(root: Path, record: Mapping[str, object], field: str, work: Path, label: str) -> bytes:
    suffix = "argv.json" if field == "argv" else "cwd.json" if field == "cwd" else field
    return assert_identity(root, record[field], f"{label} {field}", expected=work / f"{label}.{suffix}").read_bytes()


def action_specs() -> tuple[tuple[str, str, tuple[str, ...], str], ...]:
    return (
        ("calendar", "calendar-differential", ("/fixture/calendar-private.tzif",), "differential"),
        ("calendar-malformed", "calendar-malformed-tzif", ("/fixture/calendar-private.tzif",), "candidate-only"),
        ("calendar-real-zones", "calendar-real-zones", (), "differential"),
        ("calendar-real-zones-missing-lord-howe", "calendar-real-zones", ("--missing-lord-howe",), "fixture-required"),
        ("tzif-check", "tzif-specification", ("/fixture/tzif-private.tzif", "check"), "tzif-specification"),
        ("tzif-observe", "tzif-specification", ("/fixture/tzif-private.tzif", "observe"), "musl-defect"),
        ("strptime", "strptime", (), "differential"),
        ("strptime-zone-guard", "strptime", ("zone-guard",), "musl-fault-correction"),
        ("strptime-zone-delimiters", "strptime", ("zone-delimiters",), "musl-delimiter-correction"),
        ("getdate", "getdate", (), "differential"),
        ("adjustment-query", "legacy-clock-control", ("adjustment-query",), "differential"),
        ("adjustment-guards", "legacy-clock-control", ("adjustment-guards",), "differential-capability-absent"),
        ("settimeofday-null", "legacy-clock-control", ("settimeofday-null",), "differential"),
        ("settimeofday-guards", "legacy-clock-control", ("settimeofday-guards",), "differential-capability-absent"),
        ("adjustment-seccomp", "legacy-clock-control", ("adjustment-seccomp",), "differential-seccomp-denied"),
        ("clock-adjtime-rejected", "clock-adjtime-rejected", (), "differential"),
    )


def execution_roots(work: Path) -> dict[str, Path]:
    return {f"{cell}/{action}": work / "roots" / cell / action for cell in EXECUTION_CELLS
            for action, _role, _args, classification in action_specs() if classification != "musl-defect"}


def command_plan(root: Path, work: Path, static_product: Path, dynamic_product: Path,
                 tools: Mapping[str, object]) -> dict[str, list[str]]:
    """Return the exact finite command argv map used by the producer."""
    tool = lambda name: str(tools[name]["path"])
    m = lambda path: mounted(root, path)
    objects = {role: work / "objects" / f"{role}.o" for role in role_map()}
    plan: dict[str, list[str]] = {}
    for role, source, defines, _comparison in ROLE_SPECS:
        source_path = root / source
        plan[f"header-{role}"] = [tool("compiler"), "-nostdinc", "-isystem", m(dynamic_product / "usr/include"),
                                   "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-std=c11", "-fPIE",
                                   "-E", "-H", *defines, m(source_path)]
        plan[f"compile-{role}"] = [tool("dynamic_driver"), "--dynamic-pie", "-std=c11", "-D_GNU_SOURCE", "-pthread",
                                    "-fno-builtin", "-fno-stack-protector", *defines, "-c", m(source_path), "-o", m(objects[role])]
        if role != EXTRA_ROLE:
            plan[f"oracle-link-{role}"] = [tool("oracle"), "-std=c11", "-pthread", "-static", "-fno-pie", "-no-pie",
                                               m(objects[role]), "-o", m(work / "oracle" / role)]
        for output, flag, linkage in (("static", "-static", "static"), ("static-pie", "-static-pie", "static-pie")):
            executable = work / "executables" / output / role
            receipt = executable.with_name(executable.name + ".crabc-link.json")
            # The installed static driver writes a caller-owned sidecar and
            # resolves its receipt's map and trace records below its process
            # cwd. The producer therefore runs this command in the sidecar's
            # parent and supplies only the safe basename.
            sidecar = receipt.name
            plan[f"{output}-link-{role}"] = [tool("static_driver"), flag, "--link-receipt", sidecar, m(objects[role]), "-o", m(executable)]
            plan[f"{output}-validate-{role}"] = ["python3", "-B", "-", SOURCE_MOUNT, m(static_product), m(objects[role]),
                                                    m(executable), m(receipt), linkage]
        for output, linkage in (("dynamic-pie", "pie"), ("dynamic-non-pie", "non-pie")):
            executable = work / "executables" / output / role
            receipt = executable.with_name(executable.name + ".crabc-link.json")
            plan[f"{output}-link-{role}"] = [tool("dynamic_driver"), f"--dynamic-{linkage}", "-std=c11", "-pthread",
                                                m(objects[role]), "-o", m(executable)]
            plan[f"{output}-validate-{role}"] = ["python3", "-B", "-", SOURCE_MOUNT, m(dynamic_product), m(objects[role]),
                                                    m(executable), m(receipt), linkage]
    for action, role, args, classification in action_specs():
        if classification not in {"candidate-only", "tzif-specification"}:
            plan[f"oracle-{action}"] = [tool("chroot"), m(work / "oracle-roots" / action), f"/consumer-{role}", *args]
        for cell in EXECUTION_CELLS:
            if classification == "musl-defect":
                continue
            execution_root = execution_roots(work)[f"{cell}/{action}"]
            consumer = f"/consumer-{role}"
            command = [tool("chroot"), m(execution_root), *(([INTERPRETER] if cell.endswith("direct") else [])), consumer, *args]
            if classification == "differential-capability-absent":
                capability = work / "capability" / f"{cell}-{action}.status"
                command = [tool("shell"), "-c",
                           f"grep -E '^Cap(Eff|Prm|Inh|Amb|Bnd):' /proc/self/status > {m(capability)}; exec \"$@\"",
                           "calendar-capability-absent", *command]
            plan[f"candidate-{cell}-{action}"] = command
    return plan


def command_cwd(root: Path, work: Path, label: str) -> str:
    for mode in ("static", "static-pie", "dynamic-pie", "dynamic-non-pie"):
        prefix = f"{mode}-link-"
        if label.startswith(prefix):
            role = label.removeprefix(prefix)
            require(role in role_map(), f"{label} product link role differs")
            return mounted(root, work / "executables" / mode)
    return SOURCE_MOUNT


def snapshot_file(root: Path, value: object, description: str, expected: Path) -> dict:
    path = assert_identity(root, value, description, expected=expected)
    observed = read_json(path, description)
    require(isinstance(observed, dict), f"{description} snapshot is not an object")
    return observed


def _fixture_file_roster(directory: Path) -> set[str]:
    directory = physical_directory(directory, "calendar TZif fixture directory")
    observed: set[str] = set()
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), f"calendar TZif fixture path is a symlink: {relative}")
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), f"calendar TZif fixture path is not a regular file: {relative}")
        physical_file(path, f"calendar TZif fixture {relative}")
        observed.add(relative)
    return observed


def _recorded_tool(value: object, description: str) -> None:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"}, f"{description} fields differ")
    require(isinstance(value["path"], str) and value["path"].startswith("/") and ".." not in Path(value["path"]).parts,
            f"{description} path differs")
    require(isinstance(value["sha256"], str) and len(value["sha256"]) == 64 and
            set(value["sha256"]) <= set("0123456789abcdef"), f"{description} hash differs")
    require(isinstance(value["size"], int) and value["size"] > 0, f"{description} size differs")


def check_tzif_input(root: Path, input_root: Path, manifest_record: object) -> dict[str, dict[str, object]]:
    """Authenticate a fixed, test-only IANA-derived TZif fixture input."""
    input_root = physical_directory(input_root, "calendar TZif input root")
    require(input_root.is_relative_to(root / ".work"), "calendar TZif input escapes checkout .work")
    manifest_path = assert_identity(root, manifest_record, "calendar TZif input manifest", expected=input_root / "manifest.json")
    manifest = read_json(manifest_path, "calendar TZif input manifest")
    required = {"schema", "image_id", "version", "archives", "tools", "recipe", "commands", "fixtures"}
    require(isinstance(manifest, dict) and set(manifest) == required, "calendar TZif input manifest fields differ")
    require(manifest["schema"] == TZIF_INPUT_SCHEMA and manifest["image_id"] == PINNED_IMAGE_ID and
            manifest["version"] == TZDATA_VERSION, "calendar TZif input provenance differs")
    archives = manifest["archives"]
    require(isinstance(archives, dict) and set(archives) == set(TZDATA_ARCHIVES), "calendar TZif archive roster differs")
    archive_names = {"tzcode": "tzcode2025b.tar.gz", "tzdata": "tzdata2025b.tar.gz"}
    for name, expected in TZDATA_ARCHIVES.items():
        item = archives[name]
        required_archive = {"url", "sha256", "signature_url", "signature_verification", "archive", "signature"}
        require(isinstance(item, dict) and set(item) == required_archive, f"{name} TZif archive fields differ")
        require(item["url"] == expected["url"] and item["sha256"] == expected["sha256"] and
                item["signature_url"] == expected["signature_url"] and
                item["signature_verification"] == "retained-unverified", f"{name} TZif archive provenance differs")
        archive = assert_identity(root, item["archive"], f"{name} TZif archive",
                                  expected=input_root / "archives" / archive_names[name])
        signature = assert_identity(root, item["signature"], f"{name} TZif signature",
                                    expected=input_root / "archives" / f"{archive_names[name]}.asc")
        require(digest(archive) == expected["sha256"] and signature.stat().st_size > 0,
                f"{name} TZif archive bytes differ")
    tools = manifest["tools"]
    require(isinstance(tools, dict) and set(tools) == {"compiler", "make", "zic"}, "calendar TZif tool roster differs")
    _recorded_tool(tools["compiler"], "calendar TZif compiler")
    _recorded_tool(tools["make"], "calendar TZif make")
    zic = assert_identity(root, tools["zic"], "calendar TZif zic", expected=input_root / "build" / "tzdb" / "zic")
    require(stat.S_IMODE(zic.stat().st_mode) & 0o111, "calendar TZif zic is not executable")
    recipe = manifest["recipe"]
    require(isinstance(recipe, dict) and set(recipe) == {"make_target", "zic_sources", "localtime_source"},
            "calendar TZif derivation recipe fields differ")
    require(recipe["make_target"] == "zic" and recipe["zic_sources"] == ["northamerica", "europe", "australasia"] and
            recipe["localtime_source"] == "America/New_York", "calendar TZif derivation recipe differs")
    commands = manifest["commands"]
    require(isinstance(commands, dict) and set(commands) == {"build-zic", "derive-zoneinfo"},
            "calendar TZif derivation command roster differs")
    command_raw: dict[str, dict[str, bytes]] = {}
    for label in ("build-zic", "derive-zoneinfo"):
        item = commands[label]
        require(isinstance(item, dict) and set(item) == {"argv", "cwd", "stdout", "stderr", "status"},
                f"calendar TZif {label} command fields differ")
        command_raw[label] = {field: artifact_bytes(root, item, field, input_root, label)
                              for field in ("argv", "cwd", "stdout", "stderr", "status")}
        require(command_raw[label]["status"] == b"0\n", f"calendar TZif {label} did not succeed")
        try:
            recorded_cwd = json.loads(command_raw[label]["cwd"], object_pairs_hook=no_duplicate_pairs)
        except (ValueError, json.JSONDecodeError) as error:
            raise CalendarReceiptError(f"calendar TZif {label} cwd is invalid JSON") from error
        require(recorded_cwd == SOURCE_MOUNT, f"calendar TZif {label} cwd differs")
    build_argv = parse_argv(command_raw["build-zic"]["argv"], "calendar TZif build-zic")
    derive_argv = parse_argv(command_raw["derive-zoneinfo"]["argv"], "calendar TZif derive-zoneinfo")
    require(build_argv == [str(tools["make"]["path"]), "-C", mounted(root, input_root / "build" / "tzdb"),
                           f"CC={tools['compiler']['path']}", "zic"],
            "calendar TZif zic build argv differs")
    require(derive_argv == [mounted(root, input_root / "build" / "tzdb" / "zic"), "-d",
                            mounted(root, input_root / "build" / "zoneinfo"),
                            mounted(root, input_root / "build" / "tzdb" / "northamerica"),
                            mounted(root, input_root / "build" / "tzdb" / "europe"),
                            mounted(root, input_root / "build" / "tzdb" / "australasia")],
            "calendar TZif zic derivation argv differs")
    fixture_root = input_root / "fixture"
    require(_fixture_file_roster(fixture_root) == {Path(path).relative_to("fixture").as_posix()
                                                    for path in TZIF_INPUT_PATHS.values()},
            "calendar TZif fixture payload has missing or extra files")
    fixtures = manifest["fixtures"]
    require(isinstance(fixtures, dict) and set(fixtures) == {name for name, _destination in TZIF_FIXTURES},
            "calendar TZif fixture manifest roster differs")
    result: dict[str, dict[str, object]] = {}
    for name, _destination in TZIF_FIXTURES:
        fixture = assert_identity(root, fixtures[name], f"{name} TZif input fixture",
                                  expected=input_root / TZIF_INPUT_PATHS[name])
        require(stat.S_IMODE(fixture.stat().st_mode) == 0o644, f"{name} TZif input mode differs")
        require({"sha256": digest(fixture), "size": fixture.stat().st_size} == TZIF_EXPECTED_FIXTURES[name],
                f"{name} TZif fixture bytes differ from the tracked derivation")
        result[name] = dict(fixtures[name])
    require(result["localtime"]["sha256"] == result["America/New_York"]["sha256"] and
            result["localtime"]["size"] == result["America/New_York"]["size"],
            "calendar /etc/localtime is not the explicit New_York fixture")
    return result


def check_fixture_manifest(root: Path, work: Path, record: object) -> dict[str, dict[str, object]]:
    require(isinstance(record, dict) and set(record) == {"input_root", "input_manifest", "staged"},
            "calendar TZif fixture fields differ")
    input_root = checkout_path(root, record["input_root"], "calendar TZif input root", directory=True)
    input_fixtures = check_tzif_input(root, input_root, record["input_manifest"])
    staged_record = record["staged"]
    require(isinstance(staged_record, dict) and set(staged_record) == set(input_fixtures),
            "calendar staged TZif fixture roster differs")
    result: dict[str, dict[str, object]] = {}
    for name, destination in TZIF_FIXTURES:
        item = staged_record[name]
        require(isinstance(item, dict) and set(item) == {"input", "staged"}, f"{name} staged fixture fields differ")
        require(item["input"] == input_fixtures[name], f"{name} staged input identity differs")
        staged = assert_identity(root, item["staged"], f"{name} staged TZif fixture", expected=work / "zoneinfo-source" / name)
        require(stat.S_IMODE(staged.stat().st_mode) == 0o644, f"{name} staged TZif mode differs")
        result[destination] = dict(item["staged"])
    return result


def check_safe_clock_source(root: Path) -> None:
    source = checkout_path(root, SOURCE_PATHS["legacy-clock-control"], "legacy clock source").read_text(encoding="utf-8")
    begin = source.index("static void run_adjustment_seccomp(void)")
    body = source[begin:source.index("int main(", begin)]
    require(body.index("install_adjustment_denial();") < body.index("adjtimex(&state)"),
            "legacy seccomp denial is not installed before adjustment")
    for syscall in SECCOMP_DENIED_SYSCALLS:
        require(f"SYS_{syscall}" in source, f"legacy seccomp filter omits {syscall}")
    direct = checkout_path(root, SOURCE_PATHS["clock-adjtime-rejected"], "clock_adjtime source").read_text(encoding="utf-8")
    for marker in ("(clockid_t)-1", "CLOCK_MONOTONIC", "struct timex record = {0}"):
        require(marker in direct, f"clock_adjtime rejected-ID fixture omits {marker}")


def fixture_destinations_for_action(action: str, fixtures: Mapping[str, Mapping[str, object]]) -> dict[str, Mapping[str, object]]:
    result = dict(fixtures)
    if action == "calendar-real-zones-missing-lord-howe":
        result.pop("/usr/share/zoneinfo/Australia/Lord_Howe", None)
    return result


def same_materialized_product_tree(copied: object, supplied: object) -> bool:
    """Compare a chroot product copy without treating container UID as payload.

    ``shutil.copy2`` retains each supplied product's file type, bytes, modes,
    symlink targets, and tree roster.  It intentionally does not replay host
    ownership: staging happens as container root so the chroot can operate on
    its private materialization.  Ownership is therefore observed in each
    retained snapshot but cannot stand in for a product mutation.  Every other
    snapshot field, especially the supplied modes, remains exact.
    """
    if not isinstance(copied, dict) or not isinstance(supplied, dict) or set(copied) != set(supplied):
        return False
    for name in copied:
        left = copied[name]
        right = supplied[name]
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        if {key: value for key, value in left.items() if key not in {"uid", "gid"}} != \
                {key: value for key, value in right.items() if key not in {"uid", "gid"}}:
            return False
    return True


def check_capability_absence(path: Path, description: str) -> None:
    """Require the container boundary to exclude SYS_TIME before direct exec.

    The guard commands cannot add a capability after this point: their shell
    immediately ``exec``s the recorded chroot command, and an absent bounding
    bit prevents a privileged executable from reacquiring it.  Requiring every
    relevant status set avoids mistaking an absent effective bit alone for the
    confinement boundary.
    """
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CalendarReceiptError(f"{description} cannot be read") from error
    observed: dict[str, int] = {}
    for line in lines:
        raw_name, separator, value = line.partition("\t")
        name = raw_name.removesuffix(":")
        require(separator and raw_name == f"{name}:" and name in CAPABILITY_STATUS_FIELDS and name not in observed and
                len(value) == 16 and all(character in "0123456789abcdef" for character in value),
                f"{description} fields differ")
        observed[name] = int(value, 16)
    require(set(observed) == set(CAPABILITY_STATUS_FIELDS), f"{description} fields differ")
    for name, value in observed.items():
        require(not (value & (1 << CAP_SYS_TIME_BIT)), f"{description} retains CAP_SYS_TIME in {name}")


def check_execution_root(root: Path, work: Path, dynamic_product: Path, record: object, cell: str, action: str,
                         executable: Path, fixtures: Mapping[str, Mapping[str, object]]) -> None:
    require(isinstance(record, dict) and set(record) == {"before", "after", "product-copy", "capability"},
            f"{cell}/{action} execution-root fields differ")
    execution_root = work / "roots" / cell / action
    audit = work / "root-audits" / f"{cell}-{action}"
    before = snapshot_file(root, record["before"], f"{cell}/{action} before root", audit / "before.json")
    after = snapshot_file(root, record["after"], f"{cell}/{action} after root", audit / "after.json")
    if cell.startswith("dynamic"):
        copied = snapshot_file(root, record["product-copy"], f"{cell}/{action} copied product", audit / "product-copy.json")
        require(same_materialized_product_tree(copied, family.snapshot(dynamic_product)),
                f"{cell}/{action} product copy differs from supplied product")
        base_names = {name for name, value in copied.items()
                      if isinstance(value, dict) and value.get("kind") != "directory"}
    else:
        require(record["product-copy"] is None, f"{cell}/{action} static root unexpectedly records a dynamic product")
        base_names = set()
    role = dict((name, role) for name, role, _args, _kind in action_specs())[action]
    consumer_name = f"consumer-{role}"
    action_fixtures = fixture_destinations_for_action(action, fixtures)
    expected_leaves = set(base_names) | {consumer_name} | {destination.lstrip("/") for destination in action_fixtures}
    deleted = ({"fixture/calendar-private.tzif"} if action in {"calendar", "calendar-malformed"} else
               {"fixture/tzif-private.tzif"} if action.startswith("tzif") else set())
    if action == "getdate":
        deleted.add("templates/mask")
    for snapshot, is_before in ((before, True), (after, False)):
        leaves = {name for name, value in snapshot.items() if isinstance(value, dict) and value.get("kind") != "directory"}
        require(leaves == expected_leaves | (deleted if is_before else set()), f"{cell}/{action} execution root roster differs")
        require(snapshot.get(consumer_name) == family.snapshot(executable.parent).get(executable.name),
                f"{cell}/{action} executed consumer differs from linked executable")
        for destination, staged_identity in action_fixtures.items():
            leaf = destination.lstrip("/")
            require(isinstance(snapshot.get(leaf), dict) and snapshot[leaf].get("sha256") == staged_identity["sha256"] and
                    snapshot[leaf].get("size") == staged_identity["size"] and snapshot[leaf].get("mode") == 0o644,
                    f"{cell}/{action} sealed TZif fixture differs")
    if record["capability"] is None:
        require(action not in {"adjustment-guards", "settimeofday-guards"},
                f"{cell}/{action} lacks CAP_SYS_TIME-absent boundary proof")
    else:
        capability = assert_identity(root, record["capability"], f"{cell}/{action} capability proof",
                                     expected=work / "capability" / f"{cell}-{action}.status")
        check_capability_absence(capability, f"{cell}/{action} capability proof")


def validate_report(root: Path, report_path: Path, *, require_static: bool = True) -> dict[str, object]:
    root = physical_directory(root, "checkout root")
    report_path = physical_file(report_path, "calendar component report")
    require(report_path.parent.is_relative_to(root / ".work") and report_path.name == "owned-calendar-products.json",
            "calendar component report is not retained below checkout .work")
    report = read_json(report_path, "calendar component report")
    required = {"schema", "source_mount", "image_id", "execution_mode", "scope", "rows", "sources", "objects", "products",
                "seals", "fixtures", "commands", "links", "execution_roots", "family_completion", "promotion_ready", "public_support"}
    require(isinstance(report, dict) and set(report) == required, "calendar component report fields differ")
    require(report["schema"] == SCHEMA and report["source_mount"] == SOURCE_MOUNT and report["image_id"] == PINNED_IMAGE_ID and
            report["execution_mode"] == FULL_MODE and report["scope"] == list(SCOPE) and report["rows"] == [list(row) for row in ROWS],
            "calendar component report contract differs")
    require(report["family_completion"] is False and report["promotion_ready"] is False and report["public_support"] is False,
            "calendar component receipt is promoting")
    require(require_static, "calendar receipt has no dynamic-only admission")
    products_record = report["products"]
    require(isinstance(products_record, dict) and set(products_record) == {"static", "dynamic"}, "calendar product roster differs")
    static_product = checkout_path(root, products_record["static"], "static calendar product", directory=True)
    dynamic_product = checkout_path(root, products_record["dynamic"], "dynamic calendar product", directory=True)
    work = report_path.parent
    current_seal = source_product_seal(root, static_product, dynamic_product)
    require(report["sources"] == current_seal["sources"], "calendar source identity differs")
    seals = report["seals"]
    require(isinstance(seals, dict) and set(seals) == {"source-product-before", "source-product-after", "tools-before", "tools-after"},
            "calendar seal roster differs")
    for name in ("source-product-before", "source-product-after"):
        path = assert_identity(root, seals[name], f"{name} seal", expected=work / f"{name}.json")
        require(read_json(path, name) == current_seal, f"{name} source/product semantics differ")
    current_tools = tool_roster(root, static_product, dynamic_product)
    for name in ("tools-before", "tools-after"):
        path = assert_identity(root, seals[name], f"{name} seal", expected=work / f"{name}.json")
        require(read_json(path, name) == current_tools, f"{name} tool semantics differ")
    fixtures = check_fixture_manifest(root, work, report["fixtures"])
    check_safe_clock_source(root)

    objects = report["objects"]
    require(isinstance(objects, dict) and set(objects) == set(role_map()), "calendar object roster differs")
    object_paths: dict[str, Path] = {}
    for role, spec in role_map().items():
        record = objects[role]
        require(isinstance(record, dict) and set(record) == {"source", "defines", "object"}, f"{role} object fields differ")
        require(record["source"] == spec["source"] and tuple(record["defines"]) == tuple(spec["defines"]),
                f"{role} source or preprocessor role differs")
        object_paths[role] = assert_identity(root, record["object"], f"{role} object", expected=work / "objects" / f"{role}.o")
        check_elf_rel(object_paths[role])

    plan = command_plan(root, work, static_product, dynamic_product, current_tools)
    commands = report["commands"]
    require(isinstance(commands, dict) and set(commands) == set(plan), "calendar command roster differs")
    raw: dict[str, dict[str, bytes]] = {}
    for label, expected_argv in plan.items():
        record = commands[label]
        require(isinstance(record, dict) and set(record) == {"argv", "cwd", "stdout", "stderr", "status"},
                f"{label} retained command fields differ")
        raw[label] = {field: artifact_bytes(root, record, field, work, label)
                      for field in ("argv", "cwd", "stdout", "stderr", "status")}
        require(parse_argv(raw[label]["argv"], label) == expected_argv, f"{label} retained argv differs")
        try:
            recorded_cwd = json.loads(raw[label]["cwd"], object_pairs_hook=no_duplicate_pairs)
        except (ValueError, json.JSONDecodeError) as error:
            raise CalendarReceiptError(f"{label} retained cwd is invalid JSON") from error
        require(recorded_cwd == command_cwd(root, work, label), f"{label} retained cwd differs")

    for role in role_map():
        trace = raw[f"header-{role}"]
        require(trace["status"] == b"0\n" and trace["stdout"], f"{role} header trace did not succeed")
        origins = header_trace_paths(trace["stderr"])
        include_root = mounted(root, dynamic_product / "usr/include") + "/"
        require(all(origin.startswith(include_root) for origin in origins), f"{role} header trace names an ambient origin")
        require(raw[f"compile-{role}"]["status"] == b"0\n", f"{role} installed-header compile failed")
    links = report["links"]
    require(isinstance(links, dict), "calendar product links are not an object")
    expected_links = {f"{mode}/{role}" for mode in ("static", "static-pie", "dynamic-pie", "dynamic-non-pie") for role in role_map()}
    require(set(links) == expected_links, "calendar product link roster differs")
    linkage_for = {"static": "static", "static-pie": "static-pie", "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}
    for label in sorted(expected_links):
        mode, role = label.split("/", 1)
        linkage = linkage_for[mode]
        product = static_product if mode.startswith("static") else dynamic_product
        executable = work / "executables" / mode / role
        receipt = executable.with_name(executable.name + ".crabc-link.json")
        product_link = assert_identity(root, links[label], f"{label} product-link", expected=work / "links" / f"{mode}-{role}.json")
        reconstructed = products.validate_retained_link(root, SOURCE_MOUNT, product, object_paths[role], executable, receipt, linkage,
                                                        {key: current_tools["linker"][key] for key in ("path", "sha256")})
        expected_link = dict(reconstructed)
        expected_link["product"] = mounted(root, product)
        require(read_json(product_link, f"{label} product-link") == expected_link, f"{label} product-link differs from reconstructed validation")
        require(raw[f"{mode}-validate-{role}"]["stdout"] == canonical(expected_link), f"{label} validate stdout differs from reconstructed validation")
        require(raw[f"{mode}-link-{role}"]["status"] == b"0\n" and raw[f"{mode}-validate-{role}"]["status"] == b"0\n",
                f"{label} retained link did not succeed")

    for action, _role, _args, classification in action_specs():
        if classification not in {"candidate-only", "tzif-specification"}:
            oracle = raw[f"oracle-{action}"]
            expected_status = b"139\n" if classification == "musl-fault-correction" else \
                b"1\n" if classification == "fixture-required" else b"0\n"
            require(oracle["status"] == expected_status,
                    f"pinned-musl {action} outcome differs")
        if classification == "musl-defect":
            classify_tzif_streams(TZIF_SPECIFICATION_STDOUT, raw[f"oracle-{action}"]["stdout"])
            continue
        for cell in EXECUTION_CELLS:
            candidate = raw[f"candidate-{cell}-{action}"]
            expected_status = b"1\n" if classification == "fixture-required" else b"0\n"
            require(candidate["status"] == expected_status, f"{cell}/{action} outcome differs")
            if classification in {"differential", "differential-capability-absent", "differential-seccomp-denied"}:
                oracle = raw[f"oracle-{action}"]
                require(candidate["stdout"] == oracle["stdout"] and candidate["stderr"] == oracle["stderr"],
                        f"{cell}/{action} transcript differs from pinned musl")
                if action == "calendar-real-zones":
                    require(candidate["stdout"] == REAL_ZONE_SUCCESS_STDOUT and candidate["stderr"] == b"",
                            f"{cell}/{action} did not prove known named-zone transitions")
            elif classification == "candidate-only":
                ordinary = raw[f"candidate-{cell}-calendar"]
                require(candidate["stdout"] == ordinary["stdout"] and candidate["stderr"] == ordinary["stderr"],
                        f"{cell}/{action} changed ordinary calendar records")
            elif classification == "tzif-specification":
                classify_tzif_streams(candidate["stdout"], raw["oracle-tzif-observe"]["stdout"])
                require(candidate["stderr"] == b"", f"{cell}/{action} wrote stderr")
            elif classification == "musl-fault-correction":
                require(candidate["stdout"] == b"" and candidate["stderr"] == b"", f"{cell}/{action} correction transcript differs")
            elif classification == "musl-delimiter-correction":
                require(candidate["stdout"] == STRPTIME_DELIMITERS_STDOUT and candidate["stderr"] == b"",
                        f"{cell}/{action} delimiter correction transcript differs")
            elif classification == "fixture-required":
                oracle = raw[f"oracle-{action}"]
                require(candidate["status"] == b"1\n" and candidate["stdout"] == b"" and
                        candidate["stderr"] == REAL_ZONE_MISSING_LORD_HOWE_STDERR and
                        candidate["stdout"] == oracle["stdout"] and candidate["stderr"] == oracle["stderr"],
                        f"{cell}/{action} missing-fixture regression differs")
            else:
                raise CalendarReceiptError(f"unknown calendar action classification: {classification}")
    roots = report["execution_roots"]
    expected_roots = set(execution_roots(work))
    require(isinstance(roots, dict) and set(roots) == expected_roots, "calendar execution-root roster differs")
    for label in sorted(expected_roots):
        cell, action = label.split("/", 1)
        role = dict((name, role) for name, role, _args, _kind in action_specs())[action]
        mode = "static" if cell == "static-et-exec" else "static-pie" if cell == "static-pie" else "dynamic-pie" if cell.startswith("dynamic-pie") else "dynamic-non-pie"
        check_execution_root(root, work, dynamic_product, roots[label], cell, action,
                             work / "executables" / mode / role, fixtures)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-report")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--require-static", action="store_true")
    args = parser.parse_args()
    try:
        validate_report(args.root, args.report, require_static=args.require_static)
    except (CalendarReceiptError, OSError, ValueError, products.ProductEvidenceError) as error:
        parser.exit(1, f"owned calendar component receipt failed: {error}\n")
    print("owned calendar component receipt: valid; bounded component evidence remains non-promoting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
