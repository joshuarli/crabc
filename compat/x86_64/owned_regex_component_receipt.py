#!/usr/bin/env python3
"""Reconstruct one bounded installed regex component receipt.

This reader is deliberately specific to ``run_owned_regex.sh``. It
does not turn this selected installed regex probe into family closure: the
report's flags remain non-promoting. It instead makes a
retained producer report useful as a component input by replaying every
recorded source, product, tool, command, link, copied-payload, and oracle
relation.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_crypt_runtime_evidence as copies
import installed_compiler_translation as translation_contract
import owned_posix_family_execution as family
import owned_posix_product_evidence as products


SCHEMA = "crabc.x86_64-owned-regex-products/v2"
SOURCE_MOUNT = "/workspace"
SCOPE = ("pattern.regex",)
HEADERS = (
    "locale.h", "regex.h", "stddef.h", "stdio.h", "stdlib.h", "string.h",
    "features.h", "bits/alltypes.h",
)
ORACLE_COMPLETION = b"owned-regex-installed-header-ok\n"
# `--bounded-backreference`: pinned musl faults reading past a guarded subject;
# the owned port rejects the out-of-subject range and reports musl's
# ordinary-memory answer (docs/evidence/x86-owned-regex.md).
BOUNDED_ARGUMENT = "--bounded-backreference"
BOUNDED_ORACLE = b"bounded-backreference source-fault signal=11\n"
BOUNDED_OWNED = b"bounded-backreference status=0 match=0,3 group=0,1\n"
API = ("regcomp", "regexec", "regerror", "regfree")
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
SOURCE_PATHS = {
    "probe": "compat/x86_64/owned_regex_probe.c",
    "runner": "compat/x86_64/run_owned_regex.sh",
    "reader": "compat/x86_64/owned_regex_component_receipt.py",
}
FULL_MODE = "full-six-mode"
DYNAMIC_MODE = "dynamic-only-four-cell-development"


class RegexReceiptError(RuntimeError):
    """A regex component receipt is incomplete or no longer reconstructs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegexReceiptError(message)


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
        raise RegexReceiptError(f"{description} is not valid JSON: {path}") from error


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
        raise RegexReceiptError(f"{description} is unreadable: {path}") from error


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
        raise RegexReceiptError(f"{description} is unreadable: {path}") from error


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
    require(not relative.is_absolute() and relative.parts and
            all(part not in {"", ".", ".."} for part in relative.parts),
            f"{description} has an unsafe checkout-relative path")
    path = root / relative
    return physical_directory(path, description) if directory else physical_file(path, description)


def identity(root: Path, path: Path) -> dict[str, object]:
    path = physical_file(path, "receipt artifact")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise RegexReceiptError(f"receipt artifact escapes checkout: {path}") from error
    return {"path": relative, "sha256": digest(path), "size": path.stat().st_size}


def assert_identity(root: Path, value: object, description: str, *, expected: Path | None = None) -> Path:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{description} identity fields differ")
    path = checkout_path(root, value["path"], description)
    if expected is not None:
        require(path == physical_file(expected, description), f"{description} path differs")
    observed = identity(root, path)
    require(value == observed, f"{description} identity differs from physical artifact")
    return path


def tool_identity(path: Path, description: str) -> dict[str, object]:
    path = physical_file(path.resolve(strict=True), description)
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size}


def tracked_source_identity(root: Path, relative: str) -> dict[str, object]:
    path = checkout_path(root, relative, "regex reader source")
    return {**identity(root, path), "mode": stat.S_IMODE(path.stat().st_mode)}


def source_product_seal(root: Path, static: Path | None, dynamic: Path) -> dict[str, object]:
    root = physical_directory(root, "checkout root")
    dynamic = checkout_path(root, dynamic.relative_to(root).as_posix(), "dynamic regex product", directory=True)
    try:
        dynamic_manifest, _ = products._validate_dynamic_product(dynamic)
    except products.ProductEvidenceError as error:
        raise RegexReceiptError(f"dynamic regex product validation failed: {error}") from error
    result: dict[str, object] = {
        "sources": {name: tracked_source_identity(root, relative) for name, relative in SOURCE_PATHS.items()},
        "dynamic": {"path": dynamic.relative_to(root).as_posix(), "manifest": identity(root, dynamic_manifest),
                    "tree": family.snapshot(dynamic)},
    }
    if static is not None:
        static = checkout_path(root, static.relative_to(root).as_posix(), "static regex product", directory=True)
        try:
            static_manifest, _ = products._validate_static_product(static)
        except products.ProductEvidenceError as error:
            raise RegexReceiptError(f"static regex product validation failed: {error}") from error
        result["static"] = {"path": static.relative_to(root).as_posix(), "manifest": identity(root, static_manifest),
                            "tree": family.snapshot(static)}
    return result


def recorded_tool_identity(root: Path, path: Path, description: str) -> dict[str, object]:
    """Record a physical tool with the fixed container spelling where applicable."""

    path = physical_file(path.resolve(strict=True), description)
    record = tool_identity(path, description)
    if path.is_relative_to(root):
        record["path"] = mounted(root, path)
    return record


def tool_roster(root: Path, dynamic: Path, static: Path | None) -> dict[str, object]:
    helper = physical_file(dynamic / "share/crabc/crabc_cc_static.py", "dynamic compiler helper")
    spec = importlib.util.spec_from_file_location("owned_regex_component_tools", helper)
    require(spec is not None and spec.loader is not None, "cannot load dynamic compiler helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        result = {
            "oracle": recorded_tool_identity(root, Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl compiler"),
            "dynamic_driver": recorded_tool_identity(root, dynamic / "bin/crabc-cc-dynamic", "dynamic compiler driver"),
            "compiler": recorded_tool_identity(root, Path(module.compiler()), "resolved compiler"),
            "linker": recorded_tool_identity(root, Path(module.linker(dynamic)), "resolved linker"),
            "nm": recorded_tool_identity(root, Path("/usr/bin/nm"), "pinned symbol reader"),
            "readelf": recorded_tool_identity(root, Path("/usr/bin/readelf"), "pinned ELF reader"),
            "env": recorded_tool_identity(root, Path("/usr/bin/env"), "pinned clean-environment launcher"),
        }
        if static is not None:
            result["static_driver"] = recorded_tool_identity(root, static / "bin/crabc-cc", "static compiler driver")
        return result
    finally:
        sys.modules.pop(spec.name, None)


def mounted(root: Path, path: Path) -> str:
    try:
        return str(Path(SOURCE_MOUNT) / path.relative_to(root))
    except ValueError as error:
        raise RegexReceiptError(f"command path escapes checkout: {path}") from error


def command_plan(paths: Mapping[str, object], tools: Mapping[str, object], mode: str) -> dict[str, list[str]]:
    """Return the exact retained argv map for the finite regex component."""

    require(mode in {FULL_MODE, DYNAMIC_MODE}, "regex execution mode differs")
    root = Path(paths["root"])
    work = Path(paths["work"])
    probe = Path(paths["probe"])
    runner = Path(paths["runner"])
    reader = Path(paths["reader"])
    dynamic = Path(paths["dynamic"])
    static = paths.get("static")
    if static is not None:
        static = Path(static)
    workload = Path(paths["workload"])
    oracle = Path(paths["oracle"])
    executables = paths["executables"]
    require(isinstance(executables, Mapping), "regex executable map differs")
    tool = lambda name: str(tools[name]["path"])
    m = lambda value: mounted(root, value)
    symbols = lambda reader, *arguments: [tool("env"), "-i", "LC_ALL=C", "LANG=C", "TZ=UTC",
                                            "PATH=/usr/bin:/bin", tool(reader), *arguments]
    plan = {
        "header-trace": [tool("compiler"), "-nostdinc", "-isystem", m(dynamic / "usr/include"),
                         *translation_contract.hosted_translation_flags(dynamic), "-std=c11", "-fPIE", "-E", "-H", m(probe)],
        "compile": [tool("dynamic_driver"), "--dynamic-pie", "-std=c11", "-fno-builtin",
                    "-c", m(probe), "-o", m(workload)],
        "object-imports": symbols("nm", "-g", "--undefined-only", "--format=posix", m(workload)),
        "oracle-link": [tool("oracle"), "-static", "-fno-pie", "-no-pie", m(workload), "-o", m(oracle)],
        "oracle-providers": symbols("nm", "-g", "--defined-only", "--format=posix", m(oracle)),
        "oracle-run": ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", m(oracle)],
        "oracle-bounded": ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", m(oracle), BOUNDED_ARGUMENT],
    }
    if mode == FULL_MODE:
        require(static is not None, "full regex mode needs a static product")
        for name, flag, linkage in (("static", "-static", "static"), ("static-pie", "-static-pie", "static-pie")):
            executable = Path(executables[name])
            receipt = work / f"{name}.crabc-link.json"
            plan[f"{name}-link"] = [tool("static_driver"), flag, "--link-receipt", receipt.name,
                                      m(workload), "-o", m(executable)]
            plan[f"{name}-validate"] = ["python3", "-B", "-", SOURCE_MOUNT, m(static), m(workload),
                                          m(executable), m(receipt), linkage]
            plan[f"{name}-run"] = ["env", "-i", "LC_ALL=C", "LANG=C", "TZ=UTC", m(executable)]
            plan[f"{name}-bounded"] = [*plan[f"{name}-run"], BOUNDED_ARGUMENT]
            plan[f"{name}-providers"] = symbols("nm", "-g", "--defined-only", "--format=posix", m(executable))
        plan["static-archive-providers"] = symbols("nm", "-g", "--defined-only", "--format=posix",
                                                     m(static / "usr/lib/libc.a"))
    for name, linkage in (("dynamic-pie", "pie"), ("dynamic-non-pie", "non-pie")):
        executable = Path(executables[name])
        root_copy = work / f"{name}-root"
        receipt = executable.with_name(executable.name + ".crabc-link.json")
        plan[f"{name}-link"] = [tool("dynamic_driver"), f"--dynamic-{linkage}", m(workload), "-o", m(executable)]
        plan[f"{name}-validate"] = ["python3", "-B", "-", SOURCE_MOUNT, m(dynamic), m(workload),
                                      m(executable), m(receipt), linkage]
        payload = ["--product", m(dynamic), "--execution-root", m(root_copy), "--source-consumer", m(executable),
                   "--execution-consumer", m(root_copy / "consumer"), "--record", m(work / f"{name}-execution-payload.json")]
        copy_tool = m(root / "compat/x86_64/owned_crypt_runtime_evidence.py")
        plan[f"{name}-copy-before"] = ["python3", "-B", copy_tool, "record", *payload]
        plan[f"{name}-copy-audit-before"] = ["python3", "-B", copy_tool, "audit", *payload]
        plan[f"{name}-kernel"] = ["chroot", m(root_copy), "/consumer"]
        plan[f"{name}-direct"] = ["chroot", m(root_copy), INTERPRETER, "/consumer"]
        plan[f"{name}-kernel-bounded"] = [*plan[f"{name}-kernel"], BOUNDED_ARGUMENT]
        plan[f"{name}-direct-bounded"] = [*plan[f"{name}-direct"], BOUNDED_ARGUMENT]
        plan[f"{name}-copy-audit-after"] = ["python3", "-B", copy_tool, "audit", *payload]
    plan["dynamic-providers"] = symbols("readelf", "--dyn-syms", "--wide", m(dynamic / "usr/lib/libc.so"))
    return plan


def artifact_bytes(root: Path, record: Mapping[str, object], field: str, work: Path, label: str) -> bytes:
    suffix = "argv.json" if field == "argv" else field
    path = assert_identity(root, record[field], f"{label} {field}", expected=work / f"{label}.{suffix}")
    return path.read_bytes()


def parse_argv(raw: bytes, label: str) -> list[str]:
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicate_pairs)
    except (ValueError, json.JSONDecodeError) as error:
        raise RegexReceiptError(f"{label} retained argv is invalid JSON") from error
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label} retained argv is not a string list")
    return value


def check_elf_rel(path: Path) -> None:
    data = path.read_bytes()
    require(len(data) >= 20 and data[:7] == b"\x7fELF\x02\x01\x01" and
            data[16:18] == b"\x01\x00" and data[18:20] == b">\x00",
            "installed-header workload is not an x86-64 ELF relocatable object")


def check_source_object_checks(root: Path, work: Path, sources: Mapping[str, object], workload: Path,
                               checks: object) -> None:
    require(isinstance(checks, dict) and set(checks) == {"before", "after"},
            "source/object check record differs")
    before = assert_identity(root, checks["before"], "source/object before", expected=work / "source-object-before.sha256")
    after = assert_identity(root, checks["after"], "source/object after", expected=work / "source-object-after.txt")
    paths = [checkout_path(root, sources[name]["path"], f"source/object {name}") for name in ("probe", "runner", "reader")]
    paths.append(workload)
    expected_before = b"".join(
        f"{digest(path)}  {mounted(root, path)}\n".encode("ascii") for path in paths
    )
    expected_after = b"".join(f"{mounted(root, path)}: OK\n".encode("utf-8") for path in paths)
    require(before.read_bytes() == expected_before, "source/object before hash list differs")
    require(after.read_bytes() == expected_after, "source/object after check differs")


def header_trace_paths(stderr: bytes) -> tuple[str, ...]:
    """Parse only Clang ``-H`` file entries and reject ambient include roots."""

    try:
        lines = stderr.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RegexReceiptError("installed header trace is not UTF-8") from error
    paths: list[str] = []
    for line in lines:
        candidate = line.lstrip(" .")
        if candidate.startswith("/"):
            paths.append(candidate)
    require(paths, "installed header trace has no parsed include paths")
    return tuple(paths)


def check_nm_api_rows(output: bytes, kind: str, description: str) -> None:
    """Require one public POSIX-nm row for every selected regex entry.

    The installed-header object must import these declarations, while the
    pinned oracle and each static owned provider must define them.  Other
    object imports and definitions belong to the fixed probe and link mode;
    this narrow check only establishes that all four regex API paths cross the
    retained object/provider boundary exactly once.
    """

    require(kind in {"U", "T"}, "regex symbol kind differs")
    try:
        rows = [line.split() for line in output.decode("utf-8").splitlines()]
    except UnicodeDecodeError as error:
        raise RegexReceiptError(f"{description} is not UTF-8") from error
    for name in API:
        matches = [row for row in rows if len(row) >= 2 and row[0] == name and row[1] == kind]
        require(len(matches) == 1, f"{description} does not contain exactly one {kind} {name} row")


def check_dynamic_api_rows(output: bytes) -> None:
    """Require each selected regex API as one defined public shared symbol."""

    try:
        rows = [line.split() for line in output.decode("utf-8").splitlines()]
    except UnicodeDecodeError as error:
        raise RegexReceiptError("dynamic regex provider output is not UTF-8") from error
    for name in API:
        matches = [row for row in rows if len(row) == 8 and row[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and
                   row[6] != "UND" and row[7] == name]
        require(len(matches) == 1, f"dynamic regex provider does not contain exactly one public {name} row")


def replay_symbol_reader(root: Path, label: str, argv: list[str]) -> bytes:
    """Re-run one sealed, read-only symbol command against current artifacts.

    The report's raw symbol text is useful provenance, but it does not itself
    establish what the rehashed ET_REL object, archive, or shared object
    contains.  The runner records the complete command with its fixed
    environment launcher and sealed reader identity.  Replay it only at the
    fixed container mount so every path still names the retained physical
    artifact; it never executes a candidate consumer.
    """

    require(root == Path(SOURCE_MOUNT), "regex symbol replay requires the pinned /workspace mount")
    try:
        completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RegexReceiptError(f"{label} sealed symbol replay could not finish") from error
    require(completed.returncode == 0, f"{label} sealed symbol replay exited {completed.returncode}")
    require(completed.stderr == b"", f"{label} sealed symbol replay emitted stderr")
    return completed.stdout


def validate_report(root: Path, report_path: Path, *, require_static: bool = False) -> dict[str, object]:
    root = physical_directory(root, "checkout root")
    report_path = physical_file(report_path, "regex component report")
    require(report_path.parent.is_relative_to(root / ".work") and report_path.name == "owned-regex-products.json",
            "regex component report is not retained below checkout .work")
    report = read_json(report_path, "regex component report")
    expected_fields = {
        "schema", "source_mount", "execution_mode", "scope", "sources", "workload", "products", "seals", "commands",
        "links", "execution_payloads", "source_object_checks", "family_completion", "promotion_ready", "public_support",
    }
    require(isinstance(report, dict) and set(report) == expected_fields, "regex component report fields differ")
    require(report["schema"] == SCHEMA and report["source_mount"] == SOURCE_MOUNT and report["scope"] == list(SCOPE),
            "regex component report contract differs")
    require(report["family_completion"] is False and report["promotion_ready"] is False and report["public_support"] is False,
            "regex component receipt is promoting")
    mode = report["execution_mode"]
    require(mode in {FULL_MODE, DYNAMIC_MODE}, "regex component execution mode differs")
    if require_static:
        require(mode == FULL_MODE, "regex component acceptance requires static/static-pie evidence")
    products_record = report["products"]
    expected_product_keys = {"dynamic", "static"} if mode == FULL_MODE else {"dynamic"}
    require(isinstance(products_record, dict) and set(products_record) == expected_product_keys,
            "regex component product roster differs")
    dynamic = checkout_path(root, products_record["dynamic"], "dynamic regex product", directory=True)
    static = checkout_path(root, products_record["static"], "static regex product", directory=True) if mode == FULL_MODE else None
    work = report_path.parent
    workload = assert_identity(root, report["workload"], "installed-header workload", expected=work / "workload.o")
    check_elf_rel(workload)

    current_seal = source_product_seal(root, static, dynamic)
    require(report["sources"] == current_seal["sources"], "regex source identity differs")
    seals = report["seals"]
    require(isinstance(seals, dict) and set(seals) == {"source-product-before", "source-product-after", "tools-before", "tools-after"},
            "regex seal roster differs")
    for name in ("source-product-before", "source-product-after"):
        path = assert_identity(root, seals[name], f"{name} seal", expected=work / f"{name}.json")
        require(read_json(path, name) == current_seal, f"{name} source/product semantics differ")
    current_tools = tool_roster(root, dynamic, static)
    for name in ("tools-before", "tools-after"):
        path = assert_identity(root, seals[name], f"{name} seal", expected=work / f"{name}.json")
        require(read_json(path, name) == current_tools, f"{name} tool semantics differ")
    check_source_object_checks(root, work, report["sources"], workload, report["source_object_checks"])

    paths: dict[str, object] = {
        "root": root, "work": work,
        "probe": checkout_path(root, SOURCE_PATHS["probe"], "regex probe"),
        "runner": checkout_path(root, SOURCE_PATHS["runner"], "regex runner"),
        "reader": checkout_path(root, SOURCE_PATHS["reader"], "regex reader"),
        "dynamic": dynamic, "static": static, "workload": workload, "oracle": work / "oracle",
        "executables": {"static": work / "static", "static-pie": work / "static-pie",
                        "dynamic-pie": work / "dynamic-pie", "dynamic-non-pie": work / "dynamic-non-pie"},
    }
    plan = command_plan(paths, current_tools, mode)
    commands = report["commands"]
    require(isinstance(commands, dict) and set(commands) == set(plan), "regex command roster differs")
    raw: dict[str, dict[str, bytes]] = {}
    for label, expected_argv in plan.items():
        record = commands[label]
        require(isinstance(record, dict) and set(record) == {"argv", "stdout", "stderr", "status"},
                f"{label} retained command fields differ")
        raw[label] = {field: artifact_bytes(root, record, field, work, label)
                      for field in ("argv", "stdout", "stderr", "status")}
        require(parse_argv(raw[label]["argv"], label) == expected_argv, f"{label} retained argv differs")
        require(raw[label]["status"] == b"0\n", f"{label} retained status is not zero")
    require(raw["header-trace"]["stdout"], "installed header trace stdout is empty")
    trace_paths = header_trace_paths(raw["header-trace"]["stderr"])
    include_root = mounted(root, dynamic / "usr/include") + "/"
    require(all(path.startswith(include_root) for path in trace_paths),
            "installed header trace names an ambient header origin")
    for header in HEADERS:
        require(mounted(root, dynamic / "usr/include" / header) in trace_paths,
                f"installed header trace omitted {header}")
    # The probe self-checks its directed contracts and exits nonzero on any
    # failure; its differential corpus is judged by candidate equality below.
    oracle_stdout = raw["oracle-run"]["stdout"]
    require((oracle_stdout == ORACLE_COMPLETION or oracle_stdout.endswith(b"\n" + ORACLE_COMPLETION))
            and raw["oracle-run"]["stderr"] == b"",
            "pinned musl regex oracle transcript is incomplete")
    require(raw["oracle-bounded"]["stdout"] == BOUNDED_ORACLE and raw["oracle-bounded"]["stderr"] == b"",
            "pinned musl bounded-backreference outcome differs")
    for label, kind in (("object-imports", "U"), ("oracle-providers", "T")):
        require(raw[label]["stderr"] == b"", f"{label} emitted stderr")
        require(replay_symbol_reader(root, label, plan[label]) == raw[label]["stdout"],
                f"{label} retained output differs from sealed symbol replay")
        check_nm_api_rows(raw[label]["stdout"], kind, label)
    require(raw["dynamic-providers"]["stderr"] == b"", "dynamic regex provider emitted stderr")
    require(replay_symbol_reader(root, "dynamic-providers", plan["dynamic-providers"]) == raw["dynamic-providers"]["stdout"],
            "dynamic regex provider retained output differs from sealed symbol replay")
    check_dynamic_api_rows(raw["dynamic-providers"]["stdout"])
    if mode == FULL_MODE:
        for label in ("static-archive-providers", "static-providers", "static-pie-providers"):
            require(raw[label]["stderr"] == b"", f"{label} emitted stderr")
            require(replay_symbol_reader(root, label, plan[label]) == raw[label]["stdout"],
                    f"{label} retained output differs from sealed symbol replay")
            check_nm_api_rows(raw[label]["stdout"], "T", label)

    links = report["links"]
    expected_links = ("static", "static-pie", "dynamic-pie", "dynamic-non-pie") if mode == FULL_MODE else ("dynamic-pie", "dynamic-non-pie")
    require(isinstance(links, dict) and set(links) == set(expected_links), "regex product link roster differs")
    for name in expected_links:
        linkage = {"static": "static", "static-pie": "static-pie", "dynamic-pie": "pie", "dynamic-non-pie": "non-pie"}[name]
        product = static if linkage.startswith("static") else dynamic
        assert product is not None
        executable = Path(paths["executables"][name])
        receipt = work / f"{name}.crabc-link.json" if linkage.startswith("static") else executable.with_name(executable.name + ".crabc-link.json")
        product_link = assert_identity(root, links[name], f"{name} product-link", expected=work / f"{name}.product-link.json")
        reconstructed = products.validate_retained_link(
            root, SOURCE_MOUNT, product, workload, executable, receipt, linkage,
            {key: current_tools["linker"][key] for key in ("path", "sha256")},
        )
        expected_link = dict(reconstructed)
        expected_link["product"] = mounted(root, product)
        require(read_json(product_link, f"{name} product-link") == expected_link,
                f"{name} product-link differs from reconstructed validation")
        require(raw[f"{name}-validate"]["stdout"] == canonical(expected_link),
                f"{name} validate stdout differs from reconstructed validation")
        if linkage.startswith("static"):
            candidate_label = f"{name}-run"
            require(raw[candidate_label]["stdout"] == raw["oracle-run"]["stdout"] and
                    raw[candidate_label]["stderr"] == raw["oracle-run"]["stderr"],
                    f"{candidate_label} transcript differs from pinned musl")
            bounded_labels = [f"{name}-bounded"]
        else:
            for entry in ("kernel", "direct"):
                candidate_label = f"{name}-{entry}"
                require(raw[candidate_label]["stdout"] == raw["oracle-run"]["stdout"] and
                        raw[candidate_label]["stderr"] == raw["oracle-run"]["stderr"],
                        f"{candidate_label} stdout differs from pinned musl")
            bounded_labels = [f"{name}-kernel-bounded", f"{name}-direct-bounded"]
        for label in bounded_labels:
            require(raw[label]["stdout"] == BOUNDED_OWNED and raw[label]["stderr"] == b"",
                    f"{label} bounded-backreference outcome differs")

    payloads = report["execution_payloads"]
    require(isinstance(payloads, dict) and set(payloads) == {"pie", "non-pie"}, "regex copied payload roster differs")
    for name in ("pie", "non-pie"):
        root_copy = work / f"dynamic-{name}-root"
        executable = work / f"dynamic-{name}"
        record = payloads[name]
        require(isinstance(record, dict) and set(record) == {"record", "before", "after"},
                f"dynamic {name} copied payload fields differ")
        payload_record = assert_identity(root, record["record"], f"dynamic {name} copied payload record",
                                         expected=work / f"dynamic-{name}-execution-payload.json")
        observed = copies.audit_execution_payload(dynamic, root_copy, executable, root_copy / "consumer", payload_record)
        expected_audit = canonical(observed)
        for point, label in (("before", f"dynamic-{name}-copy-audit-before"), ("after", f"dynamic-{name}-copy-audit-after")):
            audit_path = assert_identity(root, record[point], f"dynamic {name} copied payload {point}",
                                         expected=work / f"{label}.stdout")
            require(audit_path.read_bytes() == expected_audit, f"dynamic {name} copied payload {point} audit differs")
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
    except (RegexReceiptError, OSError, ValueError, products.ProductEvidenceError, copies.CryptRuntimeEvidenceError) as error:
        parser.exit(1, f"owned regex component receipt failed: {error}\n")
    print("owned regex component receipt: valid; bounded component evidence remains non-promoting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
