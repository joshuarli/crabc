#!/usr/bin/env python3
"""Source-bound evidence for the callback-loaded POSIX timer TLS DSO.

The four executable receipts remain the responsibility of
``owned_posix_product_evidence.validate_link``.  This module deliberately
does not treat the callback-loaded TLS DSO as an application DSO: it has no
initial consumer ``DT_NEEDED`` edge.  It instead binds its separately compiled
object, its shared-mode receipt, and the ELF that the callback loads later.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Sequence

from owned_posix_product_evidence import (
    DYNAMIC_PRODUCT_FORMAT,
    ProductEvidenceError,
    _validate_dynamic_product,
)

TIMER_WORKLOAD_COMPILE_AUDIT_SCHEMA = "crabc.x86_64-owned-posix-timers-compile/v1"
TIMER_APPLICATION_AUDIT_SCHEMA = "crabc.x86_64-owned-posix-timers-application/v1"
TIMER_TLS_AUDIT_SCHEMA = "crabc.x86_64-owned-posix-timers-tls-dso/v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PINNED_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")


class TimerEvidenceError(RuntimeError):
    """A timer compile or callback-loaded DSO lacks sealed evidence."""


def _fail(message: str) -> None:
    raise TimerEvidenceError(message)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _physical(path: Path, description: str, *, directory: bool = False) -> Path:
    """Return an existing absolute path after rejecting every symlink hop."""

    if ".." in path.parts:
        _fail(f"{description} has lexical parent traversal: {path}")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                _fail(f"{description} traverses a symlink: {path}")
        mode = absolute.lstat().st_mode
    except OSError as error:
        raise TimerEvidenceError(f"{description} is unreadable: {path}") from error
    if directory:
        if not stat.S_ISDIR(mode):
            _fail(f"{description} is not a physical directory: {path}")
    elif not stat.S_ISREG(mode):
        _fail(f"{description} is not a physical regular file: {path}")
    return absolute


def _sha256(path: Path) -> str:
    path = _physical(path, "hashed artifact")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise TimerEvidenceError(f"cannot hash artifact: {path}") from error
    return digest.hexdigest()


def _json(path: Path, description: str) -> dict[str, Any]:
    path = _physical(path, description)
    try:
        record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise TimerEvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(record, dict):
        _fail(f"{description} must be a JSON object")
    return record


def _exact_object(value: object, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{description} fields drifted")
    return value


def _recorded_file(value: object, expected: Path, description: str) -> None:
    record = _exact_object(value, {"path", "sha256"}, description)
    if record["path"] != str(expected):
        _fail(f"{description} path differs from this evidence invocation")
    if not isinstance(record["sha256"], str) or SHA256.fullmatch(record["sha256"]) is None:
        _fail(f"{description} has an invalid SHA-256")
    if record["sha256"] != _sha256(expected):
        _fail(f"{description} hash differs from the physical artifact")


def _dynamic_product(product: Path) -> tuple[Path, Path, Path]:
    root = _physical(product, "dynamic product", directory=True)
    try:
        manifest, _ = _validate_dynamic_product(root)
    except ProductEvidenceError as error:
        raise TimerEvidenceError(f"dynamic product validation failed: {error}") from error
    driver = _physical(root / "bin/crabc-cc-dynamic", "dynamic product sealed driver")
    if not driver.lstat().st_mode & 0o111:
        _fail("dynamic product sealed driver is not executable")
    return root, manifest, driver


def _pinned_compiler_builtin_root() -> Path:
    """Derive the only admitted compiler include root from the pinned compiler."""

    compiler = _physical(PINNED_COMPILER, "pinned compiler")
    if not compiler.lstat().st_mode & 0o111:
        _fail("pinned compiler is not executable")
    try:
        result = subprocess.run(
            [str(compiler), "-print-file-name=include"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
    except OSError as error:
        raise TimerEvidenceError("pinned compiler cannot report its builtin header root") from error
    if result.returncode or result.stderr or not result.stdout.endswith("\n"):
        _fail("pinned compiler did not report one builtin header root")
    reported = result.stdout[:-1]
    if not reported or "\n" in reported:
        _fail("pinned compiler reported an invalid builtin header root")
    return _physical(Path(reported), "pinned compiler builtin header root", directory=True)


def _header_records(
    trace: Path, product: Path, compiler_builtin: Path, *, require_installed: bool
) -> list[dict[str, str]]:
    """Parse one GCC ``-H`` closure; only the headerless TLS source may be empty."""
    trace = _physical(trace, "installed-header trace")
    include_root = _physical(product / "usr/include", "installed header root", directory=True)
    compiler_builtin = _physical(compiler_builtin, "pinned compiler builtin header root", directory=True)
    headers: list[dict[str, str]] = []
    try:
        lines = trace.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise TimerEvidenceError(f"installed-header trace is unreadable: {trace}") from error
    guard_suggestions = False
    for line in lines:
        if line == "Multiple include guards may be useful for:":
            if guard_suggestions or not headers:
                _fail("installed-header trace has an unexpected guard-suggestion section")
            guard_suggestions = True
            continue
        if guard_suggestions:
            match = re.fullmatch(r"(/.+)", line)
        else:
            match = re.fullmatch(r"\.+[ \t]+(/.+)", line)
        if match is None:
            _fail(f"installed-header trace has an unrecognized entry: {line!r}")
        candidate = match.group(1)
        header = _physical(Path(candidate), "installed header")
        for root, kind in ((include_root, "installed"), (compiler_builtin, "compiler-builtin")):
            try:
                header.relative_to(root)
                headers.append({"path": str(header), "sha256": _sha256(header), "root": kind})
                break
            except ValueError:
                continue
        else:
            _fail(f"header trace escaped the installed and compiler-builtin roots: {header}")
    if require_installed:
        if not headers:
            _fail("installed-header trace has no admitted headers")
        if not any(header["root"] == "installed" for header in headers):
            _fail("installed-header trace has no installed product header")
    return headers


def _headers(trace: Path, product: Path) -> list[dict[str, str]]:
    return _header_records(
        trace, product, _pinned_compiler_builtin_root(), require_installed=True
    )


def _compile_command(role: str, driver: Path, source: Path, output: Path) -> list[str]:
    if role == "application":
        mode = "--dynamic-pie"
    elif role == "timer-tls-dso":
        mode = "-shared"
    else:
        _fail("compile role must be application or timer-tls-dso")
    return [str(driver), mode, "-std=c11", "-c", str(source), "-o", str(output)]


def record_compile_audit(
    product: Path,
    role: str,
    source: Path,
    output: Path,
    driver: Path,
    header_trace: Path,
    command: Sequence[str],
) -> dict[str, Any]:
    """Return one source/object/driver/header identity for a compile step."""

    root, manifest, expected_driver = _dynamic_product(product)
    source = _physical(source, f"{role} source")
    output = _physical(output, f"{role} object")
    driver = _physical(driver, f"{role} compile driver")
    if driver != expected_driver:
        _fail(f"{role} compile driver is not this product's sealed driver")
    expected_command = _compile_command(role, driver, source, output)
    if list(command) != expected_command:
        _fail(f"{role} compile command differs from the sealed timer invocation")
    trace = _physical(header_trace, f"{role} installed-header trace")
    compiler_builtin = _pinned_compiler_builtin_root()
    return {
        "schema": TIMER_WORKLOAD_COMPILE_AUDIT_SCHEMA,
        "role": role,
        "product": {
            "path": str(root),
            "manifest": {"path": str(manifest), "sha256": _sha256(manifest)},
        },
        "source": {"path": str(source), "sha256": _sha256(source)},
        "object": {"path": str(output), "sha256": _sha256(output)},
        "driver": {"path": str(driver), "sha256": _sha256(driver)},
        "command": expected_command,
        "headers": {
            "trace": {"path": str(trace), "sha256": _sha256(trace)},
            "compiler_builtin": str(compiler_builtin),
            "resolved": _header_records(
                trace, root, compiler_builtin, require_installed=role == "application"
            ),
        },
    }


def _validate_compile_audit(
    product: Path, role: str, source: Path, output: Path, audit: Path
) -> tuple[Path, Path, Path, str]:
    root, manifest, driver = _dynamic_product(product)
    source = _physical(source, f"{role} source")
    output = _physical(output, f"{role} object")
    audit = _physical(audit, f"{role} compile audit")
    record = _json(audit, f"{role} compile audit")
    expected_fields = {"schema", "role", "product", "source", "object", "driver", "command", "headers"}
    if set(record) != expected_fields or record["schema"] != TIMER_WORKLOAD_COMPILE_AUDIT_SCHEMA:
        _fail(f"{role} compile audit fields drifted")
    if record["role"] != role:
        _fail(f"{role} compile audit role differs")
    product_record = _exact_object(record["product"], {"path", "manifest"}, f"{role} compile product")
    if product_record["path"] != str(root):
        _fail(f"{role} compile product differs from this evidence invocation")
    _recorded_file(product_record["manifest"], manifest, f"{role} compile manifest")
    _recorded_file(record["source"], source, f"{role} compile source")
    _recorded_file(record["object"], output, f"{role} compile object")
    _recorded_file(record["driver"], driver, f"{role} compile driver")
    if record["command"] != _compile_command(role, driver, source, output):
        _fail(f"{role} compile command differs from the sealed timer invocation")
    headers = _exact_object(record["headers"], {"trace", "compiler_builtin", "resolved"}, f"{role} compile headers")
    trace_record = headers["trace"]
    if not isinstance(trace_record, dict) or not isinstance(trace_record.get("path"), str):
        _fail(f"{role} compile header trace is malformed")
    trace = _physical(Path(trace_record["path"]), f"{role} installed-header trace")
    _recorded_file(trace_record, trace, f"{role} compile header trace")
    if not isinstance(headers["compiler_builtin"], str):
        _fail(f"{role} compile compiler builtin root is malformed")
    compiler_builtin = _pinned_compiler_builtin_root()
    if headers["compiler_builtin"] != str(compiler_builtin):
        _fail(f"{role} compile compiler builtin root differs from the pinned compiler")
    if headers["resolved"] != _header_records(
        trace, root, compiler_builtin, require_installed=role == "application"
    ):
        _fail(f"{role} compile headers differ from the installed trace")
    return root, manifest, driver, _sha256(audit)


def _readelf(path: Path, option: str) -> str:
    try:
        result = subprocess.run(
            ["readelf", option, str(path)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
    except OSError as error:
        raise TimerEvidenceError("readelf could not inspect the timer TLS DSO") from error
    if result.returncode:
        _fail(f"readelf {option} failed for timer TLS DSO: {result.stderr.strip()}")
    return result.stdout


def _shared_link_command(root: Path, object_path: Path, output: Path, linker: Path) -> list[str]:
    library = root / "usr/lib"
    return [
        str(linker), "-shared", "--hash-style=sysv", "-z", "relro", "-z", "now",
        "-z", "noexecstack", "-z", "text", "--no-undefined", "--allow-shlib-undefined",
        "--enable-new-dtags", "-rpath", "/usr/lib", "-soname", output.name,
        str(library / "crti.o"), str(object_path), str(library / "libc.so"),
        str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", str(output),
    ]


def _validate_shared_metadata(record: dict[str, Any]) -> None:
    """Require exact JSON scalar types before comparing a sealed receipt."""

    if type(record["schema"]) is not int:
        _fail("timer TLS DSO receipt schema must be an integer")
    if type(record["campaign_complete"]) is not bool:
        _fail("timer TLS DSO receipt campaign state must be a boolean")
    if (
        record["schema"], record["format"], record["mode"], record["binding"],
        record["runtime_imports"], record["application_runpath"], record["application_dsos"],
        record["campaign_complete"],
    ) != (1, DYNAMIC_PRODUCT_FORMAT, "shared", "now", [], "/usr/lib", {}, False):
        _fail("timer TLS DSO receipt is not the sealed callback-loaded shared link")


def _validate_shared_receipt(
    root: Path, manifest: Path, object_path: Path, output: Path, receipt: Path
) -> str:
    receipt = _physical(receipt, "timer TLS DSO receipt")
    output = _physical(output, "timer TLS DSO")
    record = _json(receipt, "timer TLS DSO receipt")
    fields = {
        "schema", "format", "mode", "binding", "runtime_imports", "application_runpath",
        "output_path", "output_sha256", "manifest_sha256", "application_dsos",
        "owned_runtime_inputs", "input_receipts", "resolved_linker", "link_command",
        "link_trace", "campaign_complete",
    }
    if set(record) != fields:
        _fail("timer TLS DSO receipt fields drifted")
    _validate_shared_metadata(record)
    if record["output_path"] != str(output):
        _fail("timer TLS DSO receipt output path differs from this evidence invocation")
    if record["output_sha256"] != _sha256(output):
        _fail("timer TLS DSO receipt output hash differs from the physical DSO")
    if record["manifest_sha256"] != _sha256(manifest):
        _fail("timer TLS DSO receipt manifest hash differs from this product")
    library = root / "usr/lib"
    runtime = [library / "crti.o", library / "libc.so", library / "crtn.o"]
    archive = library / "libcrabc-builtins.a"
    expected_runtime = sorted(path.relative_to(root).as_posix() for path in [*runtime, archive])
    if record["owned_runtime_inputs"] != expected_runtime:
        _fail("timer TLS DSO receipt runtime input roster differs")
    expected_inputs = [*runtime, object_path, archive]
    if not isinstance(record["input_receipts"], list) or len(record["input_receipts"]) != len(expected_inputs):
        _fail("timer TLS DSO receipt has the wrong input roster")
    for received, expected in zip(record["input_receipts"], expected_inputs):
        _recorded_file(received, expected, "timer TLS DSO receipt input")
    linker_record = _exact_object(record["resolved_linker"], {"path", "sha256"}, "timer TLS DSO linker")
    if not isinstance(linker_record["path"], str):
        _fail("timer TLS DSO linker path is malformed")
    linker = _physical(Path(linker_record["path"]), "timer TLS DSO linker")
    if linker.name != "ld.lld" or not linker.lstat().st_mode & 0o111:
        _fail("timer TLS DSO linker is not the sealed LLD executable")
    _recorded_file(linker_record, linker, "timer TLS DSO linker")
    if record["link_command"] != _shared_link_command(root, object_path, output, linker):
        _fail("timer TLS DSO receipt shared-mode command differs from the sealed product")
    if not isinstance(record["link_trace"], list) or not all(isinstance(line, str) for line in record["link_trace"]):
        _fail("timer TLS DSO receipt trace is malformed")
    direct = {str(path) for path in [*runtime, object_path]}
    seen: set[str] = set()
    for line in record["link_trace"]:
        if line in direct:
            seen.add(line)
        elif line == str(archive) or (line.startswith(str(archive) + "(") and line.endswith(")")):
            continue
        else:
            _fail(f"timer TLS DSO trace names an unowned input: {line}")
    if seen != direct:
        _fail("timer TLS DSO trace omits an explicit input")
    return _sha256(receipt)


def _validate_tls_elf(output: Path) -> tuple[str, list[str]]:
    header, program, dynamic = (_readelf(output, option) for option in ("-hW", "-lW", "-dW"))
    if re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", header, re.MULTILINE) is None:
        _fail("timer TLS DSO is not an x86-64 ELF")
    if re.search(r"^\s*Type:\s+DYN(?:\s|\()", header, re.MULTILINE) is None:
        _fail("timer TLS DSO is not ET_DYN")
    if re.search(r"^\s*INTERP\b", program, re.MULTILINE) is not None:
        _fail("timer TLS DSO has an interpreter")
    if re.search(r"\bTEXTREL\b", dynamic) is not None or re.search(r"\(RPATH\)", dynamic) is not None:
        _fail("timer TLS DSO has a forbidden text relocation or RPATH")
    sonames = re.findall(r"\(SONAME\).*?\[([^]]+)\]", dynamic)
    needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
    runpaths = re.findall(r"\(RUNPATH\).*?\[([^]]*)\]", dynamic)
    if sonames != [output.name] or needed != ["libc.so"] or runpaths != ["/usr/lib"]:
        _fail("timer TLS DSO SONAME, NEEDED, or RUNPATH differs from the callback contract")
    return sonames[0], needed


def validate_timer_application_compile(
    product: Path, source: Path, object_path: Path, compile_audit: Path
) -> dict[str, Any]:
    """Return the retained source/header identity for every timer executable link."""

    root, manifest, driver, compile_audit_hash = _validate_compile_audit(
        product, "application", source, object_path, compile_audit
    )
    source = _physical(source, "timer application source")
    object_path = _physical(object_path, "timer application object")
    record = _json(_physical(compile_audit, "timer application compile audit"), "timer application compile audit")
    headers = _exact_object(record["headers"], {"trace", "compiler_builtin", "resolved"}, "timer application compile headers")
    trace = _exact_object(headers["trace"], {"path", "sha256"}, "timer application compile header trace")
    return {
        "schema": TIMER_APPLICATION_AUDIT_SCHEMA,
        "product": str(root),
        "product_manifest_sha256": _sha256(manifest),
        "source_sha256": _sha256(source),
        "object_sha256": _sha256(object_path),
        "driver_sha256": _sha256(driver),
        "compile_audit_sha256": compile_audit_hash,
        "header_trace_sha256": trace["sha256"],
        "headers": headers["resolved"],
    }


def validate_timer_tls_dso(
    product: Path, source: Path, object_path: Path, compile_audit: Path, output: Path, receipt: Path
) -> dict[str, Any]:
    """Validate the separate TLS DSO without creating an application edge."""

    root, manifest, _driver, compile_audit_hash = _validate_compile_audit(
        product, "timer-tls-dso", source, object_path, compile_audit
    )
    object_path = _physical(object_path, "timer TLS object")
    output = _physical(output, "timer TLS DSO")
    receipt_hash = _validate_shared_receipt(root, manifest, object_path, output, receipt)
    soname, needed = _validate_tls_elf(output)
    return {
        "schema": TIMER_TLS_AUDIT_SCHEMA,
        "product": str(root),
        "product_manifest_sha256": _sha256(manifest),
        "source_sha256": _sha256(_physical(source, "timer TLS source")),
        "object_sha256": _sha256(object_path),
        "compile_audit_sha256": compile_audit_hash,
        "shared_object_sha256": _sha256(output),
        "receipt_sha256": receipt_hash,
        "soname": soname,
        "needed": needed,
    }


def _write_record(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    compile_parser = commands.add_parser("record-compile")
    compile_parser.add_argument("product", type=Path)
    compile_parser.add_argument("role", choices=("application", "timer-tls-dso"))
    compile_parser.add_argument("source", type=Path)
    compile_parser.add_argument("object", type=Path)
    compile_parser.add_argument("driver", type=Path)
    compile_parser.add_argument("header_trace", type=Path)
    compile_parser.add_argument("audit", type=Path)
    compile_parser.add_argument("command", nargs=argparse.REMAINDER)
    application_parser = commands.add_parser("validate-application-compile")
    application_parser.add_argument("product", type=Path)
    application_parser.add_argument("source", type=Path)
    application_parser.add_argument("object", type=Path)
    application_parser.add_argument("compile_audit", type=Path)
    dso_parser = commands.add_parser("validate-tls-dso")
    dso_parser.add_argument("product", type=Path)
    dso_parser.add_argument("source", type=Path)
    dso_parser.add_argument("object", type=Path)
    dso_parser.add_argument("compile_audit", type=Path)
    dso_parser.add_argument("output", type=Path)
    dso_parser.add_argument("receipt", type=Path)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.action == "record-compile":
            command = parsed.command[1:] if parsed.command[:1] == ["--"] else parsed.command
            _write_record(
                parsed.audit,
                record_compile_audit(
                    parsed.product, parsed.role, parsed.source, parsed.object, parsed.driver,
                    parsed.header_trace, command,
                ),
            )
        elif parsed.action == "validate-application-compile":
            json.dump(
                validate_timer_application_compile(
                    parsed.product, parsed.source, parsed.object, parsed.compile_audit,
                ),
                sys.stdout, sort_keys=True, separators=(",", ":"),
            )
            sys.stdout.write("\n")
        else:
            json.dump(
                validate_timer_tls_dso(
                    parsed.product, parsed.source, parsed.object, parsed.compile_audit,
                    parsed.output, parsed.receipt,
                ),
                sys.stdout, sort_keys=True, separators=(",", ":"),
            )
            sys.stdout.write("\n")
    except (OSError, TimerEvidenceError) as error:
        print(f"owned POSIX timers evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
