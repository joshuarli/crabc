#!/usr/bin/env python3
"""Receipts for the two immutable supplied-static fork workloads.

This helper owns only the adapter's source/header/object/link/raw binding. It
uses the shared ``owned_posix_product_evidence.validate_link`` validator for a
sealed static link and never builds a product or runs a workload.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Sequence


COMPILE_FORMAT = "crabc.x86_64-owned-posix-static-fork-compile/v2"
WORKLOAD_FORMAT = "crabc.x86_64-owned-posix-static-fork-workload/v2"
IDENTITY_FIELDS = {
    "linkage",
    "product",
    "product_format",
    "product_manifest_sha256",
    "workload_sha256",
    "executable_sha256",
    "receipt_sha256",
}
COMPILE_FIELDS = {
    "schema",
    "format",
    "role",
    "source",
    "workload",
    "product",
    "translation",
    "evidence_helper",
    "headers",
}
SHA256_HEX = frozenset("0123456789abcdef")
STATIC_SOURCE_FLAGS = ("-std=c11",)
PINNED_CLEAN_ENV = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SOURCE_DATE_EPOCH": "1",
    "TZ": "UTC",
}

# The adapter is intentionally closed over these two existing sources. Keeping
# their paths and preprocessor closure here makes a changed source/header graph
# a receipt failure rather than a silently broadened workload contract.
ROLE_SOURCES = {
    "atfork-registry": Path("compat/x86_64/owned_atfork_registry_probe.c"),
    "static-posix-forkexec": Path("compat/x86_64/owned_static_posix_probe.c"),
}
ROLE_HEADER_CLOSURES = {
    "atfork-registry": (
        "errno.h",
        "features.h",
        "bits/errno.h",
        "pthread.h",
        "bits/alltypes.h",
        "sched.h",
        "time.h",
        "stdio.h",
        "stdlib.h",
        "alloca.h",
        "sys/prctl.h",
        "stdint.h",
        "bits/stdint.h",
        "sys/syscall.h",
        "bits/syscall.h",
        "sys/wait.h",
        "signal.h",
        "bits/signal.h",
        "sys/resource.h",
        "sys/time.h",
        "sys/select.h",
        "unistd.h",
    ),
    "static-posix-forkexec": (
        "errno.h",
        "features.h",
        "bits/errno.h",
        "fcntl.h",
        "bits/alltypes.h",
        "bits/fcntl.h",
        "poll.h",
        "bits/poll.h",
        "pthread.h",
        "sched.h",
        "time.h",
        "signal.h",
        "bits/signal.h",
        "stddef.h",
        "stdlib.h",
        "alloca.h",
        "string.h",
        "strings.h",
        "sys/stat.h",
        "bits/stat.h",
        "sys/types.h",
        "endian.h",
        "sys/select.h",
        "sys/uio.h",
        "sys/wait.h",
        "sys/resource.h",
        "sys/time.h",
        "unistd.h",
    ),
}


class EvidenceError(RuntimeError):
    """One retained adapter artifact no longer proves its stated boundary."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def physical_regular(path: Path, description: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail(f"{description} is not a physical regular file: {path}")
    return path.resolve(strict=True)


def resolved_regular(path: Path, description: str) -> Path:
    """Resolve a driver-selected executable while retaining its selected path."""

    if not path.is_absolute():
        fail(f"{description} is not an absolute selected path: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    return physical_regular(resolved, description)


def physical_directory(path: Path, description: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        fail(f"{description} is not a physical directory: {path}")
    return path.resolve(strict=True)


def digest(path: Path) -> str:
    path = physical_regular(path, "hashed artifact")
    value = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
    except OSError as error:
        raise EvidenceError(f"cannot hash artifact: {path}") from error
    return value.hexdigest()


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= SHA256_HEX


def strict_equal(left: object, right: object) -> bool:
    """Compare JSON-shaped values without accepting ``True == 1`` aliases."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            strict_equal(value, expected) for value, expected in zip(left, right)
        )
    return left == right


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            physical_regular(path, description).read_text(encoding="utf-8"),
            object_pairs_hook=no_duplicate_object,
        )
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        fail(f"{description} must be a JSON object")
    return value


def new_output(path: Path, description: str) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        fail(f"{description} output is unsafe: {path}")


def write_json_new(path: Path, value: object, description: str) -> None:
    new_output(path, description)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    except OSError as error:
        raise EvidenceError(f"cannot write {description}: {path}") from error


def load_static_driver(path: Path) -> Any:
    loader = importlib.machinery.SourceFileLoader("owned_static_fork_driver_contract", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None or spec.loader is None:
        fail("cannot load the current static driver contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise EvidenceError("cannot load the current static driver contract") from error
    return module


def role_source(checkout: Path, role: str) -> Path:
    try:
        relative = ROLE_SOURCES[role]
    except KeyError:
        fail(f"unknown immutable workload role: {role}")
    return physical_regular(checkout / relative, f"{role} workload source")


def role_dependency_paths(role: str, source: Path, headers: Path) -> list[Path]:
    try:
        closure = ROLE_HEADER_CLOSURES[role]
    except KeyError:
        fail(f"unknown immutable workload role: {role}")
    paths = [source]
    for relative in closure:
        paths.append(physical_regular(headers / relative, f"{role} installed header {relative}"))
    return paths


def dependency_records(paths: Sequence[Path]) -> list[dict[str, str]]:
    return [{"path": str(path), "sha256": digest(path)} for path in paths]


def parse_dependencies(path: Path, source: Path, headers: Path) -> list[dict[str, str]]:
    """Parse the retained GCC ``-M`` file, never treating its digest as proof."""

    try:
        text = physical_regular(path, "header dependency trace").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError("header dependency trace is unreadable") from error
    _, separator, values = text.replace("\\\n", " ").partition(":")
    if not separator:
        fail("header dependency trace lacks its target separator")
    if "\\" in values:
        fail("header dependency trace contains an escaped or malformed input")
    tokens = values.split()
    if not tokens:
        fail("header dependency trace is empty")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in tokens:
        candidate = Path(value)
        if not candidate.is_absolute():
            fail(f"header dependency trace names a relative input: {value}")
        resolved = physical_regular(candidate, "header dependency")
        if resolved != source:
            try:
                resolved.relative_to(headers)
            except ValueError:
                fail(f"header dependency escapes installed source/header inputs: {resolved}")
        rendered = str(resolved)
        if rendered in seen:
            fail("header dependency trace contains duplicate inputs")
        seen.add(rendered)
        records.append({"path": rendered, "sha256": digest(resolved)})
    return records


def current_evidence_helper(checkout: Path) -> dict[str, str]:
    checkout_helper = physical_regular(
        checkout / "compat/x86_64/owned_static_fork_evidence.py",
        "current checkout evidence helper",
    )
    executing_helper = physical_regular(Path(__file__), "executing evidence helper")
    if checkout_helper != executing_helper:
        fail("current checkout evidence helper is not this validator")
    return {"path": str(checkout_helper), "sha256": digest(checkout_helper)}


def derive_static_translation(
    checkout: Path, product: Path, role: str, source: Path, workload: Path
) -> dict[str, Any]:
    """Derive the actual installed static-driver compile and audit vectors.

    ``crabc-cc`` has no separate preprocessor command surface. The adapter
    captures its real static-PIE compile vector from ``compile_source`` and
    derives the read-only ``-M -H`` audit by replacing only that vector's final
    ``-c SOURCE -o OBJECT`` action.
    """

    checkout = physical_directory(checkout, "checkout")
    product = physical_directory(product, "static product")
    source = physical_regular(source, "workload source")
    workload = physical_regular(workload, "workload object")
    if source != role_source(checkout, role):
        fail("workload source differs from the immutable role source")
    project_driver = physical_regular(
        checkout / "compat/x86_64/crabc_cc_static.py", "checkout static driver"
    )
    installed_driver = physical_regular(product / "bin/crabc-cc", "installed static driver")
    manifest = physical_regular(product / "share/crabc/manifest.json", "static product manifest")
    headers = physical_directory(product / "usr/include", "installed headers")
    if digest(project_driver) != digest(installed_driver):
        fail("installed static driver differs from the current source translator contract")

    contract = load_static_driver(project_driver)
    try:
        mode = contract.static_mode("static-pie")
    except Exception as error:
        raise EvidenceError("current static driver no longer exposes static-PIE translation") from error
    if getattr(mode, "identifier", None) != "static-pie" or getattr(mode, "compiler_flag", None) != "-fPIE":
        fail("current static-PIE translation mode drifted")

    calls: list[tuple[list[str], object]] = []
    original_run = contract.subprocess.run

    def capture(command: Sequence[str], **kwargs: object) -> SimpleNamespace:
        if not isinstance(command, (list, tuple)) or not all(isinstance(item, str) for item in command):
            fail("current static driver emitted a malformed compile command")
        calls.append((list(command), kwargs.get("env")))
        return SimpleNamespace(returncode=0)

    contract.subprocess.run = capture
    try:
        contract.compile_source(product, mode, source, workload, STATIC_SOURCE_FLAGS)
    except EvidenceError:
        raise
    except Exception as error:
        raise EvidenceError("cannot derive the current static driver compile vector") from error
    finally:
        contract.subprocess.run = original_run
    if len(calls) != 1:
        fail("current static driver compile path did not issue exactly one translation")
    compile_command, environment = calls[0]
    if not isinstance(environment, dict) or not strict_equal(environment, PINNED_CLEAN_ENV):
        fail("current static driver compile environment drifted")
    selected = compile_command[0] if compile_command else None
    if not isinstance(selected, str):
        fail("current static driver did not select a compiler")
    resolved = resolved_regular(Path(selected), "static driver selected compiler")
    expected_compile = [
        selected,
        "-nostdinc",
        "-isystem",
        str(headers),
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        *STATIC_SOURCE_FLAGS,
        "-fPIE",
        "-c",
        str(source),
        "-o",
        str(workload),
    ]
    if compile_command != expected_compile:
        fail("current static driver compile vector drifted")
    dependency_command = [*compile_command[:-4], "-M", "-H", str(source)]
    expected_dependency = [
        selected,
        "-nostdinc",
        "-isystem",
        str(headers),
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        *STATIC_SOURCE_FLAGS,
        "-fPIE",
        "-M",
        "-H",
        str(source),
    ]
    if dependency_command != expected_dependency:
        fail("current static driver preprocessor vector drifted")
    return {
        "product": {
            "path": str(product),
            "manifest_sha256": digest(manifest),
            "installed_static_driver": {
                "path": str(installed_driver),
                "sha256": digest(installed_driver),
            },
            "checkout_static_driver": {
                "path": str(project_driver),
                "sha256": digest(project_driver),
            },
        },
        "evidence_helper": current_evidence_helper(checkout),
        "translation": {
            "compiler": {
                "selected_path": selected,
                "resolved_path": str(resolved),
                "sha256": digest(resolved),
            },
            "environment": dict(PINNED_CLEAN_ENV),
            "compile_command": compile_command,
            "dependency_audit_command": dependency_command,
        },
    }


def require_exact_dependency_closure(
    role: str, source: Path, headers: Path, records: object, description: str
) -> list[dict[str, str]]:
    expected = dependency_records(role_dependency_paths(role, source, headers))
    if not strict_equal(records, expected):
        fail(f"{description} differs from the exact role-specific installed-header closure")
    return expected


def record_compile(
    checkout: Path,
    product: Path,
    role: str,
    source: Path,
    workload: Path,
    record_path: Path,
    dependencies_path: Path,
    headers_trace_path: Path,
) -> None:
    """Record the exact static-PIE source/header contract for one object."""

    checkout = physical_directory(checkout, "checkout")
    product = physical_directory(product, "static product")
    source = physical_regular(source, "workload source")
    workload = physical_regular(workload, "workload object")
    translation = derive_static_translation(checkout, product, role, source, workload)
    headers = physical_directory(product / "usr/include", "installed headers")
    new_output(record_path, "compile record")
    new_output(dependencies_path, "header dependency trace")
    new_output(headers_trace_path, "header include trace")
    try:
        with dependencies_path.open("xb") as dependencies, headers_trace_path.open("xb") as headers_trace:
            completed = subprocess.run(
                translation["translation"]["dependency_audit_command"],
                env=translation["translation"]["environment"],
                stdin=subprocess.DEVNULL,
                stdout=dependencies,
                stderr=headers_trace,
                check=False,
            )
    except OSError as error:
        raise EvidenceError("cannot run the static driver's source translator") from error
    if completed.returncode != 0:
        fail(f"installed-header dependency audit failed: {completed.returncode}")
    records = parse_dependencies(dependencies_path, source, headers)
    require_exact_dependency_closure(
        role, source, headers, records, "reparsed dependency trace"
    )
    record = {
        "schema": 2,
        "format": COMPILE_FORMAT,
        "role": role,
        "source": {"path": str(source), "sha256": digest(source)},
        "workload": {"path": str(workload), "sha256": digest(workload)},
        "product": translation["product"],
        "translation": translation["translation"],
        "evidence_helper": translation["evidence_helper"],
        "headers": {
            "root": str(headers),
            "dependencies": records,
            "dependency_trace": {
                "path": str(dependencies_path),
                "sha256": digest(dependencies_path),
            },
            "include_trace": {
                "path": str(headers_trace_path),
                "sha256": digest(headers_trace_path),
            },
        },
    }
    write_json_new(record_path, record, "compile record")


def checksum_record(path: Path, expected: Path, description: str) -> str:
    try:
        tokens = physical_regular(path, description).read_text(encoding="utf-8").split()
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError(f"{description} is unreadable") from error
    if len(tokens) != 2 or not is_sha256(tokens[0]):
        fail(f"{description} has an invalid sha256sum record")
    if tokens[1] not in {str(expected), "*" + str(expected)}:
        fail(f"{description} names the wrong artifact")
    if tokens[0] != digest(expected):
        fail(f"{description} differs from the physical artifact")
    return tokens[0]


def load_identity(path: Path, linkage: str, workload_hash: str, product: Path) -> dict[str, str]:
    record = json_object(path, f"{linkage} link identity")
    if set(record) != IDENTITY_FIELDS:
        fail(f"{linkage} link identity fields drifted")
    if record.get("linkage") != linkage or record.get("product") != str(product):
        fail(f"{linkage} link identity boundary drifted")
    if record.get("product_format") != "crabc-x86-64-owned-static-sysroot-v1":
        fail(f"{linkage} link identity product format drifted")
    if record.get("workload_sha256") != workload_hash:
        fail(f"{linkage} link identity does not bind the immutable object")
    for key in (
        "product_manifest_sha256",
        "workload_sha256",
        "executable_sha256",
        "receipt_sha256",
    ):
        if not is_sha256(record.get(key)):
            fail(f"{linkage} link identity has a malformed digest")
    return {key: record[key] for key in IDENTITY_FIELDS}


def require_file_record(value: object, expected: Path, description: str) -> None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        fail(f"{description} fields drifted")
    if value.get("path") != str(expected) or value.get("sha256") != digest(expected):
        fail(f"{description} differs from its current physical artifact")


def load_compile(
    checkout: Path,
    path: Path,
    role: str,
    source: Path,
    source_hash: str,
    workload: Path,
    workload_hash: str,
    product: Path,
) -> dict[str, str]:
    """Recompute every source-translation input before accepting one object."""

    checkout = physical_directory(checkout, "checkout")
    product = physical_directory(product, "static product")
    source = physical_regular(source, "workload source")
    workload = physical_regular(workload, "workload object")
    if source != role_source(checkout, role):
        fail("workload source differs from the immutable role source")
    record_path = physical_regular(path, "compile record")
    record = json_object(record_path, "compile record")
    if set(record) != COMPILE_FIELDS:
        fail("compile record fields drifted")
    if type(record.get("schema")) is not int or record.get("schema") != 2:
        fail("compile record schema drifted")
    if record.get("format") != COMPILE_FORMAT or record.get("role") != role:
        fail("compile record identity drifted")
    for key, expected_path, expected_hash in (
        ("source", source, source_hash),
        ("workload", workload, workload_hash),
    ):
        item = record.get(key)
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            fail(f"compile record {key} fields drifted")
        if item.get("path") != str(expected_path) or item.get("sha256") != expected_hash:
            fail(f"compile record {key} differs from the immutable workload boundary")

    current = derive_static_translation(checkout, product, role, source, workload)
    if not strict_equal(record.get("product"), current["product"]):
        fail("compile record product translator identities differ from the current files")
    if not strict_equal(record.get("evidence_helper"), current["evidence_helper"]):
        fail("compile record evidence helper differs from the current checkout helper")
    if not strict_equal(record.get("translation"), current["translation"]):
        fail("compile record no longer describes the exact static-PIE translation")

    headers = record.get("headers")
    if not isinstance(headers, dict) or set(headers) != {
        "root", "dependencies", "dependency_trace", "include_trace",
    }:
        fail("compile record header fields drifted")
    headers_root = physical_directory(product / "usr/include", "installed headers")
    if headers.get("root") != str(headers_root):
        fail("compile record header root differs from the sealed links")
    dependency_trace = headers.get("dependency_trace")
    include_trace = headers.get("include_trace")
    dependency_path = record_path.parent / "headers.d"
    include_path = record_path.parent / "headers.trace"
    require_file_record(dependency_trace, dependency_path, "compile record dependency trace")
    require_file_record(include_trace, include_path, "compile record include trace")
    reparsed = parse_dependencies(dependency_path, source, headers_root)
    expected_dependencies = require_exact_dependency_closure(
        role, source, headers_root, reparsed, "reparsed dependency trace"
    )
    if not strict_equal(headers.get("dependencies"), expected_dependencies):
        fail("compile record header closure differs from the reparsed dependency trace")
    return {
        "path": str(record_path),
        "sha256": digest(record_path),
        "product_manifest_sha256": current["product"]["manifest_sha256"],
    }


def bind_static_link_artifacts(
    role_directory: Path, linkage: str, identity: dict[str, str]
) -> None:
    """The retained identity must still describe its consumer and receipt."""

    executable = physical_regular(role_directory / linkage / "consumer", f"{linkage} executable")
    receipt = physical_regular(role_directory / linkage / "receipt.json", f"{linkage} receipt")
    if identity["executable_sha256"] != digest(executable):
        fail(f"{linkage} link identity executable differs from its consumer")
    if identity["receipt_sha256"] != digest(receipt):
        fail(f"{linkage} link identity receipt differs from its receipt")


def raw_record(
    linkage: str,
    role_directory: Path,
    oracle: dict[str, Any] | None,
    expected_candidate_hash: str | None = None,
) -> dict[str, Any]:
    """Bind the copied chroot executable before accepting its raw transcript."""

    linkage_directory = physical_directory(role_directory / linkage, f"{linkage} evidence directory")
    candidate = physical_regular(linkage_directory / "consumer", f"{linkage} candidate consumer")
    executed = physical_regular(
        linkage_directory / "root/workload/consumer", f"{linkage} executed consumer"
    )
    candidate_before = checksum_record(
        linkage_directory / "candidate-before-execution.sha256",
        candidate,
        f"{linkage} candidate-before-execution record",
    )
    executed_before = checksum_record(
        linkage_directory / "executed-consumer-before-execution.sha256",
        executed,
        f"{linkage} executed-consumer-before-execution record",
    )
    candidate_hash = digest(candidate)
    executed_hash = digest(executed)
    if candidate_before != executed_before or candidate_hash != executed_hash:
        fail(f"{linkage} executed consumer differs from its original candidate")
    if expected_candidate_hash is not None and candidate_hash != expected_candidate_hash:
        fail(f"{linkage} executed consumer differs from its sealed link identity")

    result: dict[str, Any] = {
        "consumer": {
            "candidate": {
                "path": str(candidate),
                "before_execution_sha256": candidate_before,
                "sha256": candidate_hash,
            },
            "executed": {
                "path": str(executed),
                "before_execution_sha256": executed_before,
                "sha256": executed_hash,
            },
        }
    }
    for suffix in ("stdout", "stderr", "status"):
        path = physical_regular(
            linkage_directory / f"ordinary.{suffix}", f"{linkage} raw {suffix}"
        )
        value = digest(path)
        if suffix == "status":
            try:
                status = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise EvidenceError(f"{linkage} raw status is unreadable") from error
            if status != "0\n":
                fail(f"{linkage} raw status is not success")
        if oracle is not None and value != oracle[suffix]["sha256"]:
            fail(f"{linkage} raw {suffix} differs from pinned musl")
        result[suffix] = {"path": str(path), "sha256": value}
    return result


def write_workload_evidence(
    checkout: Path, role: str, source: Path, role_directory: Path, product: Path
) -> None:
    """Seal one role after all three immutable-object links and runs exist."""

    checkout = physical_directory(checkout, "checkout")
    source = physical_regular(source, "workload source")
    if source != role_source(checkout, role):
        fail("workload source differs from the immutable role source")
    role_directory = physical_directory(role_directory, "role evidence directory")
    product = physical_directory(product, "static product")
    workload = physical_regular(role_directory / "workload.o", "workload object")
    source_before = checksum_record(
        role_directory / "source-before.sha256", source, "source-before record"
    )
    source_after = checksum_record(
        role_directory / "source-after.sha256", source, "source-after record"
    )
    workload_hash = checksum_record(
        role_directory / "workload.sha256", workload, "workload record"
    )
    if source_before != source_after:
        fail("workload source changed during evidence collection")
    compile_record = load_compile(
        checkout,
        role_directory / "compile.json",
        role,
        source,
        source_before,
        workload,
        workload_hash,
        product,
    )
    static_identity = load_identity(
        role_directory / "static/link-identity.json", "static", workload_hash, product
    )
    static_pie_identity = load_identity(
        role_directory / "static-pie/link-identity.json", "static-pie", workload_hash, product
    )
    if (
        compile_record["product_manifest_sha256"] != static_identity["product_manifest_sha256"]
        or compile_record["product_manifest_sha256"] != static_pie_identity["product_manifest_sha256"]
    ):
        fail("compile headers and sealed links consume different product manifests")
    bind_static_link_artifacts(role_directory, "static", static_identity)
    bind_static_link_artifacts(role_directory, "static-pie", static_pie_identity)
    oracle_raw = raw_record("musl", role_directory, None)
    static_raw = raw_record(
        "static", role_directory, oracle_raw, static_identity["executable_sha256"]
    )
    static_pie_raw = raw_record(
        "static-pie", role_directory, oracle_raw, static_pie_identity["executable_sha256"]
    )
    musl = physical_regular(role_directory / "musl/consumer", "musl executable")
    record = {
        "schema": 2,
        "format": WORKLOAD_FORMAT,
        "role": role,
        "source": {"path": str(source), "sha256": source_before},
        "workload": {"path": str(workload), "sha256": workload_hash},
        "compile": compile_record,
        "links": {
            "musl": {
                "executable": {"path": str(musl), "sha256": digest(musl)},
                "raw": oracle_raw,
            },
            "static": {
                "identity": static_identity,
                "raw": static_raw,
            },
            "static-pie": {
                "identity": static_pie_identity,
                "raw": static_pie_raw,
            },
        },
    }
    write_json_new(role_directory / "evidence.json", record, "role evidence")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    command = parser.add_subparsers(dest="command", required=True)
    compile_parser = command.add_parser("compile")
    compile_parser.add_argument("checkout", type=Path)
    compile_parser.add_argument("product", type=Path)
    compile_parser.add_argument("role")
    compile_parser.add_argument("source", type=Path)
    compile_parser.add_argument("workload", type=Path)
    compile_parser.add_argument("record", type=Path)
    compile_parser.add_argument("dependencies", type=Path)
    compile_parser.add_argument("headers_trace", type=Path)
    role_parser = command.add_parser("role")
    role_parser.add_argument("checkout", type=Path)
    role_parser.add_argument("role")
    role_parser.add_argument("source", type=Path)
    role_parser.add_argument("role_directory", type=Path)
    role_parser.add_argument("product", type=Path)
    return parser.parse_args()


def main() -> int:
    try:
        parsed = arguments()
        if parsed.command == "compile":
            record_compile(
                parsed.checkout,
                parsed.product,
                parsed.role,
                parsed.source,
                parsed.workload,
                parsed.record,
                parsed.dependencies,
                parsed.headers_trace,
            )
        else:
            write_workload_evidence(
                parsed.checkout,
                parsed.role,
                parsed.source,
                parsed.role_directory,
                parsed.product,
            )
    except EvidenceError as error:
        print(f"owned POSIX static fork evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
