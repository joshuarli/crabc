#!/usr/bin/env python3
"""Receipts for the two immutable supplied-static fork workloads.

This helper owns only the adapter's source/header/object/link/raw binding.  It
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
from typing import Any


COMPILE_FORMAT = "crabc.x86_64-owned-posix-static-fork-compile/v1"
WORKLOAD_FORMAT = "crabc.x86_64-owned-posix-static-fork-workload/v1"
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
    "headers",
}
SHA256_HEX = frozenset("0123456789abcdef")


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
    spec.loader.exec_module(module)
    return module


def parse_dependencies(path: Path, source: Path, headers: Path) -> list[dict[str, str]]:
    try:
        text = physical_regular(path, "header dependency trace").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError("header dependency trace is unreadable") from error
    _, separator, values = text.replace("\\\n", " ").partition(":")
    if not separator:
        fail("header dependency trace lacks its target separator")
    values = values.split()
    if not values:
        fail("header dependency trace is empty")
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in values:
        candidate = Path(value)
        if not candidate.is_absolute():
            fail(f"header dependency trace names a relative input: {value}")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise EvidenceError(f"header dependency is unreadable: {value}") from error
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
    project_driver = physical_regular(
        checkout / "compat/x86_64/crabc_cc_static.py", "checkout static driver"
    )
    installed_driver = physical_regular(product / "bin/crabc-cc", "installed static driver")
    headers = physical_directory(product / "usr/include", "installed headers")
    manifest = physical_regular(product / "share/crabc/manifest.json", "static product manifest")
    if digest(project_driver) != digest(installed_driver):
        fail("installed static driver differs from the current source translator contract")

    contract = load_static_driver(project_driver)
    mode = contract.static_mode("static-pie")
    if mode.compiler_flag != "-fPIE":
        fail("current static-PIE translation mode drifted")
    compiler = physical_regular(Path(contract.compiler()), "fixed source translator")
    environment = contract.clean_environment()
    if environment.get("PATH") != "/usr/bin:/bin":
        fail("static driver translator environment drifted")
    translation = [
        str(compiler),
        "-nostdinc",
        "-isystem",
        str(headers),
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-std=c11",
        mode.compiler_flag,
    ]
    compile_command = [*translation, "-c", str(source), "-o", str(workload)]
    dependency_command = [*translation, "-M", "-H", str(source)]
    new_output(record_path, "compile record")
    new_output(dependencies_path, "header dependency trace")
    new_output(headers_trace_path, "header include trace")
    try:
        with dependencies_path.open("xb") as dependencies, headers_trace_path.open("xb") as headers_trace:
            completed = subprocess.run(
                dependency_command,
                env=environment,
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
    record = {
        "schema": 1,
        "format": COMPILE_FORMAT,
        "role": role,
        "source": {"path": str(source), "sha256": digest(source)},
        "workload": {"path": str(workload), "sha256": digest(workload)},
        "product": {
            "path": str(product),
            "manifest_sha256": digest(manifest),
            "installed_static_driver_sha256": digest(installed_driver),
            "checkout_static_driver_sha256": digest(project_driver),
        },
        "translation": {
            "compiler": {"path": str(compiler), "sha256": digest(compiler)},
            "environment": environment,
            "compile_command": compile_command,
            "dependency_audit_command": dependency_command,
        },
        "headers": {
            "root": str(headers),
            "dependencies": records,
            "dependency_trace": {"path": str(dependencies_path), "sha256": digest(dependencies_path)},
            "include_trace": {"path": str(headers_trace_path), "sha256": digest(headers_trace_path)},
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


def load_compile(
    path: Path, role: str, source: Path, source_hash: str, workload: Path, workload_hash: str,
    product: Path,
) -> dict[str, str]:
    """Require the retained header audit to describe this exact object."""

    record_path = physical_regular(path, "compile record")
    record = json_object(record_path, "compile record")
    if set(record) != COMPILE_FIELDS:
        fail("compile record fields drifted")
    if type(record.get("schema")) is not int or record.get("schema") != 1:
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
    product_record = record.get("product")
    if not isinstance(product_record, dict) or set(product_record) != {
        "path",
        "manifest_sha256",
        "installed_static_driver_sha256",
        "checkout_static_driver_sha256",
    }:
        fail("compile record product fields drifted")
    if product_record.get("path") != str(product):
        fail("compile record product differs from the sealed links")
    if not all(is_sha256(product_record.get(key)) for key in product_record if key != "path"):
        fail("compile record product hashes are malformed")
    if product_record["manifest_sha256"] != digest(
        product / "share/crabc/manifest.json"
    ):
        fail("compile record product manifest differs from the sealed links")
    if product_record["installed_static_driver_sha256"] != digest(product / "bin/crabc-cc"):
        fail("compile record installed static driver differs from the sealed links")
    translation = record.get("translation")
    if not isinstance(translation, dict) or set(translation) != {
        "compiler", "environment", "compile_command", "dependency_audit_command",
    }:
        fail("compile record translation fields drifted")
    command = translation.get("compile_command")
    if (
        not isinstance(command, list)
        or not all(isinstance(item, str) for item in command)
        or command[-4:] != ["-c", str(source), "-o", str(workload)]
        or "-fPIE" not in command
        or "-nostdinc" not in command
    ):
        fail("compile record no longer describes the static-PIE object translation")
    dependency_command = translation.get("dependency_audit_command")
    if (
        not isinstance(dependency_command, list)
        or not all(isinstance(item, str) for item in dependency_command)
        or dependency_command[-1:] != [str(source)]
        or "-M" not in dependency_command
        or "-H" not in dependency_command
        or "-fPIE" not in dependency_command
        or "-nostdinc" not in dependency_command
    ):
        fail("compile record no longer describes the installed-header audit")
    headers = record.get("headers")
    if not isinstance(headers, dict) or set(headers) != {
        "root", "dependencies", "dependency_trace", "include_trace",
    }:
        fail("compile record header fields drifted")
    dependencies = headers.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        fail("compile record has no installed-header dependencies")
    headers_root = physical_directory(product / "usr/include", "installed headers")
    if headers.get("root") != str(headers_root):
        fail("compile record header root differs from the sealed links")
    for item in dependencies:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not is_sha256(item.get("sha256"))
        ):
            fail("compile record header dependency drifted")
        dependency = physical_regular(Path(item["path"]), "compile header dependency")
        if dependency != source:
            try:
                dependency.relative_to(headers_root)
            except ValueError:
                fail("compile record header dependency escapes the sealed headers")
        if item["sha256"] != digest(dependency):
            fail("compile record header dependency hash differs from its artifact")
    for key, filename in (("dependency_trace", "headers.d"), ("include_trace", "headers.trace")):
        trace = headers.get(key)
        expected = record_path.parent / filename
        if not isinstance(trace, dict) or set(trace) != {"path", "sha256"}:
            fail(f"compile record {key} fields drifted")
        if trace.get("path") != str(expected) or trace.get("sha256") != digest(expected):
            fail(f"compile record {key} differs from its retained artifact")
    return {
        "path": str(record_path),
        "sha256": digest(record_path),
        "product_manifest_sha256": product_record["manifest_sha256"],
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
    linkage: str, role_directory: Path, oracle: dict[str, dict[str, str]] | None
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for suffix in ("stdout", "stderr", "status"):
        path = physical_regular(
            role_directory / linkage / f"ordinary.{suffix}", f"{linkage} raw {suffix}"
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


def write_workload_evidence(role: str, source: Path, role_directory: Path, product: Path) -> None:
    """Seal one role after all three immutable-object links and runs exist."""

    source = physical_regular(source, "workload source")
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
    static_raw = raw_record("static", role_directory, oracle_raw)
    static_pie_raw = raw_record("static-pie", role_directory, oracle_raw)
    musl = physical_regular(role_directory / "musl/consumer", "musl executable")
    record = {
        "schema": 1,
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
                parsed.role, parsed.source, parsed.role_directory, parsed.product
            )
    except EvidenceError as error:
        print(f"owned POSIX static fork evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
