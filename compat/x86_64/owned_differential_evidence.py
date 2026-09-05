#!/usr/bin/env python3
"""Seal one owned-product replay of the frozen differential C workloads.

This helper owns the durable evidence around the aggregate runner.  It proves
that each source was translated once through an installed dynamic product,
that every later link consumed that exact object, and that raw observations
remain available for review.  It deliberately does not build a product or
interpret a raw mismatch as a compatibility normalization.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_posix_product_evidence as product_evidence


CASES = ("foundational", "string-memory", "allocator", "fd-filesystem", "stdio-fdopen")
REQUIRED_HEADERS = {
    "foundational": ("errno.h", "limits.h", "stdio.h", "stdlib.h", "string.h", "unistd.h"),
    "string-memory": ("errno.h", "stdio.h", "string.h"),
    "allocator": ("errno.h", "stdio.h", "stdlib.h", "string.h"),
    "fd-filesystem": ("errno.h", "fcntl.h", "stdio.h", "string.h", "sys/stat.h", "unistd.h"),
    "stdio-fdopen": ("errno.h", "fcntl.h", "stdio.h", "string.h", "unistd.h"),
}
COMPILE_SCHEMA = "crabc.owned-differential-compile/v1"
LINK_SCHEMA = "crabc.owned-differential-link/v1"
ORACLE_LINK_SCHEMA = "crabc.owned-differential-musl-link/v1"
COPY_SCHEMA = "crabc.owned-differential-copy/v1"
OBSERVATION_SCHEMA = "crabc.owned-differential-observation/v1"
SUMMARY_SCHEMA = "crabc.owned-differential-summary/v1"
ORACLE_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_LIBC = Path("/opt/musl-1.2.6/lib/libc.a")


class EvidenceError(RuntimeError):
    """A retained product input or observation cannot prove this workload."""


class RawObservation:
    """The three raw files captured by exactly one contained execution."""

    def __init__(self, *, status_path: Path, stdout_path: Path, stderr_path: Path) -> None:
        self.status_path = Path(status_path)
        self.stdout_path = Path(stdout_path)
        self.stderr_path = Path(stderr_path)


def fail(message: str) -> None:
    raise EvidenceError(message)


def physical(path: Path, description: str, *, directory: bool = False) -> Path:
    """Return one physical regular file or directory without symlink ancestry."""

    original = Path(path)
    if ".." in original.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    absolute = Path(os.path.abspath(original))
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        mode = absolute.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    if directory:
        if not stat.S_ISDIR(mode):
            fail(f"{description} is not a physical directory: {path}")
    elif not stat.S_ISREG(mode):
        fail(f"{description} is not a physical regular file: {path}")
    return absolute


def readable_compiler(path: Path) -> Path:
    """Bind the compiler selected by the installed helper, including a tool symlink."""

    candidate = Path(os.path.abspath(Path(path)))
    try:
        if not candidate.is_file():
            fail(f"installed compiler is not a readable file: {path}")
    except OSError as error:
        raise EvidenceError(f"installed compiler is unreadable: {path}") from error
    return candidate


def digest(path: Path) -> str:
    path = physical(path, "hashed artifact")
    result = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
    except OSError as error:
        raise EvidenceError(f"cannot hash artifact: {path}") from error
    return result.hexdigest()


def compiler_digest(path: Path) -> str:
    path = readable_compiler(path)
    result = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
    except OSError as error:
        raise EvidenceError(f"cannot hash installed compiler: {path}") from error
    return result.hexdigest()


def binding(path: Path, description: str = "artifact") -> dict[str, str]:
    path = physical(path, description)
    return {"path": str(path), "sha256": digest(path)}


def compiler_binding(path: Path) -> dict[str, str]:
    path = readable_compiler(path)
    return {"path": str(path), "sha256": compiler_digest(path)}


def require_keys(value: object, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{description} fields drifted")
    return value


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path, description: str) -> dict[str, Any]:
    path = physical(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        fail(f"{description} must be a JSON object")
    return value


def write_json_new(path: Path, value: dict[str, Any], description: str) -> Path:
    candidate = Path(path)
    if ".." in candidate.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    absolute = Path(os.path.abspath(candidate))
    physical(absolute.parent, f"{description} parent", directory=True)
    if absolute.exists() or absolute.is_symlink():
        fail(f"{description} already exists: {absolute}")
    try:
        with absolute.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except OSError as error:
        raise EvidenceError(f"cannot write {description}: {absolute}") from error
    return absolute


def source_path(case: str) -> Path:
    if case not in CASES:
        fail(f"unknown frozen differential case: {case}")
    return physical(ROOT / "compat/differential/tests" / f"{case}.c", f"{case} source")


def product_manifest(product: Path, kind: str) -> tuple[Path, dict[str, str]]:
    product = physical(product, f"{kind} product", directory=True)
    try:
        if kind == "dynamic":
            return product_evidence._validate_dynamic_product(product)
        if kind == "static":
            return product_evidence._validate_static_product(product)
    except product_evidence.ProductEvidenceError as error:
        raise EvidenceError(f"{kind} product is not sealed: {error}") from error
    fail(f"unsupported product kind: {kind}")


def installed_contract(product: Path) -> dict[str, Any]:
    helper = physical(product / "share/crabc/crabc_cc_static.py", "installed compiler helper")
    name = f"owned_differential_compiler_contract_{os.getpid()}"
    specification = importlib.util.spec_from_file_location(name, helper)
    if specification is None or specification.loader is None:
        fail("installed compiler helper cannot be imported")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    if Path(module.__file__).resolve() != helper.resolve():
        fail("installed compiler helper was not imported from the supplied product")
    compiler = readable_compiler(Path(module.compiler()))
    clean_environment = module.clean_environment()
    if (not isinstance(clean_environment, dict) or
            any(not isinstance(key, str) or not isinstance(value, str)
                for key, value in clean_environment.items())):
        fail("installed compiler helper has an invalid clean environment")
    return {
        "helper": helper,
        "compiler": compiler,
        "clean_environment": dict(clean_environment),
    }


def installed_identity(product: Path) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    """Capture every installed authority before or after source translation."""

    product = physical(product, "dynamic product", directory=True)
    manifest, _ = product_manifest(product, "dynamic")
    headers = physical(product / "usr/include", "installed headers", directory=True)
    driver = physical(product / "bin/crabc-cc-dynamic", "installed dynamic driver")
    if not driver.lstat().st_mode & 0o111:
        fail("installed dynamic driver is not executable")
    contract = installed_contract(product)
    return ({
        "root": str(product),
        "manifest": binding(manifest, "dynamic manifest"),
        "driver": binding(driver, "installed dynamic driver"),
        "helper": binding(contract["helper"], "installed compiler helper"),
        "compiler": compiler_binding(contract["compiler"]),
        "clean_environment": contract["clean_environment"],
    }, headers, contract)


def within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def evidence_work(work: Path) -> Path:
    work = physical(work, "evidence work directory", directory=True)
    boundary = physical(ROOT / ".work", "checkout .work boundary", directory=True)
    if not within(work, boundary):
        fail("evidence work directory escapes checkout .work")
    return work


def dependency_paths_text(record: str, source: Path, headers: Path) -> list[Path]:
    """Parse a compiler ``-M`` record and reject all non-product headers."""

    source = physical(source, "dependency source")
    headers = physical(headers, "installed headers", directory=True)
    flattened = record.replace("\\\n", " ")
    try:
        _, words = flattened.split(":", 1)
    except ValueError as error:
        raise EvidenceError("dependency record is invalid") from error
    names = words.split()
    if not names:
        fail("dependency record has no inputs")
    dependencies: list[Path] = []
    for name in names:
        dependency = physical(Path(name), "dependency input")
        if dependency != source and not within(dependency, headers):
            fail(f"dependency escapes installed headers: {dependency}")
        dependencies.append(dependency)
    if source not in dependencies:
        fail("dependency record omits its source")
    if len(dependencies) != len(set(dependencies)):
        fail("dependency record repeats an input")
    return dependencies


def run_to_files(command: list[str], stdout: Path, stderr: Path, environment: dict[str, str], description: str) -> None:
    try:
        with stdout.open("xb") as standard_output, stderr.open("xb") as standard_error:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=standard_output, stderr=standard_error,
                env=environment, cwd=ROOT, check=False,
            )
    except OSError as error:
        raise EvidenceError(f"cannot execute {description}: {error}") from error
    if result.returncode != 0:
        fail(f"{description} failed with status {result.returncode}; raw diagnostics are retained")


def compile_prefix(headers: Path) -> list[str]:
    return [
        "-nostdinc", "-isystem", str(headers), "-ffreestanding", "-fno-builtin",
        "-fstack-protector-strong",
    ]


def caller_flags() -> list[str]:
    return ["-std=c11", "-fno-builtin", "-fno-stack-protector"]


def expected_translation(headers: Path) -> dict[str, Any]:
    return {
        "driver_mode": "--dynamic-pie",
        "effective_codegen_flag": "-fPIE",
        "driver_compile_prefix": compile_prefix(headers),
        "caller_flags": caller_flags(),
        "not_selected": ["-fPIC", "-fno-pie"],
    }


def record_compile(product: Path, work: Path) -> None:
    product = physical(product, "dynamic product", directory=True)
    work = evidence_work(work)
    receipt = work / "compile.json"
    if receipt.exists() or receipt.is_symlink():
        fail("compile receipt already exists")
    # Capture the source and all installed translation authority before any
    # compiler subprocess starts.  The product manifest seals every installed
    # header payload, while the explicit helper/compiler bindings retain the
    # chosen host-tool seam.
    pre_installed, headers, contract = installed_identity(product)
    pre_sources = {case: binding(source_path(case), f"{case} source") for case in CASES}
    environment = {
        **contract["clean_environment"],
        "TMPDIR": str(work),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for directory in (work / "objects", work / "compile", work / "dependencies", work / "relocations"):
        directory.mkdir(exist_ok=False)

    cases: list[dict[str, Any]] = []
    for case in CASES:
        source = source_path(case)
        if pre_sources[case] != binding(source, f"{case} source"):
            fail(f"{case} source changed before its installed compile")
        object_path = work / "objects" / f"{case}.o"
        compile_stdout = work / "compile" / f"{case}.stdout"
        compile_stderr = work / "compile" / f"{case}.stderr"
        dependency_path = work / "dependencies" / f"{case}.d"
        dependency_stderr = work / "dependencies" / f"{case}.stderr"
        relocations = work / "relocations" / f"{case}.txt"
        relocation_stderr = work / "relocations" / f"{case}.stderr"
        command = [
            pre_installed["driver"]["path"], "--dynamic-pie", *caller_flags(), "-c", str(source), "-o", str(object_path),
        ]
        run_to_files(command, compile_stdout, compile_stderr, environment, f"installed compile for {case}")
        physical(object_path, f"{case} object")
        dependency_command = [
            str(contract["compiler"]), *compile_prefix(headers), *caller_flags(), "-fPIE", "-M", str(source),
        ]
        run_to_files(
            dependency_command, dependency_path, dependency_stderr, environment,
            f"installed-header dependency audit for {case}",
        )
        try:
            dependencies = dependency_paths_text(
                dependency_path.read_text(encoding="utf-8"), source, headers,
            )
        except (OSError, UnicodeDecodeError) as error:
            raise EvidenceError(f"dependency audit is unreadable for {case}") from error
        missing_headers = [
            name for name in REQUIRED_HEADERS[case]
            if physical(headers / name, f"required installed header {name}") not in dependencies
        ]
        if missing_headers:
            fail(f"installed-header dependency audit omits {case} header: {missing_headers[0]}")
        run_to_files(
            ["/usr/bin/readelf", "-rW", str(object_path)], relocations, relocation_stderr, environment,
            f"relocation audit for {case}",
        )
        post_installed, _, _ = installed_identity(product)
        if post_installed != pre_installed:
            fail(f"installed compiler/header identity changed during {case} compilation")
        if pre_sources[case] != binding(source, f"{case} source"):
            fail(f"{case} source changed during its installed compile")
        relocation_text = relocations.read_text(encoding="utf-8", errors="replace")
        if "R_X86_64_32" in relocation_text or "R_X86_64_32S" in relocation_text:
            fail(f"installed {case} object is not PIE-relocatable")
        cases.append({
            "case": case,
            "source": pre_sources[case],
            "object": binding(object_path, f"{case} object"),
            "actual_compile_command": command,
            "compile_stdout": binding(compile_stdout, f"{case} compile stdout"),
            "compile_stderr": binding(compile_stderr, f"{case} compile stderr"),
            "dependency_audit_command": dependency_command,
            "dependency_audit": binding(dependency_path, f"{case} dependency audit"),
            "dependency_stderr": binding(dependency_stderr, f"{case} dependency stderr"),
            "dependencies": {str(path): digest(path) for path in dependencies},
            "required_headers": list(REQUIRED_HEADERS[case]),
            "relocations": binding(relocations, f"{case} relocation audit"),
            "relocation_stderr": binding(relocation_stderr, f"{case} relocation stderr"),
        })
    post_installed, _, _ = installed_identity(product)
    if post_installed != pre_installed:
        fail("installed compiler/header identity changed after compilation")
    post_sources = {case: binding(source_path(case), f"{case} source") for case in CASES}
    if post_sources != pre_sources:
        fail("frozen differential source identity changed after compilation")
    record = {
        "schema": COMPILE_SCHEMA,
        "pre_compile": {
            "installed_dynamic": pre_installed,
            "sources": pre_sources,
            "execution_environment": environment,
        },
        "installed_dynamic": post_installed,
        "translation": expected_translation(headers),
        "cases": cases,
    }
    write_json_new(receipt, record, "compile receipt")


def require_binding(value: object, expected: Path, description: str, *, compiler: bool = False) -> None:
    record = require_keys(value, {"path", "sha256"}, description)
    actual = compiler_binding(expected) if compiler else binding(expected, description)
    if record != actual:
        fail(f"{description} changed after compilation")


def validate_compile(product: Path, work: Path) -> dict[str, Any]:
    product = physical(product, "dynamic product", directory=True)
    work = evidence_work(work)
    receipt = read_json(work / "compile.json", "compile receipt")
    require_keys(receipt, {"schema", "pre_compile", "installed_dynamic", "translation", "cases"}, "compile receipt")
    if receipt["schema"] != COMPILE_SCHEMA:
        fail("compile receipt schema drifted")
    expected_installed, headers, contract = installed_identity(product)
    if receipt["installed_dynamic"] != expected_installed:
        fail("installed dynamic product/compiler identity changed after compilation")
    pre_compile = require_keys(
        receipt["pre_compile"], {"installed_dynamic", "sources", "execution_environment"},
        "pre-compile identity",
    )
    if pre_compile["installed_dynamic"] != expected_installed:
        fail("installed dynamic product/compiler identity differs from its pre-compile capture")
    expected_sources = {case: binding(source_path(case), f"{case} source") for case in CASES}
    if pre_compile["sources"] != expected_sources:
        fail("frozen differential source identity differs from its pre-compile capture")
    expected_environment = {
        **contract["clean_environment"], "TMPDIR": str(work), "PYTHONDONTWRITEBYTECODE": "1",
    }
    if pre_compile["execution_environment"] != expected_environment:
        fail("installed compile execution environment drifted")
    if receipt["translation"] != expected_translation(headers):
        fail("installed dynamic translation contract drifted")
    records = receipt["cases"]
    if not isinstance(records, list) or [item.get("case") if isinstance(item, dict) else None for item in records] != list(CASES):
        fail("compile case roster drifted")
    expected_case_keys = {
        "case", "source", "object", "actual_compile_command", "compile_stdout", "compile_stderr",
        "dependency_audit_command", "dependency_audit", "dependency_stderr", "dependencies",
        "required_headers", "relocations", "relocation_stderr",
    }
    by_case: dict[str, Any] = {}
    for item in records:
        require_keys(item, expected_case_keys, f"{item.get('case', 'unknown')} compile record")
        case = item["case"]
        source = source_path(case)
        object_path = work / "objects" / f"{case}.o"
        if item["source"] != expected_sources[case]:
            fail(f"{case} source differs from its pre-compile identity")
        require_binding(item["object"], object_path, f"{case} object")
        expected_command = [
            expected_installed["driver"]["path"], "--dynamic-pie", *caller_flags(), "-c", str(source), "-o", str(object_path),
        ]
        if item["actual_compile_command"] != expected_command:
            fail(f"{case} actual installed-driver command drifted")
        require_binding(item["compile_stdout"], work / "compile" / f"{case}.stdout", f"{case} compile stdout")
        require_binding(item["compile_stderr"], work / "compile" / f"{case}.stderr", f"{case} compile stderr")
        expected_dependency_command = [
            str(contract["compiler"]), *compile_prefix(headers), *caller_flags(), "-fPIE", "-M", str(source),
        ]
        if item["dependency_audit_command"] != expected_dependency_command:
            fail(f"{case} installed-header dependency command drifted")
        dependency_path = work / "dependencies" / f"{case}.d"
        require_binding(item["dependency_audit"], dependency_path, f"{case} dependency audit")
        require_binding(item["dependency_stderr"], work / "dependencies" / f"{case}.stderr", f"{case} dependency stderr")
        try:
            dependencies = dependency_paths_text(dependency_path.read_text(encoding="utf-8"), source, headers)
        except (OSError, UnicodeDecodeError) as error:
            raise EvidenceError(f"{case} dependency audit is unreadable") from error
        expected_dependencies = {str(path): digest(path) for path in dependencies}
        if item["dependencies"] != expected_dependencies:
            fail(f"{case} source or installed-header dependency changed after compilation")
        if item["required_headers"] != list(REQUIRED_HEADERS[case]):
            fail(f"{case} direct installed-header roster drifted")
        for header in REQUIRED_HEADERS[case]:
            if str(physical(headers / header, f"required installed header {header}")) not in expected_dependencies:
                fail(f"{case} installed-header dependency omits {header}")
        relocation_path = work / "relocations" / f"{case}.txt"
        require_binding(item["relocations"], relocation_path, f"{case} relocation audit")
        require_binding(item["relocation_stderr"], work / "relocations" / f"{case}.stderr", f"{case} relocation stderr")
        relocation_text = relocation_path.read_text(encoding="utf-8", errors="replace")
        if "R_X86_64_32" in relocation_text or "R_X86_64_32S" in relocation_text:
            fail(f"installed {case} object is not PIE-relocatable")
        by_case[case] = item
    return by_case


def compiled_dynamic_product(work: Path) -> Path:
    """Recover and revalidate the exact installed dynamic product that compiled the objects."""

    work = evidence_work(work)
    receipt = read_json(work / "compile.json", "compile receipt")
    installed = require_keys(
        receipt.get("installed_dynamic"),
        {"root", "manifest", "driver", "helper", "compiler", "clean_environment"},
        "compile receipt installed dynamic",
    )
    root = physical(Path(installed["root"]), "compiled dynamic product", directory=True)
    validate_compile(root, work)
    return root


def validate_link(product: Path, work: Path, case: str, linkage: str, executable: Path, receipt: Path, record: Path) -> None:
    compiled_dynamic = compiled_dynamic_product(work)
    product = physical(product, "link product", directory=True)
    if linkage in {"pie", "non-pie"} and product != compiled_dynamic:
        fail("dynamic link product differs from the installed product that compiled the object")
    if case not in CASES:
        fail(f"link uses a case not present in the compile receipt: {case}")
    object_path = physical(work / "objects" / f"{case}.o", f"{case} canonical object")
    try:
        identity = product_evidence.validate_link(product, object_path, executable, receipt, linkage)
    except product_evidence.ProductEvidenceError as error:
        raise EvidenceError(f"sealed {linkage} link is invalid for {case}: {error}") from error
    value = {
        "schema": LINK_SCHEMA,
        "case": case,
        "linkage": linkage,
        "canonical_object": binding(object_path, f"{case} canonical object"),
        "sealed_link": identity,
    }
    write_json_new(record, value, "sealed link identity")


def record_oracle_link(work: Path, case: str, executable: Path, record: Path) -> None:
    work = evidence_work(work)
    compiled_dynamic_product(work)
    if case not in CASES:
        fail(f"unknown frozen differential case: {case}")
    # The caller validates the dynamic compilation receipt separately. This
    # function still binds the named canonical object rather than accepting an
    # arbitrary source-equivalent object at the musl link seam.
    object_path = physical(work / "objects" / f"{case}.o", f"{case} canonical object")
    executable = physical(executable, f"{case} musl executable")
    compiler = readable_compiler(ORACLE_COMPILER)
    musl_libc = physical(ORACLE_LIBC, "pinned musl libc archive")
    header = work / "oracle" / f"{case}.readelf-header"
    header_stderr = work / "oracle" / f"{case}.readelf-header.stderr"
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work)}
    run_to_files(
        ["/usr/bin/readelf", "-hW", str(executable)], header, header_stderr, environment,
        f"pinned musl ELF audit for {case}",
    )
    value = {
        "schema": ORACLE_LINK_SCHEMA,
        "case": case,
        "command": [str(compiler), "-static", "-fno-pie", "-no-pie", str(object_path), "-o", str(executable)],
        "compiler": compiler_binding(compiler),
        "musl_libc": binding(musl_libc, "pinned musl libc archive"),
        "canonical_object": binding(object_path, f"{case} canonical object"),
        "executable": binding(executable, f"{case} musl executable"),
        "readelf_header": binding(header, f"{case} musl ELF header"),
        "readelf_header_stderr": binding(header_stderr, f"{case} musl ELF header stderr"),
    }
    write_json_new(record, value, "pinned musl link identity")


def tree_modes(root: Path) -> dict[str, str]:
    root = physical(root, "product copy root", directory=True)
    result: dict[str, str] = {}
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise EvidenceError(f"cannot enumerate product copy: {root}") from error
    for entry in entries:
        try:
            mode = entry.lstat().st_mode
        except OSError as error:
            raise EvidenceError(f"cannot inspect product copy entry: {entry}") from error
        result[entry.relative_to(root).as_posix()] = format(stat.S_IMODE(mode), "04o")
    return result


def product_copy_identity(kind: str, source: Path, copied: Path) -> dict[str, Any]:
    source_manifest, _ = product_manifest(source, kind)
    copied_manifest, _ = product_manifest(copied, kind)
    if digest(source_manifest) != digest(copied_manifest):
        fail("product copy manifest differs from the consumed product")
    source_modes = tree_modes(source)
    copied_modes = tree_modes(copied)
    if source_modes != copied_modes:
        fail("product copy mode roster differs from the consumed product")
    return {
        "kind": kind,
        "source": {"root": str(physical(source, "source product", directory=True)), "manifest": binding(source_manifest, "source manifest")},
        "copy": {"root": str(physical(copied, "copied product", directory=True)), "manifest": binding(copied_manifest, "copied manifest")},
        "mode_roster_sha256": hashlib.sha256(
            json.dumps(source_modes, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def file_copy_identity(source: Path, copied: Path) -> dict[str, Any]:
    source = physical(source, "source executable")
    copied = physical(copied, "copied executable")
    source_mode = stat.S_IMODE(source.lstat().st_mode)
    copied_mode = stat.S_IMODE(copied.lstat().st_mode)
    if source_mode != copied_mode:
        fail("copied executable mode differs from the source executable")
    source_binding = binding(source, "source executable")
    copied_binding = binding(copied, "copied executable")
    if source_binding["sha256"] != copied_binding["sha256"]:
        fail("copied executable bytes differ from the source executable")
    return {
        "source": source_binding,
        "copy": copied_binding,
        "mode": format(source_mode, "04o"),
    }


def record_product_copy(kind: str, source: Path, copied: Path, record: Path) -> None:
    value = {"schema": COPY_SCHEMA, "copy_type": "product", **product_copy_identity(kind, source, copied)}
    write_json_new(record, value, "product copy identity")


def record_file_copy(source: Path, copied: Path, record: Path) -> None:
    value = {"schema": COPY_SCHEMA, "copy_type": "file", **file_copy_identity(source, copied)}
    write_json_new(record, value, "file copy identity")


def tree_entries(root: Path, description: str) -> dict[str, Path]:
    root = physical(root, description, directory=True)
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise EvidenceError(f"cannot enumerate {description}: {root}") from error
    return {entry.relative_to(root).as_posix(): entry for entry in entries}


def entry_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def require_same_entry(source: Path, copied: Path, relative: str) -> None:
    try:
        source_mode = source.lstat().st_mode
        copied_mode = copied.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"cannot inspect runtime copy entry: {relative}") from error
    if entry_type(source_mode) != entry_type(copied_mode):
        fail(f"runtime copy entry type differs: {relative}")
    if stat.S_IMODE(source_mode) != stat.S_IMODE(copied_mode):
        fail(f"runtime copy entry mode differs: {relative}")
    if stat.S_ISREG(source_mode):
        if digest(source) != digest(copied):
            fail(f"runtime copy entry bytes differ: {relative}")
    elif stat.S_ISLNK(source_mode):
        try:
            if os.readlink(source) != os.readlink(copied):
                fail(f"runtime copy symlink differs: {relative}")
        except OSError as error:
            raise EvidenceError(f"cannot read runtime copy symlink: {relative}") from error


def private_tmp_identity(root: Path) -> dict[str, str]:
    temporary = physical(root / "tmp", "execution-root tmp", directory=True)
    if stat.S_IMODE(temporary.lstat().st_mode) != 0o1777:
        fail("execution-root tmp mode differs from 1777")
    try:
        if any(temporary.iterdir()):
            fail("execution-root tmp is not empty after the contained workload")
    except OSError as error:
        raise EvidenceError(f"cannot inspect execution-root tmp: {temporary}") from error
    return {"path": str(temporary), "mode": "1777"}


def file_root_identity(source: Path, root: Path) -> dict[str, Any]:
    root = physical(root, "file execution root", directory=True)
    tmp = private_tmp_identity(root)
    entries = tree_entries(root, "file execution root")
    if set(entries) != {"consumer", "tmp"}:
        fail("file execution root roster differs from consumer plus tmp")
    return {
        "root": str(root),
        "consumer": file_copy_identity(source, root / "consumer"),
        "tmp": tmp,
    }


def dynamic_root_identity(source: Path, root: Path, executable: Path) -> dict[str, Any]:
    """Verify a runtime copy before or after one isolated dynamic execution."""

    source = physical(source, "dynamic source product", directory=True)
    root = physical(root, "dynamic execution root", directory=True)
    manifest, _ = product_manifest(source, "dynamic")
    tmp = private_tmp_identity(root)
    source_entries = tree_entries(source, "dynamic source product")
    copied_entries = tree_entries(root, "dynamic execution root")
    expected = set(source_entries) | {"consumer", "tmp"}
    if set(copied_entries) != expected:
        fail("dynamic execution root roster differs from copied product plus consumer/tmp")
    for relative, source_entry in source_entries.items():
        require_same_entry(source_entry, copied_entries[relative], relative)
    mode_roster = {
        relative: format(entry.lstat().st_mode & 0o7777, "04o")
        for relative, entry in source_entries.items()
    }
    return {
        "source_product": {
            "root": str(source),
            "manifest": binding(manifest, "dynamic source manifest"),
            "mode_roster_sha256": hashlib.sha256(
                json.dumps(mode_roster, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        },
        "root": str(root),
        "consumer": file_copy_identity(executable, root / "consumer"),
        "tmp": tmp,
    }


def attest_file_root(source: Path, root: Path, phase: str, record: Path) -> None:
    value = {
        "schema": COPY_SCHEMA,
        "copy_type": "file-execution-root",
        "phase": phase,
        **file_root_identity(source, root),
    }
    write_json_new(record, value, "file execution-root identity")


def attest_dynamic_root(source: Path, root: Path, executable: Path, phase: str, record: Path) -> None:
    value = {
        "schema": COPY_SCHEMA,
        "copy_type": "dynamic-execution-root",
        "phase": phase,
        **dynamic_root_identity(source, root, executable),
    }
    write_json_new(record, value, "dynamic execution-root identity")


def raw_stream(path: Path, description: str) -> dict[str, Any]:
    path = physical(path, description)
    try:
        length = path.stat().st_size
    except OSError as error:
        raise EvidenceError(f"cannot stat {description}: {path}") from error
    return {**binding(path, description), "byte_length": length}


def status_value(path: Path, description: str) -> int:
    path = physical(path, description)
    data = path.read_bytes()
    if re.fullmatch(rb"[0-9]+\n", data) is None:
        fail(f"{description} is not one raw shell status")
    return int(data[:-1])


def errno_values(case: str, path: Path) -> list[int]:
    path = physical(path, f"{case} stdout")
    pattern = re.compile(("^" + re.escape(case) + r": errno=([0-9]+) .*$").encode("ascii"))
    return [int(match.group(1)) for line in path.read_bytes().splitlines() if (match := pattern.match(line))]


def compare_observations(
    case: str, reference_label: str, reference: RawObservation,
    candidate_label: str, candidate: RawObservation,
) -> dict[str, Any]:
    """Compare complete raw status/stdout/stderr plus the workload errno marker."""

    if case not in CASES:
        fail(f"unknown frozen differential case: {case}")
    reference_status = status_value(reference.status_path, f"{reference_label} status")
    candidate_status = status_value(candidate.status_path, f"{candidate_label} status")
    reference_stdout = physical(reference.stdout_path, f"{reference_label} stdout").read_bytes()
    candidate_stdout = physical(candidate.stdout_path, f"{candidate_label} stdout").read_bytes()
    reference_stderr = physical(reference.stderr_path, f"{reference_label} stderr").read_bytes()
    candidate_stderr = physical(candidate.stderr_path, f"{candidate_label} stderr").read_bytes()
    reference_errno = errno_values(case, reference.stdout_path)
    candidate_errno = errno_values(case, candidate.stdout_path)
    differences: list[str] = []
    if reference_status != 0:
        differences.append(f"pinned musl reference status is {reference_status}")
    if candidate_status != 0:
        differences.append(f"candidate status is {candidate_status}")
    if reference_status != candidate_status:
        differences.append("status differs")
    if reference_stdout != candidate_stdout:
        differences.append("stdout differs")
    if reference_stderr != candidate_stderr:
        differences.append("stderr differs")
    if len(reference_errno) != 1:
        differences.append("pinned musl errno marker count differs from one")
    if len(candidate_errno) != 1:
        differences.append("candidate errno marker count differs from one")
    if len(reference_errno) == 1 and len(candidate_errno) == 1 and reference_errno[0] != candidate_errno[0]:
        differences.append("errno differs")
    return {
        "schema": OBSERVATION_SCHEMA,
        "case": case,
        "passed": not differences,
        "differences": differences,
        "reference": {
            "label": reference_label,
            "status": reference_status,
            "stdout": raw_stream(reference.stdout_path, f"{reference_label} stdout"),
            "stderr": raw_stream(reference.stderr_path, f"{reference_label} stderr"),
            "raw_status": raw_stream(reference.status_path, f"{reference_label} status"),
            "errno": reference_errno[0] if len(reference_errno) == 1 else None,
        },
        "candidate": {
            "label": candidate_label,
            "status": candidate_status,
            "stdout": raw_stream(candidate.stdout_path, f"{candidate_label} stdout"),
            "stderr": raw_stream(candidate.stderr_path, f"{candidate_label} stderr"),
            "raw_status": raw_stream(candidate.status_path, f"{candidate_label} status"),
            "errno": candidate_errno[0] if len(candidate_errno) == 1 else None,
        },
    }


def summary_artifact(path: Path, description: str) -> dict[str, str]:
    path = physical(path, description)
    return {"path": path.name, "sha256": digest(path)}


def frozen_matrix(static_replayed: bool) -> dict[str, list[dict[str, str | None]]]:
    """Name every retained leaf of the fixed five-source replay matrix.

    This is deliberately derived from ``CASES`` rather than from the contents
    of an evidence directory.  A report cannot turn a missing replay cell into
    an optional one merely by omitting its receipt.
    """

    links: list[dict[str, str | None]] = []
    observations: list[dict[str, str | None]] = []
    copies: list[dict[str, str | None]] = []
    for case in CASES:
        links.append({
            "name": f"{case}-musl.json", "schema": ORACLE_LINK_SCHEMA,
            "kind": "musl", "case": case, "linkage": None,
        })
        copies.extend((
            {"name": f"{case}-musl-executable.json", "kind": "musl", "copy": "file", "phase": None,
             "case": case, "linkage": None, "entry": None},
            {"name": f"{case}-musl-root-pre.json", "kind": "musl", "copy": "root", "phase": "pre",
             "case": case, "linkage": None, "entry": None},
            {"name": f"{case}-musl-root-post.json", "kind": "musl", "copy": "root", "phase": "post",
             "case": case, "linkage": None, "entry": None},
        ))
        if static_replayed:
            for linkage in ("static", "static-pie"):
                label = f"static-{linkage}"
                links.append({
                    "name": f"{case}-{label}.json", "schema": LINK_SCHEMA,
                    "kind": "static", "case": case, "linkage": linkage,
                })
                observations.append({"name": f"{case}-{label}.json", "case": case, "label": label})
                copies.extend((
                    {"name": f"{case}-{label}-executable.json", "kind": "static", "copy": "file", "phase": None,
                     "case": case, "linkage": linkage, "entry": None},
                    {"name": f"{case}-{label}-root-pre.json", "kind": "static", "copy": "root", "phase": "pre",
                     "case": case, "linkage": linkage, "entry": None},
                    {"name": f"{case}-{label}-root-post.json", "kind": "static", "copy": "root", "phase": "post",
                     "case": case, "linkage": linkage, "entry": None},
                ))
        for linkage in ("pie", "non-pie"):
            links.append({
                "name": f"{case}-dynamic-{linkage}.json", "schema": LINK_SCHEMA,
                "kind": "dynamic", "case": case, "linkage": linkage,
            })
            for entry in ("kernel", "direct"):
                label = f"dynamic-{linkage}-{entry}"
                observations.append({"name": f"{case}-{label}.json", "case": case, "label": label})
                copies.extend((
                    {"name": f"{case}-{label}-product.json", "kind": "dynamic", "copy": "product", "phase": None,
                     "case": case, "linkage": linkage, "entry": entry},
                    {"name": f"{case}-{label}-executable.json", "kind": "dynamic", "copy": "file", "phase": None,
                     "case": case, "linkage": linkage, "entry": entry},
                    {"name": f"{case}-{label}-root-pre.json", "kind": "dynamic", "copy": "root", "phase": "pre",
                     "case": case, "linkage": linkage, "entry": entry},
                    {"name": f"{case}-{label}-root-post.json", "kind": "dynamic", "copy": "root", "phase": "post",
                     "case": case, "linkage": linkage, "entry": entry},
                ))
    return {"links": links, "observations": observations, "copies": copies}


def candidate_executable(work: Path, kind: str, case: str, linkage: str | None) -> Path:
    if kind == "musl":
        if linkage is not None:
            fail("pinned musl link unexpectedly has a linkage mode")
        return work / "oracle" / case
    if kind not in {"static", "dynamic"} or linkage is None:
        fail("candidate link has an invalid matrix identity")
    return work / "candidates" / f"{case}-{kind}-{linkage}"


def execution_root(work: Path, kind: str, case: str, linkage: str | None, entry: str | None) -> Path:
    if kind == "musl":
        if linkage is not None or entry is not None:
            fail("pinned musl root has an invalid matrix identity")
        return work / "roots" / f"{case}-musl"
    if kind == "static":
        if linkage is None or entry is not None:
            fail("static root has an invalid matrix identity")
        return work / "roots" / f"{case}-static-{linkage}"
    if kind == "dynamic" and linkage is not None and entry in {"kernel", "direct"}:
        return work / "roots" / f"{case}-dynamic-{linkage}-{entry}"
    fail("dynamic root has an invalid matrix identity")


def receipt_path(work: Path, kind: str, case: str, linkage: str | None) -> Path:
    executable = candidate_executable(work, kind, case, linkage)
    if kind == "static":
        return executable.with_name(executable.name + ".receipt.json")
    if kind == "dynamic":
        return executable.with_name(executable.name + ".crabc-link.json")
    fail("pinned musl link has no owned link receipt")


def record_matches(path: Path, expected: dict[str, Any], description: str) -> None:
    if read_json(path, description) != expected:
        fail(f"{description} differs from its recomputed identity")


def validate_oracle_link_record(work: Path, case: str, path: Path) -> None:
    """Recheck the pinned-musl object-to-ELF seam without relinking it."""

    executable = candidate_executable(work, "musl", case, None)
    object_path = work / "objects" / f"{case}.o"
    header = work / "oracle" / f"{case}.readelf-header"
    header_stderr = work / "oracle" / f"{case}.readelf-header.stderr"
    compiler = readable_compiler(ORACLE_COMPILER)
    record = {
        "schema": ORACLE_LINK_SCHEMA,
        "case": case,
        "command": [str(compiler), "-static", "-fno-pie", "-no-pie", str(object_path), "-o", str(executable)],
        "compiler": compiler_binding(compiler),
        "musl_libc": binding(ORACLE_LIBC, "pinned musl libc archive"),
        "canonical_object": binding(object_path, f"{case} canonical object"),
        "executable": binding(executable, f"{case} musl executable"),
        "readelf_header": binding(header, f"{case} musl ELF header"),
        "readelf_header_stderr": binding(header_stderr, f"{case} musl ELF header stderr"),
    }
    record_matches(path, record, f"{case} pinned musl link identity")
    try:
        inspected = subprocess.run(
            ["/usr/bin/readelf", "-hW", str(physical(executable, f"{case} musl executable"))],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=False,
        )
    except OSError as error:
        raise EvidenceError(f"cannot inspect pinned musl executable for {case}: {error}") from error
    if inspected.returncode != 0:
        fail(f"pinned musl ELF inspection failed for {case}: {inspected.returncode}")
    if inspected.stdout != header.read_bytes() or inspected.stderr != header_stderr.read_bytes():
        fail(f"pinned musl ELF inspection differs from its retained raw audit for {case}")
    if re.search(rb"^\s*Type:\s+EXEC\b", inspected.stdout, re.MULTILINE) is None:
        fail(f"pinned musl executable has the wrong ELF type for {case}")


def validate_owned_link_record(
    work: Path, compiled_dynamic: Path, kind: str, case: str, linkage: str, path: Path,
) -> None:
    """Re-run the product's read-only sealed-link validator for one matrix cell."""

    record = read_json(path, f"{case} {kind} sealed link identity")
    require_keys(record, {"schema", "case", "linkage", "canonical_object", "sealed_link"}, "sealed link identity")
    if record["schema"] != LINK_SCHEMA or record["case"] != case or record["linkage"] != linkage:
        fail(f"sealed link matrix identity drifted: {path.name}")
    object_path = work / "objects" / f"{case}.o"
    if record["canonical_object"] != binding(object_path, f"{case} canonical object"):
        fail(f"sealed link object differs from the installed compile object: {path.name}")
    sealed = require_keys(
        record["sealed_link"],
        {"linkage", "product", "product_format", "product_manifest_sha256", "workload_sha256", "executable_sha256", "receipt_sha256"},
        "sealed link identity",
    )
    if not isinstance(sealed["product"], str):
        fail("sealed link product path is not a string")
    product = physical(Path(sealed["product"]), f"{case} {kind} link product", directory=True)
    if kind == "dynamic" and product != compiled_dynamic:
        fail(f"dynamic link product differs from the product that compiled {case}")
    executable = candidate_executable(work, kind, case, linkage)
    receipt = receipt_path(work, kind, case, linkage)
    try:
        identity = product_evidence.validate_link(product, object_path, executable, receipt, linkage)
    except product_evidence.ProductEvidenceError as error:
        raise EvidenceError(f"sealed {linkage} link is invalid for {case}: {error}") from error
    if sealed != identity:
        fail(f"sealed link identity differs from its current product validation: {path.name}")


def observation_paths(work: Path, case: str, label: str) -> tuple[RawObservation, RawObservation]:
    reference = RawObservation(
        status_path=work / "executions" / f"{case}-musl.status",
        stdout_path=work / "executions" / f"{case}-musl.stdout",
        stderr_path=work / "executions" / f"{case}-musl.stderr",
    )
    candidate = RawObservation(
        status_path=work / "executions" / f"{case}-{label}.status",
        stdout_path=work / "executions" / f"{case}-{label}.stdout",
        stderr_path=work / "executions" / f"{case}-{label}.stderr",
    )
    return reference, candidate


def validate_observation_record(work: Path, case: str, label: str, path: Path) -> None:
    """Recompute one byte-exact raw comparison from retained stream files."""

    reference, candidate = observation_paths(work, case, label)
    expected = compare_observations(case, "musl", reference, label, candidate)
    if expected["passed"] is not True:
        fail(f"raw observation is not a zero-status passing result: {path.name}")
    record_matches(path, expected, f"{case} {label} raw observation")


def dynamic_product_copy_after_execution(source: Path, root: Path, executable: Path) -> dict[str, Any]:
    """Recover the pre-run product-copy record from an unchanged dynamic root.

    The original copy receipt predates ``consumer`` and ``tmp``.  The post-run
    root attestation proves those two additions are the only extra entries, so
    it is sufficient to recompute the original copied-product payload without
    pretending the execution root is itself an installed product.
    """

    root_identity = dynamic_root_identity(source, root, executable)
    root = physical(root, "dynamic execution root", directory=True)
    source_product = root_identity["source_product"]
    return {
        "kind": "dynamic",
        "source": {"root": source_product["root"], "manifest": source_product["manifest"]},
        "copy": {
            "root": str(root),
            "manifest": binding(root / "share/crabc/manifest.json", "copied dynamic manifest"),
        },
        "mode_roster_sha256": source_product["mode_roster_sha256"],
    }


def validate_copy_record(work: Path, compiled_dynamic: Path, specification: dict[str, str | None], path: Path) -> None:
    """Recompute a copied executable/product/root receipt after its workload."""

    kind = str(specification["kind"])
    case = str(specification["case"])
    linkage = specification["linkage"]
    entry = specification["entry"]
    copy_kind = str(specification["copy"])
    phase = specification["phase"]
    executable = candidate_executable(work, kind, case, linkage)
    root = execution_root(work, kind, case, linkage, entry)
    if copy_kind == "file":
        expected = {"schema": COPY_SCHEMA, "copy_type": "file", **file_copy_identity(executable, root / "consumer")}
    elif kind in {"musl", "static"} and copy_kind == "root" and phase in {"pre", "post"}:
        expected = {
            "schema": COPY_SCHEMA,
            "copy_type": "file-execution-root",
            "phase": phase,
            **file_root_identity(executable, root),
        }
    elif kind == "dynamic" and copy_kind == "product":
        expected = {
            "schema": COPY_SCHEMA,
            "copy_type": "product",
            **dynamic_product_copy_after_execution(compiled_dynamic, root, executable),
        }
    elif kind == "dynamic" and copy_kind == "root" and phase in {"pre", "post"}:
        expected = {
            "schema": COPY_SCHEMA,
            "copy_type": "dynamic-execution-root",
            "phase": phase,
            **dynamic_root_identity(compiled_dynamic, root, executable),
        }
    else:
        fail(f"copy matrix identity is invalid: {path.name}")
    record_matches(path, expected, f"{case} copied execution identity")


def matrix_roster(directory: Path, expected: list[dict[str, str | None]], description: str) -> None:
    directory = physical(directory, description, directory=True)
    try:
        names = {path.name for path in directory.iterdir()}
    except OSError as error:
        raise EvidenceError(f"cannot enumerate {description}: {directory}") from error
    if names != {str(item["name"]) for item in expected}:
        fail(f"{description} roster differs from the frozen replay matrix")


def collect_summary(work: Path, static_replayed: bool) -> dict[str, Any]:
    """Revalidate every retained leaf and return the only admissible summary."""

    work = evidence_work(work)
    if type(static_replayed) is not bool:
        fail("summary static-replayed flag must be a boolean")
    compiled_dynamic = compiled_dynamic_product(work)
    matrix = frozen_matrix(static_replayed)
    links_directory = work / "links"
    observations_directory = work / "observations"
    copies_directory = work / "copies"
    matrix_roster(links_directory, matrix["links"], "link identity directory")
    matrix_roster(observations_directory, matrix["observations"], "raw observation directory")
    matrix_roster(copies_directory, matrix["copies"], "copy identity directory")

    links: dict[str, dict[str, str]] = {}
    for specification in matrix["links"]:
        name = str(specification["name"])
        kind = str(specification["kind"])
        case = str(specification["case"])
        path = links_directory / name
        if kind == "musl":
            validate_oracle_link_record(work, case, path)
        else:
            linkage = specification["linkage"]
            if linkage is None:
                fail(f"owned link is missing a linkage mode: {name}")
            validate_owned_link_record(work, compiled_dynamic, kind, case, linkage, path)
        links[f"links/{name}"] = summary_artifact(path, "link identity")

    observations: dict[str, dict[str, str]] = {}
    for specification in matrix["observations"]:
        name = str(specification["name"])
        validate_observation_record(work, str(specification["case"]), str(specification["label"]), observations_directory / name)
        observations[f"observations/{name}"] = summary_artifact(observations_directory / name, "raw observation")

    copies: dict[str, dict[str, str]] = {}
    for specification in matrix["copies"]:
        name = str(specification["name"])
        validate_copy_record(work, compiled_dynamic, specification, copies_directory / name)
        copies[f"copies/{name}"] = summary_artifact(copies_directory / name, "copy identity")

    return {
        "schema": SUMMARY_SCHEMA,
        "status": "pass",
        "static_replayed": static_replayed,
        "cases": list(CASES),
        "compile": binding(work / "compile.json", "compile receipt"),
        "links": links,
        "observations": observations,
        "copies": copies,
    }


def summarize(work: Path, static_replayed: bool) -> None:
    """Publish one pass-only index after every retained leaf has been sealed."""

    work = evidence_work(work)
    write_json_new(work / "summary.json", collect_summary(work, static_replayed), "owned differential summary")


def validate_summary(work: Path) -> dict[str, Any]:
    """Read and recompute a finished summary without invoking a workload."""

    work = evidence_work(work)
    summary = read_json(work / "summary.json", "owned differential summary")
    require_keys(
        summary, {"schema", "status", "static_replayed", "cases", "compile", "links", "observations", "copies"},
        "owned differential summary",
    )
    if summary["schema"] != SUMMARY_SCHEMA or summary["status"] != "pass":
        fail("owned differential summary is not a passing v1 report")
    if type(summary["static_replayed"]) is not bool:
        fail("owned differential summary static-replayed flag is not a boolean")
    if summary["cases"] != list(CASES):
        fail("owned differential summary case roster drifted")
    expected = collect_summary(work, summary["static_replayed"])
    if summary != expected:
        fail("owned differential summary differs from its recomputed evidence")
    return summary


def validate_inputs(root: Path, temporary: Path, dynamic: Path, static_product: Path | None) -> None:
    root = physical(root, "checkout root", directory=True)
    if root != physical(ROOT, "helper checkout root", directory=True):
        fail("checkout root differs from this runner checkout")
    temporary = physical(temporary, "TMPDIR", directory=True)
    boundary = physical(root / ".work", "checkout .work boundary", directory=True)
    if not within(temporary, boundary):
        fail("owned differential TMPDIR must be a physical checkout .work directory")
    for product, kind in ((dynamic, "dynamic"), (static_product, "static")):
        if product is None:
            continue
        product = physical(product, f"{kind} product", directory=True)
        if not within(product, boundary):
            fail(f"owned differential {kind} product must be a checkout .work directory")
        product_manifest(product, kind)
    readable_compiler(ORACLE_COMPILER)
    physical(ORACLE_LIBC, "pinned musl libc archive")


def command_validate_inputs(arguments: argparse.Namespace) -> int:
    validate_inputs(arguments.root, arguments.temporary, arguments.dynamic, arguments.static)
    return 0


def command_record_compile(arguments: argparse.Namespace) -> int:
    record_compile(arguments.dynamic, arguments.work)
    return 0


def command_verify_compile(arguments: argparse.Namespace) -> int:
    validate_compile(arguments.dynamic, arguments.work)
    return 0


def command_validate_link(arguments: argparse.Namespace) -> int:
    validate_link(
        arguments.product, arguments.work, arguments.case, arguments.linkage,
        arguments.executable, arguments.receipt, arguments.record,
    )
    return 0


def command_record_oracle_link(arguments: argparse.Namespace) -> int:
    record_oracle_link(arguments.work, arguments.case, arguments.executable, arguments.record)
    return 0


def command_record_product_copy(arguments: argparse.Namespace) -> int:
    record_product_copy(arguments.kind, arguments.source, arguments.copy, arguments.record)
    return 0


def command_record_file_copy(arguments: argparse.Namespace) -> int:
    record_file_copy(arguments.source, arguments.copy, arguments.record)
    return 0


def command_attest_file_root(arguments: argparse.Namespace) -> int:
    attest_file_root(arguments.source, arguments.root, arguments.phase, arguments.record)
    return 0


def command_attest_dynamic_root(arguments: argparse.Namespace) -> int:
    attest_dynamic_root(
        arguments.source, arguments.root, arguments.executable, arguments.phase, arguments.record,
    )
    return 0


def command_compare(arguments: argparse.Namespace) -> int:
    reference = RawObservation(
        status_path=arguments.reference_status, stdout_path=arguments.reference_stdout,
        stderr_path=arguments.reference_stderr,
    )
    candidate = RawObservation(
        status_path=arguments.candidate_status, stdout_path=arguments.candidate_stdout,
        stderr_path=arguments.candidate_stderr,
    )
    result = compare_observations(
        arguments.case, arguments.reference_label, reference, arguments.candidate_label, candidate,
    )
    write_json_new(arguments.record, result, "raw observation record")
    if not result["passed"]:
        print(
            f"owned differential {arguments.case}/{arguments.candidate_label}: FAIL: "
            + "; ".join(result["differences"]),
            file=sys.stderr,
        )
        return 1
    print(f"owned differential {arguments.case}/{arguments.candidate_label}: PASS")
    return 0


def command_summarize(arguments: argparse.Namespace) -> int:
    summarize(arguments.work, arguments.static_replayed)
    return 0


def command_validate_summary(arguments: argparse.Namespace) -> int:
    validate_summary(arguments.work)
    print(f"owned differential summary validated: {evidence_work(arguments.work) / 'summary.json'}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    inputs = commands.add_parser("validate-inputs")
    inputs.add_argument("--root", type=Path, required=True)
    inputs.add_argument("--temporary", type=Path, required=True)
    inputs.add_argument("--dynamic", type=Path, required=True)
    inputs.add_argument("--static", type=Path)
    inputs.set_defaults(handler=command_validate_inputs)

    compile_command = commands.add_parser("record-compile")
    compile_command.add_argument("--dynamic", type=Path, required=True)
    compile_command.add_argument("--work", type=Path, required=True)
    compile_command.set_defaults(handler=command_record_compile)

    verify = commands.add_parser("verify-compile")
    verify.add_argument("--dynamic", type=Path, required=True)
    verify.add_argument("--work", type=Path, required=True)
    verify.set_defaults(handler=command_verify_compile)

    link = commands.add_parser("validate-link")
    link.add_argument("--product", type=Path, required=True)
    link.add_argument("--work", type=Path, required=True)
    link.add_argument("--case", choices=CASES, required=True)
    link.add_argument("--linkage", choices=("static", "static-pie", "pie", "non-pie"), required=True)
    link.add_argument("--executable", type=Path, required=True)
    link.add_argument("--receipt", type=Path, required=True)
    link.add_argument("--record", type=Path, required=True)
    link.set_defaults(handler=command_validate_link)

    oracle = commands.add_parser("record-oracle-link")
    oracle.add_argument("--work", type=Path, required=True)
    oracle.add_argument("--case", choices=CASES, required=True)
    oracle.add_argument("--executable", type=Path, required=True)
    oracle.add_argument("--record", type=Path, required=True)
    oracle.set_defaults(handler=command_record_oracle_link)

    product_copy = commands.add_parser("record-product-copy")
    product_copy.add_argument("--kind", choices=("static", "dynamic"), required=True)
    product_copy.add_argument("--source", type=Path, required=True)
    product_copy.add_argument("--copy", type=Path, required=True)
    product_copy.add_argument("--record", type=Path, required=True)
    product_copy.set_defaults(handler=command_record_product_copy)

    file_copy = commands.add_parser("record-file-copy")
    file_copy.add_argument("--source", type=Path, required=True)
    file_copy.add_argument("--copy", type=Path, required=True)
    file_copy.add_argument("--record", type=Path, required=True)
    file_copy.set_defaults(handler=command_record_file_copy)

    file_root = commands.add_parser("attest-file-root")
    file_root.add_argument("--source", type=Path, required=True)
    file_root.add_argument("--root", type=Path, required=True)
    file_root.add_argument("--phase", choices=("pre", "post"), required=True)
    file_root.add_argument("--record", type=Path, required=True)
    file_root.set_defaults(handler=command_attest_file_root)

    dynamic_root = commands.add_parser("attest-dynamic-root")
    dynamic_root.add_argument("--source", type=Path, required=True)
    dynamic_root.add_argument("--root", type=Path, required=True)
    dynamic_root.add_argument("--executable", type=Path, required=True)
    dynamic_root.add_argument("--phase", choices=("pre", "post"), required=True)
    dynamic_root.add_argument("--record", type=Path, required=True)
    dynamic_root.set_defaults(handler=command_attest_dynamic_root)

    compare = commands.add_parser("compare")
    compare.add_argument("--case", choices=CASES, required=True)
    compare.add_argument("--reference-label", required=True)
    compare.add_argument("--reference-status", type=Path, required=True)
    compare.add_argument("--reference-stdout", type=Path, required=True)
    compare.add_argument("--reference-stderr", type=Path, required=True)
    compare.add_argument("--candidate-label", required=True)
    compare.add_argument("--candidate-status", type=Path, required=True)
    compare.add_argument("--candidate-stdout", type=Path, required=True)
    compare.add_argument("--candidate-stderr", type=Path, required=True)
    compare.add_argument("--record", type=Path, required=True)
    compare.set_defaults(handler=command_compare)

    summary = commands.add_parser(
        "summarize",
        help="write one pass-only summary after all fixed matrix leaves are retained",
    )
    summary.add_argument("--work", type=Path, required=True)
    summary.add_argument("--static-replayed", action="store_true")
    summary.set_defaults(handler=command_summarize)

    validate_summary_command = commands.add_parser(
        "validate-summary",
        help="read and recompute a finished summary without rerunning workloads",
    )
    validate_summary_command.add_argument("--work", type=Path, required=True)
    validate_summary_command.set_defaults(handler=command_validate_summary)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        return arguments.handler(arguments)
    except EvidenceError as error:
        print(f"owned differential evidence: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
