#!/usr/bin/env python3
"""Seal the ordinary-DSO fork workload to its retained object roles.

The general dynamic fork probe instantiates one library source three times:
its initial TLS/callback provider and two runtime-loaded providers.  The same
consumer source has a semantic role shared unchanged with pinned musl and a
crabc-private layout-witness role. This helper records every source/tag
preprocessing identity, validates installed-driver receipts, linker traces and
actual ELF DSO topology, then seals raw observations. It is local workload
evidence; it does not change the shared POSIX validator or qualify a family.
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


ROOT = Path(__file__).resolve().parents[2]
PRODUCT_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
TARGET = "x86_64-unknown-linux-musl"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
COMPILE_SCHEMA = "crabc.dynamic-fork-compile/v1"
ORACLE_PRODUCTS_SCHEMA = "crabc.dynamic-fork-oracle-products/v1"
EXECUTION_PAYLOAD_SCHEMA = "crabc.dynamic-fork-execution-payload/v1"
ORACLE_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
LIBRARY = ROOT / "compat/x86_64/general_dynamic_fork_library.c"
CONSUMER = ROOT / "compat/x86_64/general_dynamic_fork_consumer.c"
DSO_TOPOLOGY = (
    ("initial", 0, "libfork-initial.so", ()),
    ("one", 1, "libfork-one.so", ("libfork-initial.so",)),
    ("two", 2, "libfork-two.so", ("libfork-initial.so",)),
)
CONSUMER_ROLES = (
    ("semantic-consumer", "consumer", ()),
    ("owned-layout-consumer", "consumer-owned-layout", ("CRABC_OWNED_WITNESS",)),
)
OBSERVATION_SCHEMA = "crabc.dynamic-fork-observations/v2"
WORKER_SURVIVOR_BODY = b"dynamic fork survives adopted main exit: ok\n"
WORKER_SURVIVOR_PROTOCOL = re.compile(
    rb"(?P<pid>[1-9][0-9]*)\n" + re.escape(WORKER_SURVIVOR_BODY)
)


class EvidenceError(RuntimeError):
    """The retained product evidence no longer describes this fork workload."""


def fail(message: str) -> None:
    raise EvidenceError(f"dynamic-fork evidence: {message}")


def physical(path: Path, description: str, *, directory: bool = False) -> Path:
    if ".." in path.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        mode = absolute.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    expected = stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)
    if not expected:
        fail(f"{description} is not a physical {'directory' if directory else 'regular file'}: {path}")
    return absolute


def digest(path: Path) -> str:
    path = physical(path, "hashed artifact")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def json_object(path: Path, description: str) -> dict[str, Any]:
    path = physical(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise EvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        fail(f"{description} must be an object")
    return value


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_keys(value: object, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{description} fields drifted")
    return value


def require_hash(value: object, actual: str, description: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(f"{description} has an invalid SHA-256")
    if value != actual:
        fail(f"{description} hash differs from its physical artifact")


def product_manifest(product: Path) -> Path:
    product = physical(product, "dynamic product", directory=True)
    manifest = product / "share/crabc/manifest.json"
    record = json_object(manifest, "dynamic product manifest")
    if (record.get("schema"), record.get("format"), record.get("target")) != (1, PRODUCT_FORMAT, TARGET):
        fail("dynamic product manifest identity drifted")
    if record.get("symlinks") != {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}:
        fail("dynamic product alias roster drifted")
    files = record.get("files")
    if not isinstance(files, dict):
        fail("dynamic product manifest has no file roster")
    required = {
        "bin/crabc-cc-dynamic", "share/crabc/crabc_cc_static.py", "usr/include/stdint.h",
        "lib/ld-crabc-x86_64.so.1", "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/crti.o",
        "usr/lib/crtn.o", "usr/lib/crabc-dynamic-attach.o", "usr/lib/libc.so",
        "usr/lib/libcrabc-builtins.a",
    }
    if not required <= set(files):
        fail("dynamic product manifest omits required payload")
    observed_files: set[str] = set()
    observed_links: dict[str, str] = {}
    for path in product.rglob("*"):
        relative = path.relative_to(product).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            observed_links[relative] = os.readlink(path)
            continue
        if not stat.S_ISREG(mode):
            fail(f"dynamic product has nonregular payload: {relative}")
        if relative != "share/crabc/manifest.json":
            observed_files.add(relative)
    if observed_files != set(files) or observed_links != record["symlinks"]:
        fail("dynamic product payload roster drifted")
    for relative, expected in files.items():
        candidate = Path(relative)
        if not isinstance(relative, str) or candidate.is_absolute() or ".." in candidate.parts:
            fail("dynamic product manifest has unsafe payload path")
        require_hash(expected, digest(product / candidate), f"dynamic product payload {relative}")
    return manifest


def compiler_contract(product: Path):
    helper = physical(product / "share/crabc/crabc_cc_static.py", "dynamic compiler helper")
    name = "owned_dynamic_fork_compiler_contract"
    spec = importlib.util.spec_from_file_location(name, helper)
    if spec is None or spec.loader is None:
        fail("dynamic compiler helper cannot be imported")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return {"helper": helper, "compiler": module.compiler, "clean_environment": module.clean_environment}


def artifact_identity(path: Path, description: str) -> dict[str, str]:
    path = physical(path, description)
    return {"path": str(path), "sha256": digest(path)}


def selected_compiler(contract: dict[str, Any]) -> Path:
    return physical(Path(contract["compiler"]()), "selected dynamic compiler")


def require_identity(value: object, expected: Path, description: str) -> None:
    record = require_keys(value, {"path", "sha256"}, description)
    expected = physical(expected, description)
    if record["path"] != str(expected):
        fail(f"{description} path drifted")
    require_hash(record["sha256"], digest(expected), description)


def evidence_work(work: Path) -> Path:
    work = physical(work, "evidence work directory", directory=True)
    if not work.is_relative_to(ROOT / ".work"):
        fail("evidence work directory escapes checkout .work")
    return work


def run(command: list[str], *, output: Path, environment: dict[str, str]) -> None:
    with output.open("wb") as stream:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.PIPE, env=environment, check=False)
    if completed.returncode:
        raise EvidenceError(
            f"compiler preprocessing failed ({completed.returncode}): {completed.stderr.decode(errors='replace')}"
        )


def capture(command: list[str], *, environment: dict[str, str]) -> bytes:
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, check=False)
    if completed.returncode:
        raise EvidenceError(
            f"compiler audit failed ({completed.returncode}): {completed.stderr.decode(errors='replace')}"
        )
    return completed.stdout


def dependency_names_text(record: str, source: Path, headers: Path) -> list[Path]:
    try:
        record = record.replace("\\\n", " ")
        _, words = record.split(":", 1)
    except ValueError as error:
        raise EvidenceError("dependency record is invalid") from error
    result: list[Path] = []
    for word in words.split():
        candidate = physical(Path(word), "dependency input")
        if candidate != source and not candidate.is_relative_to(headers):
            fail(f"dependency escapes installed headers: {candidate}")
        result.append(candidate)
    if source not in result:
        fail("dependency roster omits its source")
    return result


def dependency_names(path: Path, source: Path, headers: Path) -> list[Path]:
    try:
        return dependency_names_text(path.read_text(encoding="utf-8"), source, headers)
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError(f"dependency record is invalid: {path}") from error


def unit_record(
    contract: dict[str, Any], product: Path, work: Path, identifier: str, source: Path,
    object_path: Path, codegen: str, defines: list[str], driver_mode: str, extra: dict[str, Any],
) -> dict[str, Any]:
    source = physical(source, f"{identifier} source")
    object_path = physical(object_path, f"{identifier} object")
    headers = physical(product / "usr/include", "installed headers", directory=True)
    compiler = str(selected_compiler(contract))
    environment = contract["clean_environment"]()
    base = [compiler, "-nostdinc", "-isystem", str(headers), "-std=c11", "-ffreestanding",
            "-fno-builtin", "-fstack-protector-strong", codegen, *(f"-D{item}" for item in defines)]
    dependencies_path = work / "dependencies" / f"{identifier}.d"
    preprocessed_path = work / "preprocessed" / f"{identifier}.i"
    run([*base, "-M", str(source)], output=dependencies_path, environment=environment)
    run([*base, "-E", "-P", str(source)], output=preprocessed_path, environment=environment)
    dependencies = dependency_names(dependencies_path, source, headers)
    return {
        "id": identifier,
        "source": str(source),
        "source_sha256": digest(source),
        "object": str(object_path),
        "object_sha256": digest(object_path),
        "driver_compile_command": [
            str(product / "bin/crabc-cc-dynamic"), driver_mode, "-std=c11", "-fno-builtin",
            *(f"-D{item}" for item in defines), "-c", str(source), "-o", str(object_path),
        ],
        "codegen": codegen,
        "defines": defines,
        "preprocessed": str(preprocessed_path),
        "preprocessed_sha256": digest(preprocessed_path),
        "dependencies": {str(path): digest(path) for path in dependencies},
        "dependency_audit_command": [*base, "-M", str(source)],
        "preprocessor_command": [*base, "-E", "-P", str(source)],
        **extra,
    }


def record_compile(product: Path, work: Path) -> None:
    manifest = product_manifest(product)
    work = evidence_work(work)
    (work / "dependencies").mkdir(exist_ok=True)
    (work / "preprocessed").mkdir(exist_ok=True)
    contract = compiler_contract(product)
    libraries = []
    for name, tag, _, _ in DSO_TOPOLOGY:
        libraries.append(unit_record(
            contract, product, work, name, LIBRARY, work / "objects" / f"libfork-{name}.o",
            "-fPIC", [f"FORK_LIBRARY_TAG={tag}"], "--dynamic-shared-object", {"tag": tag},
        ))
    consumers = [
        unit_record(
            contract, product, work, role, CONSUMER, work / "objects" / f"{role}.o",
            "-fPIE", list(defines), "--dynamic-pie", {},
        )
        for role, _, defines in CONSUMER_ROLES
    ]
    if len({item["preprocessed_sha256"] for item in libraries}) != len(libraries):
        fail("library tag preprocessing identities collapsed")
    if len({item["preprocessed_sha256"] for item in consumers}) != len(consumers):
        fail("consumer preprocessor identities collapsed")
    record = {
        "schema": COMPILE_SCHEMA,
        "driver_sha256": digest(product / "bin/crabc-cc-dynamic"),
        "driver": artifact_identity(product / "bin/crabc-cc-dynamic", "installed dynamic driver"),
        "compiler_helper": artifact_identity(contract["helper"], "dynamic compiler helper"),
        "selected_compiler": artifact_identity(selected_compiler(contract), "selected dynamic compiler"),
        "manifest_sha256": digest(manifest),
        "libraries": libraries,
        "consumers": consumers,
    }
    path = work / "compile.json"
    if path.exists() or path.is_symlink():
        fail("compile record already exists")
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def expected_base(product: Path, output: Path, mode: str, object_path: Path, dsos: list[Path], linker: str) -> tuple[list[Path], list[str]]:
    library = product / "usr/lib"
    runtime = [library / "crti.o", library / "libc.so", library / "crtn.o"]
    command = [linker]
    if mode == "shared":
        command.append("-shared")
    elif mode == "pie":
        command.append("-pie")
    elif mode != "exec":
        fail("unsupported receipt mode")
    command += ["--hash-style=sysv", "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
                "--no-undefined", "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib"]
    if mode != "shared":
        entry = library / ("Scrt1.o" if mode == "pie" else "crt1.o")
        runtime += [entry, library / "crabc-dynamic-attach.o"]
        command += ["--dynamic-linker", INTERPRETER, str(entry), str(library / "crabc-dynamic-attach.o")]
    else:
        command += ["-soname", output.name]
    command += [str(library / "crti.o"), str(object_path), *(str(path) for path in dsos),
                str(library / "libc.so"), str(library / "libcrabc-builtins.a"), str(library / "crtn.o"),
                "-o", str(output)]
    inputs = [*runtime, object_path, *dsos, library / "libcrabc-builtins.a"]
    return inputs, command


def readelf(path: Path, option: str) -> str:
    completed = subprocess.run(["readelf", option, str(path)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if completed.returncode:
        fail(f"readelf {option} failed for {path}: {completed.stderr.strip()}")
    return completed.stdout


def receipt_record(path: Path) -> dict[str, Any]:
    record = json_object(path, "dynamic link receipt")
    expected = {
        "schema", "format", "mode", "binding", "runtime_imports", "application_runpath", "output_path",
        "output_sha256", "manifest_sha256", "application_dsos", "owned_runtime_inputs", "input_receipts",
        "resolved_linker", "link_command", "link_trace", "campaign_complete",
    }
    return require_keys(record, expected, "dynamic link receipt")


def audit_receipt(product: Path, manifest: Path, output: Path, object_path: Path, mode: str,
                  dsos: list[Path], expected_needed: tuple[str, ...]) -> None:
    output = physical(output, "linked output")
    object_path = physical(object_path, "linked workload object")
    record = receipt_record(Path(str(output) + ".crabc-link.json"))
    if (record.get("schema"), record.get("format"), record.get("mode")) != (1, PRODUCT_FORMAT, mode):
        fail("dynamic producer receipt mode differs from the requested link")
    if mode == "shared" and record.get("mode") != "shared":
        fail("dynamic producer receipt shared mode drifted")
    if record.get("binding") != "now" or record.get("runtime_imports") != []:
        fail("dynamic producer receipt import contract drifted")
    if record.get("application_runpath") != "/usr/lib" or record.get("campaign_complete") is not False:
        fail("dynamic producer receipt search or campaign state drifted")
    if record.get("output_path") != str(output):
        fail("dynamic producer receipt output path drifted")
    require_hash(record.get("output_sha256"), digest(output), "dynamic producer output")
    require_hash(record.get("manifest_sha256"), digest(manifest), "dynamic producer manifest")
    expected_dsos = {path.name: digest(path) for path in dsos}
    if record.get("application_dsos") != expected_dsos:
        fail("dynamic producer receipt application_dsos drifted")
    linker_record = require_keys(record.get("resolved_linker"), {"path", "sha256"}, "resolved linker")
    linker_path = physical(Path(str(linker_record["path"])), "resolved linker")
    if linker_path.name != "ld.lld" or not linker_path.stat().st_mode & 0o111:
        fail("dynamic producer receipt linker is not an executable ld.lld")
    require_hash(linker_record["sha256"], digest(linker_path), "dynamic producer linker")
    inputs, command = expected_base(product, output, mode, object_path, dsos, str(linker_path))
    library = product / "usr/lib"
    runtime = [library / "crti.o", library / "libc.so", library / "crtn.o"]
    if mode != "shared":
        runtime += [library / ("Scrt1.o" if mode == "pie" else "crt1.o"), library / "crabc-dynamic-attach.o"]
    expected_runtime = sorted(path.relative_to(product).as_posix() for path in [*runtime, library / "libcrabc-builtins.a"])
    if record.get("owned_runtime_inputs") != expected_runtime:
        fail("dynamic producer receipt runtime input roster drifted")
    received = record.get("input_receipts")
    if not isinstance(received, list) or len(received) != len(inputs):
        fail("dynamic producer receipt input roster drifted")
    for item, expected in zip(received, inputs):
        item = require_keys(item, {"path", "sha256"}, "dynamic producer input")
        if item["path"] != str(expected):
            fail("dynamic producer receipt input path drifted")
        require_hash(item["sha256"], digest(expected), "dynamic producer input")
    if record.get("link_command") != command:
        fail("dynamic producer receipt link command drifted")
    trace = record.get("link_trace")
    direct = {str(path) for path in inputs if path.name != "libcrabc-builtins.a"}
    archive = str(library / "libcrabc-builtins.a")
    if not isinstance(trace, list) or not all(isinstance(item, str) for item in trace):
        fail("dynamic producer receipt link_trace is invalid")
    seen: set[str] = set()
    for line in trace:
        if line in direct:
            seen.add(line)
        elif line == archive or (line.startswith(archive + "(") and line.endswith(")")):
            continue
        else:
            fail(f"dynamic producer receipt link_trace admits {line}")
    if seen != direct:
        fail("dynamic producer receipt link_trace omits an explicit input")
    header, programs, dynamic = readelf(output, "-hW"), readelf(output, "-lW"), readelf(output, "-dW")
    expected_type = "DYN" if mode in {"shared", "pie"} else "EXEC"
    if re.search(rf"^\s*Type:\s+{expected_type}(?:\s|\()", header, re.MULTILINE) is None:
        fail("linked output ELF type drifted")
    if re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", header, re.MULTILINE) is None:
        fail("linked output is not x86-64")
    if "TEXTREL" in dynamic or re.search(r"\(RPATH\)", dynamic):
        fail("linked output has forbidden text relocation or RPATH")
    runpaths = re.findall(r"\(RUNPATH\).*?\[([^\]]*)\]", dynamic)
    if runpaths != ["/usr/lib"]:
        fail("linked output RUNPATH drifted")
    needed = tuple(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic))
    if needed != expected_needed:
        fail(f"linked output DT_NEEDED topology drifted: {needed}")
    if mode == "shared":
        if re.search(r"^\s*INTERP\b", programs, re.MULTILINE):
            fail("shared DSO has PT_INTERP")
        sonames = re.findall(r"\(SONAME\).*?\[([^\]]+)\]", dynamic)
        if sonames != [output.name]:
            fail("shared DSO SONAME drifted")
    else:
        requested = re.findall(r"Requesting program interpreter:\s*([^\]\n]+)", programs)
        if requested != [INTERPRETER]:
            fail("dynamic consumer interpreter drifted")


def audit_compile(product: Path, work: Path, manifest: Path) -> None:
    record = json_object(work / "compile.json", "compile record")
    expected_keys = {
        "schema", "driver_sha256", "driver", "compiler_helper", "selected_compiler",
        "manifest_sha256", "libraries", "consumers",
    }
    require_keys(record, expected_keys, "compile record")
    if record.get("schema") != COMPILE_SCHEMA:
        fail("compile record schema drifted")
    driver = product / "bin/crabc-cc-dynamic"
    require_hash(record.get("driver_sha256"), digest(driver), "compile driver")
    require_identity(record["driver"], driver, "compile driver")
    contract = compiler_contract(product)
    require_identity(record["compiler_helper"], contract["helper"], "compile helper")
    compiler_path = selected_compiler(contract)
    require_identity(record["selected_compiler"], compiler_path, "selected compile compiler")
    require_hash(record.get("manifest_sha256"), digest(manifest), "compile manifest")
    libraries = record.get("libraries")
    consumers = record.get("consumers")
    if not isinstance(libraries, list) or len(libraries) != len(DSO_TOPOLOGY):
        fail("compile record library roster drifted")
    if not isinstance(consumers, list) or len(consumers) != len(CONSUMER_ROLES):
        fail("compile record consumer roster drifted")
    expected_units = [
        (name, LIBRARY, work / "objects" / f"libfork-{name}.o", "-fPIC", [f"FORK_LIBRARY_TAG={tag}"], "--dynamic-shared-object", tag)
        for name, tag, _, _ in DSO_TOPOLOGY
    ]
    expected_units += [
        (role, CONSUMER, work / "objects" / f"{role}.o", "-fPIE", list(defines), "--dynamic-pie", None)
        for role, _, defines in CONSUMER_ROLES
    ]
    headers = physical(product / "usr/include", "installed headers", directory=True)
    compiler = str(compiler_path)
    environment = contract["clean_environment"]()
    units = [*libraries, *consumers]
    preprocessed: set[str] = set()
    for unit, expected in zip(units, expected_units):
        identifier, source, object_path, codegen, defines, driver_mode, tag = expected
        keys = {
            "id", "source", "source_sha256", "object", "object_sha256", "driver_compile_command", "codegen", "defines",
            "preprocessed", "preprocessed_sha256", "dependencies", "dependency_audit_command", "preprocessor_command",
        } | ({"tag"} if tag is not None else set())
        unit = require_keys(unit, keys, "compile unit")
        if (unit["id"], unit["source"], unit["object"], unit["codegen"], unit["defines"]) != (
            identifier, str(source), str(object_path), codegen, defines
        ):
            fail("compile unit source/tag/object identity drifted")
        if tag is not None and unit["tag"] != tag:
            fail("compile unit source tag drifted")
        require_hash(unit["source_sha256"], digest(source), "compile source")
        require_hash(unit["object_sha256"], digest(object_path), "compile object")
        expected_driver_command = [
            str(driver), driver_mode, "-std=c11", "-fno-builtin", *(f"-D{item}" for item in defines),
            "-c", str(source), "-o", str(object_path),
        ]
        if unit["driver_compile_command"] != expected_driver_command:
            fail("installed driver compile command or prescribed flags drifted")
        # The exact installed-driver compiler contract and role flags are
        # recomputed here, rather than trusting the recorded command fields.
        expected_base = [compiler, "-nostdinc", "-isystem", str(headers), "-std=c11", "-ffreestanding",
                         "-fno-builtin", "-fstack-protector-strong", codegen,
                         *(f"-D{item}" for item in defines)]
        expected_dependency_command = [*expected_base, "-M", str(source)]
        expected_preprocessor_command = [*expected_base, "-E", "-P", str(source)]
        if unit["dependency_audit_command"] != expected_dependency_command:
            fail("compile dependency audit command drifted")
        if unit["preprocessor_command"] != expected_preprocessor_command:
            fail("compile preprocessor command drifted")
        expected_preprocessed_path = work / "preprocessed" / f"{identifier}.i"
        if unit["preprocessed"] != str(expected_preprocessed_path):
            fail("compile preprocessed path drifted")
        preprocessed_path = physical(expected_preprocessed_path, "preprocessed source")
        require_hash(unit["preprocessed_sha256"], digest(preprocessed_path), "preprocessor identity")
        current_preprocessed = capture(expected_preprocessor_command, environment=environment)
        current_preprocessed_sha256 = hashlib.sha256(current_preprocessed).hexdigest()
        require_hash(unit["preprocessed_sha256"], current_preprocessed_sha256,
                     "current preprocessor identity")
        preprocessed.add(unit["preprocessed_sha256"])
        dependencies = unit["dependencies"]
        if not isinstance(dependencies, dict):
            fail("compile dependency roster drifted")
        current_dependencies = dependency_names_text(
            capture(expected_dependency_command, environment=environment).decode(encoding="utf-8"),
            source, headers,
        )
        if len(current_dependencies) < 2:
            fail("compile dependency closure omits installed headers")
        expected_dependencies = {str(path): digest(path) for path in current_dependencies}
        if dependencies != expected_dependencies:
            fail("compile dependency roster or installed-header hashes drifted")
    if len(preprocessed) != len(DSO_TOPOLOGY) + len(CONSUMER_ROLES):
        fail("compile preprocessor identities collapsed")


def oracle_library_spec(work: Path, name: str, filename: str) -> tuple[str, Path, list[str], Path, list[str]]:
    object_path = work / "objects" / f"libfork-{name}.o"
    binary = work / "oracle" / filename
    flags = ["-shared"]
    command = [str(ORACLE_COMPILER), "-shared", str(object_path)]
    if name != "initial":
        flags += [f"-L{work / 'oracle'}", "-l:libfork-initial.so"]
        command += [f"-L{work / 'oracle'}", "-l:libfork-initial.so"]
    soname = f"-Wl,-z,now,-soname,{filename}"
    flags.append(soname)
    command += [soname, "-o", str(binary)]
    return name, object_path, flags, binary, command


def oracle_consumer_spec(work: Path, mode: str) -> tuple[str, Path, list[str], Path, list[str]]:
    object_path = work / "objects" / "semantic-consumer.o"
    binary = work / "oracle" / f"consumer-{mode}"
    entry = ["-fPIE", "-pie"] if mode == "pie" else ["-fno-pie", "-no-pie"]
    flags = ["-std=c11", *entry, f"-L{work / 'oracle'}", f"-Wl,-rpath,{work / 'oracle'}", "-l:libfork-initial.so"]
    command = [
        str(ORACLE_COMPILER), "-std=c11", *entry, str(object_path), f"-L{work / 'oracle'}",
        f"-Wl,-rpath,{work / 'oracle'}", "-l:libfork-initial.so", "-o", str(binary),
    ]
    return f"semantic-consumer-{mode}", object_path, flags, binary, command


def oracle_product_record(
    role: str, object_path: Path, flags: list[str], binary: Path, command: list[str],
) -> dict[str, Any]:
    return {
        "role": role,
        "object": str(object_path),
        "object_sha256": digest(object_path),
        "flags": flags,
        "binary": str(binary),
        "binary_sha256": digest(binary),
        "link_command": command,
    }


def record_oracle(work: Path) -> None:
    """Record the pinned-musl products before they are allowed to execute."""

    work = evidence_work(work)
    compiler = physical(ORACLE_COMPILER, "pinned musl compiler")
    libraries = [
        oracle_product_record(*oracle_library_spec(work, name, filename))
        for name, _, filename, _ in DSO_TOPOLOGY
    ]
    consumers = [
        oracle_product_record(*oracle_consumer_spec(work, mode))
        for mode in ("pie", "non-pie")
    ]
    record = {
        "schema": ORACLE_PRODUCTS_SCHEMA,
        "compiler": artifact_identity(compiler, "pinned musl compiler"),
        "libraries": libraries,
        "consumers": consumers,
    }
    path = work / "oracle-products.json"
    if path.exists() or path.is_symlink():
        fail("oracle product record already exists")
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def audit_oracle_record(
    value: object, role: str, object_path: Path, flags: list[str], binary: Path, command: list[str],
) -> None:
    record = require_keys(
        value,
        {"role", "object", "object_sha256", "flags", "binary", "binary_sha256", "link_command"},
        "oracle product",
    )
    if (record["role"], record["object"], record["flags"], record["binary"], record["link_command"]) != (
        role, str(object_path), flags, str(binary), command,
    ):
        fail("oracle product role/object/flags command drifted")
    require_hash(record["object_sha256"], digest(object_path), "oracle product object")
    require_hash(record["binary_sha256"], digest(binary), "oracle product binary")


def audit_oracle(work: Path) -> str:
    """Recheck the pre-run pinned-musl DSO and consumer products."""

    work = evidence_work(work)
    record = json_object(work / "oracle-products.json", "oracle product record")
    require_keys(record, {"schema", "compiler", "libraries", "consumers"}, "oracle product record")
    if record["schema"] != ORACLE_PRODUCTS_SCHEMA:
        fail("oracle product record schema drifted")
    require_identity(record["compiler"], ORACLE_COMPILER, "pinned musl compiler")
    libraries = record["libraries"]
    consumers = record["consumers"]
    if not isinstance(libraries, list) or len(libraries) != len(DSO_TOPOLOGY):
        fail("oracle product library roster drifted")
    if not isinstance(consumers, list) or len(consumers) != 2:
        fail("oracle product consumer roster drifted")
    for item, (name, _, filename, _) in zip(libraries, DSO_TOPOLOGY):
        audit_oracle_record(item, *oracle_library_spec(work, name, filename))
    for item, mode in zip(consumers, ("pie", "non-pie")):
        audit_oracle_record(item, *oracle_consumer_spec(work, mode))
    return digest(work / "oracle-products.json")


APPLICATION_COPY_ROSTER = (
    ("initial-dso-workload", "libfork-initial.so", "libfork-initial.so"),
    ("one-dso-workload", "libfork-one.so", "libfork-one.so"),
    ("two-dso-workload", "libfork-two.so", "libfork-two.so"),
    ("initial-dso-runtime", "libfork-initial.so", "usr/lib/libfork-initial.so"),
    ("semantic-consumer-pie", "consumer-pie", "consumer-pie"),
    ("owned-layout-consumer-pie", "consumer-owned-layout-pie", "consumer-owned-layout-pie"),
    ("semantic-consumer-non-pie", "consumer-non-pie", "consumer-non-pie"),
    ("owned-layout-consumer-non-pie", "consumer-owned-layout-non-pie", "consumer-owned-layout-non-pie"),
)


def copied_payload_record(source: Path, execution: Path, description: str) -> dict[str, str]:
    source = physical(source, f"{description} source")
    execution = physical(execution, f"{description} execution copy")
    source_hash = digest(source)
    execution_hash = digest(execution)
    if source_hash != execution_hash:
        fail(f"{description} execution copy differs from its source")
    return {
        "source": str(source),
        "source_sha256": source_hash,
        "execution": str(execution),
        "execution_sha256": execution_hash,
    }


def product_payload_paths(product: Path, manifest: Path) -> dict[str, Path]:
    record = json_object(manifest, "dynamic product manifest")
    files = record["files"]
    if not isinstance(files, dict):
        fail("dynamic product manifest has no file roster")
    return {
        "share/crabc/manifest.json": manifest,
        **{relative: product / relative for relative in sorted(files)},
    }


def record_execution(product: Path, work: Path) -> None:
    """Record every physical file copied into the private execution root."""

    product = physical(product, "dynamic product", directory=True)
    work = evidence_work(work)
    manifest = product_manifest(product)
    execution_root = physical(work / "execution-root", "execution root", directory=True)
    payload = {
        relative: copied_payload_record(source, execution_root / relative, f"installed payload {relative}")
        for relative, source in product_payload_paths(product, manifest).items()
    }
    applications = []
    for role, source_relative, execution_relative in APPLICATION_COPY_ROSTER:
        applications.append({
            "role": role,
            **copied_payload_record(
                work / source_relative, execution_root / execution_relative, f"application payload {role}",
            ),
        })
    record = {
        "schema": EXECUTION_PAYLOAD_SCHEMA,
        "product": {
            "path": str(product),
            "manifest": str(manifest),
            "manifest_sha256": digest(manifest),
        },
        "execution_root": str(execution_root),
        "product_payload": payload,
        "application_payload": applications,
    }
    path = work / "execution-payload.json"
    if path.exists() or path.is_symlink():
        fail("execution payload record already exists")
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def audit_copied_payload(value: object, source: Path, execution: Path, description: str) -> None:
    record = require_keys(value, {"source", "source_sha256", "execution", "execution_sha256"}, description)
    if (record["source"], record["execution"]) != (str(source), str(execution)):
        fail(f"{description} paths drifted")
    source_hash = digest(source)
    execution_hash = digest(execution)
    require_hash(record["source_sha256"], source_hash, f"{description} source")
    require_hash(record["execution_sha256"], execution_hash, f"{description} execution copy")
    if source_hash != execution_hash:
        fail(f"{description} execution copy differs from its source")


def audit_execution(product: Path, work: Path) -> str:
    """Recheck the copied runtime and workload files that candidate runs use."""

    product = physical(product, "dynamic product", directory=True)
    work = evidence_work(work)
    manifest = product_manifest(product)
    execution_root = physical(work / "execution-root", "execution root", directory=True)
    record = json_object(work / "execution-payload.json", "execution payload record")
    require_keys(
        record,
        {"schema", "product", "execution_root", "product_payload", "application_payload"},
        "execution payload record",
    )
    if record["schema"] != EXECUTION_PAYLOAD_SCHEMA:
        fail("execution payload record schema drifted")
    product_record = require_keys(record["product"], {"path", "manifest", "manifest_sha256"}, "execution product")
    if (product_record["path"], product_record["manifest"]) != (str(product), str(manifest)):
        fail("execution product paths drifted")
    require_hash(product_record["manifest_sha256"], digest(manifest), "execution product manifest")
    if record["execution_root"] != str(execution_root):
        fail("execution root path drifted")
    expected_product_payload = product_payload_paths(product, manifest)
    payload = record["product_payload"]
    if not isinstance(payload, dict) or set(payload) != set(expected_product_payload):
        fail("execution product payload roster drifted")
    for relative, source in expected_product_payload.items():
        audit_copied_payload(payload[relative], source, execution_root / relative, f"installed payload {relative}")
    applications = record["application_payload"]
    if not isinstance(applications, list) or len(applications) != len(APPLICATION_COPY_ROSTER):
        fail("execution application payload roster drifted")
    for item, (role, source_relative, execution_relative) in zip(applications, APPLICATION_COPY_ROSTER):
        item = require_keys(
            item, {"role", "source", "source_sha256", "execution", "execution_sha256"},
            "execution application payload",
        )
        if item["role"] != role:
            fail("execution application payload role drifted")
        audit_copied_payload(
            {key: item[key] for key in ("source", "source_sha256", "execution", "execution_sha256")},
            work / source_relative, execution_root / execution_relative, f"application payload {role}",
        )
    return digest(work / "execution-payload.json")


def validate_consumed(product: Path, work: Path) -> dict[str, Any]:
    """Audit source products and the exact files that were actually executed."""

    validation = validate(product, work)
    return {
        **validation,
        "oracle_products_sha256": audit_oracle(work),
        "execution_payload_sha256": audit_execution(product, work),
    }


def validate(product: Path, work: Path) -> dict[str, Any]:
    product = physical(product, "dynamic product", directory=True)
    work = physical(work, "evidence work directory", directory=True)
    manifest = product_manifest(product)
    audit_compile(product, work, manifest)
    link_receipts: dict[str, str] = {}
    for name, _, filename, dependencies in DSO_TOPOLOGY:
        dsos = [work / dependency for dependency in dependencies]
        expected_needed = (*dependencies, "libc.so")
        audit_receipt(product, manifest, work / filename, work / "objects" / f"libfork-{name}.o",
                      "shared", dsos, expected_needed)
        link_receipts[filename] = digest(Path(str(work / filename) + ".crabc-link.json"))
    for role, consumer_name, _ in CONSUMER_ROLES:
        for mode in ("pie", "non-pie"):
            audit_receipt(product, manifest, work / f"{consumer_name}-{mode}",
                          work / "objects" / f"{role}.o", "pie" if mode == "pie" else "exec",
                          [work / "libfork-initial.so"], ("libfork-initial.so", "libc.so"))
            link_receipts[f"{consumer_name}-{mode}"] = digest(
                Path(str(work / f"{consumer_name}-{mode}") + ".crabc-link.json")
            )
    return {
        "product_manifest_sha256": digest(manifest),
        "compile_sha256": digest(work / "compile.json"),
        "link_receipts": link_receipts,
    }


def observation(path: Path) -> dict[str, Any]:
    stdout = physical(Path(str(path) + ".stdout"), "raw observation stdout")
    stderr = physical(Path(str(path) + ".stderr"), "raw observation stderr")
    status_path = physical(Path(str(path) + ".status"), "raw observation status")
    status = status_path.read_text(encoding="utf-8")
    if status != "0\n":
        fail(f"raw observation failed or timed out: {path.name} ({status.strip()})")
    return {"stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
            "status_sha256": digest(status_path), "status": 0}


def worker_survivor_observation(path: Path) -> dict[str, Any]:
    """Bind the live-PID protocol to its stable differential projection.

    The parent must see the PID before it can establish that the adopted main
    thread has become a zombie.  That PID is necessarily distinct across musl
    and every candidate process, so `.raw.stdout` is parsed and sealed but is
    deliberately not byte-compared.  `.stdout` is the fixed tail that remains
    in the semantic musl differential.
    """
    stdout = physical(Path(str(path) + ".stdout"), "worker-survivor semantic stdout")
    raw_stdout = physical(Path(str(path) + ".raw.stdout"), "worker-survivor raw stdout")
    stderr = physical(Path(str(path) + ".stderr"), "raw observation stderr")
    status_path = physical(Path(str(path) + ".status"), "raw observation status")
    status = status_path.read_text(encoding="utf-8")
    if status != "0\n":
        fail(f"raw observation failed or timed out: {path.name} ({status.strip()})")
    semantic = stdout.read_bytes()
    raw = raw_stdout.read_bytes()
    match = WORKER_SURVIVOR_PROTOCOL.fullmatch(raw)
    if match is None:
        fail(f"worker-survivor raw protocol differs: {path.name}")
    if semantic != WORKER_SURVIVOR_BODY:
        fail(f"worker-survivor semantic projection differs: {path.name}")
    return {
        "raw_stdout_sha256": digest(raw_stdout),
        "semantic_stdout_sha256": digest(stdout),
        "stderr_sha256": digest(stderr),
        "status_sha256": digest(status_path),
        "status": 0,
        "survivor_pid": int(match.group("pid")),
    }


def seal_observations(work: Path, product: Path) -> None:
    work = physical(work, "evidence work directory", directory=True)
    # This is the final seal after execution, rather than a mere list of raw
    # files. Recheck the source product, compile/header/object identities,
    # link receipts, ELF topology, pinned-musl products, and execution-root
    # copies so no completed observation can outlive what it claims to run.
    validation = validate_consumed(product, work)
    scenarios = ("main", "worker", "kernel-main", "kernel-worker", "recursive", "abandoned", "failure", "finalizer-single")
    special = ("finalizer-held", "worker-survivor")
    semantic_oracle: dict[str, dict[str, Any]] = {}
    semantic_candidate: dict[str, dict[str, Any]] = {}
    owned_layout: dict[str, dict[str, Any]] = {}
    for mode in ("pie", "non-pie"):
        for scenario in scenarios:
            oracle_label = f"oracle-{mode}-{scenario}"
            semantic_oracle[oracle_label] = observation(work / oracle_label)
            for entry in ("kernel", "direct"):
                semantic_label = f"semantic-{mode}-{entry}-{scenario}"
                layout_label = f"owned-layout-{mode}-{entry}-{scenario}"
                semantic_candidate[semantic_label] = observation(work / semantic_label)
                owned_layout[layout_label] = observation(work / layout_label)
                for suffix in ("stdout", "stderr", "status"):
                    if (work / f"{oracle_label}.{suffix}").read_bytes() != (work / f"{semantic_label}.{suffix}").read_bytes():
                        fail(f"semantic same-object differential differs: {semantic_label}")
        for scenario in special:
            oracle_label = f"oracle-{mode}-{scenario}"
            observe = worker_survivor_observation if scenario == "worker-survivor" else observation
            semantic_oracle[oracle_label] = observe(work / oracle_label)
            for entry in ("kernel", "direct"):
                semantic_label = f"semantic-{mode}-{entry}-{scenario}"
                layout_label = f"owned-layout-{mode}-{entry}-{scenario}"
                semantic_candidate[semantic_label] = observe(work / semantic_label)
                owned_layout[layout_label] = observe(work / layout_label)
                for suffix in ("stdout", "stderr", "status"):
                    if (work / f"{oracle_label}.{suffix}").read_bytes() != (work / f"{semantic_label}.{suffix}").read_bytes():
                        fail(f"semantic same-object differential differs: {semantic_label}")
    record = {
        "schema": OBSERVATION_SCHEMA,
        "validation": validation,
        "semantic_consumer": {"role": "semantic-consumer", "oracle": semantic_oracle,
                              "candidate": semantic_candidate},
        "owned_layout_consumer": {"role": "owned-layout-consumer", "candidate": owned_layout},
    }
    path = work / "observations.json"
    if path.exists() or path.is_symlink():
        fail("observation receipt already exists")
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("record-compile", "validate", "record-execution"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--product", type=Path, required=True)
        subparser.add_argument("--work", type=Path, required=True)
    oracle = commands.add_parser("record-oracle")
    oracle.add_argument("--work", type=Path, required=True)
    observations = commands.add_parser("seal-observations")
    observations.add_argument("--product", type=Path, required=True)
    observations.add_argument("--work", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "record-compile":
            record_compile(args.product, args.work)
        elif args.command == "validate":
            validate(args.product, args.work)
        elif args.command == "record-oracle":
            record_oracle(args.work)
        elif args.command == "record-execution":
            record_execution(args.product, args.work)
        else:
            seal_observations(args.work, args.product)
    except (EvidenceError, OSError, KeyError, TypeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
