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
OBSERVATION_SCHEMA = "crabc.dynamic-fork-observations/v1"


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
    return {"compiler": module.compiler, "clean_environment": module.clean_environment}


def run(command: list[str], *, output: Path, environment: dict[str, str]) -> None:
    with output.open("wb") as stream:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.PIPE, env=environment, check=False)
    if completed.returncode:
        raise EvidenceError(
            f"compiler preprocessing failed ({completed.returncode}): {completed.stderr.decode(errors='replace')}"
        )


def dependency_names(path: Path, source: Path, headers: Path) -> list[Path]:
    try:
        record = path.read_text(encoding="utf-8").replace("\\\n", " ")
        _, words = record.split(":", 1)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise EvidenceError(f"dependency record is invalid: {path}") from error
    result: list[Path] = []
    for word in words.split():
        candidate = physical(Path(word), "dependency input")
        if candidate != source and not candidate.is_relative_to(headers):
            fail(f"dependency escapes installed headers: {candidate}")
        result.append(candidate)
    if source not in result:
        fail("dependency roster omits its source")
    return result


def unit_record(
    contract: dict[str, Any], product: Path, work: Path, identifier: str, source: Path,
    object_path: Path, codegen: str, defines: list[str], extra: dict[str, Any],
) -> dict[str, Any]:
    source = physical(source, f"{identifier} source")
    object_path = physical(object_path, f"{identifier} object")
    headers = physical(product / "usr/include", "installed headers", directory=True)
    compiler = contract["compiler"]()
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
    work = physical(work, "evidence work directory", directory=True)
    if not work.is_relative_to(ROOT / ".work"):
        fail("evidence work directory escapes checkout .work")
    (work / "dependencies").mkdir(exist_ok=True)
    (work / "preprocessed").mkdir(exist_ok=True)
    contract = compiler_contract(product)
    libraries = []
    for name, tag, _, _ in DSO_TOPOLOGY:
        libraries.append(unit_record(
            contract, product, work, name, LIBRARY, work / "objects" / f"libfork-{name}.o",
            "-fPIC", [f"FORK_LIBRARY_TAG={tag}"], {"tag": tag},
        ))
    consumers = [
        unit_record(
            contract, product, work, role, CONSUMER, work / "objects" / f"{role}.o",
            "-fPIE", list(defines), {},
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
    expected_keys = {"schema", "driver_sha256", "manifest_sha256", "libraries", "consumers"}
    require_keys(record, expected_keys, "compile record")
    if record.get("schema") != COMPILE_SCHEMA:
        fail("compile record schema drifted")
    require_hash(record.get("driver_sha256"), digest(product / "bin/crabc-cc-dynamic"), "compile driver")
    require_hash(record.get("manifest_sha256"), digest(manifest), "compile manifest")
    libraries = record.get("libraries")
    consumers = record.get("consumers")
    if not isinstance(libraries, list) or len(libraries) != len(DSO_TOPOLOGY):
        fail("compile record library roster drifted")
    if not isinstance(consumers, list) or len(consumers) != len(CONSUMER_ROLES):
        fail("compile record consumer roster drifted")
    expected_units = [
        (name, LIBRARY, work / "objects" / f"libfork-{name}.o", "-fPIC", [f"FORK_LIBRARY_TAG={tag}"], tag)
        for name, tag, _, _ in DSO_TOPOLOGY
    ]
    expected_units += [
        (role, CONSUMER, work / "objects" / f"{role}.o", "-fPIE", list(defines), None)
        for role, _, defines in CONSUMER_ROLES
    ]
    units = [*libraries, *consumers]
    preprocessed: set[str] = set()
    for unit, expected in zip(units, expected_units):
        identifier, source, object_path, codegen, defines, tag = expected
        keys = {
            "id", "source", "source_sha256", "object", "object_sha256", "codegen", "defines",
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
        preprocessed_path = physical(Path(unit["preprocessed"]), "preprocessed source")
        require_hash(unit["preprocessed_sha256"], digest(preprocessed_path), "preprocessor identity")
        preprocessed.add(unit["preprocessed_sha256"])
        dependencies = unit["dependencies"]
        if not isinstance(dependencies, dict) or str(source) not in dependencies:
            fail("compile dependency roster drifted")
        for name, expected_hash in dependencies.items():
            dependency = physical(Path(name), "compile dependency")
            if dependency != source and not dependency.is_relative_to(product / "usr/include"):
                fail("compile dependency escapes installed headers")
            require_hash(expected_hash, digest(dependency), "compile dependency")
    if len(preprocessed) != len(DSO_TOPOLOGY) + len(CONSUMER_ROLES):
        fail("compile preprocessor identities collapsed")

def validate(product: Path, work: Path) -> None:
    product = physical(product, "dynamic product", directory=True)
    work = physical(work, "evidence work directory", directory=True)
    manifest = product_manifest(product)
    audit_compile(product, work, manifest)
    for name, _, filename, dependencies in DSO_TOPOLOGY:
        dsos = [work / dependency for dependency in dependencies]
        expected_needed = (*dependencies, "libc.so")
        audit_receipt(product, manifest, work / filename, work / "objects" / f"libfork-{name}.o",
                      "shared", dsos, expected_needed)
    for role, consumer_name, _ in CONSUMER_ROLES:
        for mode in ("pie", "non-pie"):
            audit_receipt(product, manifest, work / f"{consumer_name}-{mode}",
                          work / "objects" / f"{role}.o", "pie" if mode == "pie" else "exec",
                          [work / "libfork-initial.so"], ("libfork-initial.so", "libc.so"))


def observation(path: Path) -> dict[str, Any]:
    stdout = physical(Path(str(path) + ".stdout"), "raw observation stdout")
    stderr = physical(Path(str(path) + ".stderr"), "raw observation stderr")
    status_path = physical(Path(str(path) + ".status"), "raw observation status")
    status = status_path.read_text(encoding="utf-8")
    if status != "0\n":
        fail(f"raw observation failed or timed out: {path.name} ({status.strip()})")
    return {"stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
            "status_sha256": digest(status_path), "status": 0}


def seal_observations(work: Path) -> None:
    work = physical(work, "evidence work directory", directory=True)
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
            semantic_oracle[oracle_label] = observation(work / oracle_label)
            for entry in ("kernel", "direct"):
                semantic_label = f"semantic-{mode}-{entry}-{scenario}"
                layout_label = f"owned-layout-{mode}-{entry}-{scenario}"
                semantic_candidate[semantic_label] = observation(work / semantic_label)
                owned_layout[layout_label] = observation(work / layout_label)
                for suffix in ("stdout", "stderr", "status"):
                    if (work / f"{oracle_label}.{suffix}").read_bytes() != (work / f"{semantic_label}.{suffix}").read_bytes():
                        fail(f"semantic same-object differential differs: {semantic_label}")
    record = {
        "schema": OBSERVATION_SCHEMA,
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
    for command in ("record-compile", "validate"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--product", type=Path, required=True)
        subparser.add_argument("--work", type=Path, required=True)
    observations = commands.add_parser("seal-observations")
    observations.add_argument("--work", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "record-compile":
            record_compile(args.product, args.work)
        elif args.command == "validate":
            validate(args.product, args.work)
        else:
            seal_observations(args.work)
    except (EvidenceError, OSError, KeyError, TypeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
