#!/usr/bin/env python3
"""Qualify Lua's pinned dynamic source graph through an owned x86 sysroot.

This is intentionally a native companion to, rather than a generalization of,
the established AArch64 runner.  It keeps the installed dynamic driver's
closed application-input boundary intact and uses the frozen Lua 5.4.8 graph:
versioned liblua, lua, upstream-private-unit luac, and two loadable modules.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import json
import math
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

import run as LUA


ROOT = LUA.ROOT
FIXTURES = LUA.FIXTURES
MANIFEST = LUA.MANIFEST
CACHE = LUA.CACHE
MUSL_ROOT = LUA.MUSL_ROOT
X86_MUSL_COMPILER = LUA.X86_MUSL_COMPILER
DEFAULT_WORK_ROOT = ROOT / ".work/x86_64/lua-dynamic-source-build"
DEFAULT_REPORT = ROOT / "compat/reports/lua/x86_64-dynamic-latest.json"
DYNAMIC_SYSROOT_BUILDER = ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"
DYNAMIC_PACKAGE_TOOL = ROOT / "compat/x86_64/owned_dynamic_package.py"
CANONICAL_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"


def require_native_x86_64() -> None:
    """Refuse a result produced through an emulation path."""

    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise LUA.RunnerError("native Lua dynamic source-build gate requires native Linux/x86-64")


def dynamic_environment(state: Path) -> dict[str, str]:
    """Give every build and execution child checkout-local mutable state."""

    return LUA.static_environment(state)


def require_regular(path: Path, description: str) -> Path:
    return LUA.require_physical_regular_file(path, description)


def owned_dynamic_sysroot(path: Path) -> tuple[Path, Path, dict[str, Path], dict[str, object]]:
    """Validate a complete installed dynamic tree before it compiles Lua."""

    root = LUA.require_physical_directory(
        Path(os.path.abspath(path)), "owned x86 dynamic sysroot"
    )
    manifest_path = require_regular(root / "share/crabc/manifest.json", "dynamic sysroot manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LUA.RunnerError(f"invalid owned x86 dynamic sysroot manifest: {manifest_path}") from error
    aliases = {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}
    if not isinstance(manifest, dict) or (
        manifest.get("schema"),
        manifest.get("format"),
        manifest.get("target"),
        manifest.get("symlinks"),
    ) != (1, FORMAT, "x86_64-unknown-linux-musl", aliases):
        raise LUA.RunnerError("manifest does not identify the owned x86 dynamic sysroot")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise LUA.RunnerError("owned x86 dynamic sysroot manifest lacks payload hashes")
    expected: dict[str, str] = {}
    for relative, digest in files.items():
        candidate = Path(relative) if isinstance(relative, str) else Path()
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise LUA.RunnerError("owned x86 dynamic sysroot manifest has an invalid payload hash")
        expected[relative] = digest
    observed_files: set[str] = set()
    observed_aliases: dict[str, str] = {}
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            observed_aliases[relative] = os.readlink(entry)
        elif entry.is_dir():
            continue
        elif entry.is_file():
            if relative != "share/crabc/manifest.json":
                observed_files.add(relative)
        else:
            raise LUA.RunnerError(f"owned x86 dynamic sysroot contains a non-regular entry: {relative}")
    if observed_files != set(expected) or observed_aliases != aliases:
        raise LUA.RunnerError("owned x86 dynamic sysroot payload roster drifted")
    for relative, digest in expected.items():
        artifact = require_regular(root / relative, f"dynamic sysroot payload {relative}")
        if LUA.sha256_file(artifact) != digest:
            raise LUA.RunnerError(f"owned x86 dynamic sysroot payload hash drifted: {relative}")
    wrapper = require_regular(root / "bin/crabc-cc-dynamic", "owned x86 dynamic compiler wrapper")
    if not os.access(wrapper, os.X_OK):
        raise LUA.RunnerError("owned x86 dynamic compiler wrapper is not executable")
    runtime = {
        "headers": root / "usr/include",
        "loader": root / "lib/ld-crabc-x86_64.so.1",
        "crt1.o": root / "usr/lib/crt1.o",
        "Scrt1.o": root / "usr/lib/Scrt1.o",
        "crti.o": root / "usr/lib/crti.o",
        "crtn.o": root / "usr/lib/crtn.o",
        "attach": root / "usr/lib/crabc-dynamic-attach.o",
        "libc.so": root / "usr/lib/libc.so",
        "builtins": root / "usr/lib/libcrabc-builtins.a",
    }
    LUA.require_physical_directory(runtime["headers"], "owned x86 dynamic headers")
    for name, artifact in runtime.items():
        if name != "headers":
            require_regular(artifact, f"owned x86 dynamic runtime {name}")
    return root, wrapper, runtime, manifest


def dynamic_flags() -> list[str]:
    """Select Lua's Linux module path while leaving target policy to the driver."""

    return [
        "-std=gnu99",
        "-O2",
        "-fno-builtin",
        "-fno-stack-protector",
        "-DLUA_USE_LINUX",
        "-DLUA_COMPAT_5_3",
    ]


def command(
    arguments: Sequence[str], *, work: Path, state: Path, timeout: float
) -> dict[str, object]:
    return LUA.command_record(
        arguments, cwd=work, environment=dynamic_environment(state), timeout=timeout
    )


def require_success(record: Mapping[str, object], description: str) -> None:
    LUA.require_success(record, description)


def dynamic_driver_plan(
    wrapper: Path, sysroot: Path, runtime: Mapping[str, Path], work: Path, timeout: float
) -> dict[str, object]:
    """Bind the source build to the installed PIE driver before any translation."""

    record = command(
        [str(wrapper), "--dynamic-pie", "--print-link-plan"],
        work=work,
        state=work / "driver-plan",
        timeout=timeout,
    )
    require_success(record, "sealed dynamic driver plan")
    stdout = record["stdout"]
    assert isinstance(stdout, dict)
    try:
        plan = json.loads(str(stdout["text"]))
    except json.JSONDecodeError as error:
        raise LUA.RunnerError("sealed dynamic driver emitted invalid JSON") from error
    if not isinstance(plan, dict) or (
        plan.get("format"),
        plan.get("mode"),
        plan.get("binding"),
        plan.get("application_runpath"),
    ) != (FORMAT, "pie", "now", "/usr/lib"):
        raise LUA.RunnerError("sealed dynamic driver selected the wrong Lua PIE plan")
    linker = plan.get("linker")
    if not isinstance(linker, list):
        raise LUA.RunnerError("sealed dynamic driver plan lacks linker argv")
    required = (
        "--dynamic-linker",
        CANONICAL_INTERPRETER,
        str(runtime["Scrt1.o"]),
        str(runtime["crabc-dynamic-attach.o"]) if "crabc-dynamic-attach.o" in runtime else str(runtime["attach"]),
    )
    for item in required:
        if item not in linker:
            raise LUA.RunnerError(f"sealed dynamic driver plan omits owned input: {item}")
    record["plan_audit"] = {
        "status": "passed",
        "headers": str(sysroot / "usr/include"),
        "interpreter": CANONICAL_INTERPRETER,
        "runpath": "/usr/lib",
    }
    return record


def dynamic_compile(
    wrapper: Path,
    flags: Sequence[str],
    source: Path,
    output: Path,
    work: Path,
    state: Path,
    timeout: float,
) -> dict[str, object]:
    """Compile exactly one application source as PIC through the sealed driver."""

    if not source.is_file() or source.is_symlink():
        raise LUA.RunnerError(f"native Lua dynamic source is absent or unsafe: {source}")
    record = command(
        [
            str(wrapper),
            "--dynamic-shared-object",
            *flags,
            "-c",
            str(source),
            "-o",
            str(output),
        ],
        work=work,
        state=state,
        timeout=timeout,
    )
    require_success(record, f"sealed dynamic compile {source.name}")
    if not output.is_file() or output.is_symlink():
        raise LUA.RunnerError(f"sealed dynamic compile did not produce {output.name}")
    return record


def parallel_dynamic_compiles(
    wrapper: Path,
    flags: Sequence[str],
    sources: Sequence[tuple[str, Path]],
    object_directory: Path,
    work: Path,
    timeout: float,
    jobs: int,
) -> tuple[dict[str, object], dict[str, Path]]:
    """Compile the full Lua roster with bounded independent driver children."""

    if not sources or len({name for name, _ in sources}) != len(sources):
        raise LUA.RunnerError("native Lua dynamic compile source roster is empty or ambiguous")
    object_directory.mkdir(parents=True, exist_ok=False)
    state_root = work / "compile-state"
    state_root.mkdir(parents=True, exist_ok=False)
    prepared = [
        (
            name,
            source,
            object_directory / f"{index:02d}-{name.replace('/', '_').replace('.', '_')}.o",
            state_root / f"{index:02d}",
        )
        for index, (name, source) in enumerate(sources)
    ]

    def one(item: tuple[str, Path, Path, Path]) -> tuple[str, dict[str, object], Path]:
        name, source, output, state = item
        return name, dynamic_compile(wrapper, flags, source, output, work, state, timeout), output

    completed: dict[str, tuple[dict[str, object], Path]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(jobs, len(prepared))) as executor:
        futures = [executor.submit(one, item) for item in prepared]
        try:
            for future in futures:
                name, record, output = future.result()
                completed[name] = (record, output)
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    return (
        {name: completed[name][0] for name, _, _, _ in prepared},
        {name: completed[name][1] for name, _, _, _ in prepared},
    )


def audit_dynamic_receipt(
    *,
    sysroot: Path,
    runtime: Mapping[str, Path],
    mode: str,
    objects: Sequence[Path],
    application_dsos: Sequence[Path],
    output: Path,
) -> dict[str, object]:
    """Check the installed driver's immutable trace and sidecar binding."""

    receipt = Path(f"{output}.crabc-link.json")
    try:
        decoded = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LUA.RunnerError(f"sealed dynamic link receipt is unreadable: {receipt}") from error
    if not isinstance(decoded, dict) or (
        decoded.get("schema"),
        decoded.get("format"),
        decoded.get("mode"),
        decoded.get("output_path"),
        decoded.get("output_sha256"),
    ) != (1, FORMAT, mode, str(output.resolve()), LUA.sha256_file(output)):
        raise LUA.RunnerError(f"sealed dynamic {output.name} receipt drifted")
    if decoded.get("manifest_sha256") != LUA.sha256_file(sysroot / "share/crabc/manifest.json"):
        raise LUA.RunnerError("sealed dynamic receipt does not bind its installed sysroot")
    expected_dsos = {path.name: LUA.sha256_file(path) for path in application_dsos}
    if decoded.get("application_dsos") != expected_dsos:
        raise LUA.RunnerError(f"sealed dynamic {output.name} DSO receipt drifted")
    # The installed driver's sidecar lists its common C-runtime inputs before
    # the executable-only entry/attach pair. The actual linker trace retains
    # entry-first link order and is audited independently below.
    runtime_paths = (
        (runtime["crti.o"], runtime["libc.so"], runtime["crtn.o"])
        if mode == "shared"
        else (
            runtime["crti.o"],
            runtime["libc.so"],
            runtime["crtn.o"],
            runtime["Scrt1.o"] if mode == "pie" else runtime["crt1.o"],
            runtime["attach"],
        )
    )
    archive = runtime["builtins"]
    direct = [*runtime_paths, *(path.resolve(strict=True) for path in objects), *application_dsos]
    expected_inputs = [
        {"path": str(path), "sha256": LUA.sha256_file(path)} for path in [*direct, archive]
    ]
    if decoded.get("input_receipts") != expected_inputs:
        raise LUA.RunnerError(f"sealed dynamic {output.name} input receipt drifted")
    if decoded.get("owned_runtime_inputs") != sorted(
        path.relative_to(sysroot).as_posix() for path in [*runtime_paths, archive]
    ):
        raise LUA.RunnerError(f"sealed dynamic {output.name} runtime roster drifted")
    trace = decoded.get("link_trace")
    if not isinstance(trace, list) or any(not isinstance(line, str) for line in trace):
        raise LUA.RunnerError(f"sealed dynamic {output.name} trace is invalid")
    permitted = {str(path) for path in direct}
    seen: set[str] = set()
    for line in trace:
        if line in permitted:
            seen.add(line)
        elif line == str(archive) or (
            line.startswith(f"{archive}(") and line.endswith(")")
        ):
            seen.add(str(archive))
        else:
            raise LUA.RunnerError(f"sealed dynamic link consumed an unowned input: {line}")
    # The driver records the fixed helper archive even when this source graph
    # does not extract a member.  LLD therefore need not print the archive in
    # its trace; every direct input remains mandatory.
    if seen != permitted:
        raise LUA.RunnerError(f"sealed dynamic {output.name} trace omitted a closed input")
    text = "\n".join(trace)
    for marker in ("/opt/musl-", "/usr/lib/gcc", "compiler-rt", "libgcc", "ld-linux"):
        if marker in text:
            raise LUA.RunnerError(f"sealed dynamic receipt names a foreign runtime input: {marker}")
    return {
        "status": "passed",
        "receipt": LUA.artifact_record(receipt),
        "input_count": len(expected_inputs),
        "application_dsos": expected_dsos,
    }


def dynamic_link(
    *,
    wrapper: Path,
    sysroot: Path,
    runtime: Mapping[str, Path],
    mode: str,
    objects: Sequence[Path],
    output: Path,
    application_dsos: Sequence[Path],
    work: Path,
    timeout: float,
) -> dict[str, object]:
    """Link one DSO or PIE with no search-path or target-library hole."""

    flags = {
        "shared": ["--dynamic-shared-object"],
        "pie": ["--dynamic-pie"],
    }.get(mode)
    if flags is None:
        raise LUA.RunnerError(f"unsupported native Lua dynamic mode: {mode}")
    record = command(
        [
            str(wrapper),
            *flags,
            *(item for dso in application_dsos for item in ("--application-dso", str(dso))),
            *(str(path.resolve(strict=True)) for path in objects),
            "-o",
            str(output),
        ],
        work=work,
        state=work / f"link-{output.name}",
        timeout=timeout,
    )
    require_success(record, f"sealed dynamic link {output.name}")
    if not output.is_file() or output.is_symlink():
        raise LUA.RunnerError(f"sealed dynamic link did not produce {output.name}")
    record["receipt_audit"] = audit_dynamic_receipt(
        sysroot=sysroot,
        runtime=runtime,
        mode=mode,
        objects=objects,
        application_dsos=application_dsos,
        output=output,
    )
    return record


def dynamic_elf(path: Path, *, executable: bool, label: str) -> dict[str, object]:
    """Inspect the actual x86 dynamic boundary rather than trusting the receipt."""

    header = LUA.readelf(path, "-h")
    segments = LUA.readelf(path, "-lW")
    dynamic = LUA.readelf(path, "-dW")
    relocations = LUA.readelf(path, "-rW")
    if "Advanced Micro Devices X86-64" not in header or not re.search(r"Type:\s+DYN\b", header):
        raise LUA.RunnerError(f"{label} is not an x86-64 ET_DYN artifact")
    if executable:
        if CANONICAL_INTERPRETER not in segments:
            raise LUA.RunnerError(f"{label} does not name the canonical crabc loader")
    elif "INTERP" in segments:
        raise LUA.RunnerError(f"{label} DSO unexpectedly has an interpreter")
    text = "\n".join((header, segments, dynamic, relocations))
    for marker in ("ld-musl-", "libc.musl-", "/opt/musl-", "libc.so.6", "ld-linux"):
        if marker in text:
            raise LUA.RunnerError(f"{label} ELF leaks a foreign runtime marker: {marker}")
    return {
        "artifact": LUA.artifact_record(path),
        "header": header,
        "program_headers": segments,
        "dynamic": dynamic,
        "relocations": relocations,
    }


def prepare_dynamic_modules(source: Path) -> tuple[Path, dict[str, object]]:
    """Stage only fixture source beside the immutable Lua local headers."""

    support = source / "src"
    if not support.is_dir() or support.is_symlink():
        raise LUA.RunnerError("pinned Lua source directory is absent or unsafe")
    staged: dict[str, Path] = {}
    for name in ("crabc_probe.c", "crabc_fail.c"):
        origin = FIXTURES / name
        if not origin.is_file() or origin.is_symlink():
            raise LUA.RunnerError(f"Lua dynamic fixture is absent or unsafe: {name}")
        destination = support / f"{name[:-2]}.crabc-dynamic.c"
        shutil.copy2(origin, destination)
        staged[name] = destination
    return support, {
        "status": "passed",
        "fixtures": {name: LUA.artifact_record(path) for name, path in staged.items()},
        "contract": "fixture C sources are copied beside pinned Lua local headers; no include-path escape is admitted",
    }


def dynamic_roster(source: Path) -> tuple[tuple[str, Path], ...]:
    roster = [(f"src/{name}", source / "src" / name) for name in (*LUA.CORE_SOURCES, *LUA.LIB_SOURCES)]
    roster.extend((("src/lua.c", source / "src/lua.c"), ("src/luac.c", source / "src/luac.c")))
    if len({name for name, _ in roster}) != len(roster):
        raise LUA.RunnerError("native Lua dynamic source roster has duplicate names")
    return tuple(roster)


def build_candidate(
    source: Path,
    sysroot: Path,
    wrapper: Path,
    runtime: Mapping[str, Path],
    work: Path,
    timeout: float,
    jobs: int,
) -> dict[str, object]:
    """Build the complete selected dynamic Lua source graph through crabc-cc."""

    work.mkdir(parents=True, exist_ok=False)
    support, fixture_record = prepare_dynamic_modules(source)
    plan = dynamic_driver_plan(wrapper, sysroot, runtime, work, timeout)
    flags = dynamic_flags()
    header = dynamic_compile(
        wrapper, flags, FIXTURES / "header_probe.c", work / "header-probe.o", work, work / "header-state", timeout
    )
    roster = dynamic_roster(source)
    records, objects = parallel_dynamic_compiles(
        wrapper, flags, roster, work / "objects", work, timeout, jobs
    )
    module_records: dict[str, object] = {}
    module_objects: dict[str, Path] = {}
    for name, source_path in (
        ("crabc_probe.so", support / "crabc_probe.crabc-dynamic.c"),
        ("crabc_fail.so", support / "crabc_fail.crabc-dynamic.c"),
    ):
        output = work / "objects" / f"{name}.o"
        module_records[name] = dynamic_compile(
            wrapper, flags, source_path, output, work, work / f"module-{name}", timeout
        )
        module_objects[name] = output
    application = work / "application"
    libraries = application / "lib"
    binaries = application / "bin"
    libraries.mkdir(parents=True)
    binaries.mkdir()
    shared = [
        objects[name]
        for name, _ in roster
        if name not in {"src/lua.c", "src/luac.c"}
    ]
    liblua = libraries / "liblua.so.5.4"
    links: dict[str, object] = {
        "liblua": dynamic_link(
            wrapper=wrapper,
            sysroot=sysroot,
            runtime=runtime,
            mode="shared",
            objects=shared,
            output=liblua,
            application_dsos=(),
            work=work,
            timeout=timeout,
        )
    }
    lua = binaries / "lua"
    links["lua"] = dynamic_link(
        wrapper=wrapper,
        sysroot=sysroot,
        runtime=runtime,
        mode="pie",
        objects=[objects["src/lua.c"]],
        output=lua,
        application_dsos=[liblua],
        work=work,
        timeout=timeout,
    )
    luac = binaries / "luac"
    links["luac"] = dynamic_link(
        wrapper=wrapper,
        sysroot=sysroot,
        runtime=runtime,
        mode="pie",
        objects=[*shared, objects["src/luac.c"]],
        output=luac,
        application_dsos=(),
        work=work,
        timeout=timeout,
    )
    for name in ("crabc_probe.so", "crabc_fail.so"):
        links[name] = dynamic_link(
            wrapper=wrapper,
            sysroot=sysroot,
            runtime=runtime,
            mode="shared",
            objects=[module_objects[name]],
            output=libraries / name,
            application_dsos=[liblua],
            work=work,
            timeout=timeout,
        )
    shutil.copy2(libraries / "crabc_probe.so", libraries / "crabc_missing.so")
    artifacts = {
        "liblua": dynamic_elf(liblua, executable=False, label="candidate liblua"),
        "lua": dynamic_elf(lua, executable=True, label="candidate lua"),
        "luac": dynamic_elf(luac, executable=True, label="candidate luac"),
        "probe": dynamic_elf(libraries / "crabc_probe.so", executable=False, label="candidate probe"),
        "failure": dynamic_elf(libraries / "crabc_fail.so", executable=False, label="candidate failure"),
        "missing_symbol": dynamic_elf(libraries / "crabc_missing.so", executable=False, label="candidate missing module"),
    }
    for name in ("lua", "probe", "failure"):
        dynamic = artifacts[name]["dynamic"]
        assert isinstance(dynamic, str)
        if "liblua.so.5.4" not in dynamic:
            raise LUA.RunnerError(f"candidate {name} is not linked to the versioned liblua DSO")
    return {
        "paths": {"lua": lua, "luac": luac, "libraries": libraries, "liblua": liblua},
        "records": {
            "driver_plan": plan,
            "header_probe": header,
            "compile": records,
            "module_compile": module_records,
            "links": links,
            "artifacts": artifacts,
            "module_staging": fixture_record,
        },
    }


def reference_compile(
    compiler: Path, flags: Sequence[str], source: Path, output: Path, work: Path, state: Path, timeout: float
) -> dict[str, object]:
    record = command(
        [str(compiler), "-fPIC", *flags, "-c", str(source), "-o", str(output)],
        work=work,
        state=state,
        timeout=timeout,
    )
    require_success(record, f"pinned-musl dynamic compile {source.name}")
    return record


def build_reference(
    source: Path, support: Path, work: Path, timeout: float
) -> dict[str, object]:
    """Build fresh pinned-musl source bytes; candidate bytes are never reused."""

    compiler = require_regular(X86_MUSL_COMPILER, "pinned x86 musl oracle compiler")
    reference = work / "reference"
    objects_directory = reference / "objects"
    libraries = reference / "lib"
    binaries = reference / "bin"
    objects_directory.mkdir(parents=True)
    libraries.mkdir()
    binaries.mkdir()
    flags = dynamic_flags()
    roster = dynamic_roster(source)
    records: dict[str, object] = {}
    objects: dict[str, Path] = {}
    for index, (name, source_path) in enumerate(roster):
        output = objects_directory / f"{index:02d}-{name.replace('/', '_').replace('.', '_')}.o"
        records[name] = reference_compile(
            compiler, flags, source_path, output, work, work / f"reference-{index}", timeout
        )
        objects[name] = output
    module_objects: dict[str, Path] = {}
    for index, (name, source_path) in enumerate(
        (("crabc_probe.so", support / "crabc_probe.crabc-dynamic.c"), ("crabc_fail.so", support / "crabc_fail.crabc-dynamic.c"))
    ):
        output = objects_directory / f"module-{index}.o"
        records[name] = reference_compile(
            compiler, flags, source_path, output, work, work / f"reference-module-{index}", timeout
        )
        module_objects[name] = output
    shared = [objects[name] for name, _ in roster if name not in {"src/lua.c", "src/luac.c"}]

    def link(arguments: Sequence[str], output: Path, label: str) -> dict[str, object]:
        record = command(arguments, work=work, state=work / f"reference-link-{label}", timeout=timeout)
        require_success(record, f"pinned-musl dynamic link {label}")
        if not output.is_file() or output.is_symlink():
            raise LUA.RunnerError(f"pinned-musl dynamic link did not produce {label}")
        return record

    liblua = libraries / "liblua.so.5.4"
    links = {
        "liblua": link(
            [str(compiler), "-shared", "-Wl,-soname,liblua.so.5.4", *(str(path) for path in shared), "-lm", "-ldl", "-o", str(liblua)],
            liblua,
            "liblua",
        )
    }
    (libraries / "liblua.so").symlink_to("liblua.so.5.4")
    lua = binaries / "lua"
    links["lua"] = link(
        [str(compiler), "-fPIE", "-pie", str(objects["src/lua.c"]), "-L", str(libraries), "-llua", "-lm", "-ldl", "-o", str(lua)],
        lua,
        "lua",
    )
    luac = binaries / "luac"
    links["luac"] = link(
        [str(compiler), "-fPIE", "-pie", *(str(path) for path in shared), str(objects["src/luac.c"]), "-lm", "-ldl", "-o", str(luac)],
        luac,
        "luac",
    )
    for name in ("crabc_probe.so", "crabc_fail.so"):
        output = libraries / name
        links[name] = link(
            [str(compiler), "-shared", "-Wl,-soname," + name, str(module_objects[name]), "-L", str(libraries), "-llua", "-o", str(output)],
            output,
            name,
        )
    shutil.copy2(libraries / "crabc_probe.so", libraries / "crabc_missing.so")
    return {
        "paths": {"lua": lua, "luac": luac, "libraries": libraries},
        "records": {
            "compiler": LUA.artifact_record(compiler),
            "role": "fresh pinned-musl 1.2.6 dynamic Lua source execution oracle; never candidate input",
            "compile": records,
            "links": links,
        },
    }


@contextlib.contextmanager
def staged_canonical_loader(loader: Path) -> Iterator[None]:
    """Temporarily expose only the owned canonical interpreter for candidate execution."""

    target = Path(CANONICAL_INTERPRETER)
    if target.exists() or target.is_symlink():
        raise LUA.RunnerError(f"native canonical loader path is already occupied: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(loader, target)
    try:
        if LUA.sha256_file(target) != LUA.sha256_file(loader):
            raise LUA.RunnerError("staged native canonical loader hash drifted")
        yield
    finally:
        if target.is_file() and not target.is_symlink():
            target.unlink()


def verify_candidate_maps(maps: str, runtime: Mapping[str, Path], libraries: Path) -> dict[str, object]:
    expected = {
        "owned_loader": runtime["loader"],
        "owned_libc": runtime["libc.so"],
        "liblua": libraries / "liblua.so.5.4",
        "probe": libraries / "crabc_probe.so",
    }
    identities = [{"path": str(path), "sha256": LUA.sha256_file(path)} for path in LUA.mapped_files(maps)]
    records: dict[str, object] = {}
    missing: list[str] = []
    for name, path in expected.items():
        digest = LUA.sha256_file(path)
        mapped = any(item["sha256"] == digest for item in identities)
        records[name] = {"path": str(path), "sha256": digest, "mapped": mapped}
        if not mapped:
            missing.append(name)
    forbidden = ("/opt/musl-1.2.6", "libc.so.6", "ld-linux", "libc.musl-", "ld-musl-")
    foreign = [item for item in identities if any(marker in item["path"] for marker in forbidden)]
    return {
        "status": "passed" if not missing and not foreign else "rejected",
        "path": "/proc/<candidate>/maps",
        "text": maps,
        "mapped_files": identities,
        "expected_artifacts": records,
        "errors": {"missing_expected_artifacts": missing, "foreign_runtime_identities": foreign},
    }


def run_workloads(
    candidate: Mapping[str, Path],
    reference: Mapping[str, Path],
    runtime: Mapping[str, Path],
    work: Path,
    timeout: float,
) -> dict[str, object]:
    """Run source and bytecode modules in distinct candidate and musl processes."""

    script = FIXTURES / "exercise.lua"
    candidate_libraries = candidate["libraries"]
    reference_libraries = reference["libraries"]
    candidate_runtime = f"{runtime['libc.so'].parent}:{candidate_libraries}"
    reference_runtime = str(reference_libraries)
    fixture_root = work / "fixture-state"
    fixture_root.mkdir(parents=True, exist_ok=False)
    bytecode = work / "bytecode"
    bytecode.mkdir(parents=True, exist_ok=False)
    candidate_bytecode = bytecode / "candidate.luac"
    reference_bytecode = bytecode / "reference.luac"

    def command_with_runtime(
        arguments: Sequence[str], *, runtime_path: str, state: Path, label: str
    ) -> dict[str, object]:
        environment = dynamic_environment(state)
        environment["LD_LIBRARY_PATH"] = runtime_path
        record = LUA.command_record(arguments, cwd=work, environment=environment, timeout=timeout)
        require_success(record, label)
        return record

    for name in ("source-reference", "source-candidate", "bytecode-reference", "bytecode-candidate", "diagnostic"):
        (fixture_root / name).mkdir()
    with staged_canonical_loader(runtime["loader"]):
        candidate_luac = command_with_runtime(
            [str(candidate["luac"]), "-o", str(candidate_bytecode), str(script)],
            runtime_path=candidate_runtime,
            state=work / "candidate-luac",
            label="candidate dynamic luac bytecode build",
        )
        reference_luac = command_with_runtime(
            [str(reference["luac"]), "-o", str(reference_bytecode), str(script)],
            runtime_path=reference_runtime,
            state=work / "reference-luac",
            label="pinned-musl dynamic luac bytecode build",
        )
        if not candidate_bytecode.is_file() or not reference_bytecode.is_file():
            raise LUA.RunnerError("dynamic luac did not produce both bytecode artifacts")
        source_reference, _ = LUA.run_lua(
            [str(MUSL_ROOT / "lib/ld-musl-x86_64.so.1"), str(reference["lua"])],
            script,
            reference_libraries,
            reference_runtime,
            fixture_root / "source-reference",
            timeout,
            False,
        )
        source_candidate, maps = LUA.run_lua(
            [str(candidate["lua"])],
            script,
            candidate_libraries,
            candidate_runtime,
            fixture_root / "source-candidate",
            timeout,
            True,
        )
        bytecode_reference, _ = LUA.run_lua(
            [str(MUSL_ROOT / "lib/ld-musl-x86_64.so.1"), str(reference["lua"])],
            reference_bytecode,
            reference_libraries,
            reference_runtime,
            fixture_root / "bytecode-reference",
            timeout,
            False,
        )
        bytecode_candidate, _ = LUA.run_lua(
            [str(candidate["lua"])],
            candidate_bytecode,
            candidate_libraries,
            candidate_runtime,
            fixture_root / "bytecode-candidate",
            timeout,
            False,
        )
        if maps is None:
            raise LUA.RunnerError("candidate dynamic Lua process did not provide map evidence")
        maps_record = verify_candidate_maps(maps, runtime, candidate_libraries)
        trace = LUA.syscall_diagnostic(
            [str(candidate["lua"])],
            script,
            candidate_libraries,
            candidate_runtime,
            fixture_root / "diagnostic",
            work / "traces/normal.strace",
            timeout,
        )
    source = LUA.result_comparison(source_reference, source_candidate)
    bytecode_result = LUA.result_comparison(bytecode_reference, bytecode_candidate)
    if maps_record["status"] != "passed":
        raise LUA.RunnerError(f"candidate dynamic Lua map isolation failed: {maps_record['errors']}")
    if source["passed"] is not True or bytecode_result["passed"] is not True:
        raise LUA.RunnerError("dynamic Lua source or bytecode differs from the pinned-musl oracle")
    return {
        "candidate_luac": candidate_luac,
        "reference_luac": reference_luac,
        "bytecode_artifacts": {
            "candidate": LUA.artifact_record(candidate_bytecode),
            "reference": LUA.artifact_record(reference_bytecode),
        },
        "source": source,
        "bytecode": bytecode_result,
        "candidate_maps": maps_record,
        "syscalls": trace,
        "module_boundary": {
            "runtime_dso_loading": "required: Lua loads success, failure, and missing-symbol C-module paths",
            "io_popen": "required by both source and bytecode workloads",
        },
    }


def run_dynamic_lane(
    *,
    sysroot_path: Path,
    work_root: Path,
    cache: Path,
    offline: bool,
    jobs: int,
    timeout: float,
) -> dict[str, object]:
    require_native_x86_64()
    root = LUA.native_work_root(work_root)
    manifest = LUA.load_manifest(MANIFEST)
    archive = LUA.fetch_archive(manifest, offline, cache)
    sysroot, wrapper, runtime, installed_manifest = owned_dynamic_sysroot(sysroot_path)
    lane = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "crabc-lua-native-x86-dynamic-source-build",
        "result": "fail",
        "passed": False,
        "manifest": {"path": str(MANIFEST), "sha256": LUA.sha256_file(MANIFEST), "contents": manifest},
        "source_archive": LUA.artifact_record(archive),
        "work_directory": str(lane),
        "environment": {
            "sysroot": str(sysroot),
            "compiler_wrapper": LUA.artifact_record(wrapper),
            "owned_runtime_inputs": {name: LUA.artifact_record(path) for name, path in runtime.items() if name != "headers"},
            "owned_headers": str(runtime["headers"]),
            "sysroot_manifest": installed_manifest,
            "musl_compiler": LUA.artifact_record(require_regular(X86_MUSL_COMPILER, "pinned x86 musl oracle compiler")),
            "musl_role": "fresh source build and execution oracle; never a candidate input",
            "timeout_seconds": timeout,
            "jobs": jobs,
        },
    }
    try:
        lua = manifest["lua"]
        assert isinstance(lua, dict)
        source = LUA.safe_extract(archive, lane / "source", str(lua["archive_root"]))
        candidate = build_candidate(source, sysroot, wrapper, runtime, lane / "candidate", timeout, jobs)
        support = source / "src"
        reference = build_reference(source, support, lane / "oracle", timeout)
        candidate_paths = candidate["paths"]
        reference_paths = reference["paths"]
        assert isinstance(candidate_paths, dict) and isinstance(reference_paths, dict)
        workloads = run_workloads(candidate_paths, reference_paths, runtime, lane, timeout)
        report["candidate"] = candidate["records"]
        report["reference"] = reference["records"]
        report["workloads"] = workloads
        report["passed"] = True
        report["result"] = "pass"
    except LUA.RunnerError as error:
        report["error"] = str(error)
    return report


def source_artifact_hashes(report: Mapping[str, object]) -> dict[str, str]:
    """Return a stable checked subset for installed/extracted source reproducibility."""

    candidate = report.get("candidate")
    if not isinstance(candidate, Mapping):
        raise LUA.RunnerError("dynamic Lua lane report lacks candidate artifacts")
    artifacts = candidate.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise LUA.RunnerError("dynamic Lua lane report lacks candidate ELF records")
    hashes: dict[str, str] = {}
    for name in ("liblua", "lua", "luac", "probe", "failure", "missing_symbol"):
        entry = artifacts.get(name)
        if not isinstance(entry, Mapping):
            raise LUA.RunnerError(f"dynamic Lua lane artifact is absent: {name}")
        artifact = entry.get("artifact")
        if not isinstance(artifact, Mapping) or not isinstance(artifact.get("sha256"), str):
            raise LUA.RunnerError(f"dynamic Lua lane artifact hash is absent: {name}")
        hashes[name] = artifact["sha256"]
    return hashes


def publish_report(report: Path, latest_report: Path) -> Path:
    report = require_regular(report, "native Lua dynamic dispatcher report")
    latest_report = Path(os.path.abspath(latest_report))
    LUA.reject_symlinked_components(latest_report.parent, "native Lua dynamic report directory")
    latest_report.parent.mkdir(parents=True, exist_ok=True)
    parent = LUA.require_physical_directory(latest_report.parent, "native Lua dynamic report directory")
    latest = parent / latest_report.name
    if os.path.lexists(latest) and latest.is_symlink():
        raise LUA.RunnerError(f"native Lua dynamic latest report is a symlink: {latest}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".x86_64-dynamic-latest.", dir=parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(report.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(latest)
    except OSError as error:
        raise LUA.RunnerError("cannot publish native Lua dynamic latest report") from error
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return require_regular(latest, "native Lua dynamic published latest report")


def run_dynamic_dispatch(
    *, jobs: int, timeout: float, offline: bool, state_parent: Path = DEFAULT_WORK_ROOT,
    latest_report: Path = DEFAULT_REPORT
) -> tuple[dict[str, object], Path, Path | None]:
    """Build, package/extract, and source-qualify one isolated dynamic Lua graph."""

    if jobs < 1 or jobs > LUA.MAX_JOBS:
        raise LUA.RunnerError(f"native Lua dynamic dispatcher jobs must be from 1 through {LUA.MAX_JOBS}")
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
        raise LUA.RunnerError("native Lua dynamic dispatcher timeout must be > 0 and <= 300")
    LUA.disable_core_dump_inheritance()
    state = LUA.allocate_x86_static_dispatch_state(state_parent)
    report_path = state / "report.json"
    installed = state / "sysroot"
    package = state / "runtime.tar"
    extracted = state / "extracted"
    dispatcher: dict[str, object] = {
        "state_root": str(state),
        "authoritative_report": str(report_path),
        "latest_report": str(Path(os.path.abspath(latest_report))),
        "latest_report_publication": "only after a passing installed-and-extracted report",
    }
    report: dict[str, object] = {
        "schema_version": 1,
        "runner": "crabc-lua-native-x86-dynamic-source-build-dispatch",
        "result": "fail",
        "passed": False,
        "dispatcher": dispatcher,
    }
    try:
        builder = require_regular(DYNAMIC_SYSROOT_BUILDER, "native Lua dynamic sysroot builder")
        producer = command(
            [sys.executable, "-B", str(builder), "--output", str(installed)],
            work=ROOT,
            state=state / "producer",
            timeout=timeout,
        )
        dispatcher["producer"] = producer
        require_success(producer, "native Lua dynamic sysroot producer")
        package_tool = require_regular(DYNAMIC_PACKAGE_TOOL, "native Lua dynamic sysroot package tool")
        packaged = command(
            [sys.executable, "-B", str(package_tool), "package", str(installed), str(package)],
            work=ROOT,
            state=state / "package",
            timeout=timeout,
        )
        dispatcher["package"] = packaged
        require_success(packaged, "native Lua dynamic sysroot package")
        extracted_record = command(
            [sys.executable, "-B", str(package_tool), "extract", str(package), str(extracted)],
            work=ROOT,
            state=state / "extract",
            timeout=timeout,
        )
        dispatcher["extract"] = extracted_record
        require_success(extracted_record, "native Lua dynamic sysroot extraction")
        cache = LUA.native_source_cache(state)
        installed_lane = run_dynamic_lane(
            sysroot_path=installed, work_root=state / "installed-runs", cache=cache,
            offline=offline, jobs=jobs, timeout=timeout,
        )
        extracted_lane = run_dynamic_lane(
            sysroot_path=extracted, work_root=state / "extracted-runs", cache=cache,
            offline=True, jobs=jobs, timeout=timeout,
        )
        report["installed"] = installed_lane
        report["extracted"] = extracted_lane
        installed_hashes = source_artifact_hashes(installed_lane)
        extracted_hashes = source_artifact_hashes(extracted_lane)
        report["reproducibility"] = {
            "status": "passed" if installed_hashes == extracted_hashes else "rejected",
            "installed_artifacts": installed_hashes,
            "extracted_artifacts": extracted_hashes,
            "contract": "identical pinned source through installed and package-extracted owned dynamic sysroots",
        }
        report["passed"] = (
            installed_lane.get("passed") is True
            and extracted_lane.get("passed") is True
            and installed_hashes == extracted_hashes
        )
        report["result"] = "pass" if report["passed"] else "fail"
    except LUA.RunnerError as error:
        report["error"] = str(error)
    LUA.write_json_atomic(report_path, report)
    if report.get("passed") is not True:
        return report, report_path, None
    latest = publish_report(report_path, latest_report)
    return report, report_path, latest


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=LUA.DEFAULT_JOBS)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.jobs > LUA.MAX_JOBS:
        parser.error(f"--jobs must be an integer from 1 through {LUA.MAX_JOBS}")
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be > 0 and <= 300")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report, report_path, latest = run_dynamic_dispatch(
            jobs=args.jobs, timeout=args.timeout, offline=args.offline
        )
    except LUA.RunnerError as error:
        print(f"x86 Lua dynamic source-build dispatcher failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "state_root": str(report_path.parent),
        "report": str(report_path),
        "latest_report": str(latest) if latest is not None else None,
        "passed": report.get("passed") is True,
    }, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
