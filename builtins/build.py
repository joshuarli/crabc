#!/usr/bin/env python3
"""Build and audit crabc's Linux/AArch64 compiler-helper archive.

The archive combines crabc's small Rust-only compatibility helpers with a
fresh source build of the pinned ``compiler_builtins`` tree from rust-src.
It deliberately never repackages rustup's prebuilt target archive: Cargo's
``-Zbuild-std=core,compiler_builtins`` path compiles the relevant sources in a
new temporary target directory, with the C feature disabled, before this
script extracts only its Rust object members.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Mapping, Sequence


ROOT = pathlib.Path(__file__).resolve().parent
SOURCE = ROOT / "src" / "lib.rs"
TARGET = "aarch64-unknown-linux-musl"
ARCHIVE_MEMBER = "crabc-builtins.o"
TOOLCHAIN_CONFIG = ROOT.parent / "rust-toolchain.toml"
UPSTREAM_WORKSPACE_RELATIVE = pathlib.Path("lib/rustlib/src/rust/library/compiler-builtins")
UPSTREAM_PACKAGE_RELATIVE = UPSTREAM_WORKSPACE_RELATIVE / "compiler-builtins"
UPSTREAM_PACKAGE = "compiler_builtins"
UPSTREAM_VERSION = "0.1.160"
UPSTREAM_SOURCE_BUILD_COMPONENTS = ("core", "compiler_builtins")
UPSTREAM_REQUIRED_FEATURES = frozenset({"arch", "compiler-builtins", "default", "unmangled-names"})
UPSTREAM_FORBIDDEN_FEATURES = frozenset({"c", "mem"})
SOURCE_BUILD_INHERITED_ENVIRONMENT = ("HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "PATH", "RUSTUP_HOME", "SSL_CERT_DIR", "SSL_CERT_FILE")
SEALED_SOURCE_BUILD_ENVIRONMENT_KEYS = frozenset(
    {
        "AR",
        "AS",
        "CC",
        "CFLAGS",
        "CXX",
        "CXXFLAGS",
        "LDFLAGS",
        "RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    }
)
NATIVE_BUILD_EXECUTABLES = frozenset({"ar", "as", "cc", "clang", "clang++", "gcc", "g++", "ld", "nasm"})

# Keep the established Rust translations while the source-built upstream
# archive supplies the complete AArch64 binary128 arithmetic/conversion family.
# These symbols are a minimum contract, not an inferred substitute for the
# complete archive inventory recorded in provenance.
EXPECTED_SYMBOLS = (
    "__addoti4",
    "__addtf3",
    "__ashlti3",
    "__ashrti3",
    "__bswapdi2",
    "__bswapsi2",
    "__bswapti2",
    "__clzti2",
    "__ctzti2",
    "__divmodti4",
    "__divtf3",
    "__divti3",
    "__eqtf2",
    "__extenddftf2",
    "__extendsftf2",
    "__ffsti2",
    "__floatditf",
    "__floatsitf",
    "__floatunditf",
    "__gttf2",
    "__letf2",
    "__lshrti3",
    "__lttf2",
    "__modti3",
    "__muldc3",
    "__muloti4",
    "__multf3",
    "__multi3",
    "__netf2",
    "__parityti2",
    "__popcountti2",
    "__suboti4",
    "__subtf3",
    "__trunctfdf2",
    "__trunctfsf2",
    "__udivmodti4",
    "__udivti3",
    "__umodti3",
    "__unordtf2",
)
FORBIDDEN_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".s", ".S", ".asm"})
FORBIDDEN_SOURCE_TOKENS = (
    "extern crate alloc",
    "use alloc::",
    "alloc::",
    "global_asm!",
    "asm!",
    "#[link",
)
FORBIDDEN_SECTIONS = (".eh_frame", ".gcc_except_table", ".ARM.exidx", ".ARM.extab")
FORBIDDEN_EXPORT_TOKENS = (
    "memcpy",
    "memmove",
    "memset",
    "bcopy",
    "bzero",
    "__aarch64_",
    "__atomic_",
    "__sync_",
    "__stack_chk_",
    "__gcc_",
    "__gxx_",
    "__cxa_",
    "__aeabi_unwind",
)

# compiler_builtins also carries a small all-Rust libm compatibility surface.
# These names are intentionally acceptable only as archive members: the driver
# puts crabc libc first, so ordinary C programs continue to resolve their
# public libm entry points from libc rather than silently replacing them here.
APPROVED_COMPATIBILITY_EXPORTS = frozenset(
    {
        "cbrt",
        "cbrtf",
        "ceil",
        "ceilf",
        "ceilf16",
        "ceilf128",
        "copysign",
        "copysignf",
        "copysignf16",
        "copysignf128",
        "fabs",
        "fabsf",
        "fabsf16",
        "fabsf128",
        "fdim",
        "fdimf",
        "fdimf16",
        "fdimf128",
        "floor",
        "floorf",
        "floorf16",
        "floorf128",
        "fma",
        "fmaf",
        "fmaf16",
        "fmaf128",
        "fmax",
        "fmaxf",
        "fmaxf16",
        "fmaxf128",
        "fmaximum",
        "fmaximum_num",
        "fmaximum_numf",
        "fmaximum_numf16",
        "fmaximum_numf128",
        "fmaximumf",
        "fmaximumf16",
        "fmaximumf128",
        "fmin",
        "fminf",
        "fminf16",
        "fminf128",
        "fminimum",
        "fminimum_num",
        "fminimum_numf",
        "fminimum_numf16",
        "fminimum_numf128",
        "fminimumf",
        "fminimumf16",
        "fminimumf128",
        "fmod",
        "fmodf",
        "fmodf16",
        "fmodf128",
        "rint",
        "rintf",
        "rintf16",
        "rintf128",
        "round",
        "roundeven",
        "roundevenf",
        "roundevenf16",
        "roundevenf128",
        "roundf",
        "roundf16",
        "roundf128",
        "sqrt",
        "sqrtf",
        "sqrtf16",
        "sqrtf128",
        "trunc",
        "truncf",
        "truncf16",
        "truncf128",
    }
)


class BuildError(RuntimeError):
    """A violated archive-purity or artifact contract."""


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_completed(
    command: Sequence[str],
    *,
    cwd: pathlib.Path = ROOT,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=None if environment is None else dict(environment),
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise BuildError(f"required host tool is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        rendered = " ".join(command)
        raise BuildError(
            f"command failed: {rendered}\nstdout:\n{error.stdout}\nstderr:\n{error.stderr}"
        ) from error
    return completed


def run(
    command: Sequence[str],
    *,
    cwd: pathlib.Path = ROOT,
    environment: Mapping[str, str] | None = None,
) -> str:
    return run_completed(command, cwd=cwd, environment=environment).stdout


def require_tool(value: str) -> str:
    resolved = shutil.which(value)
    if resolved is None:
        raise BuildError(f"required host tool is unavailable: {value}")
    return resolved


def pinned_tool(tool: str) -> tuple[str, ...]:
    toolchain = tomllib.loads(TOOLCHAIN_CONFIG.read_text(encoding="utf-8"))
    channel = toolchain.get("toolchain", {}).get("channel")
    if not isinstance(channel, str) or not channel.startswith("nightly-"):
        raise BuildError("repository rust-toolchain.toml must name the pinned nightly channel")
    return (require_tool("rustup"), "run", channel, tool)


def pinned_rustc() -> tuple[str, ...]:
    return pinned_tool("rustc")


def pinned_cargo() -> tuple[str, ...]:
    return pinned_tool("cargo")


def source_files() -> list[pathlib.Path]:
    # C/assembly fixtures consume the produced archive in separate x86 ABI
    # tests. They are never compiled into the production helper archive.
    # Keep native-source rejection intact everywhere outside that test tree.
    files = sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and "target" not in path.parts
        and path.relative_to(ROOT).parts[0] != "fixtures"
    )
    for path in files:
        if path.suffix in FORBIDDEN_SOURCE_SUFFIXES:
            raise BuildError(f"native source is forbidden in this component: {path.relative_to(ROOT)}")
        if path.name == "build.rs":
            raise BuildError("Cargo build scripts are forbidden in the crabc-owned helper component")
    return files


def audit_source() -> list[dict[str, str]]:
    source_files()
    cargo_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if cargo_manifest.get("dependencies") != {} or cargo_manifest.get("build-dependencies"):
        raise BuildError("Cargo manifest must have no normal or build dependencies")
    package = cargo_manifest.get("package", {})
    if package.get("links") is not None:
        raise BuildError("Cargo links metadata is forbidden in the crabc-owned helper component")
    if package.get("build") is not False:
        raise BuildError("Cargo build scripts are forbidden in the crabc-owned helper component")

    contract = tomllib.loads((ROOT / "provenance.toml").read_text(encoding="utf-8"))
    implementation_contract = contract.get("implementation", {})
    if (
        implementation_contract.get("uses_alloc") is not False
        or implementation_contract.get("uses_unwinding") is not False
        or implementation_contract.get("requires_panic_runtime") is not False
        or implementation_contract.get("uses_external_assembly") is not False
    ):
        raise BuildError("provenance implementation contract does not preserve the pure-Rust target boundary")
    archive_contract = contract.get("archive", {})
    if archive_contract.get("local_member") != ARCHIVE_MEMBER:
        raise BuildError("provenance archive member does not match the builder contract")
    if archive_contract.get("local_symbol_source") != "src/lib.rs":
        raise BuildError("provenance must identify src/lib.rs as the local helper symbol source")
    if tuple(sorted(archive_contract.get("required_symbols", ()))) != tuple(sorted(EXPECTED_SYMBOLS)):
        raise BuildError("provenance required-symbol inventory does not match the builder contract")
    upstream_contract = contract.get("upstream_compiler_builtins", {})
    if (
        upstream_contract.get("package") != UPSTREAM_PACKAGE
        or upstream_contract.get("version") != UPSTREAM_VERSION
        or upstream_contract.get("source") != "pinned rust-src"
        or tuple(upstream_contract.get("source_build", ())) != UPSTREAM_SOURCE_BUILD_COMPONENTS
        or upstream_contract.get("locked_resolution") is not True
        or set(upstream_contract.get("required_features", ())) != UPSTREAM_REQUIRED_FEATURES
        or set(upstream_contract.get("forbidden_features", ())) != UPSTREAM_FORBIDDEN_FEATURES
        or upstream_contract.get("links_metadata") != "compiler-rt"
        or upstream_contract.get("native_build") is not False
        or upstream_contract.get("prebuilt_target_archive") is not False
    ):
        raise BuildError("provenance upstream compiler_builtins contract is incomplete")

    rust_source = SOURCE.read_text(encoding="utf-8")
    if "#![no_std]" not in rust_source:
        raise BuildError("compiler helper source must remain no_std")
    for token in FORBIDDEN_SOURCE_TOKENS:
        if token in rust_source:
            raise BuildError(f"forbidden source dependency or assembly facility: {token}")

    production_inputs = (ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "build.py", ROOT / "provenance.toml", SOURCE)
    return [
        {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)}
        for path in production_inputs
    ]


def target_contract(rustc: Sequence[str]) -> list[str]:
    configuration = run((*rustc, "--print", "cfg", "--target", TARGET)).splitlines()
    required = {
        'target_arch="aarch64"',
        'target_os="linux"',
        'target_endian="little"',
        'target_pointer_width="64"',
        'target_env="musl"',
    }
    missing = sorted(required.difference(configuration))
    if missing:
        raise BuildError(f"target does not satisfy the crabc helper ABI: {', '.join(missing)}")
    return configuration


def compiler_command(rustc: Sequence[str], object_path: pathlib.Path) -> list[str]:
    """Compile crabc's small, directly-owned helper object."""

    return [
        *rustc,
        "--crate-name",
        "crabc_builtins",
        "--crate-type",
        "lib",
        "--edition=2021",
        "--target",
        TARGET,
        "--emit=obj",
        "-C",
        "panic=abort",
        "-C",
        "force-unwind-tables=no",
        "-C",
        "overflow-checks=off",
        "-C",
        "opt-level=2",
        "-C",
        "codegen-units=1",
        "-C",
        "debuginfo=0",
        "-C",
        "relocation-model=pic",
        "-C",
        "target-feature=-outline-atomics",
        "-C",
        "embed-bitcode=no",
        "-C",
        "metadata=crabc-builtins-v2",
        "--remap-path-prefix",
        f"{ROOT}=crabc-builtins",
        "-o",
        str(object_path),
        str(SOURCE),
    ]


def rust_sysroot(rustc: Sequence[str]) -> pathlib.Path:
    sysroot = pathlib.Path(run((*rustc, "--print", "sysroot")).strip()).resolve()
    if not sysroot.is_dir():
        raise BuildError("pinned rustc did not report an existing sysroot")
    return sysroot


def upstream_package_root(rustc: Sequence[str]) -> pathlib.Path:
    package = rust_sysroot(rustc) / UPSTREAM_PACKAGE_RELATIVE
    manifest = package / "Cargo.toml"
    if not manifest.is_file():
        raise BuildError("the pinned rust-src component does not contain compiler_builtins source")
    value = tomllib.loads(manifest.read_text(encoding="utf-8"))
    package_table = value.get("package", {})
    if package_table.get("name") != UPSTREAM_PACKAGE or package_table.get("version") != UPSTREAM_VERSION:
        raise BuildError("pinned compiler_builtins source does not match the recorded package/version")
    if package_table.get("links") != "compiler-rt":
        raise BuildError("pinned compiler_builtins links metadata changed; review its native-build boundary")
    features = value.get("features", {})
    if features.get("c") != ["dep:cc"] or "mem" not in features:
        raise BuildError("pinned compiler_builtins feature boundary changed; review the source-build contract")
    return package


def portable_local_rustc_command(command: Sequence[str], object_path: pathlib.Path) -> list[str]:
    """Retain a reproducible local-helper command record without stage paths."""

    normalized: list[str] = []
    for argument in command:
        if argument == str(object_path):
            normalized.append("$CRABC_BUILTINS_STAGE/crabc-builtins.o")
        elif argument == str(SOURCE):
            normalized.append("/crabc/builtins/src/lib.rs")
        elif argument == f"{ROOT}=crabc-builtins":
            normalized.append("/crabc/builtins=crabc-builtins")
        else:
            normalized.append(argument)
    return normalized


def source_build_rustflags(stage: pathlib.Path, upstream: pathlib.Path) -> tuple[str, ...]:
    """Return the target codegen policy applied to Cargo's source-built lane."""

    return (
        "-C",
        "panic=abort",
        "-C",
        "force-unwind-tables=no",
        "-C",
        "overflow-checks=off",
        "-C",
        "debuginfo=0",
        "-C",
        "embed-bitcode=no",
        "-C",
        "target-feature=-outline-atomics",
        "--remap-path-prefix",
        f"{stage}=/crabc/builtins-stage",
        "--remap-path-prefix",
        f"{upstream.parent}=/rust-src/library/compiler-builtins",
    )


def source_build_environment(stage: pathlib.Path, flags: Sequence[str]) -> dict[str, str]:
    """Create the focused source-build environment without target overrides.

    The helper lane is intentionally the only expensive standard-library
    source build.  It may inherit cache/network discovery needed to resolve
    the pinned lock, but no caller-selected Rust flags, target linker, C
    compiler, or C flags can alter the produced AArch64 archive.
    """

    environment = {
        key: os.environ[key]
        for key in SOURCE_BUILD_INHERITED_ENVIRONMENT
        if key in os.environ
    }
    environment.update(
        {
            "CARGO_TARGET_DIR": str(stage / "source-build-target"),
            "CARGO_HOME": str(stage / "cargo-home"),
            # Cargo and rustc can create short-lived intermediates while
            # source-building core and compiler_builtins. Keep them inside
            # this disposable archive stage instead of accepting /tmp.
            "TMPDIR": str(stage / "source-build-tmp"),
            "CARGO_INCREMENTAL": "0",
            "CARGO_TERM_COLOR": "never",
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
            "LC_ALL": "C",
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        }
    )
    return environment


def write_source_build_probe(stage: pathlib.Path) -> pathlib.Path:
    """Make a disposable no_std root which asks Cargo to source-build std bits."""

    probe = stage / "source-build-probe"
    source = probe / "src"
    source.mkdir(parents=True)
    (probe / "Cargo.toml").write_text(
        "[package]\n"
        "name = \"crabc-builtins-source-build-probe\"\n"
        "version = \"0.0.0\"\n"
        "edition = \"2024\"\n\n"
        "[lib]\n"
        "crate-type = [\"rlib\"]\n\n"
        "[workspace]\n\n"
        "[profile.release]\n"
        "panic = \"abort\"\n"
        "debug = 0\n",
        encoding="utf-8",
    )
    # Cargo refuses `--locked` before it can even ask rust-src for the
    # build-std packages when a standalone probe has no lockfile. The probe
    # has no registry dependencies, so its tiny deterministic lock records
    # only itself; the separately recorded rust-src library lock remains the
    # resolution authority for `core` and `compiler_builtins`.
    (probe / "Cargo.lock").write_text(
        "# This file is automatically @generated by Cargo.\n"
        "# It is not intended for manual editing.\n"
        "version = 4\n\n"
        "[[package]]\n"
        "name = \"crabc-builtins-source-build-probe\"\n"
        "version = \"0.0.0\"\n",
        encoding="utf-8",
    )
    (source / "lib.rs").write_text(
        "#![no_std]\n"
        "#![feature(f128)]\n\n"
        "#[inline(never)]\n"
        "pub fn retain_binary128_configuration(value: f128) -> f128 {\n"
        "    value\n"
        "}\n",
        encoding="utf-8",
    )
    return probe


def find_one(path: pathlib.Path, pattern: str, description: str) -> pathlib.Path:
    candidates = sorted(path.glob(pattern))
    if len(candidates) != 1:
        raise BuildError(f"expected one {description}, found {[candidate.name for candidate in candidates]!r}")
    return candidates[0]


def compiler_builtins_features(log: str, target_dir: pathlib.Path) -> list[str]:
    lines = [line for line in log.splitlines() if "--crate-name compiler_builtins" in line]
    if len(lines) != 1:
        raise BuildError("source build did not record exactly one compiler_builtins rustc invocation")
    line = lines[0]
    features = sorted(set(re.findall(r'feature="([^"]+)"', line)))
    if set(features) != UPSTREAM_REQUIRED_FEATURES:
        raise BuildError(f"compiler_builtins selected an unsafe feature set: {features!r}")
    if "--extern core=" not in line or str(target_dir) not in line:
        raise BuildError("compiler_builtins did not consume the newly source-built core metadata")
    if "--crate-name core" not in log:
        raise BuildError("-Zbuild-std did not source-build core alongside compiler_builtins")
    return features


def native_build_commands_from_log(log: str) -> list[dict[str, str]]:
    """Reject native-tool invocations emitted by Cargo's verbose source build."""

    commands: list[dict[str, str]] = []
    for rendered in re.findall(r"Running `([^`]+)`", log):
        try:
            arguments = shlex.split(rendered)
        except ValueError as error:
            raise BuildError("source-build log has an unparsable Cargo command") from error
        if not arguments:
            continue
        executable = pathlib.Path(arguments[0]).name
        if executable in NATIVE_BUILD_EXECUTABLES:
            commands.append(
                {
                    "executable": executable,
                    "command_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                }
            )
    if commands:
        raise BuildError(f"compiler_builtins source build invoked native tools: {commands!r}")
    return commands


def compiler_builtins_build_log_audit(log: str, target_dir: pathlib.Path) -> dict[str, object]:
    """Prove the selected Cargo lane neither links nor compiles native runtime code."""

    features = compiler_builtins_features(log, target_dir)
    native_commands = native_build_commands_from_log(log)
    directives = [
        line.split("cargo:", 1)[1].strip()
        for line in log.splitlines()
        if "compiler_builtins" in line and "cargo:" in line
    ]
    linker_directives = [
        line
        for line in directives
        if "rustc-link-lib" in line or "rustc-link-search" in line
    ]
    if linker_directives:
        raise BuildError(f"compiler_builtins build script emitted target link directives: {linker_directives!r}")
    directive_keys = sorted({line.split("=", 1)[0] for line in directives})
    if "compiler-rt" not in directive_keys:
        raise BuildError("compiler_builtins build script did not expose its audited compiler-rt metadata")
    return {
        "selected_features": features,
        "native_build_commands": native_commands,
        "target_link_directives": linker_directives,
        "metadata_directive_keys": directive_keys,
    }


def upstream_build_script_inputs(upstream: pathlib.Path) -> list[dict[str, str]]:
    """Record every Rust source imported by compiler_builtins' build script.

    The upstream build script imports ``../libm/configure.rs`` with ``#[path]``.
    It selects target cfgs before compiler_builtins is compiled, so it is a real
    source input even though it does not appear in the target rlib's dep-info.
    """

    inputs = (upstream.parent / "libm" / "configure.rs",)
    records: list[dict[str, str]] = []
    for path in inputs:
        if not path.is_file():
            raise BuildError(f"pinned compiler_builtins build-script input is unavailable: {path}")
        records.append(
            {
                "path": f"rust-src/library/compiler-builtins/{path.relative_to(upstream.parent).as_posix()}",
                "sha256": sha256(path),
            }
        )
    return records


def selected_upstream_sources(rlib: pathlib.Path, upstream: pathlib.Path) -> list[dict[str, str]]:
    dependency_candidates = [rlib.with_suffix(".d")]
    if rlib.name.startswith("lib"):
        dependency_candidates.append(rlib.with_name(rlib.name[3:]).with_suffix(".d"))
    dependency_file = next((path for path in dependency_candidates if path.is_file()), None)
    if dependency_file is None:
        raise BuildError("source-built compiler_builtins rlib has no dependency file")
    contents = dependency_file.read_text(encoding="utf-8").replace("\\\n", " ")
    if ":" not in contents:
        raise BuildError("compiler_builtins dependency file has an invalid format")
    selected: set[pathlib.Path] = set()
    workspace = upstream.parent.resolve()
    for token in contents.split(":", 1)[1].split():
        candidate = pathlib.Path(token)
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        try:
            resolved.relative_to(workspace)
        except ValueError as error:
            if resolved.suffix == ".rs":
                raise BuildError(
                    f"compiler_builtins selected a Rust source outside pinned rust-src: {resolved}"
                ) from error
            # Toolchain metadata and generated dependency records outside the
            # pinned compiler-builtins workspace are not target implementation
            # sources. They cannot introduce a native compiler-runtime input.
            continue
        if resolved.suffix in FORBIDDEN_SOURCE_SUFFIXES:
            raise BuildError(
                "compiler_builtins selected a forbidden native source input: "
                f"{resolved.relative_to(workspace)}"
            )
        if resolved.suffix in {".a", ".o", ".so"}:
            raise BuildError(
                "compiler_builtins selected a forbidden native archive/object input: "
                f"{resolved.relative_to(workspace)}"
            )
        if resolved.suffix == ".rs":
            selected.add(resolved)
    if not selected:
        raise BuildError("compiler_builtins dependency file did not identify selected Rust source files")
    return [
        {
            "path": f"rust-src/library/compiler-builtins/{path.relative_to(workspace).as_posix()}",
            "sha256": sha256(path),
        }
        for path in sorted(selected)
    ]


def extract_upstream_members(
    llvm_ar: str,
    rlib: pathlib.Path,
    destination: pathlib.Path,
) -> list[pathlib.Path]:
    destination.mkdir()
    run((llvm_ar, "x", str(rlib)), cwd=destination)
    members = sorted(destination.glob("*.o"))
    if not members:
        raise BuildError("source-built compiler_builtins archive contained no object members")
    for member in members:
        if not member.name.startswith("compiler_builtins-"):
            raise BuildError(f"compiler_builtins rlib carried a non-compiler-builtins object member: {member.name}")
    return members


def source_build_compiler_builtins(
    *,
    cargo: Sequence[str],
    rustc: Sequence[str],
    llvm_ar: str,
    stage: pathlib.Path,
) -> dict[str, Any]:
    """Compile compiler_builtins from pinned rust-src and extract its objects."""

    upstream = upstream_package_root(rustc)
    probe = write_source_build_probe(stage)
    flags = source_build_rustflags(stage, upstream)
    environment = source_build_environment(stage, flags)
    target_dir = pathlib.Path(environment["CARGO_TARGET_DIR"])
    pathlib.Path(environment["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    command = [
        *cargo,
        "build",
        "--manifest-path",
        str(probe / "Cargo.toml"),
        "--release",
        "--target",
        TARGET,
        "--locked",
        "-Zbuild-std=core,compiler_builtins",
        "-vv",
    ]
    completed = run_completed(command, environment=environment)
    log = completed.stdout + completed.stderr
    source_build_audit = compiler_builtins_build_log_audit(log, target_dir)
    dependencies = target_dir / TARGET / "release" / "deps"
    rlib = find_one(dependencies, "libcompiler_builtins-*.rlib", "source-built compiler_builtins rlib")
    selected_sources = selected_upstream_sources(rlib, upstream)
    members = extract_upstream_members(llvm_ar, rlib, stage / "compiler-builtins-members")
    manifest = upstream / "Cargo.toml"
    build_script = upstream / "build.rs"
    rust_src_lock = upstream.parent.parent / "Cargo.lock"
    if not rust_src_lock.is_file():
        raise BuildError("pinned rust-src library lockfile is unavailable for compiler_builtins source build")
    return {
        "members": members,
        "selected_features": source_build_audit["selected_features"],
        "native_build_audit": source_build_audit,
        "source_files": selected_sources,
        "package_manifest": {
            "path": "rust-src/library/compiler-builtins/compiler-builtins/Cargo.toml",
            "sha256": sha256(manifest),
        },
        "build_script": {
            "path": "rust-src/library/compiler-builtins/compiler-builtins/build.rs",
            "sha256": sha256(build_script),
        },
        "build_script_inputs": upstream_build_script_inputs(upstream),
        "portable_command": [
            "cargo",
            "build",
            "--manifest-path",
            "/crabc/builtins/source-build-probe/Cargo.toml",
            "--release",
            "--target",
            TARGET,
            "--locked",
            "-Zbuild-std=core,compiler_builtins",
            "-vv",
        ],
        "rustflags": [
            "-C",
            "panic=abort",
            "-C",
            "force-unwind-tables=no",
            "-C",
            "overflow-checks=off",
            "-C",
            "debuginfo=0",
            "-C",
            "embed-bitcode=no",
            "-C",
            "target-feature=-outline-atomics",
            "--remap-path-prefix",
            "$CRABC_BUILTINS_STAGE=/crabc/builtins-stage",
            "--remap-path-prefix",
            "/rust-src/library/compiler-builtins=/rust-src/library/compiler-builtins",
        ],
        "source_build": list(UPSTREAM_SOURCE_BUILD_COMPONENTS),
        "source_built_rlib_name": rlib.name,
        "source_built_rlib_sha256": sha256(rlib),
        "rust_src_lock": {
            "path": "rust-src/library/Cargo.lock",
            "sha256": sha256(rust_src_lock),
        },
    }


def archive_members(llvm_ar: str, archive: pathlib.Path) -> list[str]:
    members = [line for line in run((llvm_ar, "t", str(archive))).splitlines() if line]
    if not members or members[0] != ARCHIVE_MEMBER:
        raise BuildError(f"archive must begin with its crabc-owned member {ARCHIVE_MEMBER!r}, found {members!r}")
    if len(members) == 1 or len(members) != len(set(members)):
        raise BuildError("archive must contain unique crabc and source-built compiler_builtins members")
    if any(not name.endswith(".o") for name in members):
        raise BuildError(f"archive contained a non-object member: {members!r}")
    if any(not name.startswith("compiler_builtins-") for name in members[1:]):
        raise BuildError(f"archive contained an unclassified upstream member: {members!r}")
    return members


def nm_symbols(llvm_nm: str, artifact: pathlib.Path, flag: str) -> list[str]:
    lines = run((llvm_nm, flag, "--extern-only", str(artifact))).splitlines()
    symbols: list[str] = []
    for line in lines:
        fields = line.split()
        if fields and not line.endswith(":") and len(fields) >= 2:
            symbols.append(fields[-1])
    return sorted(set(symbols))


def elf_facts(llvm_readelf: str, object_path: pathlib.Path) -> dict[str, Any]:
    header = run((llvm_readelf, "--file-header", str(object_path)))
    required_header = (
        "Class:                             ELF64",
        "Data:                              2's complement, little endian",
        "Type:                              REL (Relocatable file)",
        "Machine:                           AArch64",
    )
    missing = [line for line in required_header if line not in header]
    if missing:
        raise BuildError(f"object is not a Linux/AArch64 ELF relocatable: {missing!r}")
    sections = run((llvm_readelf, "--sections", str(object_path)))
    forbidden = [section for section in FORBIDDEN_SECTIONS if section in sections]
    if forbidden:
        raise BuildError(f"unwind section is forbidden in compiler helper object: {forbidden!r}")
    return {
        "class": "ELF64",
        "data": "little-endian",
        "type": "REL",
        "machine": "AArch64",
        "sections": [line.strip() for line in sections.splitlines() if "]" in line],
    }


def ensure_no_absolute_build_paths(archive: pathlib.Path, paths: Sequence[pathlib.Path]) -> None:
    data = archive.read_bytes()
    for path in paths:
        raw = os.fsencode(str(path.resolve()))
        if raw and raw in data:
            raise BuildError(f"archive contains an absolute build path: {path}")


def assert_symbol_surface(defined: Sequence[str]) -> None:
    missing = sorted(set(EXPECTED_SYMBOLS).difference(defined))
    if missing:
        raise BuildError(f"archive is missing required C compiler helpers: {missing!r}")
    rejected: list[str] = []
    for symbol in defined:
        # These are Rust implementation details kept externally visible only
        # for cross-codegen-unit references. They are not C ABI exports, so a
        # mangled implementation named ``memcpy`` cannot shadow crabc libc.
        if symbol.startswith("_R") or symbol.startswith("anon.") or symbol.startswith("DW.ref.") or symbol.startswith(".L"):
            continue
        if any(token in symbol for token in FORBIDDEN_EXPORT_TOKENS):
            rejected.append(symbol)
            continue
        if symbol.startswith("__") or symbol in APPROVED_COMPATIBILITY_EXPORTS:
            continue
        rejected.append(symbol)
    if rejected:
        raise BuildError(f"archive exports an unclassified non-Rust helper symbol: {sorted(rejected)!r}")


def closure_undefined_symbols(llvm_nm: str, lld: str, archive: pathlib.Path, stage: pathlib.Path) -> list[str]:
    """Resolve every member once to distinguish internal from external U refs."""

    closure = stage / "all-helpers.o"
    run((lld, "-r", "--whole-archive", str(archive), "--no-whole-archive", "-o", str(closure)))
    undefined = nm_symbols(llvm_nm, closure, "--undefined-only")
    if undefined:
        raise BuildError(f"compiler helper archive requests another runtime after closure: {undefined!r}")
    return undefined


def build_archive(
    *,
    rustc: Sequence[str],
    cargo: Sequence[str],
    llvm_ar: str,
    llvm_nm: str,
    llvm_readelf: str,
    lld: str,
    output: pathlib.Path,
) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="crabc-builtins-", dir=output.parent) as temporary:
        stage = pathlib.Path(temporary)
        local_object = stage / ARCHIVE_MEMBER
        local_command = compiler_command(rustc, local_object)
        run(local_command)
        upstream = source_build_compiler_builtins(cargo=cargo, rustc=rustc, llvm_ar=llvm_ar, stage=stage)
        objects = [local_object, *upstream["members"]]
        member_facts = {path.name: elf_facts(llvm_readelf, path) for path in objects}
        staged_archive = stage / output.name
        run((llvm_ar, "rcsD", str(staged_archive), *(str(path) for path in objects)))
        members = archive_members(llvm_ar, staged_archive)
        defined = nm_symbols(llvm_nm, staged_archive, "--defined-only")
        assert_symbol_surface(defined)
        member_undefined = nm_symbols(llvm_nm, staged_archive, "--undefined-only")
        undefined = closure_undefined_symbols(llvm_nm, lld, staged_archive, stage)
        ensure_no_absolute_build_paths(staged_archive, (ROOT, stage, upstream_package_root(rustc)))
        shutil.copyfile(staged_archive, output)
        upstream_member_paths = [
            f"$CRABC_BUILTINS_STAGE/compiler-builtins-members/{path.name}"
            for path in upstream["members"]
        ]
        operations = [
            {
                "kind": "compile_local_helpers",
                "command": portable_local_rustc_command(local_command, local_object),
            },
            {
                "kind": "source_build_compiler_builtins",
                "command": upstream["portable_command"],
                "rustflags": upstream["rustflags"],
                "audit": upstream["native_build_audit"],
            },
            {
                "kind": "extract_source_built_members",
                "command": [
                    pathlib.Path(llvm_ar).name,
                    "x",
                    "$CRABC_BUILTINS_STAGE/source-build-target/"
                    f"{TARGET}/release/deps/{upstream['source_built_rlib_name']}",
                ],
            },
            {
                "kind": "create_deterministic_archive",
                "command": [
                    pathlib.Path(llvm_ar).name,
                    "rcsD",
                    f"$CRABC_BUILTINS_OUT/{output.name}",
                    "$CRABC_BUILTINS_STAGE/crabc-builtins.o",
                    *upstream_member_paths,
                ],
            },
            {
                "kind": "audit_archive_surface",
                "commands": [
                    [pathlib.Path(llvm_ar).name, "t", f"$CRABC_BUILTINS_OUT/{output.name}"],
                    [pathlib.Path(llvm_nm).name, "--defined-only", "--extern-only", f"$CRABC_BUILTINS_OUT/{output.name}"],
                    [pathlib.Path(llvm_nm).name, "--undefined-only", "--extern-only", f"$CRABC_BUILTINS_OUT/{output.name}"],
                    [
                        pathlib.Path(lld).name,
                        "-r",
                        "--whole-archive",
                        f"$CRABC_BUILTINS_OUT/{output.name}",
                        "--no-whole-archive",
                        "-o",
                        "$CRABC_BUILTINS_STAGE/all-helpers.o",
                    ],
                ],
            },
        ]
        return {
            "archive_sha256": sha256(output),
            "members": members,
            "defined_symbols": defined,
            "member_undefined_symbols": member_undefined,
            "undefined_symbols": undefined,
            "member_elf": member_facts,
            "local_rustc_command": local_command,
            "portable_local_rustc_command": portable_local_rustc_command(local_command, local_object),
            "source_build": upstream,
            "producer_operations": operations,
        }


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    path.write_text(rendered, encoding="utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True, help="output libcrabc-builtins.a path")
    parser.add_argument("--provenance", type=pathlib.Path, help="deterministic adjacent JSON provenance path")
    parser.add_argument("--llvm-ar", default="llvm-ar", help="LLVM archive tool")
    parser.add_argument("--llvm-nm", default="llvm-nm", help="LLVM symbol inspector")
    parser.add_argument("--llvm-readelf", default="llvm-readelf", help="LLVM ELF inspector")
    parser.add_argument("--ld-lld", default="ld.lld", help="LLVM linker used for archive-closure audit")
    parser.add_argument(
        "--verify-reproducible",
        action="store_true",
        help="perform a second clean source build and require identical archive bytes",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    output = arguments.output.resolve()
    if output.name != "libcrabc-builtins.a":
        raise BuildError("the installed helper archive name must be libcrabc-builtins.a")
    provenance_path = (arguments.provenance or output.with_suffix(output.suffix + ".provenance.json")).resolve()
    rustc = pinned_rustc()
    cargo = pinned_cargo()
    llvm_ar = require_tool(arguments.llvm_ar)
    llvm_nm = require_tool(arguments.llvm_nm)
    llvm_readelf = require_tool(arguments.llvm_readelf)
    lld = require_tool(arguments.ld_lld)
    sources = audit_source()
    configuration = target_contract(rustc)
    archive = build_archive(
        rustc=rustc,
        cargo=cargo,
        llvm_ar=llvm_ar,
        llvm_nm=llvm_nm,
        llvm_readelf=llvm_readelf,
        lld=lld,
        output=output,
    )

    reproducible = None
    if arguments.verify_reproducible:
        with tempfile.TemporaryDirectory(
            prefix="crabc-builtins-repro-", dir=output.parent
        ) as temporary:
            comparison = pathlib.Path(temporary) / "libcrabc-builtins.a"
            comparison_archive = build_archive(
                rustc=rustc,
                cargo=cargo,
                llvm_ar=llvm_ar,
                llvm_nm=llvm_nm,
                llvm_readelf=llvm_readelf,
                lld=lld,
                output=comparison,
            )
            reproducible = archive["archive_sha256"] == comparison_archive["archive_sha256"]
            if not reproducible:
                raise BuildError("clean helper archive builds produced different SHA-256 values")

    source_build = archive["source_build"]
    commands_path = output.with_suffix(output.suffix + ".commands.json")
    exact_command_record = {
        "schema": 1,
        "archive": output.name,
        "operations": archive["producer_operations"],
    }
    write_json(commands_path, exact_command_record)
    provenance = {
        "archive": {
            "name": output.name,
            "sha256": archive["archive_sha256"],
            "members": archive["members"],
            "defined_symbols": archive["defined_symbols"],
            "member_undefined_symbols": archive["member_undefined_symbols"],
            "undefined_symbols": archive["undefined_symbols"],
            "member_elf": archive["member_elf"],
        },
        "build": {
            "rustc_version": run((*rustc, "--version")).strip(),
            "cargo_version": run((*cargo, "--version")).strip(),
            "exact_command_record": {
                "name": commands_path.name,
                "sha256": sha256(commands_path),
            },
            "rust_toolchain": rustc[2],
            "target_cfg": configuration,
            "codegen": {
                "panic": "abort",
                "unwind_tables": "disabled",
                "target_feature": "-outline-atomics",
                "source_built_standard_components": list(UPSTREAM_SOURCE_BUILD_COMPONENTS),
            },
            "reproducible": reproducible,
        },
        "component": {
            "name": "crabc-builtins",
            "target": TARGET,
            "archive_member": ARCHIVE_MEMBER,
        },
        "dependency_purity": {
            "cargo_dependencies": [],
            "build_dependencies": [],
            "links": False,
            "uses_alloc": False,
            "uses_unwinding": False,
            "requires_panic_runtime": False,
            "uses_native_source": False,
            "uses_native_assembly": False,
            "upstream_source_build": {
                "package": UPSTREAM_PACKAGE,
                "version": UPSTREAM_VERSION,
                "links_metadata": "compiler-rt",
                "selected_features": source_build["selected_features"],
                "disabled_features": ["c", "mem"],
                "native_build_commands": source_build["native_build_audit"]["native_build_commands"],
                "target_link_directives": source_build["native_build_audit"]["target_link_directives"],
                "prebuilt_compiler_builtins_input": False,
                "source_built_standard_components": source_build["source_build"],
                "source_built_rlib_sha256": source_build["source_built_rlib_sha256"],
            },
        },
        "source": {
            "languages": ["Rust"],
            "files": sources,
            "upstream_package_manifest": source_build["package_manifest"],
            "upstream_build_script": source_build["build_script"],
            "upstream_build_script_inputs": source_build["build_script_inputs"],
            "upstream_rust_src_lock": source_build["rust_src_lock"],
            "upstream_selected_files": source_build["source_files"],
        },
    }
    write_json(provenance_path, provenance)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        print(f"crabc-builtins: {error}", file=sys.stderr)
        raise SystemExit(1)
