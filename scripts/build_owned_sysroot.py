#!/usr/bin/env python3
"""Build, assemble, and prove the crabc-owned application sysroot.

This is the native Docker-side implementation behind ``scripts/dev.sh
sysroot``. It deliberately performs two fresh production builds in separate
disposable build directories. Rust path remapping keeps their installed output
reproducible while the distinct roots prove that no object or absolute build
path was accidentally reused.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target"
PRIMARY_BUILD_ROOT = TARGET / "crabc-sysroot-build-primary"
COMPARISON_BUILD_ROOT = TARGET / "crabc-sysroot-build-comparison"
PRIMARY_SYSROOT = TARGET / "crabc-sysroot"
COMPARISON_SYSROOT = TARGET / "crabc-sysroot-repro"
REPORT = ROOT / "compat/reports/sysroot/latest.json"
TARGET_TRIPLE = "aarch64-unknown-linux-musl"
CANONICAL_INTERPRETER = "/lib/ld-crabc-aarch64.so.1"
RUNTIME_RUSTFLAGS = (
    "-C",
    "link-dead-code",
    "-C",
    "target-feature=-crt-static,-outline-atomics",
    # The private crabc-mimalloc lifecycle roots are part of libc's startup
    # image. Rust has no per-static TLS-model annotation, so preserve the
    # native runtime's initial-exec contract even though this builder replaces
    # Cargo's config rustflags with its sealed reproducible environment.
    "-Ztls-model=initial-exec",
)
RUNTIME_CFLAGS_KEY = "CFLAGS_aarch64_unknown_linux_musl"
RUNTIME_CFLAGS = "-mno-outline-atomics"
RUNTIME_LIFECYCLE_TLS_SYMBOL = re.compile(
    r"crabc_mimalloc.*runtime_lifecycle.*THREAD_LIFECYCLE"
)
RUNTIME_LIFECYCLE_TLS_RELOCATIONS = (
    "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21",
    "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC",
)
RUNTIME_LIFECYCLE_TLS_FORBIDDEN_FORMS = (
    "TLSDESC",
    "TLSGD",
    "TLSLD",
    "DTPMOD",
    "DTPREL",
    "__tls_get_addr",
)

# Cargo's `staticlib` emitter embeds the target's stock compiler-builtins and
# its native compiler-rt fallbacks even though the installed C driver owns a
# separately audited Rust-only helper archive.  The installed libc archive is
# deliberately reconstructed from the two runtime roots below: crabc's Rust
# libc object and the current native mimalloc object.  The latter remains the
# explicitly recorded full-runtime-purity blocker; no compiler-rt member is
# allowed to cross this archive boundary.
LIBC_RUNTIME_MEMBER = re.compile(r"^c\.c\.[0-9a-f]+-cgu\.[0-9]+\.rcgu\.o$")
NATIVE_ALLOCATOR_MEMBER = re.compile(r"^[0-9a-f]+-static\.o$")
NATIVE_COMPILER_RT_MEMBER = re.compile(
    r"^[0-9a-f]+-(?:aarch64|lse_(?:cas|swp|ldadd|ldclr|ldeor|ldset)[0-9]+_(?:relax|acq|rel|acq_rel)|"
    r"(?:absv|addv|cmp|div|ffs|fp_mode|int_util|mul|neg|parity|popcount|subv|ucmp)[a-z0-9_]*)(?:\.o)$"
)


class BuildError(RuntimeError):
    """A production build or evidence boundary failed."""


@dataclasses.dataclass(frozen=True)
class StaticRuntimeArchiveSelection:
    """The only Cargo-staticlib members permitted in installed ``libc.a``."""

    runtime_member: str
    allocator_member: str
    excluded_members: tuple[str, ...]

    @property
    def selected_members(self) -> tuple[str, str]:
        return (self.runtime_member, self.allocator_member)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def repository_source_identity() -> dict[str, object]:
    """Bind generated evidence to the exact checked-out source inputs.

    The working tree is intentionally allowed to be dirty while this command
    runs.  Hashing tracked and non-ignored untracked regular files therefore
    records the actual sources consumed by both production builds instead of
    merely naming the repository's last commit.
    """

    environment = deterministic_environment()
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.decode("ascii").strip()
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
    except (OSError, subprocess.CalledProcessError) as error:
        raise BuildError("cannot bind sysroot evidence to the source tree") from error

    tracked_paths = {Path(value.decode("utf-8")) for value in tracked if value}
    untracked_paths = {Path(value.decode("utf-8")) for value in untracked if value}
    files = sorted(tracked_paths | untracked_paths)
    digest = hashlib.sha256()
    included = 0
    for relative in files:
        path = ROOT / relative
        if not path.is_file() and not path.is_symlink():
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8"))
        else:
            digest.update(b"file\0")
            digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
        included += 1
    return {
        "git_head": head,
        "tree_sha256": digest.hexdigest(),
        "tracked_file_count": len(tracked_paths),
        "untracked_file_count": len(untracked_paths),
        "hashed_file_count": included,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def deterministic_environment() -> dict[str, str]:
    environment = dict(os.environ)
    # The C wrapper itself seals all target search variables. Removing them
    # here as well keeps production artifact construction independent from a
    # developer shell that happens to point at another sysroot.
    for key in (
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "LIBRARY_PATH",
        "COMPILER_PATH",
        "GCC_EXEC_PREFIX",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CC",
        "CFLAGS",
        "CXX",
        "CXXFLAGS",
        "CPPFLAGS",
        "AR",
        "ARFLAGS",
    ):
        environment.pop(key, None)
    for key in tuple(environment):
        if key.startswith("CARGO_TARGET_") and key.endswith(("_LINKER", "_RUSTFLAGS")):
            environment.pop(key, None)
        if key.startswith(("CC_", "CFLAGS_", "CXX_", "CXXFLAGS_", "AR_", "ARFLAGS_")):
            environment.pop(key, None)
    # Cargo artifacts are produced under two deliberately different target
    # roots below. Keep paths from either tree out of object/debug metadata so
    # the installed comparison proves reproducibility rather than path reuse.
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join((*RUNTIME_RUSTFLAGS, f"--remap-path-prefix={ROOT}=/crabc"))
    # The native allocator is the only temporary non-Rust runtime component.
    # Keep its AArch64 atomics inline so Rust's normal target archive cannot
    # smuggle compiler-rt's external LSE assembly into a static application.
    environment[RUNTIME_CFLAGS_KEY] = RUNTIME_CFLAGS
    environment.update({"SOURCE_DATE_EPOCH": "0", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    return environment


def select_static_runtime_members(members: Sequence[str]) -> StaticRuntimeArchiveSelection:
    """Select the explicit installed ``libc.a`` roots from Cargo's staticlib.

    The regular Cargo staticlib is an intermediate producer. It carries a
    large stock compiler-builtins closure and native compiler-rt fallbacks
    whose symbols would otherwise win before `libcrabc-builtins.a` on a C
    static link.  Keep only the crabc Rust runtime object and the one known
    native allocator object. Reject unfamiliar members instead of silently
    dropping a new runtime dependency.
    """

    names = tuple(members)
    if not names or len(names) != len(set(names)):
        raise BuildError("Cargo libc.a must contain a non-empty, unique member list")
    runtime = tuple(name for name in names if LIBC_RUNTIME_MEMBER.fullmatch(name))
    allocator = tuple(name for name in names if NATIVE_ALLOCATOR_MEMBER.fullmatch(name))
    if len(runtime) != 1:
        raise BuildError(f"Cargo libc.a must contain exactly one crabc Rust runtime member, found {runtime!r}")
    if len(allocator) != 1:
        raise BuildError(f"Cargo libc.a must contain exactly one native allocator member, found {allocator!r}")
    selected = {runtime[0], allocator[0]}
    unclassified = [
        name
        for name in names
        if name not in selected and not name.startswith("compiler_builtins-") and not NATIVE_COMPILER_RT_MEMBER.fullmatch(name)
    ]
    if unclassified:
        raise BuildError(
            "Cargo libc.a introduced unclassified transitive runtime members: " + ", ".join(unclassified)
        )
    excluded = tuple(name for name in names if name not in selected)
    if not any(name.startswith("compiler_builtins-") for name in excluded):
        raise BuildError("Cargo libc.a did not expose the stock compiler-builtins members this boundary must exclude")
    if not any(NATIVE_COMPILER_RT_MEMBER.fullmatch(name) for name in excluded):
        raise BuildError("Cargo libc.a did not expose the native compiler-rt members this boundary must exclude")
    return StaticRuntimeArchiveSelection(runtime[0], allocator[0], excluded)


def _archive_member_symbols(llvm_nm: str, member: Path, records: list[dict[str, object]]) -> list[str]:
    output = run_checked([llvm_nm, "--defined-only", "--extern-only", str(member)], records)
    symbols: list[str] = []
    for line in output.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if fields and not line.endswith(":") and len(fields) >= 2:
            symbols.append(fields[-1])
    return sorted(set(symbols))


def audit_static_runtime_lifecycle_tls(
    readelf: str,
    member: Path,
    records: list[dict[str, object]],
) -> dict[str, object]:
    """Bind the selected static Rust root to the private IE lifecycle TLS.

    Release fat-LTO deliberately merges crabc-mimalloc into libc's one Rust
    archive member.  Symbol membership alone would not prove that the private
    pthread lifecycle survived that merge with its required TLS access model.
    Keep the proof at this exact post-LTO object boundary.
    """

    symbols = run_checked([readelf, "-sW", str(member)], records).decode("utf-8", errors="replace")
    matches = [line for line in symbols.splitlines() if RUNTIME_LIFECYCLE_TLS_SYMBOL.search(line)]
    if len(matches) != 1:
        raise BuildError(
            "selected Rust libc member must contain exactly one private "
            f"runtime lifecycle TLS symbol, found {matches!r}"
        )
    fields = matches[0].split()
    # readelf's wide symbol-table row is: index:, value, size, type, bind,
    # visibility, section, name. The symbol is deliberately local in the
    # static root; it is not an installed C ABI.
    if len(fields) != 8 or fields[3:6] != ["TLS", "LOCAL", "DEFAULT"]:
        raise BuildError(f"runtime lifecycle TLS symbol has wrong binding: {matches[0]}")
    try:
        size = int(fields[2])
    except ValueError as error:
        raise BuildError(f"runtime lifecycle TLS symbol has invalid size: {matches[0]}") from error
    if size == 0:
        raise BuildError("runtime lifecycle TLS symbol must have nonzero storage")
    symbol_name = fields[7]

    relocations = run_checked([readelf, "-rW", str(member)], records).decode("utf-8", errors="replace")
    root_relocations = [line for line in relocations.splitlines() if symbol_name in line]
    observed = {
        relocation
        for relocation in RUNTIME_LIFECYCLE_TLS_RELOCATIONS
        if any(relocation in line for line in root_relocations)
    }
    if observed != set(RUNTIME_LIFECYCLE_TLS_RELOCATIONS):
        raise BuildError(
            "runtime lifecycle TLS root lacks its complete initial-exec relocation pair: "
            + ", ".join(sorted(set(RUNTIME_LIFECYCLE_TLS_RELOCATIONS) - observed))
        )
    forbidden = [
        form
        for form in RUNTIME_LIFECYCLE_TLS_FORBIDDEN_FORMS
        if any(form in line for line in root_relocations)
    ]
    if forbidden:
        raise BuildError(
            "runtime lifecycle TLS root uses a forbidden dynamic access form: " + ", ".join(forbidden)
        )
    return {
        "access_model": "initial-exec",
        "symbol": {
            "name": symbol_name,
            "size": size,
            "type": "TLS",
            "binding": "LOCAL",
            "visibility": "DEFAULT",
        },
        "required_relocations": list(RUNTIME_LIFECYCLE_TLS_RELOCATIONS),
        "forbidden_tls_forms": [],
    }


def rebuild_static_runtime_archive(
    source: Path,
    output: Path,
    records: list[dict[str, object]],
) -> tuple[Path, Path, Path]:
    """Create the deterministic, compiler-rt-free installed static libc archive.

    The raw Cargo archive is preserved only beneath the disposable build root.
    The generated provenance binds the installed archive to the selected
    members, their symbols, and the rejected stock compiler-runtime closure.
    """

    cargo_staticlib = source.resolve()
    if not cargo_staticlib.is_file():
        raise BuildError(f"Cargo did not produce libc.a: {cargo_staticlib}")
    llvm_ar = shutil.which("llvm-ar")
    llvm_nm = shutil.which("llvm-nm")
    readelf = shutil.which("readelf")
    if llvm_ar is None or llvm_nm is None or readelf is None:
        raise BuildError("llvm-ar, llvm-nm, and readelf are required to construct the owned static runtime archive")
    members_output = run_checked([llvm_ar, "t", str(cargo_staticlib)], records)
    members = [line for line in members_output.decode("utf-8", errors="replace").splitlines() if line]
    selection = select_static_runtime_members(members)

    output.parent.mkdir(parents=True, exist_ok=True)
    selected_member_records: list[dict[str, object]]
    with tempfile.TemporaryDirectory(prefix="crabc-static-runtime-", dir=output.parent) as temporary:
        stage = Path(temporary)
        run_checked(
            [llvm_ar, "x", str(cargo_staticlib), *selection.selected_members],
            records,
            cwd=stage,
        )
        selected_paths = tuple(stage / name for name in selection.selected_members)
        if any(not path.is_file() for path in selected_paths):
            raise BuildError("llvm-ar did not extract every selected static runtime member")
        runtime_symbols = _archive_member_symbols(llvm_nm, selected_paths[0], records)
        allocator_symbols = _archive_member_symbols(llvm_nm, selected_paths[1], records)
        if "__libc_start_main" not in runtime_symbols:
            raise BuildError("selected Rust libc member does not define __libc_start_main")
        if "mi_malloc" not in allocator_symbols:
            raise BuildError("selected allocator member does not define mimalloc's mi_malloc")
        runtime_lifecycle_tls = audit_static_runtime_lifecycle_tls(readelf, selected_paths[0], records)
        staged_archive = stage / output.name
        run_checked([llvm_ar, "rcsD", str(staged_archive), *(str(path) for path in selected_paths)], records)
        rebuilt_output = run_checked([llvm_ar, "t", str(staged_archive)], records)
        rebuilt_members = tuple(line for line in rebuilt_output.decode("utf-8", errors="replace").splitlines() if line)
        if rebuilt_members != selection.selected_members:
            raise BuildError(f"rebuilt libc.a has the wrong member order: {rebuilt_members!r}")
        selected_member_records = [
            {
                "role": "crabc_rust_runtime",
                "name": selection.runtime_member,
                "sha256": sha256_file(selected_paths[0]),
                "required_symbol": "__libc_start_main",
                "defined_symbols": runtime_symbols,
            },
            {
                "role": "native_allocator_exception",
                "name": selection.allocator_member,
                "sha256": sha256_file(selected_paths[1]),
                "required_symbol": "mi_malloc",
                "defined_symbols": allocator_symbols,
            },
        ]
        shutil.copyfile(staged_archive, output)

    commands_path = output.with_suffix(output.suffix + ".commands.json")
    provenance_path = output.with_suffix(output.suffix + ".provenance.json")
    portable_source = "$CRABC_CARGO_RUNTIME/libc.a"
    portable_output = f"$CRABC_STATIC_RUNTIME/{output.name}"
    operations: list[dict[str, object]] = [
        {
            "kind": "enumerate_cargo_staticlib_members",
            "command": [Path(llvm_ar).name, "t", portable_source],
            "members": members,
        },
        {
            "kind": "extract_selected_runtime_members",
            "command": [Path(llvm_ar).name, "x", portable_source, *selection.selected_members],
            "selected_members": list(selection.selected_members),
        },
        {
            "kind": "create_deterministic_static_runtime_archive",
            "command": [
                Path(llvm_ar).name,
                "rcsD",
                portable_output,
                *(f"$CRABC_STATIC_RUNTIME/members/{name}" for name in selection.selected_members),
            ],
        },
        {
            "kind": "audit_selected_runtime_members",
            "commands": [
                [Path(llvm_ar).name, "t", portable_output],
                [Path(llvm_nm).name, "--defined-only", "--extern-only", f"$CRABC_STATIC_RUNTIME/members/{selection.runtime_member}"],
                [Path(llvm_nm).name, "--defined-only", "--extern-only", f"$CRABC_STATIC_RUNTIME/members/{selection.allocator_member}"],
                [Path(readelf).name, "-sW", f"$CRABC_STATIC_RUNTIME/members/{selection.runtime_member}"],
                [Path(readelf).name, "-rW", f"$CRABC_STATIC_RUNTIME/members/{selection.runtime_member}"],
            ],
        },
    ]
    commands = {"schema": 1, "archive": output.name, "operations": operations}
    write_json(commands_path, commands)
    provenance = {
        "schema": 1,
        "component": {"name": "crabc-libc-static", "target": TARGET_TRIPLE},
        "archive": {
            "name": output.name,
            "sha256": sha256_file(output),
            "members": selected_member_records,
        },
        "source_staticlib": {"sha256": sha256_file(cargo_staticlib), "member_count": len(members)},
        "excluded_members": {
            "all": list(selection.excluded_members),
            "stock_compiler_builtins": [name for name in selection.excluded_members if name.startswith("compiler_builtins-")],
            "native_compiler_rt": [name for name in selection.excluded_members if NATIVE_COMPILER_RT_MEMBER.fullmatch(name)],
        },
        "native_allocator_exception": {
            "status": "blocked_by_native_allocator",
            "member": selection.allocator_member,
            "reason": "libmimalloc-sys remains the separately tracked full-runtime-purity blocker",
        },
        "runtime_lifecycle_tls": runtime_lifecycle_tls,
        "build": {
            "runtime_rustflags": list(RUNTIME_RUSTFLAGS),
            "runtime_cflags": {RUNTIME_CFLAGS_KEY: RUNTIME_CFLAGS},
            "exact_command_record": {"name": commands_path.name, "sha256": sha256_file(commands_path)},
        },
    }
    write_json(provenance_path, provenance)
    return output, provenance_path, commands_path


def run_checked(command: Sequence[str], records: list[dict[str, object]], *, cwd: Path = ROOT) -> bytes:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=deterministic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    record = {
        "command": list(command),
        "status": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }
    records.append(record)
    if completed.returncode != 0:
        rendered = " ".join(command)
        raise BuildError(
            f"command failed ({completed.returncode}): {rendered}\n"
            f"stdout:\n{completed.stdout.decode(errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode(errors='replace')}"
        )
    return completed.stdout


def remove_generated_build_root(build_root: Path) -> None:
    """Remove only this tool's exact disposable build directory."""

    if not build_root.exists():
        return
    if build_root.is_symlink() or not build_root.is_dir():
        raise BuildError(f"refusing to remove non-directory generated build root: {build_root}")
    shutil.rmtree(build_root)


def remove_owned_sysroot(path: Path) -> None:
    """Replace only a prior sysroot marked with crabc's installed manifest."""

    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise BuildError(f"refusing to replace non-directory sysroot output: {path}")
    manifest = path / "share/crabc/manifest.json"
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BuildError(f"refusing to replace unrecognized existing sysroot: {path}") from error
    if value.get("target") != TARGET_TRIPLE or value.get("canonical_interpreter") != CANONICAL_INTERPRETER:
        raise BuildError(f"refusing to replace unrecognized existing sysroot: {path}")
    shutil.rmtree(path)


def assert_native_target() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise BuildError("owned sysroot production evidence requires native Linux/AArch64")


def build_once(output: Path, build_root: Path) -> dict[str, object]:
    """Perform one clean runtime build and assemble exactly one sysroot."""

    remove_generated_build_root(build_root)
    build_root.mkdir(parents=True)
    records: list[dict[str, object]] = []
    cargo = shutil.which("cargo")
    if cargo is None:
        raise BuildError("cargo is unavailable")
    python = sys.executable
    cargo_target = build_root / "cargo"
    run_checked(
        [cargo, "build", "--workspace", "--release", "--locked", "--target-dir", str(cargo_target)], records
    )
    root_metadata = run_checked([cargo, "metadata", "--locked", "--format-version", "1"], records)
    builtins_metadata = run_checked(
        [cargo, "metadata", "--locked", "--format-version", "1", "--manifest-path", "builtins/Cargo.toml"], records
    )
    root_metadata_path = build_root / "cargo-metadata.json"
    builtins_metadata_path = build_root / "builtins-cargo-metadata.json"
    root_metadata_path.write_bytes(root_metadata)
    builtins_metadata_path.write_bytes(builtins_metadata)

    crt_dir = build_root / "crt"
    run_checked([python, "crt/build.py", "--out-dir", str(crt_dir)], records)
    builtins_dir = build_root / "builtins"
    builtins_archive = builtins_dir / "libcrabc-builtins.a"
    run_checked(
        [python, "builtins/build.py", "--output", str(builtins_archive), "--verify-reproducible"], records
    )
    builtins_provenance = builtins_archive.with_suffix(".a.provenance.json")
    builtins_commands = builtins_archive.with_suffix(".a.commands.json")
    if not builtins_provenance.is_file():
        raise BuildError(f"compiler-helper builder did not write provenance: {builtins_provenance}")
    if not builtins_commands.is_file():
        raise BuildError(f"compiler-helper builder did not write producer-command record: {builtins_commands}")
    if not (crt_dir / "commands.json").is_file():
        raise BuildError(f"CRT builder did not write producer-command record: {crt_dir / 'commands.json'}")

    runtime = cargo_target / "release"
    static_runtime, static_runtime_provenance, static_runtime_commands = rebuild_static_runtime_archive(
        runtime / "libc.a",
        build_root / "static-runtime" / "libc.a",
        records,
    )
    remove_owned_sysroot(output)
    assembly = [
        python,
        "scripts/crabc_sysroot.py",
        "assemble",
        "--output",
        str(output),
        "--include-dir",
        "include",
        "--libc-shared",
        str(runtime / "libc.so"),
        "--libc-static",
        str(static_runtime),
        "--libc-static-provenance",
        str(static_runtime_provenance),
        "--libc-static-commands",
        str(static_runtime_commands),
        "--loader",
        str(runtime / "libldso.so"),
        "--crt-dir",
        str(crt_dir),
        "--crt-provenance",
        str(crt_dir / "objects.json"),
        "--crt-commands",
        str(crt_dir / "commands.json"),
        "--builtins",
        str(builtins_archive),
        "--builtins-provenance",
        str(builtins_provenance),
        "--builtins-commands",
        str(builtins_commands),
        "--runtime-source-root",
        "libc/src",
        "--runtime-source-root",
        "ldso/src",
        "--runtime-source-root",
        "crabc-mimalloc/src",
        "--runtime-source-root",
        "crt/src",
        "--runtime-source-root",
        "builtins/src",
        "--cargo-manifest",
        "libc/Cargo.toml",
        "--cargo-manifest",
        "ldso/Cargo.toml",
        "--cargo-manifest",
        "crabc-mimalloc/Cargo.toml",
        "--cargo-manifest",
        "crt/Cargo.toml",
        "--cargo-manifest",
        "builtins/Cargo.toml",
        "--cargo-metadata",
        str(root_metadata_path),
        "--cargo-metadata",
        str(builtins_metadata_path),
    ]
    run_checked(assembly, records)
    record_path = build_root / "build-record.json"
    write_json(record_path, {"schema": 1, "commands": records})

    purity_path = output / "share/crabc/purity.json"
    purity = json.loads(purity_path.read_text(encoding="utf-8"))
    if purity.get("crt_sysroot_pure_rust") is not True:
        raise BuildError("assembled sysroot did not satisfy the CRT/sysroot purity contract")
    if purity.get("full_runtime_pure_rust") is False and purity.get("full_runtime_purity_status") != "blocked_by_native_allocator":
        raise BuildError("full-runtime purity is false for an undocumented reason")
    return {
        "output": str(output),
        "build_record": str(record_path),
        "runtime": {
            name: {
                "path": str(static_runtime if name == "libc.a" else runtime / name),
                "sha256": sha256_file(static_runtime if name == "libc.a" else runtime / name),
            }
            for name in ("libc.so", "libc.a", "libldso.so")
        },
        "purity": purity,
    }


def regular_file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def write_reproducibility_status(outputs: Sequence[Path]) -> None:
    """Record the successful clean comparison identically in both trees."""

    for output in outputs:
        purity_path = output / "share/crabc/purity.json"
        purity = json.loads(purity_path.read_text(encoding="utf-8"))
        purity["reproducible"] = {
            "status": "passed",
            "method": "two clean production builds in separate roots with remapped source paths",
        }
        write_json(purity_path, purity)
    first, second = (regular_file_hashes(output) for output in outputs)
    differences = sorted(key for key in set(first) | set(second) if first.get(key) != second.get(key))
    if differences:
        raise BuildError("post-report sysroot trees diverged: " + ", ".join(differences))


def run_focused_contract_tests(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Run the producer/driver parser tests inside the pinned native image."""

    commands = (
        (
            "sysroot_driver_and_evidence_parsers",
            [sys.executable, "compat/sysroot/tests/test_runner.py"],
        ),
        (
            "owned_static_runtime_archive_contracts",
            [sys.executable, "scripts/tests/test_build_owned_sysroot.py"],
        ),
        (
            "docker_source_mount_git_ownership",
            [sys.executable, "scripts/tests/test_dev_container.py"],
        ),
        (
            "sysroot_release_workflow_shell",
            [sys.executable, "scripts/tests/test_sysroot_workflow.py"],
        ),
        (
            "crt_object_contracts",
            [sys.executable, "crt/tests/test_build.py"],
        ),
        (
            "crt_static_pie_contracts",
            [sys.executable, "crt/tests/test_static_pie_link.py"],
        ),
        (
            "builtins_source_contracts",
            [sys.executable, "builtins/tests/test_build.py"],
        ),
        (
            "builtins_link_contracts",
            [sys.executable, "builtins/tests/test_link.py"],
        ),
    )
    evidence: list[dict[str, object]] = []
    for name, command in commands:
        run_checked(command, records)
        evidence.append({"name": name, **records[-1]})
    return evidence


def bind_report_evidence(
    report: dict[str, object],
    first: dict[str, object],
    second: dict[str, object],
    focused_tests: Sequence[dict[str, object]],
    static_pthread_record: dict[str, object],
) -> None:
    """Attach production and supplemental proof without weakening report status."""

    production_builds: list[dict[str, object]] = []
    for name, result in (("primary", first), ("comparison", second)):
        record_path = Path(str(result["build_record"]))
        if not record_path.is_file():
            raise BuildError(f"missing {name} source-bound build record: {record_path}")
        runtime = result.get("runtime")
        if not isinstance(runtime, dict):
            raise BuildError(f"{name} build record lacks runtime hashes")
        production_builds.append(
            {
                "name": name,
                "build_record": {"path": str(record_path), "sha256": sha256_file(record_path)},
                "runtime": runtime,
            }
        )

    static_report = ROOT / "compat/reports/static-pthread-tls/latest.json"
    if not static_report.is_file():
        raise BuildError("static pthread/TLS runner did not write its report")
    try:
        static_result = json.loads(static_report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BuildError("static pthread/TLS report is invalid JSON") from error
    if static_result.get("passed") is not True:
        raise BuildError("static pthread/TLS candidate evidence is not passing")

    report["source_identity"] = repository_source_identity()
    report["production_builds"] = production_builds
    report["supplementary_evidence"] = {
        "focused_contract_tests": list(focused_tests),
        "static_pthread_tls": {
            "command": static_pthread_record,
            "report": str(static_report),
            "sha256": sha256_file(static_report),
            "passed": True,
        },
    }


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--no-stage-canonical-loader",
        action="store_true",
        help="diagnostic-only: omit the required normal-kernel interpreter execution proof",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        assert_native_target()
        if args.timeout <= 0 or args.timeout > 300:
            raise BuildError("--timeout must be > 0 and <= 300")
        first = build_once(PRIMARY_SYSROOT, PRIMARY_BUILD_ROOT)
        second = build_once(COMPARISON_SYSROOT, COMPARISON_BUILD_ROOT)
        evidence_records: list[dict[str, object]] = []
        focused_tests = run_focused_contract_tests(evidence_records)
        runner = [
            sys.executable,
            "compat/sysroot/run.py",
            "--sysroot",
            str(PRIMARY_SYSROOT),
            "--comparison-sysroot",
            str(COMPARISON_SYSROOT),
            "--report",
            str(REPORT),
            "--timeout",
            str(args.timeout),
        ]
        if not args.no_stage_canonical_loader:
            runner.append("--stage-canonical-loader")
        run_checked(runner, evidence_records)
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        if report.get("passed") is not True:
            raise BuildError("owned sysroot evidence report is not passing")
        write_reproducibility_status((PRIMARY_SYSROOT, COMPARISON_SYSROOT))
        static_pthread_command = [
            sys.executable,
            "compat/static-pthread-tls/run.py",
            "--sysroot",
            str(PRIMARY_SYSROOT),
            "--timeout",
            str(args.timeout),
        ]
        run_checked(static_pthread_command, evidence_records)
        report["purity"] = json.loads(
            (PRIMARY_SYSROOT / "share/crabc/purity.json").read_text(encoding="utf-8")
        )
        bind_report_evidence(report, first, second, focused_tests, evidence_records[-1])
        # The harness writes atomically; retain that property after binding
        # the producer and static-link evidence it intentionally does not own.
        report_path = REPORT
        temporary = report_path.with_name(f".{report_path.name}.{os.getpid()}.tmp")
        write_json(temporary, report)
        os.replace(temporary, report_path)
        print(
            json.dumps(
                {
                    "schema": 1,
                    "primary": first,
                    "comparison": second,
                    "report": str(REPORT),
                    "evidence_commands": evidence_records,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except BuildError as error:
        print(f"crabc-owned-sysroot: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
