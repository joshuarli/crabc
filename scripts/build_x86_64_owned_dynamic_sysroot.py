#!/usr/bin/env python3
"""Produce the native shared runtime, without ambient target inputs.

Tool attestation, header provenance and Cargo archive membership classification
are shared with the static producer. Final shared linkage is separate: every
member is explicit and the sole accepted foreign implementation is the pinned
existing C mimalloc backend. This is not dynamic-product campaign completion.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import stat
import sys
import re

sys.dont_write_bytecode = True
import build_x86_64_owned_sysroot as common

ROOT = common.ROOT
FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
LOADER_PROVENANCE_SCHEMA = "crabc.x86_64-owned-loader-provenance/v1"
LOADER_FEATURE = "x86_64-owned-dynamic-runtime"
LOADER_ARTIFACT = "lib/ld-crabc-x86_64.so.1"
LOADER_DEPENDENCY_ARTIFACT = "libldso.so"
# This is the checked byte-for-byte musl 1.2.6 `dynamic.list` input.  Musl
# configure adds it only to libc's shared link: public data remains available
# for copy relocations, and the listed allocation entrypoints deliberately
# remain interposable.  It is not a substitute for the source's explicit
# public versus hidden internal calls, and it must never be applied to the
# loader, application DSOs, or static archives.
SHARED_LIBC_DYNAMIC_LIST = ROOT / "libc/src/c_abi/x86_64/owned_dynamic.list"
MUSL_1_2_6_DYNAMIC_LIST_SHA256 = "264ae3bf630a7f6d894a51f91f9acae45b89a5f639537353d03af1a04e9da0f9"
MUSL_1_2_6_DYNAMIC_LIST_MEMBERS = (
    "environ", "__environ", "stdin", "stdout", "stderr",
    "malloc", "calloc", "realloc", "free", "memalign", "posix_memalign",
    "aligned_alloc", "malloc_usable_size",
    "timezone", "daylight", "tzname", "__timezone", "__daylight", "__tzname",
    "signgam", "__signgam", "optarg", "optind", "opterr", "optopt", "optreset",
    "__optreset", "getdate_err", "h_errno", "program_invocation_name",
    "program_invocation_short_name", "__progname", "__progname_full", "__stack_chk_guard",
)
MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS = (
    "malloc", "calloc", "realloc", "free", "memalign", "posix_memalign",
    "aligned_alloc", "malloc_usable_size",
)
MUSL_1_2_6_DYNAMIC_LIST_DATA_SYMBOLS = tuple(
    member for member in MUSL_1_2_6_DYNAMIC_LIST_MEMBERS
    if member not in MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS
)
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import crabc_cc_owned_dynamic as installed_driver
import owned_static_sysroot_package as shared_package
import owned_dynamic_qualification as qualification


def audit_shared_elf(path: Path) -> dict[str, str]:
    """The actual installed ELF must be self-contained and position independent."""
    dynamic = common.run(["/usr/bin/readelf", "-dW", str(path)]).decode()
    relocations = common.run(["/usr/bin/readelf", "-rW", str(path)]).decode()
    segments = common.run(["/usr/bin/readelf", "-lW", str(path)]).decode()
    if "(NEEDED)" in dynamic or "TEXTREL" in dynamic or "INTERP" in segments:
        raise common.BuildError(f"owned shared ELF has a foreign dependency/interpreter or text relocation: {path}")
    if re.search(r"\bR_X86_64_32S?\b", relocations):
        raise common.BuildError(f"owned shared ELF retains an absolute 32-bit relocation: {path}")
    if "GNU_RELRO" not in segments or not re.search(r"GNU_STACK.* RW +", segments):
        raise common.BuildError(f"owned shared ELF lacks RELRO or non-executable stack: {path}")
    return {"dynamic": dynamic, "relocations": relocations, "segments": segments}


def _source_file_identity(path: Path, description: str) -> dict[str, object]:
    """Record one physical source input by checkout-relative identity."""

    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise common.BuildError(f"{description} is missing or unsafe: {path}") from error
    source_root = ROOT.resolve()
    if (not stat.S_ISREG(details.st_mode) or path.is_symlink() or resolved != path
            or not resolved.is_relative_to(source_root)):
        raise common.BuildError(f"{description} is not a physical checkout file: {path}")
    return {
        "path": resolved.relative_to(source_root).as_posix(),
        "sha256": common.sha256_file(resolved),
        "mode": stat.S_IMODE(details.st_mode),
    }


def _normalized_loader_argument(argument: str, stage: Path) -> str:
    """Replace build-local prefixes without changing an arbitrary argument."""

    if argument.startswith("--dynamic-list="):
        return "--dynamic-list=" + _normalized_loader_argument(
            argument.removeprefix("--dynamic-list="), stage
        )
    for physical, replacement in ((stage.resolve(), "$BUILD"), (ROOT.resolve(), "$SOURCE")):
        spelling = str(physical)
        if argument == spelling:
            return replacement
        if argument.startswith(spelling + os.sep):
            return replacement + argument[len(spelling):]
    return argument


def shared_libc_dynamic_list() -> dict[str, object]:
    """Read only the pinned musl shared-libc interposition exception list.

    `--dynamic-list` has a deliberately narrow meaning here.  The ordinary
    exported functions bind locally within `libc.so`; listed data remains
    interposable for copy relocations, while the allocation family remains
    interposable as musl's explicit function exception.  The input is exact so
    a future change cannot silently widen either category.
    """

    identity = _source_file_identity(SHARED_LIBC_DYNAMIC_LIST, "native libc shared dynamic-list")
    if identity["sha256"] != MUSL_1_2_6_DYNAMIC_LIST_SHA256:
        raise common.BuildError("native libc shared dynamic-list differs from pinned musl 1.2.6")
    try:
        text = SHARED_LIBC_DYNAMIC_LIST.read_text(encoding="utf-8")
    except OSError as error:
        raise common.BuildError("native libc shared dynamic-list cannot be read") from error
    if re.fullmatch(r"\s*\{\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*;\s*)*\}\s*;\s*", text) is None:
        raise common.BuildError("native libc shared dynamic-list has unsupported syntax")
    members = tuple(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*;", text))
    if members != MUSL_1_2_6_DYNAMIC_LIST_MEMBERS:
        raise common.BuildError("native libc shared dynamic-list member/order contract differs")
    return {
        "source": identity,
        "data_symbols": list(MUSL_1_2_6_DYNAMIC_LIST_DATA_SYMBOLS),
        "allocation_entrypoints": list(MUSL_1_2_6_DYNAMIC_LIST_ALLOCATION_ENTRYPOINTS),
    }


def shared_libc_link_command(
    lld: Path,
    dynamic_list: Path,
    objects: Path,
    selected: tuple[str, ...],
    builtins: Path,
    library: Path,
) -> list[str]:
    """Return the one musl-shaped shared-libc link, with no global policy leak."""

    return [
        str(lld), "-shared", "--hash-style=sysv", "-soname", "libc.so",
        f"--dynamic-list={dynamic_list}",
        "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
        *(str(objects / item) for item in selected), str(builtins), "-o", str(library / "libc.so"),
    ]


def loader_dependency_provenance(dependencies: Path, artifact: Path) -> list[dict[str, object]]:
    """Translate Cargo's one compiler dep-info rule into selected source inputs.

    Cargo emits this file beside the final cdylib.  It is the compiler's
    actual source closure for this artifact, rather than a guessed walk of
    ``ldso/src`` or a collection of source markers.
    """

    try:
        details = dependencies.lstat()
        text = dependencies.read_text(encoding="utf-8")
    except OSError as error:
        raise common.BuildError(f"loader compiler dependency trace is missing: {dependencies}") from error
    if not stat.S_ISREG(details.st_mode) or dependencies.is_symlink():
        raise common.BuildError("loader compiler dependency trace is not a regular file")
    lines = [line for line in text.replace("\\\n", " ").splitlines() if line.strip()]
    if len(lines) != 1:
        raise common.BuildError("loader compiler dependency trace must contain one rule")
    target, separator, inputs = lines[0].partition(":")
    if not separator or ":" in inputs:
        raise common.BuildError("loader compiler dependency trace has an invalid rule")
    try:
        targets = shlex.split(target)
        sources = shlex.split(inputs)
    except ValueError as error:
        raise common.BuildError("loader compiler dependency trace cannot be parsed") from error
    if len(targets) != 1 or not sources:
        raise common.BuildError("loader compiler dependency trace has an incomplete rule")
    target_path = Path(targets[0])
    try:
        target_details = target_path.lstat()
        resolved_target = target_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise common.BuildError("loader compiler dependency target is missing or unsafe") from error
    if (not target_path.is_absolute() or not stat.S_ISREG(target_details.st_mode)
            or target_path.is_symlink() or resolved_target != target_path):
        raise common.BuildError("loader compiler dependency target is not a physical artifact")
    try:
        expected_target = artifact.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise common.BuildError(f"loader artifact is missing or unsafe: {artifact}") from error
    if resolved_target != expected_target:
        raise common.BuildError("loader compiler dependency target does not bind the installed artifact")

    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for spelling in sources:
        path = Path(spelling)
        if not path.is_absolute():
            raise common.BuildError("loader compiler dependency source is not absolute")
        record = _source_file_identity(path, "loader compiler dependency source")
        name = record["path"]
        if not isinstance(name, str) or not name.startswith("ldso/"):
            raise common.BuildError("loader compiler dependency source is outside ldso")
        if name in seen:
            raise common.BuildError("loader compiler dependency trace has duplicate sources")
        seen.add(name)
        records.append(record)
    records.sort(key=lambda record: str(record["path"]))
    required = {"ldso/build.rs", "ldso/src/lib.rs"}
    if not required <= seen:
        raise common.BuildError("loader compiler dependency trace lacks build.rs or lib.rs")
    return records


def loader_provenance(
    stage: Path,
    command: list[str],
    rustflags: str,
    compiler_artifact: Path,
    installed_artifact: Path,
) -> dict[str, object]:
    """Bind the installed loader to Cargo's selected source closure and config."""

    dependencies = stage / "loader" / common.TARGET / "release" / "libldso.d"
    expected_dependency_artifact = dependencies.with_name(LOADER_DEPENDENCY_ARTIFACT)
    if compiler_artifact != expected_dependency_artifact:
        raise common.BuildError("loader artifact does not have the expected Cargo dependency location")
    try:
        compiler_details = compiler_artifact.lstat()
        installed_details = installed_artifact.lstat()
    except OSError as error:
        raise common.BuildError("loader compiler or installed artifact is missing") from error
    if (not stat.S_ISREG(compiler_details.st_mode) or compiler_artifact.is_symlink()
            or not stat.S_ISREG(installed_details.st_mode) or installed_artifact.is_symlink()
            or common.sha256_file(compiler_artifact) != common.sha256_file(installed_artifact)):
        raise common.BuildError("installed loader differs from its compiler artifact")
    configuration = [
        _source_file_identity(ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py", "loader producer"),
        _source_file_identity(ROOT / "scripts/build_x86_64_owned_sysroot.py", "shared producer configuration"),
        _source_file_identity(ROOT / "Cargo.toml", "workspace Cargo configuration"),
        _source_file_identity(ROOT / "Cargo.lock", "workspace Cargo lock"),
        _source_file_identity(ROOT / "rust-toolchain.toml", "pinned Rust toolchain configuration"),
        _source_file_identity(ROOT / ".cargo/config.toml", "workspace Cargo configuration"),
        _source_file_identity(ROOT / "ldso/Cargo.toml", "loader Cargo configuration"),
    ]
    installed = {
        "path": LOADER_ARTIFACT,
        "sha256": common.sha256_file(installed_artifact),
        "mode": stat.S_IMODE(installed_details.st_mode),
    }
    return {
        "schema": LOADER_PROVENANCE_SCHEMA,
        "target": common.TARGET,
        "artifact": installed,
        "cargo": {
            "argv": [_normalized_loader_argument(argument, stage) for argument in command],
            "rustflags": rustflags,
        },
        "compiler_dependencies": loader_dependency_provenance(dependencies, compiler_artifact),
        "configuration": configuration,
    }


def build(output: Path) -> None:
    common.assert_native_target()
    source_before_build = qualification.source_digest()
    output = common.validate_output_path(output)
    if not output.is_relative_to(ROOT / ".work"):
        raise common.BuildError("dynamic output must remain below checkout .work")
    if output.exists() or output.is_symlink():
        raise common.BuildError("dynamic output already exists; choose a fresh owned output")
    stage = output.parent / (output.name + ".build")
    if stage.exists() or stage.is_symlink():
        raise common.BuildError("dynamic build state already exists; choose a fresh owned output")
    stage.mkdir(parents=True, mode=0o700)
    staged_output = stage / "installed"
    build_staged_payload(staged_output, stage)
    if qualification.source_digest() != source_before_build:
        raise common.BuildError("source changed during dynamic product build")
    try:
        installed_driver.validate(staged_output)
        shared_package.publish_noreplace(staged_output, output, "dynamic sysroot output")
    except (installed_driver.shared.DriverError, shared_package.PackageError) as error:
        raise common.BuildError(str(error)) from error


def build_staged_payload(output: Path, stage: Path) -> None:
    """Build the complete candidate privately; only build() may publish it.

    Failure retains diagnostic/build state under the dedicated .build owner,
    never a partially populated public output. The final manifest must pass
    the installed driver's exact validation before atomic no-replace rename.
    """
    environment = common.deterministic_environment()
    tools = common.resolve_pinned_producer_tools()
    rustup = tools["rustup"]["path"]
    ar = common.producer_tool_path(tools, "llvm-ar")
    nm = common.producer_tool_path(tools, "llvm-nm")
    objdump = common.producer_tool_path(tools, "llvm-objdump")
    rust_sysroot = common.pinned_rustc_sysroot(Path(rustup))
    lld = rust_sysroot / "lib/rustlib" / common.TARGET / "bin/gcc-ld/ld.lld"
    shared_dynamic_list = shared_libc_dynamic_list()
    run = common.run
    dependency_file = stage / "allocator.d"
    c_flags = ["-nostdinc", "-isystem", str(ROOT / "include"), "-fPIC",
               "-ftls-model=initial-exec", "-fstack-protector-strong",
               # The Rust libc owns the matching init/fini entries.  Do not
               # let the fixed C backend install a second hidden constructor.
               common.MIMALLOC_LIFECYCLE_C_FLAG,
               f"-ffile-prefix-map={ROOT}=/crabc", "-MD", "-MF", str(dependency_file)]
    environment.update({"CC_x86_64_unknown_linux_musl": "/usr/bin/gcc",
                        "CFLAGS_x86_64_unknown_linux_musl": shlex.join(c_flags),
                        "CC_SHELL_ESCAPED_FLAGS": "1"})
    cargo = [rustup, "run", common.PINNED_TOOLCHAIN, "cargo"]
    libc_command = [*cargo, "rustc", "--locked", "-p", "crabc-libc", "--lib", "--release",
         "--features", "x86-owned-dynamic-runtime", "--target", common.TARGET,
         "--target-dir", str(stage / "cargo"), "--", "--cfg", "crabc_owned_static_sysroot",
         "--cfg", common.MIMALLOC_LIFECYCLE_RUST_CFG,
         "-C", "relocation-model=pic", "-C", "panic=abort", "-Ztls-model=initial-exec",
         "--remap-path-prefix", f"{ROOT}=/crabc"]
    # The linkage feature selects the general dlfcn bridge. The historical
    # static cfg remains for other shared source-owner visibility choices.
    run(libc_command, environment=environment)
    raw = stage / "cargo" / common.TARGET / "release/libc.a"
    backends = list((stage / "cargo" / common.TARGET / "release/build").glob("libmimalloc-sys-*/out/libmimalloc.a"))
    if len(backends) != 1:
        raise common.BuildError("expected one accepted C allocator archive")
    allocator_lifecycle = common.owned_mimalloc_lifecycle_profile(
        c_flags, libc_command, backends[0], raw,
        llvm_ar=ar, llvm_nm=nm, llvm_objdump=objdump,
        stage=stage / "allocator-lifecycle-profile",
    )
    backend_members = run([ar, "t", str(backends[0])]).decode().splitlines()
    if len(backend_members) != 1:
        raise common.BuildError("accepted allocator archive must have one object")
    member = backend_members[0]
    if run([ar, "p", str(raw), member]) != run([ar, "p", str(backends[0]), member]):
        raise common.BuildError("Cargo allocator member differs from attested backend")
    members = tuple(run([ar, "t", str(raw)]).decode().splitlines())
    selected, excluded = common.classify_libc_members(members, allocator_member=member)
    objects = stage / "objects"
    objects.mkdir()
    run([ar, "x", str(raw), *selected], cwd=objects)
    builtins = stage / "libcrabc-builtins.a"
    run([sys.executable, str(ROOT / "builtins/build_x86_64.py"), "--output", str(builtins),
         "--provenance", str(stage / "builtins.json"), "--verify-reproducible"])
    output.mkdir()
    library = output / "usr/lib"
    library.mkdir(parents=True)
    common.copy_regular_tree(ROOT / "include", output / "usr/include")
    # Musl's configure applies its dynamic list to libc.so only. It binds
    # ordinary internal libc calls locally without changing public weak alias
    # metadata, while retaining its data and allocation interposition scope.
    libc_shared_link_command = shared_libc_link_command(
        lld, SHARED_LIBC_DYNAMIC_LIST, objects, selected, builtins, library
    )
    run(libc_shared_link_command)
    undefined = run([nm, "--undefined-only", str(library / "libc.so")]).decode().splitlines()
    allowed = {"__crabc_x86_64_initial_tls_allocate", "__crabc_x86_64_initial_tls_release",
               "__crabc_x86_64_resolve_initial_tls", "__crabc_x86_64_reset_current_tls_v1",
               "__crabc_x86_64_loader_conventional_startup_v1",
               "__crabc_x86_64_runtime_fork_prepare", "__crabc_x86_64_runtime_fork_complete",
               "__crabc_x86_64_runtime_open", "__crabc_x86_64_runtime_symbol",
               "__crabc_x86_64_runtime_close", "__crabc_x86_64_runtime_address",
               "__crabc_x86_64_runtime_information", "__crabc_x86_64_runtime_iterate"}
    unexpected = [line for line in undefined if line.split()[-1] not in allowed]
    if unexpected:
        raise common.BuildError(f"shared libc has unexpected unresolved symbols: {unexpected}")
    crt = stage / "crt"
    run([sys.executable, str(ROOT / "crt/build_x86_64.py"), "--owned-dynamic-sysroot",
         "--out-dir", str(crt), "--llvm-objdump", objdump])
    # This explicit CRT mode builds both dynamic entries from the same
    # authenticated handoff owner; default/static CRT production is unchanged.
    for name in ("crt1.o", "Scrt1.o", "crti.o", "crtn.o"):
        common.copy_artifact(crt / name, library / name)
    # Main-resident attachment preserves the established main-only weak wire.
    run([rustup, "run", common.PINNED_TOOLCHAIN, "rustc", "--edition=2021",
         "--crate-name", "crabc_dynamic_attachment", "--crate-type", "lib", "--emit=obj",
         "-C", "opt-level=2", "-C", "panic=abort", "-C", "relocation-model=pic",
         "--remap-path-prefix", f"{ROOT}=/crabc",
         str(ROOT / "libc/src/c_abi/x86_64/owned_dynamic_attachment.rs"),
         "-o", str(library / "crabc-dynamic-attach.o")])
    common.copy_artifact(builtins, library / builtins.name)
    loader_env = common.deterministic_environment()
    loader_env["RUSTFLAGS"] = "-C link-dead-code -C target-feature=-crt-static -C relocation-model=pic"
    loader_command = [*cargo, "build", "--locked", "-p", "crabc-ldso", "--release", "--target", common.TARGET,
                      "--target-dir", str(stage / "loader"), "--no-default-features", "--features",
                      LOADER_FEATURE]
    run(loader_command, environment=loader_env)
    interpreter = output / "lib/ld-crabc-x86_64.so.1"
    loader_artifact = stage / "loader" / common.TARGET / "release/libldso.so"
    common.copy_artifact(loader_artifact, interpreter)
    interpreter.chmod(0o755)
    libc_elf = audit_shared_elf(library / "libc.so")
    loader_elf = audit_shared_elf(interpreter)
    (interpreter.parent / "ld-musl-x86_64.so.1").symlink_to(interpreter.name)
    metadata = output / "share/crabc"
    metadata.mkdir(parents=True)
    common.copy_artifact(crt / "objects.json", metadata / "crt.provenance.json")
    common.copy_artifact(crt / "commands.json", metadata / "crt.commands.json")
    common.copy_artifact(stage / "builtins.json", metadata / "builtins.provenance.json")
    common.write_json(metadata / "producer-tools.json", tools)
    common.write_json(metadata / "libc-shared.elf.json", libc_elf)
    common.write_json(metadata / "loader.elf.json", loader_elf)
    common.write_json(
        metadata / "loader.provenance.json",
        loader_provenance(stage, loader_command, loader_env["RUSTFLAGS"], loader_artifact, interpreter),
    )
    for source, name in ((ROOT / "compat/x86_64/crabc_cc_owned_dynamic.py", "bin/crabc-cc-dynamic"),
                         (ROOT / "compat/x86_64/crabc_cc_static.py", "share/crabc/crabc_cc_static.py"),
                         (ROOT / "compat/x86_64/owned_dynamic_receipt.py", "share/crabc/owned_dynamic_receipt.py")):
        common.copy_artifact(source, output / name)
    (output / "bin/crabc-cc-dynamic").chmod(0o755)
    provenance = {"selected_members": {item: common.sha256_file(objects / item) for item in selected},
                  "excluded_members": list(excluded), "accepted_allocator": common.accepted_allocator_pin(),
                  "allocator_headers": common.allocator_header_provenance(dependency_file, Path(environment["CARGO_HOME"])),
                  "allocator_compiler": common.executable_identity(Path("/usr/bin/gcc"), "pinned allocator C compiler"),
                  "allocator_flags": [flag.replace(str(stage), "$BUILD").replace(str(ROOT), "$SOURCE") for flag in c_flags],
                  "allocator_lifecycle_profile": allocator_lifecycle,
                  "libc_command": [arg.replace(str(stage), "$BUILD").replace(str(ROOT), "$SOURCE") for arg in libc_command],
                  "libc_shared_link_command": [_normalized_loader_argument(arg, stage) for arg in libc_shared_link_command],
                  "shared_dynamic_list": shared_dynamic_list,
                  "loader_imports": sorted(allowed)}
    common.write_json(metadata / "libc-shared.provenance.json", provenance)
    payload_files = {path.relative_to(output).as_posix(): common.sha256_file(path)
                     for path in sorted(output.rglob("*")) if path.is_file() and not path.is_symlink()}
    common.write_json(metadata / "dynamic-product-state.json", {
        "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
        "status": "materialized-unqualified", "source_sha256": qualification.source_digest(),
        "contracts": qualification.contract_digests(), "payload_files": payload_files,
        "runtime_v1_published": False, "campaign_complete": False, "public_support": False,
        "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
        "runtime_profile": qualification.MATERIALIZATION_PROFILE,
        "qualification": qualification.MATERIALIZATION_QUALIFICATION})
    files = {path.relative_to(output).as_posix(): common.sha256_file(path)
             for path in sorted(output.rglob("*")) if path.is_file() and not path.is_symlink()}
    common.write_json(metadata / "manifest.json", {"schema": 1, "format": FORMAT,
        "target": common.TARGET, "files": files,
        "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.output)
    except (common.BuildError, OSError) as error:
        print(f"owned dynamic sysroot: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
