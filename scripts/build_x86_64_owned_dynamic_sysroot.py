#!/usr/bin/env python3
"""Produce the native initial-graph shared runtime, without ambient target inputs.

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
import sys
import re

sys.dont_write_bytecode = True
import build_x86_64_owned_sysroot as common

ROOT = common.ROOT
FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import crabc_cc_owned_dynamic as installed_driver
import owned_static_sysroot_package as shared_package


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


def build(output: Path) -> None:
    common.assert_native_target()
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
    run = common.run
    dependency_file = stage / "allocator.d"
    c_flags = ["-nostdinc", "-isystem", str(ROOT / "include"), "-fPIC",
               "-ftls-model=initial-exec", "-fstack-protector-strong",
               f"-ffile-prefix-map={ROOT}=/crabc", "-MD", "-MF", str(dependency_file)]
    environment.update({"CC_x86_64_unknown_linux_musl": "/usr/bin/gcc",
                        "CFLAGS_x86_64_unknown_linux_musl": shlex.join(c_flags),
                        "CC_SHELL_ESCAPED_FLAGS": "1"})
    cargo = [rustup, "run", common.PINNED_TOOLCHAIN, "cargo"]
    libc_command = [*cargo, "rustc", "--locked", "-p", "crabc-libc", "--lib", "--release",
         "--features", "x86-owned-dynamic-runtime", "--target", common.TARGET,
         "--target-dir", str(stage / "cargo"), "--", "--cfg", "crabc_owned_static_sysroot",
         "-C", "relocation-model=pic", "-C", "panic=abort", "-Ztls-model=initial-exec",
         "--remap-path-prefix", f"{ROOT}=/crabc"]
    # The historical cfg selects only the unavailable dlfcn trampoline. This
    # installed initial-graph component must not import a fixed-fixture record.
    run(libc_command, environment=environment)
    raw = stage / "cargo" / common.TARGET / "release/libc.a"
    backends = list((stage / "cargo" / common.TARGET / "release/build").glob("libmimalloc-sys-*/out/libmimalloc.a"))
    if len(backends) != 1:
        raise common.BuildError("expected one accepted C allocator archive")
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
    run([str(lld), "-shared", "--hash-style=sysv", "-soname", "libc.so",
         "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text",
         *(str(objects / item) for item in selected), str(builtins), "-o", str(library / "libc.so")])
    undefined = run([nm, "--undefined-only", str(library / "libc.so")]).decode().splitlines()
    allowed = {"__crabc_x86_64_initial_tls_allocate", "__crabc_x86_64_initial_tls_release",
               "__crabc_x86_64_resolve_initial_tls"}
    unexpected = [line for line in undefined if line.split()[-1] not in allowed]
    if unexpected:
        raise common.BuildError(f"shared libc has unexpected unresolved symbols: {unexpected}")
    crt = stage / "crt"
    run([sys.executable, str(ROOT / "crt/build_x86_64.py"), "--general-dynamic-lifecycle",
         "--out-dir", str(crt), "--llvm-objdump", objdump])
    # crt1.o from the current CRT producer is static-only. Do not install it
    # under a misleading dynamic non-PIE contract; that mode remains explicit
    # remaining work until it has an owned dynamic entry and ELF admission.
    for name in ("Scrt1.o", "crti.o", "crtn.o"):
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
    run([*cargo, "build", "--locked", "-p", "crabc-ldso", "--release", "--target", common.TARGET,
         "--target-dir", str(stage / "loader"), "--no-default-features", "--features",
         "x86_64-owned-dynamic-runtime"], environment=loader_env)
    interpreter = output / "lib/ld-crabc-x86_64.so.1"
    common.copy_artifact(stage / "loader" / common.TARGET / "release/libldso.so", interpreter)
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
    for source, name in ((ROOT / "compat/x86_64/crabc_cc_owned_dynamic.py", "bin/crabc-cc-dynamic"),
                         (ROOT / "compat/x86_64/crabc_cc_static.py", "share/crabc/crabc_cc_static.py")):
        common.copy_artifact(source, output / name)
    (output / "bin/crabc-cc-dynamic").chmod(0o755)
    provenance = {"selected_members": {item: common.sha256_file(objects / item) for item in selected},
                  "excluded_members": list(excluded), "accepted_allocator": common.accepted_allocator_pin(),
                  "allocator_headers": common.allocator_header_provenance(dependency_file, Path(environment["CARGO_HOME"])),
                  "allocator_compiler": common.executable_identity(Path("/usr/bin/gcc"), "pinned allocator C compiler"),
                  "allocator_flags": [flag.replace(str(stage), "$BUILD").replace(str(ROOT), "$SOURCE") for flag in c_flags],
                  "libc_command": [arg.replace(str(stage), "$BUILD").replace(str(ROOT), "$SOURCE") for arg in libc_command],
                  "loader_imports": sorted(allowed)}
    common.write_json(metadata / "libc-shared.provenance.json", provenance)
    common.write_json(metadata / "dynamic-product-state.json", {
        "schema": 1, "status": "materialized-initial-graph-component",
        "campaign_complete": False, "public_support": False,
        "modes": ["dynamic-pie", "dynamic-shared-object"],
        "dlfcn": "unavailable legacy bridge; no runtime module admission",
        "remaining": ["dynamic-non-pie", "runtime-load-close-reopen", "worker-dtv-growth", "dynamic-fork-repair", "complete-dynamic-campaign"]})
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
