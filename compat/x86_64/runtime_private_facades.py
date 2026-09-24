#!/usr/bin/env python3
"""Run crabc-rs's private RuntimeV1 facades through an installed dynamic product.

`runtime.private-facades` maps the frozen AArch64 `crabc-core` RuntimeV1
consumers (`crabc_rs::{dl, runtime_thread, cfile}`) onto native x86-64. This
runner proves that native path end to end:

* dependency: the facade's normal Cargo graph for the three runtime features
  is exactly `crabc-rs`, `crabc-core`, and `bitflags`;
* LTO/ABI: each probe is a release fat-LTO object whose only external runtime
  import is the private `__crabc_runtime_v1` getter plus compiler memory
  primitives. Public dlfcn, pthread, stdio, and `errno` symbols are rejected;
* behavior, error, and ownership: the probes are linked by the installed
  `crabc-cc-dynamic` driver into PIE and non-PIE executables and run through
  both kernel and direct interpreter entry in a private copy of the product.
  The three frozen AArch64 probes run unchanged; the x86 probes compare every
  copied loader, thread, and memory-stream observation with the same
  product's public C ABI in the same process.

It is focused evidence for one capability. It does not qualify the
`ldso.dynamic-runtime` family, a product cohort, or public x86 support.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
SCHEMA = "crabc.x86_64-runtime-private-facades/v1"
PRIVATE_RUNTIME = "__crabc_runtime_v1"
FEATURES = ("runtime-loader", "runtime-thread-alloc", "runtime-stdio")
# The facade's complete normal dependency graph for those features.
EXPECTED_PACKAGES = ("bitflags", "crabc-core", "crabc-rs")
# Code generation may call these compiler memory primitives; the installed
# libc supplies them. Every other undefined symbol must be declared per probe.
MEMORY_PRIMITIVES = frozenset({"memcpy", "memmove", "memset", "memcmp", "bcmp"})
# Public C ABI and errno names which a native facade object must never import.
FORBIDDEN_IMPORTS = frozenset({
    "dlopen", "dlsym", "dlclose", "dlerror", "dladdr", "dlinfo", "dl_iterate_phdr",
    "pthread_create", "pthread_join", "pthread_detach", "pthread_self", "pthread_cancel",
    "pthread_setcancelstate", "pthread_setcanceltype", "pthread_testcancel",
    "pthread_key_create", "pthread_key_delete", "pthread_getspecific", "pthread_setspecific",
    "fmemopen", "fread", "fwrite", "fflush", "fseeko", "ftello", "fseek", "ftell",
    "feof", "ferror", "clearerr", "rewind", "fclose",
    "__errno_location", "malloc", "calloc", "realloc", "free",
})
# crabc-rs's signal module defines this one assembler restorer globally; it
# is linked, never called by these probes, and is not a runtime import.
FACADE_GLOBAL_DEFINITIONS = frozenset({"crabc_rs_signal_restorer"})
TIMEOUT_SECONDS = 30


class EvidenceError(RuntimeError):
    """The runtime private-facade proof did not hold."""


@dataclasses.dataclass(frozen=True)
class Dso:
    """One application shared object installed below `/usr/lib`."""

    name: str
    source: Path
    defines: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Probe:
    """One Rust facade probe and the C executable which drives it."""

    example: str
    features: tuple[str, ...]
    entries: frozenset[str]
    fixture: Path
    expected_stdout: bytes
    same_source_aarch64: bool
    # Fixture-provided C oracle callbacks the probe may import by name.
    fixture_imports: frozenset[str] = frozenset()
    dsos: tuple[str, ...] = ()


DSOS = (
    Dso("libloader_dlfcn_close.so", ROOT / "tests/fixtures/loader_dlfcn_basic_dso.c",
        ("-DLOADER_STATE_SYMBOL=loader_dlfcn_close_state", "-DLOADER_VALUE_SYMBOL=loader_dlfcn_value")),
    Dso("libloader_dlfcn_drop.so", ROOT / "tests/fixtures/loader_dlfcn_basic_dso.c",
        ("-DLOADER_STATE_SYMBOL=loader_dlfcn_drop_state", "-DLOADER_VALUE_SYMBOL=loader_dlfcn_drop_value")),
    Dso("libruntime_facade_tls.so", ROOT / "compat/x86_64/runtime_private_facades_tls_dso.c"),
)

PROBES = (
    Probe("loader_runtime_probe", ("runtime-loader",), frozenset({"crabc_rs_loader_runtime_probe"}),
          ROOT / "tests/fixtures/loader_runtime_test.c", b"runtime loader runtime ok\n", True),
    Probe("runtime_thread_probe", ("runtime-thread",), frozenset({"crabc_rs_runtime_thread_probe"}),
          ROOT / "tests/fixtures/runtime_thread_test.c", b"runtime runtime thread ok\n", True),
    Probe("cfile_direct_probe", ("runtime-stdio",), frozenset({"crabc_rs_cfile_direct_probe"}),
          ROOT / "tests/fixtures/cfile_runtime_test.c", b"compat cfile runtime ok\n", True),
    Probe("x86_64_loader_facade_probe", ("runtime-loader",), frozenset({
              "crabc_rs_x86_64_facade_open_error", "crabc_rs_x86_64_facade_symbol_error",
              "crabc_rs_x86_64_facade_symbol", "crabc_rs_x86_64_facade_address",
              "crabc_rs_x86_64_facade_information", "crabc_rs_x86_64_facade_snapshot",
              "crabc_rs_x86_64_facade_lifecycle"}),
          ROOT / "compat/x86_64/runtime_private_facades_loader.c",
          b"x86 runtime private loader facade ok\n", False),
    Probe("x86_64_thread_facade_probe", ("runtime-thread-alloc",), frozenset({
              "crabc_rs_x86_64_thread_facade_current", "crabc_rs_x86_64_thread_facade_probe"}),
          ROOT / "compat/x86_64/runtime_private_facades_thread.c",
          b"x86 runtime private thread facade ok\n", False,
          fixture_imports=frozenset({"crabc_x86_64_thread_facade_c_self"})),
    Probe("x86_64_cfile_facade_probe", ("runtime-stdio",), frozenset({
              "crabc_rs_x86_64_cfile_facade_run", "crabc_rs_x86_64_cfile_facade_directions"}),
          ROOT / "compat/x86_64/runtime_private_facades_cfile.c",
          b"x86 runtime private cfile facade ok\n", False),
)


def fail(message: str) -> None:
    raise EvidenceError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_channel() -> str:
    config = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    channel = config["toolchain"]["channel"]
    if re.fullmatch(r"nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}", channel) is None:
        fail("rust-toolchain.toml has no dated nightly channel")
    return channel


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        fail(f"command failed ({result.returncode}): {' '.join(command)}\n"
             f"{result.stderr.decode('utf-8', 'replace')[-4000:]}")
    return result.stdout.decode("utf-8", "replace")


def rust_environment() -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "TZ": "UTC"}
    for name in ("CARGO_HOME", "RUSTUP_HOME"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def llvm_tools(channel: str) -> dict[str, str]:
    sysroot = run(["rustup", "run", channel, "rustc", "--print", "sysroot"],
                  env=rust_environment()).strip()
    tools = Path(sysroot) / "lib/rustlib" / TARGET / "bin"
    resolved = {name: tools / f"llvm-{name}" for name in ("ar", "nm", "readobj")}
    for name, path in resolved.items():
        if not path.is_file():
            fail(f"pinned llvm-{name} is missing: {path}")
    return {name: str(path) for name, path in resolved.items()}


def dependency_graph(channel: str, target_dir: Path) -> list[str]:
    output = run(["rustup", "run", channel, "cargo", "tree", "--locked", "-p", "crabc-rs",
                  "--target", TARGET, "--no-default-features", "--features", ",".join(FEATURES),
                  "--edges", "normal", "--prefix", "none", "--format", "{p}"],
                 cwd=ROOT, env={**rust_environment(), "CARGO_TARGET_DIR": str(target_dir)})
    packages = sorted({line.split()[0] for line in output.splitlines() if line.strip()})
    if tuple(packages) != EXPECTED_PACKAGES:
        fail(f"facade normal dependency graph changed: {packages}")
    return packages


def build_probe(channel: str, target_dir: Path, probe: Probe) -> Path:
    """Build one no-std release probe with only its own runtime feature."""

    run(["rustup", "run", channel, "cargo", "build", "--locked", "-p", "crabc-rs", "--release",
         "--target", TARGET, "--target-dir", str(target_dir), "--no-default-features",
         "--features", ",".join(probe.features), "--example", probe.example],
        cwd=ROOT, env=rust_environment())
    return target_dir / TARGET / "release/examples" / f"lib{probe.example}.a"


def symbols(nm: str, path: Path, *flags: str) -> list[str]:
    names = []
    for line in run([nm, *flags, str(path)]).splitlines():
        fields = line.split()
        if fields:
            names.append(fields[-1])
    return sorted(names)


def select_lto_member(members: list[str], example: str) -> str:
    """Select the one fat-LTO member which holds every Rust crate but builtins.

    A release staticlib also carries compiler-builtins members; those are not
    part of the facade object and are never linked from this archive.
    """

    pattern = re.compile(rf"{re.escape(example)}-[0-9a-f]+\.{re.escape(example)}\.[0-9a-f]+-cgu\.0\.rcgu\.o")
    selected = [member for member in members if pattern.fullmatch(member)]
    if len(selected) != 1:
        fail(f"lib{example}.a must hold exactly one fat-LTO facade member: {selected}")
    return selected[0]


def extract_lto_object(tools: dict[str, str], archive: Path, example: str, output: Path) -> Path:
    member = select_lto_member(run([tools["ar"], "t", str(archive)]).splitlines(), example)
    output.mkdir(parents=True, exist_ok=True)
    run([tools["ar"], "x", str(archive), member], cwd=output)
    selected = output / f"{example}.o"
    (output / member).rename(selected)
    return selected


def admit_probe_symbols(probe: Probe, undefined: list[str], defined: list[str]) -> None:
    """Fail closed unless the object reaches runtime state only via RuntimeV1.

    The forbidden-name check runs first, so a fixture callback declaration can
    never admit a public C ABI or errno import. After fat LTO, the facade's
    own definitions must be internal: only probe entries remain global.
    """

    if PRIVATE_RUNTIME not in undefined:
        fail(f"{probe.example} does not import the private runtime getter")
    forbidden = sorted(FORBIDDEN_IMPORTS.intersection(undefined))
    if forbidden:
        fail(f"{probe.example} imports public C ABI/errno symbols: {forbidden}")
    unexpected = sorted(set(undefined) - {PRIVATE_RUNTIME} - MEMORY_PRIMITIVES - probe.fixture_imports)
    if unexpected:
        fail(f"{probe.example} has undeclared imports: {unexpected}")
    missing_entries = sorted(probe.entries - set(defined))
    if missing_entries:
        fail(f"{probe.example} lacks probe entries: {missing_entries}")
    extra = sorted(set(defined) - probe.entries - FACADE_GLOBAL_DEFINITIONS)
    if extra:
        fail(f"{probe.example} did not internalize facade definitions: {extra}")


def inspect_probe(tools: dict[str, str], probe: Probe, obj: Path) -> dict[str, object]:
    header = run([tools["readobj"], "--file-headers", str(obj)])
    if "Format: elf64-x86-64" not in header or "Type: Relocatable" not in header:
        fail(f"{obj.name} is not an x86-64 ELF relocatable object")
    undefined = symbols(tools["nm"], obj, "--undefined-only")
    defined = symbols(tools["nm"], obj, "--defined-only", "--extern-only")
    admit_probe_symbols(probe, undefined, defined)
    return {
        "features": list(probe.features),
        "object": obj.name,
        "sha256": sha256(obj),
        "undefined": undefined,
        "global_definitions": defined,
        "same_source_aarch64": probe.same_source_aarch64,
    }


def compile_products(installed: Path, work: Path, objects: dict[str, Path]) -> dict[str, dict[str, str]]:
    driver = installed / "bin/crabc-cc-dynamic"
    output = work / "products"
    output.mkdir()
    built: dict[str, dict[str, str]] = {"dsos": {}, "executables": {}}
    for dso in DSOS:
        path = output / dso.name
        run([str(driver), "--dynamic-shared-object", "-std=c11", *dso.defines,
             str(dso.source), "-o", str(path)], cwd=work)
        built["dsos"][dso.name] = sha256(path)
    for probe in PROBES:
        for mode in ("pie", "non-pie"):
            path = output / f"{probe.example}-{mode}"
            run([str(driver), f"--dynamic-{mode}", "-std=c11", str(probe.fixture),
                 str(objects[probe.example]), "-o", str(path)], cwd=work)
            built["executables"][path.name] = sha256(path)
    return built


def execute(installed: Path, work: Path) -> list[dict[str, object]]:
    chroot = shutil.which("chroot", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if chroot is None:
        fail("the evidence image has no chroot executable")
    root = work / "execution-root"
    shutil.copytree(installed, root, symlinks=True)
    for dso in DSOS:
        shutil.copy2(work / "products" / dso.name, root / "usr/lib" / dso.name)
    observations = []
    for probe in PROBES:
        for mode in ("pie", "non-pie"):
            name = f"{probe.example}-{mode}"
            shutil.copy2(work / "products" / name, root / name)
            for entry in ("kernel", "direct"):
                command = [chroot, str(root), *([INTERPRETER] if entry == "direct" else []), f"/{name}"]
                label = f"{name}-{entry}"
                try:
                    result = subprocess.run(command, env={"PATH": "/usr/bin:/bin"}, check=False,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            timeout=TIMEOUT_SECONDS)
                    status = result.returncode
                    stdout, stderr = result.stdout, result.stderr
                except subprocess.TimeoutExpired as error:
                    status, stdout, stderr = "timeout", error.stdout or b"", error.stderr or b""
                raw = work / "raw"
                raw.mkdir(exist_ok=True)
                (raw / f"{label}.stdout").write_bytes(stdout)
                (raw / f"{label}.stderr").write_bytes(stderr)
                (raw / f"{label}.status").write_text(f"{status}\n", encoding="utf-8")
                passed = status == 0 and stdout == probe.expected_stdout and stderr == b""
                observations.append({"probe": probe.example, "mode": mode, "entry": entry,
                                     "status": status, "passed": passed})
    failed = [item for item in observations if not item["passed"]]
    if failed:
        fail(f"facade executions failed (raw evidence in {work / 'raw'}): {failed}")
    return observations


def run_evidence(supplied: Path | None) -> Path:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        fail("runtime private facades require native Linux/x86-64")
    temporary = Path(os.environ.get("TMPDIR", ""))
    if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(ROOT / ".work"):
        fail("TMPDIR must be a physical checkout .work directory")
    work = Path(tempfile.mkdtemp(prefix="runtime-private-facades.", dir=temporary))
    work.chmod(0o755)
    print(f"runtime private facades evidence: {work}", flush=True)
    if supplied is None:
        installed = work / "installed"
        run([sys.executable, "-B", str(ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"),
             "--output", str(installed)], cwd=ROOT)
    else:
        installed = supplied.resolve()
        if not (installed / "bin/crabc-cc-dynamic").is_file() or not installed.is_relative_to(ROOT / ".work"):
            fail("supplied dynamic sysroot must be an installed product below checkout .work")
    libc = installed / "usr/lib/libc.so"
    channel = pinned_channel()
    tools = llvm_tools(channel)
    if PRIVATE_RUNTIME not in symbols(tools["nm"], libc, "--dynamic", "--defined-only"):
        fail("installed libc.so does not export the private runtime getter")
    target_dir = work / "cargo"
    packages = dependency_graph(channel, target_dir)
    objects = {}
    inspections = {}
    for probe in PROBES:
        archive = build_probe(channel, target_dir, probe)
        obj = extract_lto_object(tools, archive, probe.example, work / "objects")
        objects[probe.example] = obj
        inspections[probe.example] = inspect_probe(tools, probe, obj)
    products = compile_products(installed, work, objects)
    observations = execute(installed, work)
    report = {
        "schema": SCHEMA,
        "capability": "runtime.private-facades",
        "family": "ldso.dynamic-runtime",
        "target": TARGET,
        "toolchain": channel,
        "features": list(FEATURES),
        "normal_dependencies": packages,
        "installed_libc_sha256": sha256(libc),
        "probes": inspections,
        "products": products,
        "executions": observations,
        "family_qualified": False,
        "public_support": False,
    }
    path = work / "report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"runtime private facades: PASS ({len(observations)} executions, report {path})")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dynamic-sysroot", type=Path,
                        help="reuse an installed dynamic product instead of building one")
    arguments = parser.parse_args(argv)
    try:
        run_evidence(arguments.dynamic_sysroot)
    except EvidenceError as error:
        print(f"runtime private facades: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
