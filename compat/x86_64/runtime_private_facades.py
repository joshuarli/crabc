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

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import compiler_helper_evidence as compiler_helper
import owned_posix_timers_evidence as timer_evidence
import owned_posix_product_evidence as product_evidence


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
SCHEMA = "crabc.x86_64-runtime-private-facades/v2"
PRIVATE_RUNTIME = "__crabc_runtime_v1"
FEATURES = ("runtime-loader", "runtime-thread-alloc", "runtime-stdio")
REPORT_FIELDS = {
    "schema", "capability", "family", "target", "toolchain", "features", "normal_dependencies",
    "source", "product", "probes", "products", "executions", "family_qualified", "promotion_ready",
    "public_support", "limits",
}
LIMITS = (
    "Only the six RuntimeV1 facade probes and their exact shared getter provider are attached.",
    "Family qualification, product qualification, promotion, and public support remain false.",
)
EXPECTED_PACKAGES = ("bitflags", "crabc-core", "crabc-rs")
MEMORY_PRIMITIVES = frozenset({"memcpy", "memmove", "memset", "memcmp", "bcmp"})
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


def inspect_probe(tools: dict[str, str], probe: Probe, obj: Path, work: Path) -> dict[str, object]:
    header = run([tools["readobj"], "--file-headers", str(obj)])
    if "Format: elf64-x86-64" not in header or "Type: Relocatable" not in header:
        fail(f"{obj.name} is not an x86-64 ELF relocatable object")
    undefined = symbols(tools["nm"], obj, "--undefined-only")
    defined = symbols(tools["nm"], obj, "--defined-only", "--extern-only")
    admit_probe_symbols(probe, undefined, defined)
    return {
        "features": list(probe.features),
        "object": artifact_identity(obj, work),
        "undefined": undefined,
        "global_definitions": defined,
        "same_source_aarch64": probe.same_source_aarch64,
    }


def artifact_identity(path: Path, root: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        fail(f"evidence artifact is not a physical file: {path}")
    try:
        relative = path.relative_to(root)
    except ValueError:
        fail(f"evidence artifact escapes its retained root: {path}")
    metadata = path.stat()
    return {"path": relative.as_posix(), "sha256": sha256(path), "size": metadata.st_size,
            "mode": metadata.st_mode & 0o777}


def source_identity() -> dict[str, object]:
    try:
        return inventory.collector_source_seal()
    except inventory.InventoryError as error:
        raise EvidenceError(f"RuntimeV1 evidence requires a clean source checkout: {error}") from error


def product_identity(installed: Path) -> dict[str, object]:
    if (installed.is_symlink() or not installed.is_dir() or installed.resolve() != installed
            or not installed.is_relative_to(ROOT / ".work/x86_64")):
        fail("dynamic product must be a physical installed product below checkout .work/x86_64")
    try:
        compiler_helper.validate_materialized_dynamic_product(ROOT, installed)
    except compiler_helper.CompilerHelperEvidenceError as error:
        raise EvidenceError(f"installed dynamic product is not source-matched: {error}") from error
    manifest_path = installed / "share/crabc/manifest.json"
    manifest = artifact_identity(manifest_path, installed)
    libc = artifact_identity(installed / "usr/lib/libc.so", installed)
    return {
        "root": str(installed.relative_to(ROOT)),
        "manifest": manifest,
        "libc": libc,
    }


def compile_products(installed: Path, work: Path, objects: dict[str, Path]) -> dict[str, dict[str, dict[str, object]]]:
    driver = installed / "bin/crabc-cc-dynamic"
    output = work / "products"
    output.mkdir()
    object_root = work / "objects"
    built: dict[str, dict[str, dict[str, object]]] = {"dsos": {}, "executables": {}}
    for dso in DSOS:
        object_path = object_root / f"{dso.name}.o"
        run([str(driver), "--dynamic-shared-object", "-std=c11", *dso.defines,
             "-c", str(dso.source), "-o", str(object_path)], cwd=work)
        path = output / dso.name
        run([str(driver), "--dynamic-shared-object", str(object_path), "-o", str(path)], cwd=work)
        built["dsos"][dso.name] = {
            "artifact": artifact_identity(path, work),
            "object": artifact_identity(object_path, work),
            "receipt": artifact_identity(Path(str(path) + ".crabc-link.json"), work),
        }
    for probe in PROBES:
        for mode in ("pie", "non-pie"):
            c_object = object_root / f"{probe.example}-{mode}-fixture.o"
            run([str(driver), f"--dynamic-{mode}", "-std=c11", "-c", str(probe.fixture),
                 "-o", str(c_object)], cwd=work)
            path = output / f"{probe.example}-{mode}"
            run([str(driver), f"--dynamic-{mode}", str(objects[probe.example]), str(c_object),
                 "-o", str(path)], cwd=work)
            built["executables"][path.name] = {
                "artifact": artifact_identity(path, work),
                "objects": [artifact_identity(objects[probe.example], work), artifact_identity(c_object, work)],
                "receipt": artifact_identity(Path(str(path) + ".crabc-link.json"), work),
            }
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
                                     "status": status, "passed": passed,
                                     "stdout": artifact_identity(raw / f"{label}.stdout", work),
                                     "stderr": artifact_identity(raw / f"{label}.stderr", work),
                                     "status_file": artifact_identity(raw / f"{label}.status", work)})
    failed = [item for item in observations if not item["passed"]]
    if failed:
        fail(f"facade executions failed (raw evidence in {work / 'raw'}): {failed}")
    return observations


def _artifact_path(root: Path, value: object, description: str) -> Path:
    if type(value) is not dict or set(value) != {"path", "sha256", "size", "mode"}:
        fail(f"{description} artifact identity fields differ")
    relative = value["path"]
    digest = value["sha256"]
    size = value["size"]
    mode = value["mode"]
    path = Path(relative) if type(relative) is str else Path("/")
    if (type(relative) is not str or not relative or path.is_absolute() or ".." in path.parts
            or path.as_posix() != relative or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int or isinstance(size, bool) or size < 0
            or type(mode) is not int or isinstance(mode, bool) or not 0 <= mode <= 0o777):
        fail(f"{description} artifact identity values differ")
    artifact = root / path
    if artifact.is_symlink() or not artifact.is_file() or artifact.resolve() != artifact or not artifact.is_relative_to(root):
        fail(f"{description} retained artifact is not a physical file")
    metadata = artifact.stat()
    if metadata.st_size != size or metadata.st_mode & 0o777 != mode or sha256(artifact) != digest:
        fail(f"{description} retained artifact bytes differ")
    return artifact


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate RuntimeV1 report field: {key}")
        result[key] = value
    return result


def validate_report(report_path: Path, *, expected_source: dict[str, object],
                    dynamic_product: Path, dynamic_libc_sha256: str) -> dict[str, object]:
    if (not report_path.is_file() or report_path.is_symlink() or report_path.resolve() != report_path
            or not report_path.is_relative_to(ROOT / ".work")):
        fail("RuntimeV1 report must be a physical file below checkout .work")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("RuntimeV1 report is not valid JSON") from error
    if type(report) is not dict or set(report) != REPORT_FIELDS:
        fail("RuntimeV1 report fields differ")
    source = source_identity()
    if (report["schema"] != SCHEMA or report["capability"] != "runtime.private-facades"
            or report["family"] != "ldso.dynamic-runtime" or report["target"] != TARGET
            or report["toolchain"] != pinned_channel() or report["features"] != list(FEATURES)
            or report["normal_dependencies"] != list(EXPECTED_PACKAGES)
            or report["source"] != source or source != expected_source
            or report["family_qualified"] is not False or report["promotion_ready"] is not False
            or report["public_support"] is not False or report["limits"] != list(LIMITS)):
        fail("RuntimeV1 source, probe, or non-promotion boundary differs")
    current_product = product_identity(dynamic_product)
    if report["product"] != current_product or current_product["libc"]["sha256"] != dynamic_libc_sha256:
        fail("RuntimeV1 product identity differs from selected dynamic libc")
    tools = llvm_tools(report["toolchain"])
    work = report_path.parent
    probes = report["probes"]
    if type(probes) is not dict or set(probes) != {probe.example for probe in PROBES}:
        fail("RuntimeV1 probe roster differs")
    for probe in PROBES:
        row = probes[probe.example]
        if type(row) is not dict or set(row) != {
            "features", "object", "undefined", "global_definitions", "same_source_aarch64",
        }:
            fail(f"RuntimeV1 probe fields differ: {probe.example}")
        if (row["features"] != list(probe.features) or row["same_source_aarch64"] is not probe.same_source_aarch64
                or type(row["undefined"]) is not list or row["undefined"] != sorted(set(row["undefined"]))
                or type(row["global_definitions"]) is not list
                or row["global_definitions"] != sorted(set(row["global_definitions"]))):
            fail(f"RuntimeV1 probe source or symbol rows differ: {probe.example}")
        admit_probe_symbols(probe, row["undefined"], row["global_definitions"])
        obj = _artifact_path(work, row["object"], f"RuntimeV1 {probe.example} object")
        if obj.relative_to(work).as_posix() != f"objects/{probe.example}.o":
            fail(f"RuntimeV1 probe object path differs: {probe.example}")
        if inspect_probe(tools, probe, obj, work) != row:
            fail(f"RuntimeV1 probe rows differ from retained ELF object: {probe.example}")
    product_rows = report["products"]
    if type(product_rows) is not dict or set(product_rows) != {"dsos", "executables"}:
        fail("RuntimeV1 linked-product roster differs")
    expected_dsos = {dso.name for dso in DSOS}
    dsos = product_rows["dsos"]
    if type(dsos) is not dict or set(dsos) != expected_dsos:
        fail("RuntimeV1 DSO roster differs")
    for name, record in dsos.items():
        if type(record) is not dict or set(record) != {"artifact", "object", "receipt"}:
            fail(f"RuntimeV1 DSO link record fields differ: {name}")
        artifact = _artifact_path(work, record["artifact"], f"RuntimeV1 DSO {name}")
        if artifact.relative_to(work).as_posix() != f"products/{name}":
            fail(f"RuntimeV1 DSO path differs: {name}")
        object_path = _artifact_path(work, record["object"], f"RuntimeV1 DSO object {name}")
        if object_path.relative_to(work).as_posix() != f"objects/{name}.o":
            fail(f"RuntimeV1 DSO object path differs: {name}")
        receipt = _artifact_path(work, record["receipt"], f"RuntimeV1 DSO receipt {name}")
        if receipt.relative_to(work).as_posix() != f"products/{name}.crabc-link.json":
            fail(f"RuntimeV1 DSO receipt path differs: {name}")
        try:
            timer_evidence._validate_shared_receipt(
                dynamic_product, dynamic_product / "share/crabc/manifest.json",
                object_path, artifact, receipt,
            )
            timer_evidence._validate_tls_elf(artifact)
        except timer_evidence.TimerEvidenceError as error:
            raise EvidenceError(f"RuntimeV1 DSO link receipt differs: {name}: {error}") from error
    executable_roles = {
        f"{probe.example}-{mode}": (probe.example, mode)
        for probe in PROBES for mode in ("pie", "non-pie")
    }
    expected_executables = set(executable_roles)
    executables = product_rows["executables"]
    if type(executables) is not dict or set(executables) != expected_executables:
        fail("RuntimeV1 executable roster differs")
    for name, record in executables.items():
        if type(record) is not dict or set(record) != {"artifact", "objects", "receipt"}:
            fail(f"RuntimeV1 executable link record fields differ: {name}")
        artifact = _artifact_path(work, record["artifact"], f"RuntimeV1 executable {name}")
        if artifact.relative_to(work).as_posix() != f"products/{name}":
            fail(f"RuntimeV1 executable path differs: {name}")
        probe_name, mode = executable_roles[name]
        object_rows = record["objects"]
        if type(object_rows) is not list or len(object_rows) != 2:
            fail(f"RuntimeV1 executable object roster differs: {name}")
        object_paths = tuple(
            _artifact_path(work, value, f"RuntimeV1 executable input {name}") for value in object_rows
        )
        if (object_paths[0].relative_to(work).as_posix() != f"objects/{probe_name}.o"
                or object_rows[0] != probes[probe_name]["object"]
                or object_paths[1].relative_to(work).as_posix() != f"objects/{name}-fixture.o"):
            fail(f"RuntimeV1 executable input paths differ: {name}")
        receipt = _artifact_path(work, record["receipt"], f"RuntimeV1 executable receipt {name}")
        if receipt.relative_to(work).as_posix() != f"products/{name}.crabc-link.json":
            fail(f"RuntimeV1 executable receipt path differs: {name}")
        try:
            product_evidence.validate_multi_object_link(
                dynamic_product, object_paths, artifact, receipt, mode,
            )
        except product_evidence.ProductEvidenceError as error:
            raise EvidenceError(f"RuntimeV1 executable link receipt differs: {name}: {error}") from error
    expected_executions = [
        (probe, mode, entry)
        for probe in PROBES for mode in ("pie", "non-pie") for entry in ("kernel", "direct")
    ]
    executions = report["executions"]
    if type(executions) is not list or len(executions) != len(expected_executions):
        fail("RuntimeV1 execution matrix differs")
    for row, (probe, mode, entry) in zip(executions, expected_executions, strict=True):
        if type(row) is not dict or set(row) != {
            "probe", "mode", "entry", "status", "passed", "stdout", "stderr", "status_file",
        }:
            fail("RuntimeV1 execution fields differ")
        if ((row["probe"], row["mode"], row["entry"]) != (probe.example, mode, entry)
                or type(row["status"]) is not int or row["status"] != 0 or row["passed"] is not True):
            fail("RuntimeV1 execution result differs")
        label = f"{probe.example}-{mode}-{entry}"
        stdout = _artifact_path(work, row["stdout"], f"RuntimeV1 stdout {label}")
        stderr = _artifact_path(work, row["stderr"], f"RuntimeV1 stderr {label}")
        status_file = _artifact_path(work, row["status_file"], f"RuntimeV1 status {label}")
        if (stdout.relative_to(work).as_posix() != f"raw/{label}.stdout"
                or stderr.relative_to(work).as_posix() != f"raw/{label}.stderr"
                or status_file.relative_to(work).as_posix() != f"raw/{label}.status"
                or stdout.read_bytes() != probe.expected_stdout or stderr.read_bytes() != b""
                or status_file.read_text(encoding="utf-8") != "0\n"):
            fail(f"RuntimeV1 raw execution bytes differ: {label}")
    return report


def run_evidence(supplied: Path | None) -> Path:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        fail("runtime private facades require native Linux/x86-64")
    temporary = Path(os.environ.get("TMPDIR", ""))
    if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(ROOT / ".work"):
        fail("TMPDIR must be a physical checkout .work directory")
    source_before = source_identity()
    work = Path(tempfile.mkdtemp(prefix="runtime-private-facades.", dir=temporary))
    work.chmod(0o755)
    print(f"runtime private facades evidence: {work}", flush=True)
    if supplied is None:
        product_work = Path(tempfile.mkdtemp(
            prefix="runtime-private-facades-product.", dir=ROOT / ".work/x86_64"
        ))
        installed = product_work / "installed"
        run([sys.executable, "-B", str(ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"),
             "--output", str(installed)], cwd=ROOT)
    else:
        installed = Path(os.path.abspath(supplied))
        if (supplied.is_symlink() or installed.resolve() != installed
                or not (installed / "bin/crabc-cc-dynamic").is_file()
                or not installed.is_relative_to(ROOT / ".work/x86_64")):
            fail("supplied dynamic sysroot must be an installed product below checkout .work/x86_64")
    selected_product = product_identity(installed)
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
        inspections[probe.example] = inspect_probe(tools, probe, obj, work)
    products = compile_products(installed, work, objects)
    observations = execute(installed, work)
    source_after = source_identity()
    product_after = product_identity(installed)
    if source_after != source_before or product_after != selected_product:
        fail("RuntimeV1 source or dynamic product changed during evidence collection")
    report = {
        "schema": SCHEMA,
        "capability": "runtime.private-facades",
        "family": "ldso.dynamic-runtime",
        "target": TARGET,
        "toolchain": channel,
        "features": list(FEATURES),
        "normal_dependencies": packages,
        "source": source_before,
        "product": selected_product,
        "probes": inspections,
        "products": products,
        "executions": observations,
        "family_qualified": False,
        "promotion_ready": False,
        "public_support": False,
        "limits": list(LIMITS),
    }
    if set(report) != REPORT_FIELDS:
        fail("RuntimeV1 producer report fields differ")
    path = work / "report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validate_report(path, expected_source=source_before, dynamic_product=installed,
                    dynamic_libc_sha256=selected_product["libc"]["sha256"])
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
