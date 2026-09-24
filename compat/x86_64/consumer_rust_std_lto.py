#!/usr/bin/env python3
"""Native x86 ``consumer.rust-std-lto`` gate through installed owned products.

The frozen AArch64 family is four gates, each with its fixtures, build
contract and controls: ``rust-std`` and ``rust-std-dependent``
(``compat/rust-std``), ``lto`` and ``lto-native-facade`` (``compat/lto``).
This runner reproduces them on native Linux/x86-64 with one adaptation the
x86 purity contract requires: a candidate image is never a pinned-musl link
run with a swapped runtime. Each candidate is linked by the Cargo origin of
``unwinder/owned_rust_link.py`` from the installed static or dynamic product
(its CRT objects, ``libc.a``/``libc.so``, ``libcrabc-builtins.a`` and
canonical interpreter) plus the fresh ``unwinder/build.py`` provider archive,
which Rust's own ``-lunwind``/``-lgcc_s`` request selects by ordinary archive
extraction. Where a frozen gate compared against pinned musl, the same Cargo
graph is built a second time with the pinned musl oracle compiler as its
linker, and both images run in private roots that differ only in runtime
files; status, stdout and stderr compare raw.

The frozen fixtures build with ``panic = "abort"``. That profile belongs to
their contract, not to this gate's unwind evidence: std still resolves
``_Unwind_Backtrace`` from the provider, and the separate unwind matrix runs
``unwinder/owned_cleanup.py`` (stock and source-built std, panic cleanup and
``resume_unwind`` across calls, a worker thread and a runtime-loaded DSO)
against both the installed and the extracted product pair.

Products come from the same current-source cohort the POSIX family matrix
admits (``owned-posix-static-products`` plus a passing
``materialized-dynamic-sysroot`` qualification). ``--development-*``
products exercise the same path for iteration and never produce a
qualifying receipt. ``validate_receipt`` is the gate's reader.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
for _path in (ROOT, ROOT / "compat/x86_64", ROOT / "unwinder"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
from scripts.rust_toolchain import pinned_toolchain  # noqa: E402
import build as provider_build  # noqa: E402  (unwinder/build.py)
import owned_cleanup  # noqa: E402
import owned_rust_link  # noqa: E402

SCHEMA = "crabc.x86_64-consumer-rust-std-lto/v1"
GATE = "consumer.rust-std-lto"
TARGET = "x86_64-unknown-linux-musl"
CHANNEL = pinned_toolchain(ROOT)
FROZEN_GATES = ("rust-std", "rust-std-dependent", "lto", "lto-native-facade")
# The frozen consumers run on the installed pair; the unwind matrix also runs
# on the extracted pair. Labels are the static preparation's product names.
CONSUMER_PRODUCT = "primary"
UNWIND_PRODUCTS = ("primary", "extracted")
DEVELOPMENT_PRODUCT = "development"
PASS_MARKER = "x86 consumer.rust-std-lto: PASS (rust-std, rust-std-dependent, lto, lto-native-facade, unwind; installed/extracted owned products)"
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
MUSL_LIB = Path("/opt/musl-1.2.6/lib")
LIBGCC_S = Path("/usr/lib/libgcc_s.so.1")
LINKER = ROOT / "unwinder/owned_rust_link.py"
FIXTURES = {
    "rust-std": ROOT / "compat/rust-std/fixtures",
    "rust-std-dependent": ROOT / "compat/rust-std/dependent-fixture",
    "lto": ROOT / "compat/lto/fixtures",
    "native-facade": ROOT / "compat/lto/native-facade-lto-fixture",
    "native-std": ROOT / "compat/lto/native-std-lto-fixture",
    "cross-dso": ROOT / "unwinder/fixtures/cross_dso",
}
CROSS_DSO_FRAME = FIXTURES["cross-dso"] / "frame.c"
CROSS_DSO_INITIAL = "libcrabc_unwind_frame_initial.so"
CROSS_DSO_RUNTIME = "libcrabc_unwind_frame_runtime.so"
CROSS_DSO_FLAGS = ("-C", "panic=unwind", "-C", "force-unwind-tables=yes", "-C", "target-feature=-crt-static")
CROSS_DSO_STDOUT = b"unwind: cross-dso cleanup resume initial runtime main worker\n"
# The standalone provider regressions for bounded malformed and truncated
# frame metadata and DWARF expressions (``unwinder/README.md``). They inject
# their own ``dl_iterate_phdr`` images, so they run in the pinned-musl
# harness; they supplement, never replace, the owned-product consumers.
PROVIDER_REGRESSIONS = (
    "metadata_bounds.py", "eh_frame_bounds.py", "dynamic_bounds.py",
    "indirect_personality_bounds.py", "metadata_target_bounds.py", "frame_bounds.py",
)
SECTIONS = (*FROZEN_GATES, "unwind", "provider-regressions")
# Locked registry closures the offline fixture vendor must contain exactly.
VENDORED_FIXTURES = ("rust-std-dependent", "native-facade", "native-std")
BUILD_STD = {"panic_abort": ("-Z", "build-std=std,panic_abort"), "panic_unwind": ("-Z", "build-std=std,panic_unwind")}
# Frozen per-gate Rust flags (compat/rust-std/run.py, compat/lto/run.py and
# compat/lto/native_facade_lto.py). The linker selection is appended below.
RUST_STD_FLAGS = ("-C", "target-feature=-crt-static")
LTO_BASE_FLAGS = ("-C", "opt-level=3", "-C", "codegen-units=1", "-C", "panic=abort")
LTO_C_FLAGS = (*LTO_BASE_FLAGS, "-C", "target-feature=-crt-static")
LTO_D_FLAGS = (*LTO_BASE_FLAGS, "-C", "target-feature=+crt-static", "-C", "lto=fat",
               "-C", "embed-bitcode=yes", "-C", "linker-plugin-lto")
FACADE_FLAGS = (*LTO_BASE_FLAGS, "-C", "embed-bitcode=yes", "-C", "target-feature=-crt-static")
STATIC_C_FLAGS = ("-O3", "-fno-builtin", "-fno-stack-protector")
ORACLE_FLAGS = ("-C", f"linker={ORACLE_CC}", "-C", "link-arg=-L/usr/lib")
EXECUTION_ENVIRONMENT = {"PATH": "/bin:/usr/bin", "HOME": "/", "LC_ALL": "C", "CRABC_RUST_STD_TEST": "musl-abi"}
# Oracle and candidate roots carry the same fixture nodes. The frozen
# workloads write /tmp, resolve localhost, open /dev/null and spawn
# ``current_exe()``; nothing else from the container is visible.
HOSTS_FIXTURE = "127.0.0.1\tlocalhost\n::1\tlocalhost\n"
EXECUTABLE = "consumer"
EXECUTION_TIMEOUT = 120
EXPECTED_STDOUT = {
    "lto-c": b"lto-static-c:ok\n",
    "native-facade": b"native-facade:ok\n",
    "native-std": b"native-std:ok\n",
}
NATIVE_FACADE_WITNESS = "crabc_rs_native_facade_getpid_witness"
FORBIDDEN_WITNESS_CALLS = ("getpid", "write", "__errno_location")
X86_SYSCALLS = {"getpid": 39, "write": 1}


class GateError(RuntimeError):
    """A declared input or boundary cannot be established."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Retained:
    """Every file a receipt names, so its reader can rehash all of them."""

    def __init__(self, output: Path) -> None:
        self.output = output
        self.files: dict[str, str] = {}

    def record(self, path: Path) -> dict[str, str]:
        path = Path(os.path.abspath(path))
        require(path.is_file() and not path.is_symlink(), f"retained evidence is not a regular file: {path}")
        record = {"path": str(path), "sha256": sha256_file(path)}
        self.files[record["path"]] = record["sha256"]
        return record

    def write(self, relative: str, data: bytes) -> dict[str, str]:
        path = self.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
        return self.record(path)


def run(argv: Sequence[str | Path], *, env: Mapping[str, str], cwd: Path | None = None,
        timeout: float | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(item) for item in argv], env=dict(env), cwd=cwd, capture_output=True,
                          timeout=timeout, check=False)


def tool_environment() -> dict[str, str]:
    """Minimal environment for pinned tools; no inherited compiler state."""

    environment = {"PATH": "/opt/cargo/bin:/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C",
                   "HOME": os.environ.get("HOME", "/root"), "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
    if "RUSTUP_HOME" in os.environ:
        environment["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    return environment


def checked_output(argv: Sequence[str | Path], description: str) -> str:
    result = run(argv, env=tool_environment())
    require(result.returncode == 0, f"{description} failed: {result.stderr.decode(errors='replace')[-2000:]}")
    return result.stdout.decode()


def toolchain_identity(retained: Retained) -> dict[str, Any]:
    """Bind the pinned compiler, standard-library sources and LTO linker.

    Linker-plugin LTO in these lanes is LLD's builtin LLVM, so the IR producer
    (rustc) and IR consumer (the pinned ``ld.lld``) must carry one LLVM version.
    """

    rustc = ["rustup", "run", CHANNEL, "rustc"]
    rustc_vv = checked_output([*rustc, "-Vv"], "rustc -Vv")
    cargo_vv = checked_output(["rustup", "run", CHANNEL, "cargo", "-Vv"], "cargo -Vv")
    sysroot = Path(checked_output([*rustc, "--print", "sysroot"], "rustc sysroot").strip())
    target_libdir = Path(checked_output([*rustc, "--target", TARGET, "--print", "target-libdir"],
                                        "rustc target libdir").strip())
    host = re.search(r"^host: (\S+)$", rustc_vv, re.MULTILINE)
    llvm = re.search(r"^LLVM version: (\S+)$", rustc_vv, re.MULTILINE)
    require(host is not None and host.group(1) == TARGET and llvm is not None,
            f"pinned rustc is not a native {TARGET} host with an LLVM identity")
    tools = sysroot / "lib/rustlib" / TARGET / "bin"
    lld = tools / "gcc-ld/ld.lld"
    lld_version = checked_output([lld, "--version"], "pinned ld.lld --version").strip()
    lld_llvm = re.search(r"LLD (\d+\.\d+\.\d+)", lld_version)
    require(lld_llvm is not None and llvm.group(1).startswith(lld_llvm.group(1)),
            f"linker-plugin LLD {lld_version!r} does not carry rustc LLVM {llvm.group(1)}")
    library = sysroot / "lib/rustlib/src/rust/library"
    return {
        "channel": CHANNEL,
        "rustc_vv": rustc_vv,
        "cargo_vv": cargo_vv,
        "sysroot": str(sysroot),
        "target_libdir": str(target_libdir),
        "llvm_version": llvm.group(1),
        "lld": {**retained.record(lld), "version": lld_version},
        "channel_manifest": retained.record(sysroot / "lib/rustlib/multirust-channel-manifest.toml"),
        "rust_src_manifest": retained.record(sysroot / "lib/rustlib/manifest-rust-src"),
        "rust_std_manifest": retained.record(sysroot / f"lib/rustlib/manifest-rust-std-{TARGET}"),
        "rust_src_library_lock": retained.record(library / "Cargo.lock"),
        "tools": {name: str(tools / name) for name in ("llvm-nm", "llvm-objdump", "llvm-ar")},
    }


# ---------------------------------------------------------------------------
# Dependency vendor


def fixture_lock_closure() -> dict[str, tuple[str, str, str]]:
    """Union of the frozen fixtures' locked crates.io packages."""

    closure: dict[str, tuple[str, str, str]] = {}
    for name in VENDORED_FIXTURES:
        lock = FIXTURES[name] / "Cargo.lock"
        for directory, identity in owned_cleanup.locked_registry_vendor_packages(lock, f"{name} lock").items():
            require(closure.get(directory, identity) == identity, f"fixture locks disagree about {directory}")
            closure[directory] = identity
    return closure


def dependency_vendor(root: Path) -> tuple[dict[str, Any], dict[str, tuple[str, str, str]]]:
    """Authenticate a prepared vendor against the fixture locks, file by file."""

    expected = fixture_lock_closure()
    root = owned_cleanup.work_child(root, "fixture dependency vendor", existing=True)
    return owned_cleanup.cargo_vendor_tree(root, expected, "fixture dependency vendor"), expected


def prepare_vendor(output: Path) -> Path:
    """Vendor the frozen fixtures' locked crates (the only networked step)."""

    output = owned_cleanup.work_child(output, "fixture dependency vendor")
    cargo_home = output.parent / f".{output.name}.cargo-home"
    require(not cargo_home.exists(), f"vendor Cargo home must be fresh: {cargo_home}")
    cargo_home.mkdir()
    manifests = [FIXTURES[name] / "Cargo.toml" for name in VENDORED_FIXTURES]
    command = ["rustup", "run", CHANNEL, "cargo", "vendor", "--locked", "--versioned-dirs",
               "--manifest-path", str(manifests[0])]
    for manifest in manifests[1:]:
        command += ["--sync", str(manifest)]
    command.append(str(output))
    result = run(command, env={**tool_environment(), "CARGO_HOME": str(cargo_home)}, cwd=output.parent)
    shutil.rmtree(cargo_home, ignore_errors=True)
    require(result.returncode == 0, f"cargo vendor failed: {result.stderr.decode(errors='replace')[-2000:]}")
    dependency_vendor(output)
    return output


# ---------------------------------------------------------------------------
# Products


def cohort_products(static_preparation: Path, dynamic_qualification: Path) -> tuple[dict[str, Any], dict[str, dict[str, Path]]]:
    """Reuse the POSIX family matrix's product reader for one source cohort."""

    import owned_posix_family_execution as family  # pylint: disable=import-outside-toplevel

    request = {
        "schema": family.SCHEMA,
        "source_mount": "/workspace",
        "static_preparation": Path(os.path.abspath(static_preparation)).relative_to(ROOT).as_posix(),
        "dynamic_qualification": Path(os.path.abspath(dynamic_qualification)).relative_to(ROOT).as_posix(),
    }
    evidence, products = family.input_products(ROOT, request)
    return {"request": request, "evidence": evidence}, products


def product_pair(label: str, static_root: Path, dynamic_root: Path) -> dict[str, Any]:
    static = owned_cleanup.product_snapshot(static_root, "static")
    dynamic = owned_cleanup.product_snapshot(dynamic_root, "dynamic")
    require(static["root"] != dynamic["root"], "static and dynamic product roots must be distinct")
    return {"label": label, "static": static, "dynamic": dynamic}


# ---------------------------------------------------------------------------
# Cargo consumers


class Context:
    def __init__(self, *, output: Path, retained: Retained, toolchain: dict[str, Any], provider: dict[str, Any],
                 cargo_home: Path, products: dict[str, dict[str, Any]], consumer: str) -> None:
        self.output = output
        self.consumer = consumer
        self.retained = retained
        self.toolchain = toolchain
        self.provider = provider
        self.cargo_home = cargo_home
        self.products = products

    def root(self, mode: str) -> Path:
        """The consumer pair's installed ``static`` or ``dynamic`` product root."""

        return Path(self.products[self.consumer][mode]["root"])

    def tool(self, name: str) -> str:
        return self.toolchain["tools"][name]


def has_path_dependency(manifest: Path) -> bool:
    document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    return any(isinstance(value, dict) and "path" in value for value in document.get("dependencies", {}).values())


def package_name(manifest: Path) -> str:
    return tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["name"]


def cargo_consumer(
    context: Context, lane: Path, *, fixture: str, build_std: bool, flags: Sequence[str], link: str,
    product: str | None = None, panic_runtime: str = "panic_abort", application_dsos: Sequence[Path] = (),
) -> dict[str, Any]:
    """Build one frozen fixture with Cargo; ``link`` is owned-static/-dynamic or oracle."""

    lane.mkdir(parents=True)
    source = FIXTURES[fixture]
    manifest = source / "Cargo.toml"
    locked = (source / "Cargo.lock").is_file()
    if has_path_dependency(manifest):
        # Path dependencies are spelled relative to the checkout, so build in
        # place; ``--locked --offline`` leaves the source tree untouched.
        require(locked, f"{fixture} fixture with path dependencies must carry its lock")
    else:
        project = lane / "project"
        (project / "src").mkdir(parents=True)
        for name in ("Cargo.toml", "Cargo.lock"):
            if (source / name).is_file():
                shutil.copy2(source / name, project / name)
        shutil.copy2(source / "src/main.rs", project / "src/main.rs")
        manifest = project / "Cargo.toml"
    target = lane / "target"
    target.mkdir()
    rustflags = list(flags)
    environment = {
        **tool_environment(),
        "CARGO_HOME": str(context.cargo_home),
        "CARGO_TARGET_DIR": str(target),
        "CARGO_INCREMENTAL": "0",
        "SOURCE_DATE_EPOCH": "0",
    }
    if link == "oracle":
        rustflags += ORACLE_FLAGS
    else:
        mode = {"owned-static": "static", "owned-dynamic": "dynamic"}[link]
        require(product is not None, "owned consumer link requires a product")
        pair = context.products[product]
        rustflags += ["-C", "link-self-contained=no", "-C", f"linker={LINKER}"]
        environment.update({
            "CRABC_OWNED_RUST_LINK_MODE": mode,
            "CRABC_OWNED_RUST_PRODUCT": pair[mode]["root"],
            "CRABC_OWNED_RUST_STOCK_LIBDIR": context.toolchain["target_libdir"],
            "CRABC_OWNED_RUST_PROVIDER": context.provider["archive"]["path"],
            "CRABC_OWNED_RUST_CHANNEL": CHANNEL,
            owned_rust_link.CARGO_TARGET_ENV: str(target),
            owned_rust_link.CARGO_STD_ENV: "build-std" if build_std else "stock",
            owned_rust_link.CARGO_APPLICATION_DSOS_ENV: os.pathsep.join(map(str, application_dsos)),
        })
    environment["RUSTFLAGS"] = " ".join(rustflags)
    command = [
        "rustup", "run", CHANNEL, "cargo", "build", "--release", "--offline", "--target", TARGET,
        "--manifest-path", str(manifest), "--message-format=json-render-diagnostics",
        *(BUILD_STD[panic_runtime] if build_std else ()), *(("--locked",) if locked else ()),
    ]
    result = run(command, env=environment, cwd=lane)
    record: dict[str, Any] = {
        "fixture": str(source.relative_to(ROOT)),
        "link": link,
        "product": product,
        "build_std": build_std,
        "command": command,
        "rustflags": environment["RUSTFLAGS"],
        "linker_environment": {key: value for key, value in environment.items() if key.startswith("CRABC_OWNED_RUST_")},
        "returncode": result.returncode,
        "stdout": context.retained.write(f"{lane.relative_to(context.output)}/cargo.jsonl", result.stdout),
        "stderr": context.retained.write(f"{lane.relative_to(context.output)}/cargo.stderr", result.stderr),
    }
    executable: Path | None = None
    name = package_name(manifest)
    for line in result.stdout.decode(errors="replace").splitlines():
        if line.startswith("{"):
            message = json.loads(line)
            if message.get("reason") == "compiler-artifact" and message.get("executable") \
                    and message["target"]["name"] == name:
                executable = Path(message["executable"])
    if result.returncode != 0 or executable is None:
        record["status"] = "build-failed"
        record["stderr_tail"] = result.stderr.decode(errors="replace")[-4000:]
        return record
    record["executable"] = context.retained.record(executable)
    if link != "oracle":
        digest = record["executable"]["sha256"]
        receipts = [path for path in target.rglob("*" + ".crabc-owned-rust-link.json")
                    if json.loads(path.read_text())["output"]["sha256"] == digest]
        require(len(receipts) == 1, f"{lane.name}: expected one owned link receipt for the executable")
        receipt = json.loads(receipts[0].read_text())
        record["link_receipt"] = context.retained.record(receipts[0])
        record["link_facts"] = {
            "mode": receipt["mode"],
            "std_origin": receipt["std_origin"],
            "unwind_requests": receipt["unwind_requests"],
            "provider_members_extracted": receipt["provider_members_extracted"],
            "input_kinds": sorted({item.get("kind", "rlib") for item in receipt["application_inputs"]}),
            "linker_plugin_options": receipt["linker_plugin_options"],
            "resolved_input_trace": receipt["resolved_input_trace"],
        }
    record["status"] = "built"
    return record


def owned_link_conditions(name: str, build: Mapping[str, Any], *, provider: Mapping[str, Any]) -> list[str]:
    """The owned-link facts every candidate must show."""

    if build.get("status") != "built":
        return [f"{name}: {build.get('status')}: {build.get('stderr_tail', '')[-600:]}"]
    link = build["link_facts"]
    unmet = []
    if link["unwind_requests"] and link["provider_members_extracted"] != [provider_build.PROVIDER_MEMBER]:
        unmet.append(f"{name}: unwind request did not extract the provider member by ordinary archive extraction")
    if not link["unwind_requests"]:
        unmet.append(f"{name}: std graph made no native unwinder request")
    return unmet


# ---------------------------------------------------------------------------
# ELF inspection and execution


def inspect_elf(context: Context, path: Path, *, dynamic: bool, needed_dsos: Sequence[str] = ()) -> dict[str, Any]:
    header = checked_output(["readelf", "-hW", path], "readelf -h")
    segments = checked_output(["readelf", "-lW", path], "readelf -l")
    dynamic_section = checked_output(["readelf", "-dW", path], "readelf -d")
    defined = checked_output([context.tool("llvm-nm"), "--defined-only", path], "llvm-nm defined")
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^]]+)\]", dynamic_section)
    interpreter = re.search(r"Requesting program interpreter: ([^]]+)\]", segments)
    unwind = sorted({line.split()[-1] for line in defined.splitlines()
                     if len(line.split()) >= 3 and line.split()[-1].startswith("_Unwind_")})
    problems = []
    if "Advanced Micro Devices X86-64" not in header or not re.search(r"Type:\s+DYN", header):
        problems.append("image is not an x86-64 ET_DYN")
    for segment in ("GNU_EH_FRAME", "GNU_RELRO", "GNU_STACK"):
        if segment not in segments:
            problems.append(f"image lacks {segment}")
    if "TEXTREL" in dynamic_section:
        problems.append("image has text relocations")
    if dynamic:
        if interpreter is None or interpreter.group(1) != owned_rust_link.INTERPRETER \
                or needed != [*needed_dsos, "libc.so"]:
            problems.append(f"dynamic image runtime is {interpreter and interpreter.group(1)} {needed}")
    elif interpreter is not None or needed:
        problems.append("static image names an interpreter or DSO")
    if not set(unwind) <= provider_build.UNWIND_ABI:
        problems.append(f"image defines an unselected unwind ABI: {unwind}")
    return {"interpreter": interpreter.group(1) if interpreter else None, "needed": needed,
            "defined_unwind_abi": unwind, "problems": problems}


def execution_root(root: Path, *, runtime: str, product: Path | None) -> list[dict[str, str]]:
    """Build one private root; oracle and candidate roots differ only in runtime."""

    if runtime == "candidate":
        assert product is not None
        shutil.copytree(product, root, symlinks=True)
        runtime_files = [product / "lib/ld-crabc-x86_64.so.1", product / "usr/lib/libc.so"]
    else:
        musl = root / str(MUSL_LIB).lstrip("/")
        musl.mkdir(parents=True)
        shutil.copy2(MUSL_LIB / "libc.so", musl / "libc.so")
        (musl / "ld-musl-x86_64.so.1").symlink_to("libc.so")
        (root / "usr/lib").mkdir(parents=True)
        shutil.copy2(LIBGCC_S, root / "usr/lib/libgcc_s.so.1")
        runtime_files = [MUSL_LIB / "libc.so", LIBGCC_S]
    (root / "tmp").mkdir(exist_ok=True)
    os.chmod(root / "tmp", 0o1777)
    (root / "dev").mkdir(exist_ok=True)
    os.mknod(root / "dev/null", 0o666 | stat.S_IFCHR, os.makedev(1, 3))
    os.chmod(root / "dev/null", 0o666)
    (root / "etc").mkdir(exist_ok=True)
    (root / "etc/hosts").write_text(HOSTS_FIXTURE, encoding="ascii")
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/exe").symlink_to("/" + EXECUTABLE)
    return [{"path": str(path), "sha256": sha256_file(path)} for path in runtime_files]


def execute(context: Context, lane: Path, binary: Path, *, runtime: str, product: Path | None,
            label: str, libraries: Sequence[Path] = ()) -> dict[str, Any]:
    """Run once in a fresh root; ``libraries`` are application DSOs for ``/usr/lib``."""

    root = lane / f"root-{label}"
    runtime_files = execution_root(root, runtime=runtime, product=product)
    for library in libraries:
        shutil.copy2(library, root / "usr/lib" / library.name)
    shutil.copy2(binary, root / EXECUTABLE)
    os.chmod(root / EXECUTABLE, 0o755)

    def enter() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.chroot(root)
        os.chdir("/")

    try:
        result = subprocess.run(["/" + EXECUTABLE], env=EXECUTION_ENVIRONMENT, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=EXECUTION_TIMEOUT, preexec_fn=enter, check=False)
        status: int | str = result.returncode
        stdout, stderr = result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        status, stdout, stderr = "timeout", error.stdout or b"", error.stderr or b""
    relative = lane.relative_to(context.output)
    return {
        "runtime": runtime,
        "runtime_files": runtime_files,
        "executable": context.retained.record(root / EXECUTABLE),
        "status": status,
        "stdout": context.retained.write(f"{relative}/{label}.stdout", stdout),
        "stderr": context.retained.write(f"{relative}/{label}.stderr", stderr),
        "stdout_text": stdout.decode(errors="replace"),
        "stderr_text": stderr.decode(errors="replace"),
    }


def raw_comparison(oracle: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    same = {
        "status": oracle["status"] == candidate["status"],
        "stdout": oracle["stdout"]["sha256"] == candidate["stdout"]["sha256"],
        "stderr": oracle["stderr"]["sha256"] == candidate["stderr"]["sha256"],
    }
    return {"normalization": "none", "same": same, "oracle_succeeded": oracle["status"] == 0,
            "passed": oracle["status"] == 0 and all(same.values())}


def expected_output(name: str, execution: Mapping[str, Any], expected: bytes) -> list[str]:
    if execution["status"] != 0 or execution["stdout_text"].encode() != expected or execution["stderr_text"]:
        return [f"{name}: exit {execution['status']} with output {execution['stdout_text'][-200:]!r}"
                f" / {execution['stderr_text'][-200:]!r}, expected {expected!r}"]
    return []


def compared_lane(context: Context, name: str, fixture: str, flags: Sequence[str]) -> dict[str, Any]:
    """Build a dynamic candidate and its musl control; compare raw output."""

    lane = context.output / "gates" / name
    candidate = cargo_consumer(context, lane / "candidate", fixture=fixture, build_std=True, flags=flags,
                               link="owned-dynamic", product=context.consumer)
    oracle = cargo_consumer(context, lane / "oracle", fixture=fixture, build_std=True, flags=flags, link="oracle")
    report: dict[str, Any] = {"candidate_build": candidate, "oracle_build": oracle}
    unmet = owned_link_conditions(name, candidate, provider=context.provider)
    if oracle.get("status") != "built":
        unmet.append(f"{name}: musl control {oracle.get('status')}: {oracle.get('stderr_tail', '')[-600:]}")
    if unmet:
        report["unmet"] = unmet
        return report
    report["candidate_elf"] = inspect_elf(context, Path(candidate["executable"]["path"]), dynamic=True)
    unmet.extend(f"{name}: {problem}" for problem in report["candidate_elf"]["problems"])
    dynamic_root = context.root("dynamic")
    report["oracle"] = execute(context, lane, Path(oracle["executable"]["path"]), runtime="oracle", product=None,
                               label="oracle")
    report["candidate"] = execute(context, lane, Path(candidate["executable"]["path"]), runtime="candidate",
                                  product=dynamic_root, label="candidate")
    report["comparison"] = raw_comparison(report["oracle"], report["candidate"])
    if not report["comparison"]["passed"]:
        unmet.append(f"{name}: oracle/candidate raw comparison failed {report['comparison']['same']}"
                     f" (oracle {report['oracle']['status']}, candidate {report['candidate']['status']}:"
                     f" {report['candidate']['stderr_text'][-300:]!r})")
    report["unmet"] = unmet
    return report


def gate_rust_std(context: Context, gate: str) -> dict[str, Any]:
    fixture = "rust-std" if gate == "rust-std" else "rust-std-dependent"
    return {"lanes": {"stock-std": compared_lane(context, gate, fixture, RUST_STD_FLAGS)}}


def lto_expected_stdout() -> bytes:
    """The frozen LTO fixture's deterministic output, computed independently."""

    mask = (1 << 64) - 1
    total = 0
    for value in range(4096):
        mixed = (value * 0x9E3779B97F4A7C15) & mask
        mixed = ((mixed << 17) | (mixed >> 47)) & mask
        total = (total + (mixed ^ 0xA5A55A5AD3C3B4B4)) & mask
    return f"lto-libc:ok\nlto-workload:{total:016x}\n".encode()


def static_c_lane(context: Context, key: str) -> dict[str, Any]:
    """Frozen A (pinned musl) and B (installed sealed static driver) C lanes."""

    lane = context.output / "gates/lto" / key
    lane.mkdir(parents=True)
    source = FIXTURES["lto"] / "static.c"
    binary = lane / ("musl-static" if key == "A" else "crabc-static")
    environment = tool_environment()
    if key == "A":
        # A doubled GNU ld trace names every extracted archive member.
        steps = [[str(ORACLE_CC), *STATIC_C_FLAGS, "-static", "-no-pie", str(source), "-Wl,-t,-t", "-o", str(binary)]]
    else:
        driver = context.root("static") / "bin/crabc-cc"
        steps = [[str(driver), "-static", *STATIC_C_FLAGS, "-c", str(source), "-o", str(lane / "static.o")],
                 [str(driver), "-static", str(lane / "static.o"), "-o", str(binary),
                  "--link-receipt", "crabc-static.link.json"]]
    report: dict[str, Any] = {"steps": []}
    for index, command in enumerate(steps):
        result = run(command, env=environment, cwd=lane)
        report["steps"].append({
            "command": command, "returncode": result.returncode,
            "stdout": context.retained.write(f"gates/lto/{key}/step{index}.stdout", result.stdout),
            "stderr": context.retained.write(f"gates/lto/{key}/step{index}.stderr", result.stderr),
        })
        if result.returncode != 0:
            report["unmet"] = [f"lto/{key}: build failed: {result.stderr.decode(errors='replace')[-600:]}"]
            return report
    report["executable"] = context.retained.record(binary)
    unmet: list[str] = []
    if key == "A":
        lines = (lane / "step0.stdout").read_text(errors="replace").splitlines()
        musl_libc = str(MUSL_LIB / "libc.a")
        # GNU ld spells an archive member ``path(member)`` or ``(path)member``.
        report["musl_libc_selected"] = any(line.startswith((musl_libc + "(", f"({musl_libc})")) for line in lines)
        if not report["musl_libc_selected"]:
            unmet.append("lto/A: link trace does not select the pinned musl libc.a")
    else:
        report["link_receipt"] = context.retained.record(lane / "crabc-static.link.json")
        trace_lines = (lane / "crabc-static.link.trace").read_text(errors="replace").splitlines()
        libc = str(context.root("static") / "usr/lib/libc.a")
        report["installed_libc_selected"] = any(line.startswith(libc + "(") for line in trace_lines)
        report["foreign_runtime_in_trace"] = [line for line in trace_lines
                                             if "/opt/musl" in line or "/usr/lib/gcc" in line or "libgcc" in line]
        if not report["installed_libc_selected"] or report["foreign_runtime_in_trace"]:
            unmet.append("lto/B: trace does not prove exclusive installed libc.a selection")
    report["execution"] = execute(context, lane, binary, runtime="candidate" if key == "B" else "oracle",
                                  product=context.root("dynamic") if key == "B" else None, label="run")
    unmet.extend(expected_output(f"lto/{key}", report["execution"], EXPECTED_STDOUT["lto-c"]))
    report["unmet"] = unmet
    return report


def gate_lto(context: Context) -> dict[str, Any]:
    lanes = {key: static_c_lane(context, key) for key in ("A", "B")}
    if "executable" in lanes["A"] and "executable" in lanes["B"] \
            and lanes["A"]["executable"]["sha256"] == lanes["B"]["executable"]["sha256"]:
        lanes["B"]["unmet"].append("lto/B: crabc static image is byte-identical to the musl control")
    expected = lto_expected_stdout()
    for key, flags, link in (("C", LTO_C_FLAGS, "owned-dynamic"), ("D", LTO_D_FLAGS, "owned-static")):
        lane = context.output / "gates/lto" / key
        build = cargo_consumer(context, lane, fixture="lto", build_std=True, flags=flags, link=link,
                               product=context.consumer)
        report: dict[str, Any] = {"build": build, "expected_stdout": expected.decode()}
        unmet = owned_link_conditions(f"lto/{key}", build, provider=context.provider)
        if build.get("status") == "built":
            dynamic = link == "owned-dynamic"
            report["elf"] = inspect_elf(context, Path(build["executable"]["path"]), dynamic=dynamic)
            unmet.extend(f"lto/{key}: {problem}" for problem in report["elf"]["problems"])
            if key == "D":
                libc = str(context.root("static") / "usr/lib/libc.a")
                facts = build["link_facts"]
                report["ir"] = {
                    "rust_input_kinds": facts["input_kinds"],
                    "linker_plugin_options": facts["linker_plugin_options"],
                    "installed_libc_selected": any(line.startswith(libc + "(")
                                                   for line in facts["resolved_input_trace"].splitlines()),
                    # As in the frozen gate, the installed native libc.a
                    # carries no bitcode; no whole-program claim follows.
                    "whole_program_lto_proven": False,
                }
                if "llvm-bitcode" not in report["ir"]["rust_input_kinds"] or not report["ir"]["linker_plugin_options"]:
                    unmet.append("lto/D: linker-plugin LTO did not receive LLVM bitcode inputs")
                if not report["ir"]["installed_libc_selected"]:
                    unmet.append("lto/D: trace does not select the installed libc.a")
            report["execution"] = execute(
                context, lane, Path(build["executable"]["path"]), runtime="candidate",
                product=context.root("dynamic"), label="run")
            unmet.extend(expected_output(f"lto/{key}", report["execution"], expected))
        report["unmet"] = unmet
        lanes[key] = report
    return {"lanes": lanes}


def function_disassembly(disassembly: str, symbol: str) -> str | None:
    marker = re.compile(rf"(?m)^[0-9a-f]+ <{re.escape(symbol)}>:$")
    match = marker.search(disassembly)
    if match is None:
        return None
    following = re.search(r"(?m)^[0-9a-f]+ <[^>]+>:$", disassembly[match.end():])
    end = match.end() + following.start() if following else len(disassembly)
    return disassembly[match.start():end]


def x86_syscall_pattern(number: int) -> str:
    """Accept GNU and LLVM AT&T spellings (``mov $0x27,%eax``/``movl $0x27, %eax``)."""

    return rf"\bmov[lq]?\s+\$0x{number:x},\s*%(?:e|r)ax\b[\s\S]{{0,600}}?\bsyscall\b"


def inspect_native_route(disassembly: str) -> dict[str, Any]:
    """Function-scoped x86 evidence for the frozen facade witness.

    This is the x86 spelling of the frozen AArch64 check (``svc #0`` with
    syscall 172): the witness must reach ``getpid`` (39) directly and must not
    branch to the public C ``getpid``/``write`` or TLS ``__errno_location``.
    """

    witness = function_disassembly(disassembly, NATIVE_FACADE_WITNESS)
    if witness is None:
        return {"anchor_present": False, "direct_route_proven": False}
    getpid = len(re.findall(x86_syscall_pattern(X86_SYSCALLS["getpid"]), witness))
    write_direct = bool(re.search(x86_syscall_pattern(X86_SYSCALLS["write"]), disassembly))
    forbidden = [name for name in FORBIDDEN_WITNESS_CALLS
                 if re.search(rf"\b(?:call|jmp)\w*\s+[^\n]*<{re.escape(name)}(?:@[^>]*)?>", witness)]
    return {
        "anchor_present": True,
        "witness_direct_getpid_syscalls": getpid,
        "direct_write_syscall": write_direct,
        "branch_forbidden_symbols": forbidden,
        "direct_route_proven": getpid >= 1 and write_direct and not forbidden,
        "assembly_byte_exactness_claimed": False,
    }


def rlib_bitcode(context: Context, target: Path, crate: str) -> bool:
    """Whether every ``crate`` rlib in one lane carries embedded LLVM bitcode."""

    rlibs = sorted(target.rglob(f"lib{crate}-*.rlib"))
    if not rlibs:
        return False
    for rlib in rlibs:
        sections = checked_output([context.tool("llvm-objdump"), "--section-headers", rlib], "llvm-objdump -h")
        if ".llvmbc" not in sections:
            return False
    return True


def gate_native_facade(context: Context) -> dict[str, Any]:
    lanes: dict[str, Any] = {}
    dynamic_root = context.root("dynamic")
    for key, lto in (("control-o3", "off"), ("fat-lto", "fat")):
        lane = context.output / "gates/lto-native-facade" / key
        build = cargo_consumer(context, lane, fixture="native-facade", build_std=False,
                               flags=(*FACADE_FLAGS, "-C", f"lto={lto}"), link="owned-dynamic",
                               product=context.consumer)
        report: dict[str, Any] = {"lane_class": "candidate-native-facade", "build": build}
        unmet = [] if build.get("status") == "built" else [
            f"lto-native-facade/{key}: {build.get('status')}: {build.get('stderr_tail', '')[-600:]}"]
        if build.get("status") == "built":
            binary = Path(build["executable"]["path"])
            report["elf"] = inspect_elf(context, binary, dynamic=True)
            unmet.extend(f"lto-native-facade/{key}: {problem}" for problem in report["elf"]["problems"])
            disassembly = checked_output([context.tool("llvm-objdump"), "-d", "--no-show-raw-insn", binary],
                                         "llvm-objdump -d")
            report["route"] = inspect_native_route(disassembly)
            if not report["route"]["direct_route_proven"]:
                unmet.append(f"lto-native-facade/{key}: direct x86 getpid/write route not proven")
            if lto == "fat":
                report["crabc_rlib_bitcode"] = {crate: rlib_bitcode(context, lane / "target", crate)
                                                for crate in ("crabc_rs", "crabc_core")}
                if not all(report["crabc_rlib_bitcode"].values()):
                    unmet.append("lto-native-facade/fat-lto: crabc-rs/crabc-core rlibs lack LLVM bitcode")
            report["execution"] = execute(context, lane, binary, runtime="candidate", product=dynamic_root,
                                          label="run")
            unmet.extend(expected_output(f"lto-native-facade/{key}", report["execution"],
                                         EXPECTED_STDOUT["native-facade"]))
        report["unmet"] = unmet
        lanes[key] = report
    report = compared_lane(context, "lto-native-facade/stock-std-fat", "native-std",
                           (*FACADE_FLAGS, "-C", "lto=fat"))
    report["lane_class"] = "stock-std-with-musl-control"
    report["lto_into_dynamic_libc_proven"] = False
    if "candidate" in report:
        report["unmet"].extend(expected_output("lto-native-facade/stock-std-fat", report["candidate"],
                                               EXPECTED_STDOUT["native-std"]))
    lanes["stock-std-fat"] = report
    return {"lanes": lanes}


# ---------------------------------------------------------------------------
# Unwind matrix


def unwind_matrix(context: Context, provider_vendor: Path, labels: Sequence[str]) -> dict[str, Any]:
    """Run the existing owned cleanup consumer against each product pair."""

    results: dict[str, Any] = {}
    for label in labels:
        pair = context.products[label]
        output = context.output / "unwind" / label
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            owned_cleanup.run(Path(pair["static"]["root"]), Path(pair["dynamic"]["root"]), provider_vendor, output)
        except (owned_cleanup.OwnedCleanupError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            results[label] = {"output": str(output), "unmet": [f"unwind/{label}: {error}"]}
            continue
        receipt = json.loads((output / "receipt.json").read_text())
        results[label] = {
            "output": str(output),
            "receipt": context.retained.record(output / "receipt.json"),
            "stock_modes": sorted(receipt["stock_consumers"]),
            "source_built_modes": sorted(receipt["source_built_consumers"]),
            "unmet": [],
        }
    return results


def dynamic_symbols(context: Context, image: Path) -> set[str]:
    """Every defined or undefined dynamic-symbol name of one ELF image."""

    listing = checked_output([context.tool("llvm-nm"), "--dynamic", image], "llvm-nm --dynamic")
    return {line.split()[-1] for line in listing.splitlines() if line.split()}


def cross_dso_lane(context: Context, label: str, *, build_std: bool) -> dict[str, Any]:
    """Unwind through C frames of an initial and a runtime DSO (one product pair).

    Both DSOs are built from ``frame.c`` by the pair's installed dynamic
    driver. The executable is a stock-std or ``-Zbuild-std=std,panic_unwind``
    Cargo graph linked through ``link_cargo``, so the standalone provider
    reaches both standard-library origins by ordinary archive extraction.
    """

    origin = "build-std" if build_std else "stock-std"
    lane = context.output / "unwind" / f"cross-dso-{origin}-{label}"
    dsos = lane / "dsos"
    dsos.mkdir(parents=True)
    dynamic_root = Path(context.products[label]["dynamic"]["root"])
    driver = dynamic_root / "bin/crabc-cc-dynamic"
    report: dict[str, Any] = {"label": label, "origin": origin, "dsos": {}}
    for name in (CROSS_DSO_INITIAL, CROSS_DSO_RUNTIME):
        command = [str(driver), "--dynamic-shared-object", str(CROSS_DSO_FRAME), "-o", str(dsos / name)]
        result = run(command, env=tool_environment(), cwd=dsos)
        context.retained.write(f"{lane.relative_to(context.output)}/{name}.log", result.stdout + result.stderr)
        if result.returncode != 0:
            report["unmet"] = [f"unwind/{lane.name}: {name} build failed: {result.stderr.decode(errors='replace')[-600:]}"]
            return report
        report["dsos"][name] = context.retained.record(dsos / name)
    # A dl_iterate_phdr unwinder (this provider, libgcc or LLVM libunwind)
    # finds a C frame's FDE only through its object's PT_GNU_EH_FRAME.
    unmet: list[str] = []
    for name in report["dsos"]:
        if "GNU_EH_FRAME" not in checked_output(["readelf", "-lW", dsos / name], "readelf -l"):
            unmet.append(f"unwind/{lane.name}: installed dynamic driver linked {name} without PT_GNU_EH_FRAME"
                         " (--eh-frame-hdr), so its C frame has no discoverable FDE")
    build = cargo_consumer(context, lane / "consumer", fixture="cross-dso", build_std=build_std,
                           flags=CROSS_DSO_FLAGS, link="owned-dynamic", product=label,
                           panic_runtime="panic_unwind", application_dsos=(dsos / CROSS_DSO_INITIAL,))
    report["build"] = build
    unmet += owned_link_conditions(f"unwind/{lane.name}", build, provider=context.provider)
    if build.get("status") == "built":
        binary = Path(build["executable"]["path"])
        report["elf"] = inspect_elf(context, binary, dynamic=True, needed_dsos=(CROSS_DSO_INITIAL,))
        unmet.extend(f"unwind/{lane.name}: {problem}" for problem in report["elf"]["problems"])
        missing = {"_Unwind_RaiseException", "_Unwind_Resume", "_Unwind_Backtrace"} - set(report["elf"]["defined_unwind_abi"])
        if missing:
            unmet.append(f"unwind/{lane.name}: executable lacks provider entries {sorted(missing)}")
        # One provider per image: the executable resolves every `_Unwind_*`
        # reference through its own ordinary link, and the C DSOs carry no
        # unwinder at all, so their frames are reachable only by the
        # executable's provider walking dl_iterate_phdr.
        report["dynamic_unwind_symbols"] = {
            image.name: sorted(name for name in dynamic_symbols(context, image) if name.startswith("_Unwind_"))
            for image in (binary, dsos / CROSS_DSO_INITIAL, dsos / CROSS_DSO_RUNTIME)
        }
        shared = {name: symbols for name, symbols in report["dynamic_unwind_symbols"].items() if symbols}
        if shared:
            unmet.append(f"unwind/{lane.name}: _Unwind_* crosses an image boundary dynamically: {shared}")
        report["execution"] = execute(context, lane, binary, runtime="candidate", product=dynamic_root, label="run",
                                      libraries=[dsos / CROSS_DSO_INITIAL, dsos / CROSS_DSO_RUNTIME])
        unmet.extend(expected_output(f"unwind/{lane.name}", report["execution"], CROSS_DSO_STDOUT))
    report["unmet"] = unmet
    return report


def provider_regressions(context: Context) -> dict[str, Any]:
    """Run each standalone malformed-metadata regression once; retain its receipt."""

    results: dict[str, Any] = {}
    for script in PROVIDER_REGRESSIONS:
        result = run([sys.executable, "-B", ROOT / "unwinder" / script],
                     env={**tool_environment(), "PYTHONDONTWRITEBYTECODE": "1"}, cwd=ROOT)
        log = context.retained.write(f"provider-regressions/{script}.log", result.stdout + result.stderr)
        lines = result.stdout.decode(errors="replace").splitlines()
        record: dict[str, Any] = {"returncode": result.returncode, "log": log, "unmet": []}
        run_directory = Path(lines[-1]) if lines else None
        if result.returncode != 0 or run_directory is None or not (run_directory / "receipt.json").is_file():
            record["unmet"].append(f"provider-regressions/{script}: exit {result.returncode}; see its log")
        else:
            record["receipt"] = context.retained.record(run_directory / "receipt.json")
        results[script] = record
    return {"lanes": results}


# ---------------------------------------------------------------------------
# Gate


def lane_unmet(report: Mapping[str, Any]) -> list[str]:
    return [item for lane in report["lanes"].values() for item in lane.get("unmet", [])]


def run_gate(arguments: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "native Linux/x86-64 required")
    require(os.geteuid() == 0, "execution roots require container root for chroot and device nodes")
    import owned_dynamic_qualification as qualification  # pylint: disable=import-outside-toplevel

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source_before = qualification.source_digest()
    output = owned_cleanup.work_child(arguments.output, "consumer gate output")
    output.mkdir(mode=0o755)
    retained = Retained(output)
    if arguments.static_preparation is not None:
        cohort, cohort_paths = cohort_products(arguments.static_preparation, arguments.dynamic_qualification)
        products = {label: product_pair(label, cohort_paths[label]["static"], cohort_paths[label]["dynamic"])
                    for label in UNWIND_PRODUCTS}
        consumer_label, unwind_labels = CONSUMER_PRODUCT, UNWIND_PRODUCTS
    else:
        cohort = None
        products = {DEVELOPMENT_PRODUCT: product_pair(DEVELOPMENT_PRODUCT, arguments.development_static_sysroot,
                                                      arguments.development_dynamic_sysroot)}
        consumer_label, unwind_labels = DEVELOPMENT_PRODUCT, (DEVELOPMENT_PRODUCT,)
    toolchain = toolchain_identity(retained)

    # One fresh provider for every frozen consumer, built from the same
    # authenticated vendor input the unwind matrix rebuilds for itself.
    provider_sources = owned_cleanup.prepare_standalone_provider_cargo_home(output, arguments.provider_vendor)
    registry_source = owned_cleanup.provider_registry_unwinding_source(output, provider_sources)
    build_result = run([
        sys.executable, "-B", ROOT / "unwinder/build.py", "--output", output / "provider",
        "--stage-root", output / "provider" / "source-inputs", "--cargo-home", provider_sources["cargo_home"],
        "--registry-unwinding-source", registry_source["registry_source"],
    ], env={**tool_environment(), **{k: v for k, v in os.environ.items() if k in {"RUSTUP_HOME"}}})
    retained.write("provider-build.log", build_result.stdout + build_result.stderr)
    require(build_result.returncode == 0, "provider build failed; see provider-build.log")
    provider = owned_cleanup.provider_snapshot(output / "provider", toolchain["rustc_vv"])
    retained.record(Path(provider["archive"]["path"]))

    vendor, vendor_expected = dependency_vendor(arguments.dependency_vendor)
    cargo_home = output / "cargo-home"
    cargo_home.mkdir()
    rust_source = Path(toolchain["sysroot"]) / "lib/rustlib/src/rust/library"
    cargo_sources = owned_cleanup.compose_offline_cargo_sources(
        output, rust_source, [(vendor, vendor_expected, "fixture")], cargo_home)

    context = Context(output=output, retained=retained, toolchain=toolchain, provider=provider,
                      cargo_home=cargo_home, products=products, consumer=consumer_label)
    selected = arguments.select or list(SECTIONS)
    runners = {
        "rust-std": lambda: gate_rust_std(context, "rust-std"),
        "rust-std-dependent": lambda: gate_rust_std(context, "rust-std-dependent"),
        "lto": lambda: gate_lto(context),
        "lto-native-facade": lambda: gate_native_facade(context),
    }
    gates = {gate: runners[gate]() for gate in FROZEN_GATES if gate in selected}
    unwind: dict[str, Any] = {}
    if "unwind" in selected:
        unwind = unwind_matrix(context, arguments.provider_vendor, unwind_labels)
        for label in unwind_labels:
            unwind[label]["cross_dso"] = {
                origin: cross_dso_lane(context, label, build_std=origin == "build-std")
                for origin in ("stock-std", "build-std")
            }
            unwind[label]["unmet"] += [item for lane in unwind[label]["cross_dso"].values() for item in lane["unmet"]]
    regressions = provider_regressions(context) if "provider-regressions" in selected else {"lanes": {}}

    unmet = [f"{section} was not selected" for section in SECTIONS if section not in selected]
    unmet += [item for report in gates.values() for item in lane_unmet(report)]
    unmet += [item for record in unwind.values() for item in record["unmet"]]
    unmet += lane_unmet(regressions)
    # Input drift is an unmet condition, not an exception, so the raw lane
    # evidence of an otherwise complete run still reaches its receipt.
    for label, pair in products.items():
        for mode in ("static", "dynamic"):
            try:
                owned_cleanup.assert_same_product(pair[mode], mode)
            except owned_cleanup.OwnedCleanupError as error:
                unmet.append(f"{label} {mode} product changed during consumer execution: {error}")
    if cohort is not None:
        cohort_after, _paths = cohort_products(arguments.static_preparation, arguments.dynamic_qualification)
        if cohort_after != cohort:
            unmet.append("product cohort changed during consumer execution")
    if qualification.source_digest() != source_before:
        unmet.append("source changed during consumer execution")
    if cohort is None:
        unmet.append("development products are not a current-source installed/extracted cohort")
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "gate": GATE,
        "target": TARGET,
        "source_sha256": source_before,
        "frozen_gates": list(FROZEN_GATES),
        "toolchain": toolchain,
        "cohort": cohort,
        "products": products,
        "provider": provider,
        "cargo_sources": {"fixture_vendor": vendor["identity"],
                          "composite_vendor": cargo_sources["composite_vendor"]["identity"],
                          "cargo_config": cargo_sources["cargo_config"]},
        "gates": gates,
        "unwind": unwind,
        "provider_regressions": regressions,
        "unmet_conditions": unmet,
        "passed": not unmet,
        "qualifying": cohort is not None,
        "retained_files": dict(sorted(retained.files.items())),
    }
    path = output / "receipt.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report, path


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    """Reread one retained receipt: current source, same cohort, same bytes, passed."""

    import owned_dynamic_qualification as qualification  # pylint: disable=import-outside-toplevel

    require(root == ROOT, "consumer receipt must be read by this checkout")
    path = owned_cleanup.physical(path, "consumer gate receipt")
    require(path.name == "receipt.json", "consumer gate receipt must be named receipt.json")
    record = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(record, dict) and record.get("schema") == SCHEMA and record.get("gate") == GATE,
            "consumer gate receipt has the wrong schema")
    require(record.get("qualifying") is True and isinstance(record.get("cohort"), dict),
            "consumer gate receipt used development products")
    require(record.get("source_sha256") == qualification.source_digest(), "consumer gate receipt source is stale")
    request = record["cohort"]["request"]
    cohort, _paths = cohort_products(ROOT / request["static_preparation"], ROOT / request["dynamic_qualification"])
    require(cohort == record["cohort"], "consumer gate product cohort changed")
    retained = record.get("retained_files")
    require(isinstance(retained, dict) and retained, "consumer gate receipt retains no evidence")
    for file_path, digest in retained.items():
        candidate = Path(file_path)
        require(candidate.is_file() and not candidate.is_symlink() and sha256_file(candidate) == digest,
                f"consumer gate evidence changed: {file_path}")
    gates = record.get("gates")
    require(isinstance(gates, dict) and set(gates) == set(FROZEN_GATES), "consumer gate receipt lacks a frozen gate")
    unwind = record.get("unwind")
    require(isinstance(unwind, dict) and set(unwind) == set(UNWIND_PRODUCTS),
            "consumer gate receipt lacks the installed/extracted unwind matrix")
    require(record.get("passed") is True and record.get("unmet_conditions") == []
            and not any(lane_unmet(gate) for gate in gates.values())
            and not any(item["unmet"] for item in unwind.values()),
            "consumer gate receipt did not pass")
    regressions = record.get("provider_regressions")
    require(isinstance(regressions, dict) and set(regressions.get("lanes", ())) == set(PROVIDER_REGRESSIONS)
            and not lane_unmet(regressions), "consumer gate receipt lacks the provider regressions")
    return record


def parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    vendor = commands.add_parser("prepare-vendor", help="vendor the frozen fixtures' locked crates (network)")
    vendor.add_argument("--output", type=Path, required=True)
    gate = commands.add_parser("run", help="run the gate against one installed/extracted product cohort")
    gate.add_argument("--static-preparation", type=Path)
    gate.add_argument("--dynamic-qualification", type=Path)
    gate.add_argument("--development-static-sysroot", type=Path)
    gate.add_argument("--development-dynamic-sysroot", type=Path)
    gate.add_argument("--provider-vendor", type=Path, required=True)
    gate.add_argument("--dependency-vendor", type=Path, required=True)
    gate.add_argument("--output", type=Path, required=True)
    gate.add_argument("--select", action="append", choices=SECTIONS,
                      help="development only: run just these sections; the receipt cannot pass")
    validate = commands.add_parser("validate", help="reread one retained gate receipt")
    validate.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "run":
        cohort = (arguments.static_preparation, arguments.dynamic_qualification)
        development = (arguments.development_static_sysroot, arguments.development_dynamic_sysroot)
        if not ((all(cohort) and not any(development)) or (all(development) and not any(cohort))):
            parser.error("select either --static-preparation/--dynamic-qualification or both --development-* sysroots")
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "prepare-vendor":
            print(f"consumer.rust-std-lto fixture vendor: {prepare_vendor(arguments.output)}")
            return 0
        if arguments.command == "validate":
            validate_receipt(ROOT, arguments.receipt)
            print(PASS_MARKER)
            return 0
        report, path = run_gate(arguments)
    except (GateError, owned_cleanup.OwnedCleanupError, owned_rust_link.LinkError, OSError, KeyError, ValueError) as error:
        print(f"x86 consumer.rust-std-lto: ERROR: {error}", file=sys.stderr)
        return 2
    for condition in report["unmet_conditions"]:
        print(f"unmet: {condition}", file=sys.stderr)
    print(f"receipt: {path}")
    if report["passed"] and report["qualifying"]:
        print(PASS_MARKER)
        return 0
    print(f"x86 consumer.rust-std-lto: FAIL ({len(report['unmet_conditions'])} unmet)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
