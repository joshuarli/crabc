#!/usr/bin/env python3
"""Installed x86-64 synthetic dynamic-loader component evidence.

This is deliberately a component runner.  It does not promote the loader
family: it compiles each fixture role once through a supplied installed product,
links that object into both a pinned-musl root and an owned-product root, and
retains every command and process observation.  The frozen AArch64 suite is
the behavior contract; this file only translates its ELF ABI assertions to
x86-64 and records driver-surface gaps as failures rather than inventing a
host-linker escape hatch.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Sequence


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "compat" / "ldso" / "fixtures"
ORACLE_CC = pathlib.Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_LIBC = pathlib.Path("/opt/musl-1.2.6/lib/libc.so")
LIFECYCLE_DIRECTORY = ROOT / "compat" / "x86_64"
LIFECYCLE_HELPER = LIFECYCLE_DIRECTORY / "run_qualification_manifest.py"
LIFECYCLE_MANIFEST_HELPER = LIFECYCLE_DIRECTORY / "generate_qualification_manifest.py"
MAX_TIMEOUT_SECONDS = 120.0
CASES = (
    "nested-needed", "nested-dlopen", "search-path", "dso-origin",
    "initial-tls", "dlerror", "hash-formats", "hash-many", "relro",
    "auxv", "legacy-lifecycle", "lookup-scope", "visibility",
    "constructor-order", "main-handle", "lifecycle", "preload", "aslr",
    "dynamic-tls", "relocations", "weak-strong",
)
REQUIRED_RELOCATIONS = {
    "R_X86_64_RELATIVE", "R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"
}
ASLR = re.compile(rb"aslr=7 main=0x([0-9a-fA-F]+) dso=0x([0-9a-fA-F]+)\n")


class LoaderSyntheticError(RuntimeError):
    """An input, build, or frozen workload observation was not admissible."""


@dataclasses.dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool

    def json(self) -> dict[str, object]:
        return {
            "argv": list(self.argv), "returncode": self.returncode,
            "stdout_hex": self.stdout.hex(), "stderr_hex": self.stderr.hex(),
            "timed_out": self.timed_out,
        }


def same_observation(left: ProcessResult, right: ProcessResult) -> bool:
    """Compare process behavior, deliberately excluding path-specific argv."""

    return (left.returncode, left.stdout, left.stderr, left.timed_out) == (
        right.returncode, right.stdout, right.stderr, right.timed_out
    )


def valid_aslr_pair(results: tuple[ProcessResult, ProcessResult]) -> bool:
    parsed: list[tuple[int, int]] = []
    for result in results:
        if result.returncode != 0 or result.timed_out or result.stderr:
            return False
        match = ASLR.fullmatch(result.stdout)
        if match is None:
            return False
        parsed.append((int(match.group(1), 16), int(match.group(2), 16)))
    return parsed[0][0] != parsed[1][0] and parsed[0][1] != parsed[1][1]


def valid_lifecycle_stream(result: ProcessResult) -> bool:
    """Keep the frozen marker contract without inventing close/fini ordering."""

    return (result.returncode == 0 and not result.timed_out and not result.stderr and all(
        marker in result.stdout for marker in (b"ctor\n", b"lifecycle=73\n", b"after-close\n", b"reopened=73\n", b"dtor\n")
    ))


def has_required_relocations(names: set[str]) -> bool:
    return REQUIRED_RELOCATIONS <= names


def valid_x86_relocation_fixture(consumer: set[str], local_adapter: set[str]) -> bool:
    """Keep imported and local relocation roles separate on x86-64.

    ``reloc_consumer.c`` supplies the imported ABS64/GLOB_DAT/JUMP_SLOT
    behavior.  The target-local adapter supplies the one non-preemptible
    initialized pointer, which LLD represents as RELATIVE rather than DT_RELR
    in the current owned product.
    """

    return {"R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"} <= consumer and "R_X86_64_RELATIVE" in local_adapter


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def lifecycle_helper():
    """Load the repository's established private-descendant boundary."""

    directory = str(LIFECYCLE_DIRECTORY)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    try:
        import run_qualification_manifest as qualification
    except ImportError as error:
        raise LoaderSyntheticError("owned loader synthetic requires the qualification descendant boundary") from error
    helper_path = pathlib.Path(qualification.__file__).resolve()
    manifest_path = pathlib.Path(qualification.manifest.__file__).resolve()
    if helper_path != LIFECYCLE_HELPER or manifest_path != LIFECYCLE_MANIFEST_HELPER:
        raise LoaderSyntheticError("owned loader synthetic imported an unexpected lifecycle helper")
    return qualification


def source_seal() -> dict[str, object]:
    """Seal this runner and the exact imported descendant-boundary helpers."""

    qualification = lifecycle_helper()
    files = [ROOT / "compat" / "ldso" / "run_x86.py", ROOT / "compat" / "x86_64" / "run_owned_loader_synthetic.sh", pathlib.Path(qualification.__file__).resolve(), pathlib.Path(qualification.manifest.__file__).resolve()]
    files.extend(sorted(FIXTURES.glob("*.c")))
    entries = []
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise LoaderSyntheticError(f"tracked source is absent or unsafe: {path}")
        entries.append({"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path), "mode": stat.S_IMODE(path.stat().st_mode)})
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"entries": entries, "sha256": hashlib.sha256(payload).hexdigest()}


def reject_symlink_components(path: pathlib.Path, label: str) -> None:
    raw = path if path.is_absolute() else pathlib.Path.cwd() / path
    current = pathlib.Path(raw.anchor)
    for part in raw.parts[1:]:
        current /= part
        if current.exists() and current.is_symlink():
            raise LoaderSyntheticError(f"{label} contains a symlink component: {current}")


def checked_product_directory(path: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute():
        raise LoaderSyntheticError("supplied dynamic sysroot must be an absolute physical path")
    reject_symlink_components(path, "supplied dynamic sysroot")
    if path.is_symlink() or not path.is_dir():
        raise LoaderSyntheticError(f"supplied dynamic sysroot is missing or unsafe: {path}")
    for relative in (
        "bin/crabc-cc-dynamic", "share/crabc/manifest.json", "usr/include/stdio.h",
        "usr/lib/libc.so", "usr/lib/Scrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o",
        "usr/lib/crabc-dynamic-attach.o", "usr/lib/libcrabc-builtins.a",
        "lib/ld-crabc-x86_64.so.1", "lib/ld-musl-x86_64.so.1",
    ):
        candidate = path / relative
        if not candidate.exists() or candidate.is_symlink() and relative != "lib/ld-musl-x86_64.so.1":
            raise LoaderSyntheticError(f"supplied dynamic sysroot lacks sealed input: {relative}")
    alias = path / "lib/ld-musl-x86_64.so.1"
    if not alias.is_symlink() or os.readlink(alias) != "ld-crabc-x86_64.so.1":
        raise LoaderSyntheticError("supplied dynamic sysroot has no canonical musl-loader compatibility alias")
    return path


def checked_scratch_directory(root: pathlib.Path = ROOT) -> pathlib.Path:
    """Create the one checkout-local evidence parent after physical checks."""

    if root.is_symlink() or not root.is_dir():
        raise LoaderSyntheticError(f"checkout root is missing or unsafe: {root}")
    reject_symlink_components(root, "checkout root")
    work = root / ".work"
    if work.is_symlink() or not work.is_dir():
        raise LoaderSyntheticError(f"checkout .work is missing or unsafe: {work}")
    reject_symlink_components(work, "checkout .work")
    scratch = work / "x86_64"
    reject_symlink_components(scratch, "checkout x86 scratch")
    scratch.mkdir(mode=0o755, exist_ok=True)
    if scratch.is_symlink() or not scratch.is_dir():
        raise LoaderSyntheticError(f"checkout x86 scratch is unsafe: {scratch}")
    return scratch


def checked_selection(requested: Sequence[str] | None) -> tuple[str, ...]:
    """Accept a finite, unique subset while reserving completion for all 21."""

    selected = CASES if requested is None else tuple(requested)
    if not selected:
        raise LoaderSyntheticError("select at least one frozen synthetic-loader workload")
    if len(selected) != len(set(selected)):
        raise LoaderSyntheticError("synthetic-loader workload selection contains duplicates")
    if any(name not in CASES for name in selected):
        raise LoaderSyntheticError("synthetic-loader workload selection is outside the frozen roster")
    return selected


def checked_timeout(value: float) -> float:
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT_SECONDS:
        raise LoaderSyntheticError(f"timeout must be finite, greater than zero, and at most {MAX_TIMEOUT_SECONDS:g} seconds")
    return value


def selected_passed(cases: dict[str, dict[str, object]]) -> bool:
    return all(item.get("status") == "pass" for item in cases.values())


def exact_component_selection(selected: Sequence[str]) -> bool:
    return len(selected) == len(CASES) and set(selected) == set(CASES)


def oracle_seal() -> dict[str, object]:
    entries: dict[str, pathlib.Path] = {"compiler": ORACLE_CC, "libc": ORACLE_LIBC}
    sealed: dict[str, object] = {}
    for name, path in entries.items():
        if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
            raise LoaderSyntheticError(f"pinned musl {name} is absent or unsafe: {path}")
        sealed[name] = str(path)
        sealed[name + "_sha256"] = sha256(path)
    return sealed


def installed_driver_shared(product: pathlib.Path):
    """Load the installed driver's sealed linker selector without PATH input."""

    source = product / "share/crabc/crabc_cc_static.py"
    if source.is_symlink() or not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
        raise LoaderSyntheticError("installed dynamic product lacks its physical shared driver")
    specification = importlib.util.spec_from_file_location("_owned_loader_installed_shared", source)
    if specification is None or specification.loader is None:
        raise LoaderSyntheticError("installed dynamic product shared driver is not importable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def producer_linker_seal(product: pathlib.Path) -> dict[str, str]:
    """Seal the exact pinned LLD selected by the installed dynamic driver."""

    shared = installed_driver_shared(product)
    try:
        selected = pathlib.Path(shared.linker())
        resolved = selected.resolve(strict=True)
        metadata = resolved.lstat()
    except (OSError, shared.DriverError) as error:
        raise LoaderSyntheticError("installed dynamic driver linker is unavailable") from error
    if not selected.is_absolute() or resolved.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise LoaderSyntheticError("installed dynamic driver linker is not a physical executable")
    if resolved.name != "ld.lld":
        raise LoaderSyntheticError("installed dynamic driver selected a non-LLD linker")
    return {"path": str(resolved), "sha256": sha256(resolved)}


def preflight(dynamic_sysroot: pathlib.Path, requested: Sequence[str] | None, timeout: float) -> tuple[pathlib.Path, tuple[str, ...], float, pathlib.Path]:
    """Reject unsafe inputs before creating any collector directory."""

    product = checked_product_directory(dynamic_sysroot)
    selected = checked_selection(requested)
    bounded_timeout = checked_timeout(timeout)
    return product, selected, bounded_timeout, checked_scratch_directory()


def summary_lines(component_complete: bool, evidence: pathlib.Path, receipt: pathlib.Path) -> tuple[str, str, str]:
    """Keep the catalogue's evidence directory on its own exact log line."""

    return (
        f"owned synthetic loader: {'PASS' if component_complete else 'FAIL'}",
        f"owned synthetic loader evidence: {evidence}",
        f"owned synthetic loader receipt: {receipt}",
    )


def tree_seal(root: pathlib.Path) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    for item in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        data: dict[str, object] = {"path": relative, "mode": stat.S_IMODE(item.lstat().st_mode)}
        if item.is_symlink():
            data.update(kind="symlink", target=os.readlink(item))
        elif item.is_file():
            data.update(kind="file", sha256=sha256(item), size=item.stat().st_size)
        elif item.is_dir():
            data.update(kind="directory")
        else:
            raise LoaderSyntheticError(f"unsealed special product entry: {item}")
        entries.append(data)
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"entries": entries, "sha256": hashlib.sha256(encoded).hexdigest()}


def disable_child_core_dumps() -> None:
    """Keep signal-probe descendants from adding unsealed core files to roots."""

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Recorder:
    def __init__(self, work: pathlib.Path, timeout: float) -> None:
        self.work, self.timeout, self.index = work, timeout, 0
        self.raw = work / "raw"
        self.raw.mkdir()

    def run(self, name: str, argv: Sequence[str | pathlib.Path], *, cwd: pathlib.Path, env: dict[str, str] | None = None, timeout: float | None = None) -> ProcessResult:
        self.index += 1
        rendered = tuple(str(item) for item in argv)
        selected_env = dict(env) if env is not None else {}
        timeout_seconds = checked_timeout(self.timeout if timeout is None else timeout)
        qualification = lifecycle_helper()
        result: ProcessResult | None = None
        boundary_error: Exception | None = None
        try:
            with qualification.private_admission_subreaper() as descendants:
                process = subprocess.Popen(rendered, cwd=cwd, env=selected_env or None, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True,
                                           preexec_fn=disable_child_core_dumps)
                descendants.register_private_runner(process)
                try:
                    stdout, stderr = process.communicate(timeout=timeout_seconds)
                    result = ProcessResult(rendered, process.returncode, stdout, stderr, False)
                    # A normally exited parent can still leave an unexpected
                    # descendant. Preserve its actual streams and status even
                    # when that separate lifetime check rejects the fixture.
                    descendants.reject_unexpected_descendants()
                except subprocess.TimeoutExpired:
                    descendants.terminate_and_reap(process)
                    stdout, stderr = process.communicate()
                    result = ProcessResult(rendered, process.returncode, stdout, stderr, True)
                except BaseException:
                    descendants.terminate_and_reap(process)
                    raise
        except qualification.QualificationRunError as error:
            boundary_error = error
        if result is None:
            if boundary_error is not None:
                raise LoaderSyntheticError(f"synthetic-loader descendant boundary failed: {boundary_error}") from boundary_error
            raise LoaderSyntheticError("synthetic-loader command produced no process observation")
        stem = f"{self.index:04d}-{name}"
        (self.raw / f"{stem}.stdout").write_bytes(result.stdout)
        (self.raw / f"{stem}.stderr").write_bytes(result.stderr)
        (self.raw / f"{stem}.json").write_text(json.dumps({"cwd": str(cwd), "environment": selected_env, **result.json()}, indent=2, sort_keys=True) + "\n")
        if boundary_error is not None:
            raise LoaderSyntheticError(f"synthetic-loader descendant boundary failed: {boundary_error}") from boundary_error
        return result

    def checked(self, name: str, argv: Sequence[str | pathlib.Path], *, cwd: pathlib.Path, env: dict[str, str] | None = None) -> ProcessResult:
        result = self.run(name, argv, cwd=cwd, env=env)
        if result.returncode != 0 or result.timed_out:
            raise LoaderSyntheticError(f"{name} failed; raw receipt {self.raw}")
        return result


class FixtureBuilder:
    """One installed-header object role set, shared by oracle and candidate."""

    def __init__(self, product: pathlib.Path, work: pathlib.Path, recorder: Recorder) -> None:
        self.product, self.work, self.recorder = product, work, recorder
        self.driver = product / "bin/crabc-cc-dynamic"
        self.objects = work / "objects"
        self.objects.mkdir()
        self.cache: dict[tuple[str, tuple[str, ...]], pathlib.Path] = {}
        self.identity: list[dict[str, object]] = []
        self.links: list[dict[str, object]] = []

    def role(self, source: pathlib.Path, *defines: str) -> pathlib.Path:
        key = (str(source), tuple(defines))
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        output = self.objects / f"{len(self.cache):03d}-{source.stem}.o"
        trace = output.with_suffix(".headers.i")
        # The object is always made by the sealed driver.  This separate
        # pinned-tool preprocessing receipt makes the installed-header closure
        # inspectable without granting the product driver an unsealed flag.
        self.recorder.checked("headers-" + source.stem, [ORACLE_CC, "-nostdinc", "-isystem", self.product / "usr/include", *defines, "-H", "-E", source, "-o", trace], cwd=self.work)
        self.recorder.checked("compile-" + source.stem, [self.driver, "--dynamic-shared-object", *defines, "-c", source, "-o", output], cwd=self.work)
        if not output.is_file() or output.is_symlink():
            raise LoaderSyntheticError(f"installed driver did not produce role object: {output}")
        self.cache[key] = output
        self.identity.append({"source": str(source), "defines": list(defines), "header_trace": str(trace), "header_trace_sha256": sha256(trace), "object": str(output), "sha256": sha256(output)})
        return output

    def shared(self, arm: str, root: pathlib.Path, name: str, object_file: pathlib.Path, dependencies: Sequence[pathlib.Path] = (), *, runpath: str = "/usr/lib", hash_style: str = "sysv") -> pathlib.Path:
        output = root / "usr/lib" / name
        if arm == "candidate":
            argv: list[str | pathlib.Path] = [self.driver, "--dynamic-shared-object", "--application-hash-style", hash_style, "--application-runpath", runpath, object_file]
            for dependency in dependencies:
                argv.extend(("--application-dso", dependency))
            argv.extend(("-o", output))
        else:
            argv = [ORACLE_CC, "-shared", "-Wl,-soname," + name, object_file, *dependencies, "-Wl,--hash-style=" + hash_style, "-Wl,-rpath," + runpath, "-o", output]
        self.recorder.checked(f"{arm}-shared-{name}", argv, cwd=self.work)
        self.links.append({"kind": "shared", "arm": arm, "output": str(output), "output_sha256": sha256(output), "object": str(object_file), "object_sha256": sha256(object_file), "dependencies": [{"path": str(item), "sha256": sha256(item)} for item in dependencies]})
        return output

    def executable(self, arm: str, root: pathlib.Path, name: str, object_file: pathlib.Path, dependencies: Sequence[pathlib.Path] = (), *, export_dynamic: bool = False, runpath: str = "/usr/lib", search_kind: str = "runpath", hash_style: str = "sysv") -> pathlib.Path:
        output = root / name
        if search_kind not in {"runpath", "rpath"}:
            raise LoaderSyntheticError(f"unknown owned application search kind: {search_kind}")
        if arm == "candidate":
            argv: list[str | pathlib.Path] = [self.driver, "--dynamic-pie", "--application-hash-style", hash_style, "--application-" + search_kind, runpath]
            if export_dynamic:
                argv.append("-rdynamic")
            argv.append(object_file)
            for dependency in dependencies:
                argv.extend(("--application-dso", dependency))
            argv.extend(("-o", output))
        else:
            argv = [ORACLE_CC, "-fPIE", "-pie", object_file, *dependencies, "-Wl,--hash-style=" + hash_style, *( ["-Wl,--disable-new-dtags"] if search_kind == "rpath" else []), "-Wl,-rpath," + runpath, "-Wl,-rpath-link," + str(root / "usr/lib"), "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1"]
            if export_dynamic:
                argv.append("-Wl,--export-dynamic")
            argv.extend(("-o", output))
        self.recorder.checked(f"{arm}-executable-{name}", argv, cwd=self.work)
        self.links.append({"kind": "executable", "arm": arm, "output": str(output), "output_sha256": sha256(output), "object": str(object_file), "object_sha256": sha256(object_file), "dependencies": [{"path": str(item), "sha256": sha256(item)} for item in dependencies]})
        return output


def copy_root(product: pathlib.Path, target: pathlib.Path, *, candidate: bool) -> None:
    if candidate:
        shutil.copytree(product, target, symlinks=True)
    else:
        (target / "lib").mkdir(parents=True)
        (target / "usr/lib").mkdir(parents=True)
        shutil.copy2(ORACLE_LIBC, target / "lib/ld-musl-x86_64.so.1")
        shutil.copy2(ORACLE_LIBC, target / "usr/lib/libc.so")


def dynamic_names(output: bytes) -> set[str]:
    return set(re.findall(r"R_X86_64_[A-Z0-9_]+", output.decode(errors="replace")))


def tags(output: bytes) -> str:
    return output.decode("utf-8", errors="replace")


def needed_names(output: bytes) -> list[str]:
    return re.findall(r"Shared library: \[([^]]+)\]", tags(output))


def kernel_run(recorder: Recorder, arm: str, root: pathlib.Path, program: pathlib.Path, environment: dict[str, str] | None = None, *, direct: bool = False) -> ProcessResult:
    env = {"PATH": "/usr/bin:/bin"}
    if environment:
        env.update(environment)
    # The pinned image keeps the administrative coreutils directory outside
    # the deliberately scrubbed loader environment.  Use its canonical path
    # so the host-side process launcher never depends on that PATH.
    argv: list[str | pathlib.Path] = ["/usr/sbin/chroot", root]
    if direct:
        argv.extend(("/lib/ld-musl-x86_64.so.1", "/" + program.name))
    else:
        argv.append("/" + program.name)
    return recorder.run(f"{arm}-{'direct' if direct else 'kernel'}-{program.name}", argv, cwd=recorder.work, env=env)


def exact_reference(result: ProcessResult, expected: bytes, label: str) -> None:
    if result.returncode != 0 or result.stderr or result.timed_out or result.stdout != expected:
        raise LoaderSyntheticError(f"pinned-musl {label} did not produce its frozen stream: {result.json()}")


def compare_standard(recorder: Recorder, label: str, oracle_root: pathlib.Path, candidate_root: pathlib.Path, oracle: pathlib.Path, candidate: pathlib.Path, expected: bytes, environment: dict[str, str] | None = None) -> dict[str, object]:
    reference = kernel_run(recorder, "oracle", oracle_root, oracle, environment)
    if label == "lifecycle":
        if not valid_lifecycle_stream(reference):
            raise LoaderSyntheticError(f"pinned-musl lifecycle omitted a frozen marker or failed: {reference.json()}")
    else:
        exact_reference(reference, expected, label)
    observed = kernel_run(recorder, "candidate", candidate_root, candidate, environment)
    direct = kernel_run(recorder, "candidate", candidate_root, candidate, environment, direct=True)
    if not same_observation(reference, observed) or not same_observation(reference, direct):
        raise LoaderSyntheticError(f"candidate {label} differs from pinned musl: reference={reference.json()} candidate={observed.json()} direct={direct.json()}")
    return {"oracle": reference.json(), "candidate": observed.json(), "candidate_direct": direct.json()}


def compare_allowed_reference(recorder: Recorder, label: str, oracle_root: pathlib.Path, candidate_root: pathlib.Path, oracle: pathlib.Path, candidate: pathlib.Path, allowed: set[bytes], environment: dict[str, str] | None = None) -> dict[str, object]:
    """Use musl's exact stream after checking its frozen finite grammar."""

    reference = kernel_run(recorder, "oracle", oracle_root, oracle, environment)
    if reference.returncode != 0 or reference.timed_out or reference.stderr or reference.stdout not in allowed:
        raise LoaderSyntheticError(f"pinned-musl {label} did not select a frozen fixture: {reference.json()}")
    observed = kernel_run(recorder, "candidate", candidate_root, candidate, environment)
    direct = kernel_run(recorder, "candidate", candidate_root, candidate, environment, direct=True)
    if not same_observation(reference, observed) or not same_observation(reference, direct):
        raise LoaderSyntheticError(f"candidate {label} differs from pinned musl: reference={reference.json()} candidate={observed.json()} direct={direct.json()}")
    return {"oracle": reference.json(), "candidate": observed.json(), "candidate_direct": direct.json()}


@dataclasses.dataclass(frozen=True)
class Spec:
    main: str
    expected: bytes
    dsos: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    initial: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    export_dynamic: bool = False


SPECS: dict[str, Spec] = {
    "nested-needed": Spec("nested_main.c", b"nested=42\n", (("libnested_leaf.so", "nested_leaf.c", ()), ("libnested_mid.so", "nested_mid.c", ())), ("libnested_mid.so",)),
    "nested-dlopen": Spec("nested_dlopen.c", b"nested-dlopen=42\n", (("libnested_leaf.so", "nested_leaf.c", ()), ("libnested_mid.so", "nested_mid.c", ())), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "initial-tls": Spec("initial_tls_main.c", b"initial-tls=7,8\n", (("libinitial_tls.so", "initial_tls_dso.c", ()),), ("libinitial_tls.so",)),
    "dlerror": Spec("dlerror_main.c", b"dlerror=ok\n", (("libdlerror.so", "dlerror_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "relro": Spec("relro_main.c", b"relro=protected\n", (("librelro.so", "relro_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "auxv": Spec("auxv_main.c", b"auxv=ok\n"),
    "legacy-lifecycle": Spec("legacy_lifecycle_main.c", b"legacy-array-init\nlegacy-value\nlegacy-array-fini\n", (("liblegacy_lifecycle.so", "legacy_lifecycle_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "lookup-scope": Spec("scope_main.c", b"scope=21,34\n", (("libscope_local.so", "scope_local.c", ()), ("libscope_global.so", "scope_global.c", ())), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "visibility": Spec("visibility_main.c", b"visibility=ok\n", (("libvisibility.so", "visibility_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "constructor-order": Spec("order_main.c", b"order-leaf\norder-mid\norder-sibling\norder-main-init\norder-main\n", (("liborder_leaf.so", "order_leaf.c", ()), ("liborder_mid.so", "order_mid.c", ()), ("liborder_sibling.so", "order_sibling.c", ())), ("liborder_mid.so", "liborder_sibling.so")),
    "main-handle": Spec("main_handle_main.c", b"main-handle=ok\n", (), (), (), True),
    "lifecycle": Spec("lifecycle_main.c", b"ctor\nlifecycle=73\nafter-close\nreopened=73\ndtor\n", (("liblifecycle.so", "lifecycle_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "preload": Spec("preload_main.c", b"preload=9\n", (("libpreload_target.so", "preload_target.c", ()), ("libpreload_override.so", "preload_override.c", ())), ("libpreload_target.so",), (("LD_LIBRARY_PATH", "/usr/lib"), ("LD_PRELOAD", "/usr/lib/libpreload_override.so"))),
    "aslr": Spec("aslr_main.c", b"", (("libaslr.so", "aslr_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "dynamic-tls": Spec("tls_main.c", b"tls=6/5\n", (("libfixture_tls.so", "tls_dso.c", ()),), (), (("LD_LIBRARY_PATH", "/usr/lib"),)),
    "relocations": Spec("reloc_main.c", b"reloc=42\n", (("libreloc_provider.so", "reloc_provider.c", ()), ("libreloc_consumer.so", "reloc_consumer.c", ())), ("libreloc_consumer.so",)),
    "weak-strong": Spec("weak_strong_main.c", b"lookup=1\n", (("libweak_provider.so", "weak_provider.c", ()), ("libstrong_provider.so", "strong_provider.c", ())), ("libweak_provider.so", "libstrong_provider.so")),
}


def build_arm(builder: FixtureBuilder, arm: str, root: pathlib.Path, spec: Spec, dependency_names: dict[str, tuple[str, ...]] | None = None) -> tuple[pathlib.Path, dict[str, pathlib.Path]]:
    outputs: dict[str, pathlib.Path] = {}
    for name, source, defines in spec.dsos:
        object_file = builder.role(FIXTURES / source, *defines)
        dependency_paths = [outputs[item] for item in (dependency_names or {}).get(name, ())]
        outputs[name] = builder.shared(arm, root, name, object_file, dependency_paths)
    main = builder.role(FIXTURES / spec.main)
    # The sealed owned driver needs every provider named on its application
    # surface in order to prove a DSO's imports.  Preserve the fixture's own
    # DT_NEEDED edge as well: these extra link inputs are recorded and later
    # inspected rather than hidden behind an ambient search path.
    linked: list[str] = []
    def include(name: str) -> None:
        if name in linked:
            return
        linked.append(name)
        for child in (dependency_names or {}).get(name, ()):
            include(child)
    for item in spec.initial:
        include(item)
    executable = builder.executable(arm, root, "consumer", main, [outputs[name] for name in linked], export_dynamic=spec.export_dynamic)
    return executable, outputs


def case_standard(name: str, work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    spec = SPECS[name]
    oracle_root, candidate_root = work / "oracle-root", work / "candidate-root"
    copy_root(product, candidate_root, candidate=True)
    copy_root(product, oracle_root, candidate=False)
    dependencies = {
        "libnested_mid.so": ("libnested_leaf.so",),
        "liborder_mid.so": ("liborder_leaf.so",),
        "libreloc_consumer.so": ("libreloc_provider.so",),
    }
    oracle, oracle_dsos = build_arm(builder, "oracle", oracle_root, spec, dependencies)
    candidate, candidate_dsos = build_arm(builder, "candidate", candidate_root, spec, dependencies)
    properties: dict[str, object] = {}
    if name == "initial-tls":
        properties["program_headers"] = tags(recorder.checked("initial-tls-phdr", ["readelf", "-lW", candidate_dsos["libinitial_tls.so"]], cwd=work).stdout)
        if " TLS " not in properties["program_headers"]:
            raise LoaderSyntheticError("initial TLS DSO lacks PT_TLS")
    if name == "relro":
        headers = recorder.checked("relro-phdr", ["readelf", "-lW", candidate_dsos["librelro.so"]], cwd=work).stdout
        reloc = recorder.checked("relro-relocations", ["readelf", "-Wr", candidate_dsos["librelro.so"]], cwd=work).stdout
        properties.update(program_headers=tags(headers), relocations=tags(reloc))
        if "GNU_RELRO" not in tags(headers) or "R_X86_64_64" not in dynamic_names(reloc):
            raise LoaderSyntheticError("RELRO fixture lacks GNU_RELRO or its x86 absolute protected-pointer relocation")
    if name == "visibility":
        symbols = recorder.checked("visibility-symbols", ["readelf", "--dyn-syms", "--wide", candidate_dsos["libvisibility.so"]], cwd=work).stdout
        properties["symbols"] = tags(symbols)
        if "visibility_public" not in tags(symbols) or "visibility_hidden" in tags(symbols):
            raise LoaderSyntheticError("visibility fixture dynamic surface changed")
    if name == "lifecycle":
        dynamic = recorder.checked("lifecycle-tags", ["readelf", "-dW", candidate_dsos["liblifecycle.so"]], cwd=work).stdout
        properties["dynamic"] = tags(dynamic)
        if "(INIT_ARRAY)" not in tags(dynamic) or "(FINI_ARRAY)" not in tags(dynamic):
            raise LoaderSyntheticError("lifecycle fixture lost init/fini arrays")
    if name == "legacy-lifecycle":
        dynamic = recorder.checked("legacy-lifecycle-tags", ["readelf", "-dW", candidate_dsos["liblegacy_lifecycle.so"]], cwd=work).stdout
        properties["dynamic"] = tags(dynamic)
        if not all(marker in properties["dynamic"] for marker in ("(INIT)", "(FINI)", "(INIT_ARRAY)", "(FINI_ARRAY)")):
            raise LoaderSyntheticError("legacy lifecycle fixture lost frozen DT_INIT/DT_FINI and array tags")
    if name == "dynamic-tls":
        reloc = recorder.checked("tls-relocations", ["readelf", "-Wr", candidate_dsos["libfixture_tls.so"]], cwd=work).stdout
        properties["relocations"] = tags(reloc)
        if not ({"R_X86_64_DTPMOD64", "R_X86_64_DTPOFF64"} & dynamic_names(reloc)):
            raise LoaderSyntheticError("x86 late-TLS fixture lacks TLS module/offset relocation")
    if name == "relocations":
        reloc = recorder.checked("relocations-x86", ["readelf", "-Wr", candidate_dsos["libreloc_consumer.so"]], cwd=work).stdout
        properties["relocations"] = tags(reloc)
        observed = dynamic_names(reloc)
        if not has_required_relocations(observed):
            properties["structural_error"] = f"relocation fixture lacks frozen x86 classes: missing={sorted(REQUIRED_RELOCATIONS - observed)} observed={sorted(observed)}"
    if name in {"nested-needed", "constructor-order"}:
        middle = candidate_dsos["libnested_mid.so" if name == "nested-needed" else "liborder_mid.so"]
        dynamic = recorder.checked(name + "-middle-needed", ["readelf", "-dW", middle], cwd=work).stdout
        edge = "libnested_leaf.so" if name == "nested-needed" else "liborder_leaf.so"
        properties["middle_needed"] = needed_names(dynamic)
        if properties["middle_needed"] != [edge, "libc.so"]:
            raise LoaderSyntheticError(f"{name} middle DSO did not retain its exact acyclic dependency edge: {properties['middle_needed']}")
    if name == "weak-strong":
        dynamic = recorder.checked("weak-strong-needed", ["readelf", "-dW", candidate], cwd=work).stdout
        properties["needed"] = needed_names(dynamic)
        weak, strong = properties["needed"].index("libweak_provider.so"), properties["needed"].index("libstrong_provider.so")
        if weak >= strong:
            raise LoaderSyntheticError("weak/strong fixture lost frozen DT_NEEDED order")
    if name == "aslr":
        environment = dict(spec.environment)
        reference = tuple(kernel_run(recorder, "oracle", oracle_root, oracle, environment) for _ in range(2))
        candidate_results = tuple(kernel_run(recorder, "candidate", candidate_root, candidate, environment) for _ in range(2))
        direct = tuple(kernel_run(recorder, "candidate", candidate_root, candidate, environment, direct=True) for _ in range(2))
        if not valid_aslr_pair(reference) or not valid_aslr_pair(candidate_results) or not valid_aslr_pair(direct):
            raise LoaderSyntheticError("ASLR fixture did not retain distinct main and DSO bases across process starts")
        return {"result": "pass", "properties": properties, "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}, "oracle": [item.json() for item in reference], "candidate": [item.json() for item in candidate_results], "candidate_direct": [item.json() for item in direct]}
    behavior = compare_standard(recorder, name, oracle_root, candidate_root, oracle, candidate, spec.expected,
                                dict(spec.environment))
    result = {"result": "pass", "properties": properties, **behavior,
              "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}}
    if "structural_error" in properties:
        result.update(result="fail", error=properties["structural_error"])
    return result


def case_hash_formats(work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    """Retain actual GNU/SysV driver observations; no host-linker replacement."""
    oracle_root, candidate_root = work / "oracle-root", work / "candidate-root"
    copy_root(product, candidate_root, candidate=True)
    copy_root(product, oracle_root, candidate=False)
    gnu = builder.role(FIXTURES / "hash_dso.c", "-DHASH_VALUE=13")
    sysv = builder.role(FIXTURES / "hash_dso.c", "-DHASH_VALUE=29")
    oracle_gnu = oracle_root / "usr/lib/libhash_gnu.so"
    oracle_sysv = oracle_root / "usr/lib/libhash_sysv.so"
    recorder.checked("oracle-gnu-hash", [ORACLE_CC, "-shared", gnu, "-Wl,--hash-style=gnu", "-o", oracle_gnu], cwd=work)
    builder.links.append({"kind": "shared", "arm": "oracle", "output": str(oracle_gnu), "output_sha256": sha256(oracle_gnu), "object": str(gnu), "object_sha256": sha256(gnu), "dependencies": []})
    recorder.checked("oracle-sysv-hash", [ORACLE_CC, "-shared", sysv, "-Wl,--hash-style=sysv", "-o", oracle_sysv], cwd=work)
    builder.links.append({"kind": "shared", "arm": "oracle", "output": str(oracle_sysv), "output_sha256": sha256(oracle_sysv), "object": str(sysv), "object_sha256": sha256(sysv), "dependencies": []})
    candidate_gnu = builder.shared("candidate", candidate_root, "libhash_gnu.so", gnu, hash_style="gnu")
    candidate_sysv = builder.shared("candidate", candidate_root, "libhash_sysv.so", sysv)
    observed = {name: tags(recorder.checked("hash-tags-" + name, ["readelf", "-dW", path], cwd=work).stdout) for name, path in (("oracle-gnu", oracle_gnu), ("oracle-sysv", oracle_sysv), ("candidate-gnu", candidate_gnu), ("candidate-sysv", candidate_sysv))}
    if "(GNU_HASH)" not in observed["oracle-gnu"] or "(HASH)" not in observed["oracle-sysv"]:
        raise LoaderSyntheticError("pinned musl hash fixtures did not retain GNU and SysV tags")
    spec = Spec("hash_main.c", b"hash=13,29\n")
    oracle = builder.executable("oracle", oracle_root, "consumer", builder.role(FIXTURES / spec.main))
    candidate = builder.executable("candidate", candidate_root, "consumer", builder.role(FIXTURES / spec.main))
    behavior = compare_standard(recorder, "hash-formats", oracle_root, candidate_root, oracle, candidate,
                                spec.expected, {"LD_LIBRARY_PATH": "/usr/lib"})
    result = {"result": "pass", "dynamic": observed, **behavior,
              "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}}
    if "(GNU_HASH)" not in observed["candidate-gnu"]:
        result.update(result="fail", error="owned dynamic driver did not provide a GNU-hash fixture; recorded actual SysV-only output")
    return result


def case_hash_many(work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    oracle_root, candidate_root = work / "oracle-root", work / "candidate-root"
    copy_root(product, candidate_root, candidate=True)
    copy_root(product, oracle_root, candidate=False)
    source = work / "hash-many-1025.c"
    source.write_text("\n".join(f"int hash_many_{index}(void) {{ return {index}; }}" for index in range(1025)) + "\n")
    role = builder.role(source)
    oracle_image = oracle_root / "usr/lib/libhash_many.so"
    builder.recorder.checked("oracle-hash-many-both", [ORACLE_CC, "-shared", "-Wl,-soname,libhash_many.so", role, "-Wl,--hash-style=both", "-o", oracle_image], cwd=work)
    builder.links.append({"kind": "shared", "arm": "oracle", "output": str(oracle_image), "output_sha256": sha256(oracle_image), "object": str(role), "object_sha256": sha256(role), "dependencies": []})
    candidate_image = builder.shared("candidate", candidate_root, "libhash_many.so", role, hash_style="both")
    symbols = recorder.checked("hash-many-symbols", ["readelf", "--dyn-syms", "--wide", candidate_image], cwd=work).stdout
    dynamic = recorder.checked("hash-many-tags", ["readelf", "-dW", candidate_image], cwd=work).stdout
    count = sum("hash_many_" in line for line in tags(symbols).splitlines())
    if count != 1025:
        raise LoaderSyntheticError(f"many-symbol fixture exported {count}, expected 1025")
    oracle = builder.executable("oracle", oracle_root, "consumer", builder.role(FIXTURES / "hash_many_main.c"))
    candidate = builder.executable("candidate", candidate_root, "consumer", builder.role(FIXTURES / "hash_many_main.c"))
    behavior = compare_standard(recorder, "hash-many", oracle_root, candidate_root, oracle, candidate,
                                b"hash-many=1024,0\n", {"LD_LIBRARY_PATH": "/usr/lib"})
    result = {"result": "pass", "symbol_count": count, "dynamic": tags(dynamic), **behavior,
              "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}}
    if "(GNU_HASH)" not in result["dynamic"] or "(HASH)" not in result["dynamic"]:
        result.update(result="fail", error="owned driver did not provide the frozen GNU+SysV 1025-symbol hash fixture")
    return result


def case_relocations(work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    """Keep the frozen imported relocations and prove x86 local RELATIVE too."""
    oracle_root, candidate_root = work / "oracle-root", work / "candidate-root"
    copy_root(product, candidate_root, candidate=True)
    copy_root(product, oracle_root, candidate=False)
    executables: dict[str, pathlib.Path] = {}
    images: dict[str, dict[str, pathlib.Path]] = {}
    provider_role = builder.role(FIXTURES / "reloc_provider.c")
    consumer_role = builder.role(FIXTURES / "reloc_consumer.c")
    adapter_role = builder.role(FIXTURES / "reloc_relative_x86_adapter.c")
    companion_role = builder.role(FIXTURES / "reloc_relative_x86_companion.c")
    for arm, root in (("oracle", oracle_root), ("candidate", candidate_root)):
        provider = builder.shared(arm, root, "libreloc_provider.so", provider_role)
        consumer = builder.shared(arm, root, "libreloc_consumer.so", consumer_role, (provider,))
        adapter = builder.shared(arm, root, "libreloc_relative_x86_adapter.so", adapter_role)
        executables[arm] = builder.executable(arm, root, "consumer", companion_role, (consumer, adapter, provider))
        images[arm] = {"provider": provider, "consumer": consumer, "adapter": adapter}
    consumer_relocations = recorder.checked("relocations-consumer-x86", ["readelf", "-Wr", images["candidate"]["consumer"]], cwd=work).stdout
    adapter_relocations = recorder.checked("relocations-adapter-x86", ["readelf", "-Wr", images["candidate"]["adapter"]], cwd=work).stdout
    adapter_dynamic = recorder.checked("relocations-adapter-dynamic", ["readelf", "-dW", images["candidate"]["adapter"]], cwd=work).stdout
    consumer_names, adapter_names = dynamic_names(consumer_relocations), dynamic_names(adapter_relocations)
    if not valid_x86_relocation_fixture(consumer_names, adapter_names):
        raise LoaderSyntheticError(f"x86 relocation roles drifted: consumer={sorted(consumer_names)} adapter={sorted(adapter_names)}")
    if any("(" + item + ")" in tags(adapter_dynamic) for item in ("RELR", "RELRSZ", "RELRENT")):
        raise LoaderSyntheticError("x86 local relocation unexpectedly changed from direct RELATIVE to packed RELR")
    behavior = compare_standard(recorder, "relocations", oracle_root, candidate_root, executables["oracle"], executables["candidate"], b"reloc=42 relative=73\n")
    return {"result": "pass", "consumer_relocations": tags(consumer_relocations), "adapter_relocations": tags(adapter_relocations), "adapter_dynamic": tags(adapter_dynamic), "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}, **behavior}


def case_search_path(work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    """Exercise both owned DT_RUNPATH and owned legacy DT_RPATH precedence."""
    oracle_root, candidate_root = work / "oracle-root", work / "candidate-root"
    copy_root(product, candidate_root, candidate=True)
    copy_root(product, oracle_root, candidate=False)
    for arm, root in (("oracle", oracle_root), ("candidate", candidate_root)):
        for directory, value in (("environment", 11), ("runpath", 22), ("rpath", 33)):
            image = builder.shared(arm, root, "libsearch.so", builder.role(FIXTURES / "search_dso.c", f"-DSEARCH_VALUE={value}"))
            target = root / directory
            target.mkdir()
            image.replace(target / image.name)
            receipt = pathlib.Path(str(image) + ".crabc-link.json")
            if receipt.exists():
                receipt.replace(target / receipt.name)
    main = builder.role(FIXTURES / "search_main.c")
    oracle = builder.executable("oracle", oracle_root, "consumer-runpath", main, runpath="/runpath")
    candidate = builder.executable("candidate", candidate_root, "consumer-runpath", main, runpath="/runpath")
    oracle_rpath = builder.executable("oracle", oracle_root, "consumer-rpath", main, runpath="/rpath", search_kind="rpath")
    candidate_rpath = builder.executable("candidate", candidate_root, "consumer-rpath", main, runpath="/rpath", search_kind="rpath")
    tags_by_mode = {
        "candidate-runpath": tags(recorder.checked("search-runpath-tags", ["readelf", "-dW", candidate], cwd=work).stdout),
        "candidate-rpath": tags(recorder.checked("search-rpath-tags", ["readelf", "-dW", candidate_rpath], cwd=work).stdout),
    }
    if "(RUNPATH)" not in tags_by_mode["candidate-runpath"] or "(RPATH)" in tags_by_mode["candidate-runpath"]:
        raise LoaderSyntheticError("owned RUNPATH executable did not retain exactly its new-dtags form")
    if "(RPATH)" not in tags_by_mode["candidate-rpath"] or "(RUNPATH)" in tags_by_mode["candidate-rpath"]:
        raise LoaderSyntheticError("owned RPATH executable did not retain exactly its legacy-dtags form")
    behavior = {
        "runpath-environment": compare_standard(recorder, "search-path/runpath-environment", oracle_root, candidate_root, oracle, candidate, b"search=11\n", {"LD_LIBRARY_PATH": "/environment"}),
        "runpath-embedded": compare_standard(recorder, "search-path/runpath-embedded", oracle_root, candidate_root, oracle, candidate, b"search=22\n"),
        "rpath-environment": compare_allowed_reference(recorder, "search-path/rpath-environment", oracle_root, candidate_root, oracle_rpath, candidate_rpath, {b"search=11\n", b"search=22\n", b"search=33\n"}, {"LD_LIBRARY_PATH": "/environment"}),
        "rpath-embedded": compare_allowed_reference(recorder, "search-path/rpath-embedded", oracle_root, candidate_root, oracle_rpath, candidate_rpath, {b"search=11\n", b"search=22\n", b"search=33\n"}),
    }
    return {"result": "pass", "dynamic": tags_by_mode, "behavior": behavior, "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}}


def case_origin(work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    """Use the driver's sealed RUNPATH option to exercise DSO-local $ORIGIN."""
    oracle_root, candidate_root = work / "oracle-root", work / "candidate-root"
    copy_root(product, candidate_root, candidate=True)
    copy_root(product, oracle_root, candidate=False)
    outputs: dict[str, tuple[pathlib.Path, pathlib.Path]] = {}
    for arm, root in (("oracle", oracle_root), ("candidate", candidate_root)):
        leaf = builder.shared(arm, root, "liborigin_leaf.so", builder.role(FIXTURES / "origin_leaf.c"))
        middle = builder.shared(arm, root, "liborigin_mid.so", builder.role(FIXTURES / "origin_mid.c"), (leaf,), runpath="$ORIGIN")
        bundle = root / "bundle"
        bundle.mkdir()
        moved_leaf, moved_mid = bundle / leaf.name, bundle / middle.name
        leaf.replace(moved_leaf)
        middle.replace(moved_mid)
        outputs[arm] = (moved_leaf, moved_mid)
    oracle = builder.executable("oracle", oracle_root, "consumer", builder.role(FIXTURES / "origin_main.c"))
    candidate = builder.executable("candidate", candidate_root, "consumer", builder.role(FIXTURES / "origin_main.c"))
    dynamic = recorder.checked("origin-mid-tags", ["readelf", "-dW", outputs["candidate"][1]], cwd=work).stdout
    text = tags(dynamic)
    if "(RUNPATH)" not in text or "$ORIGIN" not in text or "liborigin_leaf.so" not in text:
        raise LoaderSyntheticError("candidate origin DSO lost frozen RUNPATH/DT_NEEDED evidence")
    behavior = compare_standard(recorder, "dso-origin", oracle_root, candidate_root, oracle, candidate,
                                b"origin=18\n")
    return {"result": "pass", "dynamic": text, **behavior,
            "execution_roots": {"oracle": tree_seal(oracle_root), "candidate": tree_seal(candidate_root)}}


def unsupported_case(name: str, work: pathlib.Path, product: pathlib.Path, recorder: Recorder, builder: FixtureBuilder) -> dict[str, object]:
    """Build and retain an exact driver-bound reason when a frozen link surface is absent."""
    if name == "hash-many":
        return case_hash_many(work, product, recorder, builder)
    if name == "search-path":
        return case_search_path(work, product, recorder, builder)
    raise LoaderSyntheticError(f"no x86 component recipe was implemented for frozen {name}")


def run_case(name: str, product: pathlib.Path, root: pathlib.Path, timeout: float) -> dict[str, object]:
    work = root / "cases" / name
    work.mkdir(parents=True)
    recorder = Recorder(work, timeout)
    builder = FixtureBuilder(product, work, recorder)
    try:
        if name == "relocations":
            result = case_relocations(work, product, recorder, builder)
        elif name in SPECS:
            result = case_standard(name, work, product, recorder, builder)
        elif name == "hash-formats":
            result = case_hash_formats(work, product, recorder, builder)
        elif name == "dso-origin":
            result = case_origin(work, product, recorder, builder)
        else:
            result = unsupported_case(name, work, product, recorder, builder)
        result["status"] = "pass" if result.get("result") == "pass" else "fail"
    except (LoaderSyntheticError, OSError) as error:
        result = {"status": "fail", "error": str(error)}
        roots = {arm: tree_seal(path) for arm, path in (("oracle", work / "oracle-root"), ("candidate", work / "candidate-root")) if path.is_dir()}
        if roots:
            result["execution_roots"] = roots
    result["objects"] = builder.identity
    result["links"] = builder.links
    result["raw_directory"] = str(recorder.raw)
    (work / "case.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dynamic-sysroot", required=True, type=pathlib.Path, help="required physical installed dynamic product")
    parser.add_argument("--case", action="append", choices=CASES, help="repeatable frozen workload selection")
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    started = time.time()
    try:
        product, selected, timeout, scratch = preflight(args.dynamic_sysroot, args.case, args.timeout)
    except (LoaderSyntheticError, OSError) as error:
        print(f"owned synthetic loader: FAIL; error: {error}")
        return 1
    report_root = pathlib.Path(tempfile.mkdtemp(prefix="owned-loader-synthetic.", dir=scratch))
    try:
        before_source, before_product, before_oracle = source_seal(), tree_seal(product), oracle_seal()
        before_linker = producer_linker_seal(product)
        cases = {name: run_case(name, product, report_root, timeout) for name in selected}
        after_source, after_product, after_oracle = source_seal(), tree_seal(product), oracle_seal()
        after_linker = producer_linker_seal(product)
        if before_source != after_source or before_product != after_product or before_oracle != after_oracle or before_linker != after_linker:
            raise LoaderSyntheticError("source, supplied product, pinned linker, or pinned musl oracle changed while evidence was collected")
        selected_ok = selected_passed(cases)
        report = {"schema": 2, "runner": "compat/ldso/run_x86.py", "architecture": "x86_64", "source_mount": str(ROOT), "selected_passed": selected_ok, "component_complete": selected_ok and exact_component_selection(selected), "family_complete": False, "selected": list(selected), "source_before": before_source, "source_after": after_source, "product_before": before_product, "product_after": after_product, "oracle_before": before_oracle, "oracle_after": after_oracle, "producer_linker_before": before_linker, "producer_linker_after": after_linker, "cases": cases, "elapsed_seconds": time.time() - started}
    except (LoaderSyntheticError, OSError) as error:
        report = {"schema": 2, "runner": "compat/ldso/run_x86.py", "component_complete": False, "family_complete": False, "error": str(error), "elapsed_seconds": time.time() - started}
    path = report_root / "report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(*summary_lines(bool(report.get("component_complete")), report_root, path), sep="\n")
    return 0 if report.get("component_complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
