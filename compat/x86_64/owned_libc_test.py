#!/usr/bin/env python3
"""Run the finite native libc-test source aggregate against one owned product.

The shell leaf only owns argument and evidence-root handling.  This module owns
source provenance, staged-source preparation, installed-driver translation,
pinned-musl links, private runtime roots, and the final non-promoting report.
It intentionally records every compile/link/runtime failure instead of turning
missing ownership into a skip.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any, Iterable, Sequence

import owned_dynamic_receipt as receipt_contract

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-libc-test/v1"
PRODUCT_FORMAT = "crabc-x86-64-owned-dynamic-sysroot-v1"
TARGET = "x86_64-unknown-linux-musl"
ORACLE_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
ORACLE_ROOT = Path("/opt/musl-1.2.6")
ORACLE_LIBC = ORACLE_ROOT / "lib/libc.so"
ORACLE_INCLUDE = ORACLE_ROOT / "include"
ORACLE_SPECS = ORACLE_ROOT / "lib/musl-gcc.specs"
CANONICAL_INTERPRETER = "/lib/ld-crabc-x86_64.so.1"
MUSL_INTERPRETER = "/lib/ld-musl-x86_64.so.1"
SOURCE_RUNTEST_TIMEOUT_SECONDS = 5
SOURCE_RUNTEST_WRAP = ""
EXECUTION_IDENTITY_UNIT = "regression/pthread_atfork-errno-clobber"
EXECUTION_IDENTITY_HELPER = Path(__file__).with_name("owned_libc_test_identity.py")

# These are source-level target translation flags from libc-test's pinned
# config.mak.def.  `-pipe` is intentionally absent: it is only a host process
# topology preference, not a C semantic input, and sealed drivers do not admit
# arbitrary process-routing flags.
BASE_TRANSLATION_FLAGS = (
    "-std=c99",
    "-D_POSIX_C_SOURCE=200809L",
    "-D_FILE_OFFSET_BITS=64",
    "-Wall",
    "-Wno-unused-function",
    "-Wno-missing-braces",
    "-Wno-unused",
    "-Wno-overflow",
    "-Wno-unknown-pragmas",
    "-fno-builtin",
    "-Werror=implicit-function-declaration",
    "-Werror=implicit-int",
    "-Werror=pointer-sign",
    "-Werror=pointer-arith",
    "-g",
    # This is not a source deviation: the installed driver appends exactly
    # this representation policy for admitted debug generation because its
    # pinned LLD has no compressed-DWARF decoder.  The direct header trace
    # repeats the precise compiler prefix before comparing its inputs.
    "-gz=none",
)
# Upstream API targets use ``-pedantic-errors``.  The sealed driver already
# admits the narrower spelling of that same diagnostic policy without growing
# a broad compiler-switch surface: enable pedantic diagnostics and make that
# diagnostic class an error, while retaining upstream's unused exemption.
API_TRANSLATION_FLAGS = ("-Wpedantic", "-Werror=pedantic", "-Wno-unused", "-D_XOPEN_SOURCE=700")
ROUNDING_FLAG = "-frounding-math"

COMMON_MEMBERS = (
    "common/fdfill",
    "common/memfill",
    "common/mtest",
    "common/path",
    "common/print",
    "common/rand",
    "common/setrlim",
    "common/utf8",
    "common/vmfill",
)
RUNTIME_HELPER = "common/runtest"
DSO_UNITS = (
    "functional/dlopen_dso",
    "functional/tls_align_dso",
    "functional/tls_init_dso",
    "regression/tls_get_new-dtv_dso",
)
EXPECTED_COUNTS = {
    "functional_source": 77,
    "functional_runtime": 74,
    "math_runtime": 199,
    "math_generator_source": 29,
    "regression_source": 69,
    "regression_runtime": 68,
    "api_compile": 79,
    "common_source": 10,
    "runtime_total": 341,
    "declared_total": 434,
}
SHELL_RUNTIME_UNITS = frozenset(
    {
        "functional/popen",
        "functional/vfork",
        "functional/wordexp",
        "regression/execle-env",
    }
)
ECHO_RUNTIME_UNITS = frozenset({"functional/spawn"})

# These are the only upstream source units whose normal runtime behavior needs
# a private-root node beyond the generic `/tmp`, `/dev/null`, and `/dev/zero`
# topology.  Named semaphores and `shm_open` use musl's `/dev/shm` backing;
# `tls_get_new-dtv` links its helper with `$ORIGIN`, which musl 1.2.6 obtains
# from `/proc/self/exe` on a kernel-entry executable.  Keep this a finite
# source-derived mapping rather than mounting or emulating a general `/proc`.
SHARED_MEMORY_RUNTIME_UNITS = frozenset(
    {
        "functional/sem_open",
        "functional/pthread_cancel-points",
        "regression/sem_close-unmap",
    }
)
TLS_ORIGIN_RUNTIME_UNIT = "regression/tls_get_new-dtv"


class EvidenceError(RuntimeError):
    """A sealed source, product, or retained evidence boundary failed."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def require(value: object, message: str) -> None:
    if not value:
        fail(message)


def digest(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            fail(f"hashed artifact is not a physical regular file: {path}")
        result = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
        return result.hexdigest()
    except OSError as error:
        raise EvidenceError(f"cannot hash artifact: {path}") from error


def physical(path: Path, description: str, *, directory: bool = False, executable: bool = False) -> Path:
    """Require an existing physical regular file/directory with no symlink path."""

    absolute = Path(os.path.abspath(path))
    if ".." in absolute.parts:
        fail(f"{description} has parent traversal: {path}")
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        mode = absolute.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    if (directory and not stat.S_ISDIR(mode)) or (not directory and not stat.S_ISREG(mode)):
        fail(f"{description} is not a physical {'directory' if directory else 'regular file'}: {path}")
    if executable and not mode & 0o111:
        fail(f"{description} is not executable: {path}")
    return absolute


def physical_within(path: Path, parent: Path, description: str, *, directory: bool = False) -> Path:
    checked = physical(path, description, directory=directory)
    try:
        checked.relative_to(parent)
    except ValueError as error:
        raise EvidenceError(f"{description} escapes its required parent: {path}") from error
    return checked


def clean_environment() -> dict[str, str]:
    return {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1", "TZ": "UTC"}


def write_json(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        fail(f"evidence output already exists or is unsafe: {path}")
    physical(path.parent, "evidence output parent", directory=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def read_json(path: Path, description: str) -> dict[str, Any]:
    physical(path, description)
    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_json)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise EvidenceError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(result, dict):
        fail(f"{description} is not an object")
    return result


def reject_duplicate_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def artifact(path: Path, description: str) -> dict[str, str]:
    path = physical(path, description)
    return {"path": str(path), "sha256": digest(path)}


def command_record(command: Sequence[str | Path], environment: dict[str, str]) -> dict[str, Any]:
    return {"command": [str(item) for item in command], "environment": dict(environment)}


def run_capture(
    command: Sequence[str | Path], *, cwd: Path, environment: dict[str, str], stdout: Path, stderr: Path,
    stdin: bytes | None = None,
) -> dict[str, Any]:
    """Run one host control-plane command while retaining both byte streams."""

    if stdout.exists() or stderr.exists():
        fail("command output path already exists")
    physical(cwd, "command working directory", directory=True)
    physical(stdout.parent, "command output parent", directory=True)
    try:
        with stdout.open("xb") as output, stderr.open("xb") as errors:
            inputs: dict[str, Any] = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
            completed = subprocess.run(
                [str(item) for item in command],
                cwd=cwd,
                env=environment,
                stdout=output,
                stderr=errors,
                check=False,
                **inputs,
            )
    except OSError as error:
        stderr.write_bytes(str(error).encode("utf-8", errors="replace") + b"\n")
        return {**command_record(command, environment), "exit_status": None, "start_error": str(error),
                "stdout": artifact(stdout, "command stdout"), "stderr": artifact(stderr, "command stderr")}
    return {**command_record(command, environment), "exit_status": completed.returncode,
            "stdout": artifact(stdout, "command stdout"), "stderr": artifact(stderr, "command stderr")}


def pin() -> tuple[str, str]:
    try:
        record = tomllib.loads((ROOT / "compat/upstreams.toml").read_text(encoding="utf-8"))
        source = record["libc_test"]
        url = source["repository"]
        revision = source["revision"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError("libc-test upstream pin is unreadable") from error
    if not isinstance(url, str) or not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        fail("libc-test upstream pin is malformed")
    return url, revision


def git_output(source: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-c", f"safe.directory={source}", *arguments], cwd=source,
            env=clean_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False,
        )
    except OSError as error:
        raise EvidenceError("git is unavailable for libc-test source verification") from error
    if completed.returncode:
        raise EvidenceError(f"libc-test source verification failed: {' '.join(arguments)}: {completed.stderr.strip()}")
    return completed.stdout


def ensure_source() -> tuple[Path, dict[str, Any]]:
    """Acquire or validate exactly the pinned libc-test checkout below `.work`."""

    url, revision = pin()
    cache = ROOT / ".work/x86_64/source-oracles" / f"laputa-libc-test-{revision}"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        if cache.is_symlink():
            fail("libc-test source cache path is an unsafe symlink")
        temporary = cache.parent / f".{cache.name}.clone"
        if temporary.exists() or temporary.is_symlink():
            fail("libc-test source clone staging path already exists")
        completed = subprocess.run(
            ["git", "clone", "--no-checkout", url, str(temporary)], cwd=ROOT, env=clean_environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if completed.returncode:
            # Git may leave a partially initialized directory after a network
            # or object-transfer failure.  It is a fresh, checked staging name,
            # so remove that incomplete clone before reporting the acquisition
            # boundary instead of treating a directory as an unlinkable file.
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary)
            elif temporary.is_symlink():
                temporary.unlink()
            raise EvidenceError("cannot acquire pinned libc-test source")
        completed = subprocess.run(
            ["git", "-C", str(temporary), "checkout", "--detach", revision], cwd=ROOT,
            env=clean_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if completed.returncode:
            shutil.rmtree(temporary, ignore_errors=True)
            raise EvidenceError("cannot check out pinned libc-test revision")
        os.replace(temporary, cache)
    cache = physical(cache, "libc-test source cache", directory=True)
    head = git_output(cache, "rev-parse", "HEAD").strip()
    tree = git_output(cache, "rev-parse", "HEAD^{tree}").strip()
    status = git_output(cache, "status", "--porcelain", "--untracked-files=all")
    require(head == revision and not status, "libc-test source cache differs from pinned detached revision")
    return cache, {"url": url, "revision": revision, "tree": tree, "path": str(cache)}


def copy_pinned_source(source: Path, destination: Path) -> dict[str, str]:
    """Copy each tracked regular source byte into a private immutable stage."""

    require(not destination.exists() and not destination.is_symlink(), "staged source destination already exists")
    names = [name for name in git_output(source, "ls-tree", "-r", "--name-only", "HEAD").splitlines() if name]
    require(names, "pinned libc-test source has no tracked files")
    destination.mkdir(mode=0o755)
    result: dict[str, str] = {}
    for name in names:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            fail("pinned libc-test tracked source has unsafe path")
        original = source / relative
        mode = original.lstat().st_mode
        if not stat.S_ISREG(mode):
            fail(f"pinned libc-test source has nonregular tracked input: {name}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        os.chmod(target, stat.S_IMODE(mode))
        if digest(original) != digest(target):
            fail(f"staged libc-test source copy drifted: {name}")
        result[name] = digest(target)
    return result


def prepare_source(stage: Path, prepared: Path) -> dict[str, Any]:
    """Make the only permitted derived source, with exact replacement counts."""

    shutil.copytree(stage, prepared, symlinks=False)
    target = prepared / "src/api/unistd.c"
    original = target.read_text(encoding="utf-8")
    replacements = (
        ("C(_PC_TIMESTAMP_RESOLUTION)", "_PC_TIMESTAMP_RESOLUTION"),
        ("C(_SC_XOPEN_UUCP)", "_SC_XOPEN_UUCP"),
    )
    transformed = original
    applied = []
    for line, macro in replacements:
        if transformed.count(line) != 1:
            fail(f"pinned api/unistd source no longer has exactly one {macro} probe")
        replacement = f"#ifdef {macro}\n{line}\n#endif"
        transformed = transformed.replace(line, replacement)
        applied.append({"line": line, "macro": macro, "occurrences": 1, "replacement": replacement})
    target.write_text(transformed, encoding="utf-8", newline="\n")
    return {
        "source": "src/api/unistd.c",
        "original_sha256": digest(stage / "src/api/unistd.c"),
        "prepared_sha256": digest(target),
        "replacements": applied,
    }


def source_path(root: Path, unit: str) -> Path:
    return root / "src" / f"{unit}.c"


def collect_inventory(prepared: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Recreate the upstream direct dynamic target graph, not a glob approximation."""

    def direct(suite: str) -> list[str]:
        directory = prepared / "src" / suite
        return sorted(path.relative_to(prepared / "src").with_suffix("").as_posix() for path in directory.glob("*.c"))

    functional = direct("functional")
    math = direct("math")
    regression = direct("regression")
    api = direct("api")
    common = direct("common")
    generators = sorted(path.relative_to(prepared / "src").as_posix() for path in (prepared / "src/math/gen").rglob("*.c"))
    require(len(functional) == EXPECTED_COUNTS["functional_source"], "functional source inventory drifted")
    require(len(math) == EXPECTED_COUNTS["math_runtime"], "math source inventory drifted")
    require(len(regression) == EXPECTED_COUNTS["regression_source"], "regression source inventory drifted")
    require(len(api) == EXPECTED_COUNTS["api_compile"], "API source inventory drifted")
    require(set(common) == {*COMMON_MEMBERS, RUNTIME_HELPER} and len(common) == EXPECTED_COUNTS["common_source"],
            "common source inventory drifted")
    require(len(generators) == EXPECTED_COUNTS["math_generator_source"], "math generator inventory drifted")
    require(set(DSO_UNITS) <= set(functional + regression), "upstream DSO helper inventory drifted")
    functional_runtime = [name for name in functional if name not in DSO_UNITS]
    regression_runtime = [name for name in regression if name not in DSO_UNITS]
    require(len(functional_runtime) == EXPECTED_COUNTS["functional_runtime"], "functional runtime inventory drifted")
    require(len(regression_runtime) == EXPECTED_COUNTS["regression_runtime"], "regression runtime inventory drifted")

    units: list[dict[str, Any]] = []
    for name in functional_runtime:
        units.append({"id": name, "suite": "functional", "kind": "runtime", "source": f"src/{name}.c"})
    for name in math:
        units.append({"id": name, "suite": "math", "kind": "runtime", "source": f"src/{name}.c"})
    for name in regression_runtime:
        units.append({"id": name, "suite": "regression", "kind": "runtime", "source": f"src/{name}.c"})
    for name in api:
        units.append({"id": name, "suite": "api", "kind": "api", "source": f"src/{name}.c"})
    for name in DSO_UNITS:
        units.append({"id": name, "suite": name.split("/", 1)[0], "kind": "dso", "source": f"src/{name}.c"})
    for name in (*COMMON_MEMBERS, RUNTIME_HELPER):
        units.append({"id": name, "suite": "common", "kind": "common", "source": f"src/{name}.c"})
    require(len(units) == EXPECTED_COUNTS["declared_total"], "full libc-test declared inventory drifted")
    units.sort(key=lambda unit: unit["id"])
    exclusions = {
        "math_generators": {"count": len(generators), "sources": generators, "reason": "upstream Makefile does not make generator C files runtime targets"},
        "musl/pleval": {"source": "src/musl/pleval.c", "reason": "upstream Makefile suppresses the non-public __pleval dynamic test"},
    }
    counts = {"functional_runtime": len(functional_runtime), "math_runtime": len(math),
              "regression_runtime": len(regression_runtime), "api_compile": len(api),
              "dso_support": len(DSO_UNITS), "common": len(common), "declared_total": len(units)}
    return units, {"counts": counts, "exclusions": exclusions}


def validate_product(product: Path) -> dict[str, Any]:
    """Validate the supplied materialized owned product without importing checkout code."""

    product = physical_within(product, ROOT / ".work", "supplied dynamic product", directory=True)
    manifest_path = product / "share/crabc/manifest.json"
    manifest = read_json(manifest_path, "supplied dynamic product manifest")
    if (manifest.get("schema"), manifest.get("format"), manifest.get("target")) != (1, PRODUCT_FORMAT, TARGET):
        fail("supplied dynamic product manifest identity drifted")
    files = manifest.get("files")
    aliases = manifest.get("symlinks")
    if not isinstance(files, dict) or aliases != {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"}:
        fail("supplied dynamic product manifest roster drifted")
    required = {
        "bin/crabc-cc-dynamic", "share/crabc/crabc_cc_static.py", "usr/lib/libc.so",
        "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/crti.o", "usr/lib/crtn.o",
        "usr/lib/crabc-dynamic-attach.o", "usr/lib/libcrabc-builtins.a", "lib/ld-crabc-x86_64.so.1",
    }
    if not required <= set(files):
        fail("supplied dynamic product omits required payload")
    observed_files: set[str] = set()
    observed_links: dict[str, str] = {}
    for item in product.rglob("*"):
        relative = item.relative_to(product).as_posix()
        mode = item.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            observed_links[relative] = os.readlink(item)
            continue
        if not stat.S_ISREG(mode):
            fail(f"supplied dynamic product has a special payload entry: {relative}")
        if relative != "share/crabc/manifest.json":
            observed_files.add(relative)
    if observed_files != set(files) or observed_links != aliases:
        fail("supplied dynamic product physical roster differs from its manifest")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            fail("supplied dynamic product manifest file identity is malformed")
        candidate = Path(relative)
        if candidate.is_absolute() or not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
            fail("supplied dynamic product manifest path is unsafe")
        if digest(product / candidate) != expected:
            fail(f"supplied dynamic product payload hash differs: {relative}")
    return {"path": str(product), "manifest": artifact(manifest_path, "supplied dynamic manifest"),
            "driver": artifact(product / "bin/crabc-cc-dynamic", "installed dynamic driver"),
            "compiler_helper": artifact(product / "share/crabc/crabc_cc_static.py", "installed compiler helper"),
            "files": dict(sorted(files.items())), "aliases": dict(sorted(aliases.items()))}


def product_payload_identity(record: dict[str, Any]) -> dict[str, Any]:
    """Return the complete materialized-product identity independent of its path.

    The manifest hash binds its format and target while the complete physical
    payload and alias maps bind every byte and loader spelling a copied root
    can use.  Do not reduce this to the driver hash: a compiler can select CRT,
    libc, headers, the linker, or an alias from elsewhere in the product.
    """

    manifest = record.get("manifest")
    files = record.get("files")
    aliases = record.get("aliases")
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("sha256"), str)
            or not isinstance(files, dict) or not isinstance(aliases, dict)):
        fail("dynamic product identity record is malformed")
    return {
        "manifest_sha256": manifest["sha256"],
        "files": dict(sorted(files.items())),
        "aliases": dict(sorted(aliases.items())),
    }


def require_same_product_payload(
    expected: dict[str, Any], observed: dict[str, Any], description: str,
) -> None:
    if product_payload_identity(expected) != product_payload_identity(observed):
        fail(f"{description} payload or aliases changed")


def seal_candidate_product(source: Path, destination: Path, source_before: dict[str, Any]) -> dict[str, Any]:
    """Copy and validate one immutable candidate product for all product uses.

    Compilers, linkers, headers, and runtime roots consume only this evidence
    copy.  The caller validates the supplied product both before and after the
    campaign, so a mutation cannot replace the product being measured midway.
    """

    if destination.exists() or destination.is_symlink():
        fail("sealed candidate product destination already exists")
    shutil.copytree(source, destination, symlinks=True)
    sealed = validate_product(destination)
    require_same_product_payload(source_before, sealed, "sealed candidate product copy")
    return sealed


def qualification_runtime_module() -> Any:
    """Load the shared native-qualification identity checker on demand.

    This script is also imported directly by its focused tests, where Python
    does not put `compat/x86_64` on `sys.path`.  The qualification module owns
    the physical file/directory identity rules and the exact musl input roster;
    this aggregate deliberately reuses those rules instead of recreating a
    second oracle boundary.
    """

    module_directory = str(Path(__file__).resolve().parent)
    if module_directory not in sys.path:
        sys.path.insert(0, module_directory)
    try:
        import run_qualification_manifest as qualification
    except ImportError as error:
        raise EvidenceError("shared native-qualification identity checker is unavailable") from error
    return qualification


def pinned_musl_identity() -> dict[str, Any]:
    """Capture the exact pinned-musl tool, specs, headers, and runtime closure.

    `run_qualification_manifest` is the owner of the physical identity rules
    used by native qualification.  Retain its full oracle roster before and
    after this aggregate, plus the pinned source-manifest semantics used by
    owned dynamic qualification, rather than treating `/opt` path names as an
    oracle identity.
    """

    qualification = qualification_runtime_module()
    expected_names = {
        "compiler_wrapper", "libc", "loader", "specs", "source_manifest", "specs_manifest", "headers",
    }
    paths = qualification.MUSL_RUNTIME_PATHS
    if set(paths) != expected_names:
        fail("shared pinned-musl identity roster drifted")
    try:
        files = {
            name: (
                qualification.physical_directory_identity(path, f"pinned musl {name}")
                if name == "headers" else qualification.physical_file_identity(path, f"pinned musl {name}")
            )
            for name, path in paths.items()
        }
    except qualification.QualificationRunError as error:
        raise EvidenceError(f"pinned musl identity is unavailable: {error}") from error

    try:
        musl_pin = tomllib.loads((ROOT / "compat/upstreams.toml").read_text(encoding="utf-8"))["musl"]
        version = musl_pin["version"]
        source_sha256 = musl_pin["sha256"]
        fallback_revision = musl_pin["fallback_revision"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError("pinned musl source record is unreadable") from error
    if version != "1.2.6" or not all(isinstance(value, str) for value in (source_sha256, fallback_revision)):
        fail("pinned musl source record drifted")
    expected_manifest = (
        "format=crabc-pinned-musl-oracle-v1\n"
        f"version={version}\nsource_sha256={source_sha256}\n"
        f"fallback_revision={fallback_revision}\narchitecture=x86_64\n"
    )
    source_manifest = Path(files["source_manifest"]["resolved_path"])
    specs_manifest = Path(files["specs_manifest"]["resolved_path"])
    if source_manifest.read_text(encoding="utf-8") != expected_manifest:
        fail("pinned musl source verification manifest drifted")
    expected_specs_manifest = f"{files['specs']['sha256']}  /opt/musl-1.2.6/lib/musl-gcc.specs\n"
    if specs_manifest.read_text(encoding="utf-8") != expected_specs_manifest:
        fail("pinned musl specs verification manifest drifted")
    if files["compiler_wrapper"]["sha256"] != digest(ROOT / "docker/x86_64-musl-oracle-gcc"):
        fail("pinned musl compiler wrapper differs from its pinned source")
    return {
        "version": f"musl-{version}",
        "pins": artifact(ROOT / "compat/upstreams.toml", "musl source pin"),
        "files": files,
    }


def installed_compiler_contract(product: Path) -> tuple[Path, dict[str, str], dict[str, str]]:
    """Load the helper copied into this exact product, never a host compiler name."""

    helper = physical(product / "share/crabc/crabc_cc_static.py", "installed compiler helper")
    specification = importlib.util.spec_from_file_location("owned_libc_test_installed_compiler", helper)
    if specification is None or specification.loader is None:
        fail("installed compiler helper cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    try:
        specification.loader.exec_module(module)
        compiler_name = module.compiler()
        environment = module.clean_environment()
    except (AttributeError, OSError, RuntimeError) as error:
        raise EvidenceError("installed compiler helper contract is incomplete") from error
    if not isinstance(compiler_name, str) or not compiler_name or not isinstance(environment, dict):
        fail("installed compiler helper has malformed compiler contract")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items()):
        fail("installed compiler helper has malformed clean environment")
    compiler = physical(Path(compiler_name), "installed selected compiler", executable=True)
    return compiler, dict(environment), artifact(compiler, "installed selected compiler")


def driver_support(product: Path) -> dict[str, Any]:
    """Record whether installed driver bytes expose every required source edge."""

    driver = physical(product / "bin/crabc-cc-dynamic", "installed dynamic driver", executable=True)
    static_helper = physical(product / "share/crabc/crabc_cc_static.py", "installed compiler helper")
    text = driver.read_text(encoding="utf-8", errors="replace")
    helper_text = static_helper.read_text(encoding="utf-8", errors="replace")
    required = {
        "quote_include": "--application-quote-include-dir",
        "rounding_math": "-frounding-math",
        "export_dynamic": "--export-dynamic",
        "uncompressed_debug": "-gz=none",
    }
    available = {name: fragment in (helper_text if name == "uncompressed_debug" else text)
                 for name, fragment in required.items()}
    return {"driver": artifact(driver, "installed dynamic driver"),
            "static_helper": artifact(static_helper, "installed compiler helper"), "required_fragments": required,
            "available": available, "complete": all(available.values())}


def header_trace_paths(trace: Path) -> list[str]:
    """Extract GCC -H file paths without treating diagnostics as header input."""

    result: list[str] = []
    for line in trace.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\.+\s+(.*)$", line)
        if match:
            result.append(match.group(1))
    return result


def allowed_header_paths(paths: Iterable[str], *, product: Path, prepared: Path, generated: Path) -> tuple[bool, list[str]]:
    allowed = (product / "usr/include", prepared / "src", generated)
    foreign: list[str] = []
    for value in paths:
        path = Path(value)
        if not path.is_absolute():
            foreign.append(value)
            continue
        resolved = Path(os.path.abspath(path))
        if not any(resolved.is_relative_to(root) for root in allowed):
            foreign.append(value)
    return not foreign, foreign


def generate_options_header(
    *, compiler: Path, environment: dict[str, str], include: Path, source: Path, output: Path, trace: Path,
) -> dict[str, Any]:
    """Reproduce the upstream options.h preprocessing transform with declared headers."""

    source = physical(source, "options template")
    include = physical(include, "options include root", directory=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    physical(output.parent, "generated options output parent", directory=True)
    if output.exists() or trace.exists():
        fail("generated options evidence path already exists")
    command = [str(compiler), "-nostdinc", "-isystem", str(include), "-ffreestanding", "-fno-builtin",
               "-fstack-protector-strong", "-std=c99", "-D_POSIX_C_SOURCE=200809L", "-D_FILE_OFFSET_BITS=64", "-E", "-H", "-"]
    prepared = source.read_bytes()
    record = run_capture(command, cwd=output.parent, environment=environment,
                         stdout=output.with_suffix(".preprocessed"), stderr=trace, stdin=prepared)
    preprocessed = output.with_suffix(".preprocessed")
    if record["exit_status"] != 0:
        return {"status": "failed", "input": artifact(source, "options template"), "record": record}
    active = False
    pending: str | None = None
    lines: list[str] = []
    for line in preprocessed.read_text(encoding="utf-8", errors="replace").splitlines():
        if "optiongroups_unistd_end" in line:
            active = True
            continue
        if not active or not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        if pending is None:
            pending = fields[0]
            if len(fields) == 1:
                continue
        lines.append(f"#define {pending} {fields[-1]}")
        pending = None
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")
    return {"status": "passed", "input": artifact(source, "options template"), "output": artifact(output, "generated options header"),
            "record": record, "trace": artifact(trace, "options header trace")}


def unit_flags(kind: str) -> tuple[str, ...]:
    return (*BASE_TRANSLATION_FLAGS, ROUNDING_FLAG,
            *(("-DSHARED",) if kind == "dso" else ()),
            *(API_TRANSLATION_FLAGS if kind == "api" else ()))


def compile_command(
    product: Path, source: Path, output: Path, *, shared_object: bool, quote_dirs: Sequence[Path], kind: str,
) -> list[str]:
    command = [str(product / "bin/crabc-cc-dynamic"), "--dynamic-shared-object" if shared_object else "--dynamic-pie"]
    for directory in quote_dirs:
        command.extend(("--application-quote-include-dir", str(directory)))
    command.extend((*unit_flags(kind), "-c", str(source), "-o", str(output)))
    return command


def header_command(
    compiler: Path, product: Path, source: Path, *, shared_object: bool, quote_dirs: Sequence[Path], kind: str,
) -> list[str]:
    command = [str(compiler), "-nostdinc"]
    for directory in quote_dirs:
        command.extend(("-iquote", str(directory)))
    command.extend(("-isystem", str(product / "usr/include"), "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
                    *unit_flags(kind), "-fPIC" if shared_object else "-fPIE", "-E", "-H", str(source)))
    return command


def compile_candidate(
    *, product: Path, compiler: Path, environment: dict[str, str], prepared: Path, generated: Path,
    unit: dict[str, Any], output: Path, evidence: Path, driver_ready: bool,
) -> dict[str, Any]:
    """Compile exactly one target source through the installed driver and trace its headers separately."""

    source = physical(prepared / unit["source"], f"source {unit['id']}")
    shared_object = unit["kind"] == "dso"
    quote_dirs = [prepared / "src/common"]
    if unit["kind"] == "api":
        quote_dirs.append(generated / "candidate")
    for directory in quote_dirs:
        physical(directory, "declared quote include directory", directory=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    trace = evidence.with_suffix(".headers.stderr")
    trace_stdout = evidence.with_suffix(".headers.stdout")
    header = run_capture(header_command(compiler, product, source, shared_object=shared_object, quote_dirs=quote_dirs, kind=unit["kind"]),
                         cwd=evidence.parent, environment=environment, stdout=trace_stdout, stderr=trace)
    paths = header_trace_paths(trace)
    header_ok, foreign_headers = allowed_header_paths(paths, product=product, prepared=prepared, generated=generated)
    command = compile_command(
        product, source, output, shared_object=shared_object, quote_dirs=quote_dirs, kind=unit["kind"],
    )
    header_record = {
        "status": "passed" if header["exit_status"] == 0 and header_ok else "failed",
        "record": header,
        "trace": artifact(trace, "header trace"),
        "trace_paths": paths,
        "foreign_headers": foreign_headers,
    }
    if not driver_ready:
        # Do not manufacture hundreds of equivalent rejected driver invocations
        # when the installed product cannot express this source graph.  The
        # retained header trace still proves the precise candidate headers;
        # the recorded command is the unattempted source edge.
        translation_record = {
            "status": "blocked",
            "reason": "installed driver lacks required sealed libc-test source inputs",
            "record": command_record(command, environment),
            "object": None,
        }
    else:
        compile_stdout = evidence.with_suffix(".compile.stdout")
        compile_stderr = evidence.with_suffix(".compile.stderr")
        translation = run_capture(command, cwd=evidence.parent, environment=environment,
                                  stdout=compile_stdout, stderr=compile_stderr)
        compiled = translation["exit_status"] == 0 and output.is_file() and not output.is_symlink()
        translation_record = {
            "status": "passed" if compiled else "failed",
            "record": translation,
            "object": artifact(output, "candidate object") if compiled else None,
        }
    return {
        "source": artifact(source, f"source {unit['id']}"),
        "kind": unit["kind"],
        "quote_include_dirs": [str(path) for path in quote_dirs],
        "header_translation": header_record,
        "candidate_translation": translation_record,
    }


def candidate_link_command(
    product: Path, objects: Sequence[Path], output: Path, *, shared_object: bool = False,
    application_dsos: Sequence[Path] = (), runpath: str | None = None, export_dynamic: bool = False,
) -> list[str]:
    command = [str(product / "bin/crabc-cc-dynamic"), "--dynamic-shared-object" if shared_object else "--dynamic-pie"]
    if runpath is not None:
        command.extend(("--application-runpath", runpath))
    if export_dynamic:
        command.append("-rdynamic")
    for dso in application_dsos:
        command.extend(("--application-dso", str(dso)))
    command.extend((str(path) for path in objects))
    command.extend(("-o", str(output)))
    return command


def oracle_link_command(
    objects: Sequence[Path], output: Path, *, shared_object: bool = False, application_dsos: Sequence[Path] = (),
    runpath: str | None = None, export_dynamic: bool = False,
) -> list[str]:
    command = [str(ORACLE_CC)]
    if shared_object:
        command.extend(("-fPIC", "-shared", f"-Wl,-soname,{output.name}"))
    else:
        command.extend(("-fPIE", "-pie", f"-Wl,--dynamic-linker,{MUSL_INTERPRETER}"))
        if export_dynamic:
            command.append("-rdynamic")
    if runpath is not None:
        command.append(f"-Wl,-rpath,{runpath}")
    command.extend(str(path) for path in objects)
    command.extend(str(path) for path in application_dsos)
    command.extend(("-o", str(output)))
    return command


def run_readelf(path: Path, output: Path, flag: str) -> dict[str, Any]:
    return run_capture(["/usr/bin/readelf", flag, "-W", str(path)], cwd=output.parent, environment=clean_environment(),
                       stdout=output, stderr=output.with_suffix(output.suffix + ".stderr"))


def verify_candidate_receipt(
    *, product: Path, output: Path, receipt_path: Path, objects: Sequence[Path], application_dsos: Sequence[Path],
    shared_object: bool, runpath: str, export_dynamic: bool,
) -> dict[str, Any]:
    """Validate the exact extended dynamic-driver receipt for this one link.

    This deliberately does not modify the generic POSIX validator: only this
    aggregate admits source-defined `$ORIGIN` and executable-export contracts.
    """

    receipt = read_json(receipt_path, "candidate dynamic link receipt")
    search = receipt_contract.validate(
        receipt, format=PRODUCT_FORMAT, label="candidate dynamic link receipt", fail=fail
    )
    mode = "shared" if shared_object else "pie"
    if (receipt["mode"], receipt["binding"], receipt["runtime_imports"], receipt["campaign_complete"]) != (mode, "now", [], False):
        fail("candidate dynamic link receipt contract drifted")
    receipt_contract.require_runpath(
        search, runpath, label="candidate dynamic link receipt", fail=fail
    )
    if receipt["output_path"] != str(output.resolve()) or receipt["output_sha256"] != digest(output):
        fail("candidate dynamic link receipt output identity drifted")
    manifest = product / "share/crabc/manifest.json"
    if receipt["manifest_sha256"] != digest(manifest):
        fail("candidate dynamic link receipt product identity drifted")
    expected_dsos = {path.name: digest(path) for path in application_dsos}
    if receipt["application_dsos"] != expected_dsos:
        fail("candidate dynamic link receipt DSO roster drifted")
    linker = receipt["resolved_linker"]
    if not isinstance(linker, dict) or set(linker) != {"path", "sha256"}:
        fail("candidate dynamic link receipt linker identity drifted")
    linker_path = physical(Path(linker["path"]), "candidate resolved linker", executable=True)
    if linker["sha256"] != digest(linker_path):
        fail("candidate dynamic link receipt linker hash drifted")
    library = product / "usr/lib"
    link = [str(linker_path), *( ["-shared"] if shared_object else ["-pie"]), "--hash-style=sysv",
            "--eh-frame-hdr", "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
            "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", runpath]
    if export_dynamic:
        link.append("--export-dynamic")
    runtime = [library / name for name in ("crti.o", "libc.so", "crtn.o")]
    if not shared_object:
        entry = library / "Scrt1.o"
        runtime.extend((entry, library / "crabc-dynamic-attach.o"))
        link.extend(("--dynamic-linker", CANONICAL_INTERPRETER, str(entry), str(library / "crabc-dynamic-attach.o")))
    if shared_object:
        link.extend(("-soname", output.name))
    link.extend((str(library / "crti.o"), *(str(path) for path in objects), *(str(path) for path in application_dsos),
                 str(library / "libc.so"), str(library / "libcrabc-builtins.a"), str(library / "crtn.o"), "-o", str(output)))
    if receipt["link_command"] != link:
        fail("candidate dynamic link receipt command drifted")
    direct = [*runtime, *objects, *application_dsos]
    expected_inputs = [{"path": str(path), "sha256": digest(path)} for path in [*direct, library / "libcrabc-builtins.a"]]
    if receipt["input_receipts"] != expected_inputs:
        fail("candidate dynamic link receipt input hashes drifted")
    expected_runtime = sorted(path.relative_to(product).as_posix() for path in [*runtime, library / "libcrabc-builtins.a"])
    if receipt["owned_runtime_inputs"] != expected_runtime:
        fail("candidate dynamic link receipt owned runtime roster drifted")
    trace = receipt["link_trace"]
    if not isinstance(trace, list) or not all(isinstance(item, str) for item in trace):
        fail("candidate dynamic link receipt trace drifted")
    direct_text = {str(path) for path in direct}
    archive = str(library / "libcrabc-builtins.a")
    seen: set[str] = set()
    for item in trace:
        if item in direct_text:
            seen.add(item)
        elif item == archive or (item.startswith(archive + "(") and item.endswith(")")):
            pass
        else:
            fail("candidate dynamic link receipt trace has an unadmitted input")
    if seen != direct_text:
        fail("candidate dynamic link receipt trace omits a direct input")
    return {"receipt": artifact(receipt_path, "candidate link receipt"), "linker": artifact(linker_path, "candidate linker"),
            "link_command": link, "link_trace": trace}


def elf_record(path: Path, directory: Path, label: str) -> dict[str, Any]:
    """Retain standard ELF observations for both raw and candidate outputs."""

    directory.mkdir(parents=True, exist_ok=True)
    outputs = {}
    for name, flag in (("header", "-h"), ("segments", "-l"), ("dynamic", "-d"), ("symbols", "--dyn-syms"), ("relocations", "-r")):
        output = directory / f"{label}.{name}.txt"
        record = run_readelf(path, output, flag)
        outputs[name] = {"record": record, "output": artifact(output, f"{label} {name} readelf")}
    return outputs


def expected_candidate_elf(path: Path, observations: dict[str, Any], *, shared_object: bool,
                           application_dsos: Sequence[Path]) -> tuple[bool, str]:
    header = Path(observations["header"]["output"]["path"]).read_text(errors="replace")
    segments = Path(observations["segments"]["output"]["path"]).read_text(errors="replace")
    dynamic = Path(observations["dynamic"]["output"]["path"]).read_text(errors="replace")
    if "Advanced Micro Devices X86-64" not in header or "Type:" not in header or "DYN" not in header:
        return False, "candidate ELF is not x86-64 ET_DYN"
    if shared_object:
        if "INTERP" in segments or "Requesting program interpreter" in segments:
            return False, "candidate shared object has PT_INTERP"
    elif CANONICAL_INTERPRETER not in segments:
        return False, "candidate executable interpreter drifted"
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
    declared_dsos = [item.name for item in application_dsos]
    # LLD is permitted to elide an otherwise unused direct libc dependency
    # from a helper DSO.  A consumer executable, on the other hand, must keep
    # its libc dependency.  In both forms no undeclared ELF provider may enter
    # the target.  The declared application DSOs are topology, so each one
    # must remain in DT_NEEDED even if its own symbols are not referenced.
    allowed_needed = {"libc.so", *declared_dsos}
    if any(name not in allowed_needed for name in needed):
        return False, "candidate NEEDED roster has an undeclared provider"
    if any(name not in needed for name in declared_dsos):
        return False, "candidate NEEDED roster omits a declared application DSO"
    if not shared_object and "libc.so" not in needed:
        return False, "candidate executable omits libc.so"
    if "TEXTREL" in dynamic:
        return False, "candidate has text relocations"
    return True, "passed"


def expected_oracle_elf(observations: dict[str, Any], *, shared_object: bool) -> tuple[bool, str]:
    header = Path(observations["header"]["output"]["path"]).read_text(errors="replace")
    segments = Path(observations["segments"]["output"]["path"]).read_text(errors="replace")
    if "Advanced Micro Devices X86-64" not in header or "DYN" not in header:
        return False, "pinned-musl output is not x86-64 ET_DYN"
    if not shared_object and MUSL_INTERPRETER not in segments:
        return False, "pinned-musl executable interpreter drifted"
    if shared_object and ("INTERP" in segments or "Requesting program interpreter" in segments):
        return False, "pinned-musl shared object has PT_INTERP"
    return True, "passed"


def copy_regular(source: Path, destination: Path, description: str) -> dict[str, str]:
    source = physical(source, description)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        destination.unlink()
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(source.lstat().st_mode))
    if digest(source) != digest(destination):
        fail(f"private-root copy drifted: {description}")
    return artifact(destination, description)


def make_char_device(path: Path, minor: int) -> None:
    if path.exists() or path.is_symlink():
        fail(f"private runtime device already exists: {path}")
    os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(1, minor))


CONTROL_DIRECTORY = "/control"
CONTROL_BUSYBOX = f"{CONTROL_DIRECTORY}/busybox"
CONTROL_LOADER = f"{CONTROL_DIRECTORY}/ld-musl-x86_64.so.1"
CONTROL_SHELL_SOURCE = b'''#include <unistd.h>

extern char **environ;

int main(int argc, char *argv[])
{
	char *command[argc + 3];
	int index;

	command[0] = "/control/ld-musl-x86_64.so.1";
	command[1] = "/control/busybox";
	command[2] = "sh";
	for (index = 1; index < argc; index++)
		command[index + 2] = argv[index];
	command[argc + 2] = 0;
	execve(command[0], command, environ);
	return 127;
}
'''
CONTROL_ECHO_SOURCE = b'''#include <unistd.h>

extern char **environ;

int main(int argc, char *argv[])
{
	char *command[argc + 3];
	int index;

	command[0] = "/control/ld-musl-x86_64.so.1";
	command[1] = "/control/busybox";
	command[2] = "echo";
	for (index = 1; index < argc; index++)
		command[index + 2] = argv[index];
	command[argc + 2] = 0;
	execve(command[0], command, environ);
	return 127;
}
'''


def physical_control_file(path: Path, description: str) -> Path:
    """Resolve a host control file without admitting it as a product input."""

    try:
        resolved = Path(os.path.realpath(path))
    except OSError as error:
        raise EvidenceError(f"cannot resolve {description}: {path}") from error
    return physical(resolved, description, executable=True)


def pinned_control_loader() -> Path:
    """Return the exact pinned-musl loader used by the raw oracle roots.

    The image may expose another musl loader at its conventional host path.
    A control fixture must not make that ambient runtime part of either side's
    execution closure: its BusyBox process is explicitly started by the same
    byte-identified loader as the pinned raw runtime.
    """

    return physical(ORACLE_LIBC, "pinned musl control loader", executable=True)


def fixed_control_fixture(
    work: Path, product: Path, compiler: Path, compiler_environment: dict[str, str],
    link_environment: dict[str, str], driver_ready: bool, oracle: dict[str, Any], *,
    fixture_name: str, launcher: str, source_bytes: bytes,
) -> dict[str, Any]:
    """Build one explicit BusyBox control launcher through both runtimes.

    The launcher is compiled once through the installed driver and linked once
    against each runtime.  Its process immediately enters the separately
    copied pinned-musl+BusyBox closure, so the control program cannot select a
    product loader alias or an ambient host executable.
    """

    work.mkdir(parents=True, exist_ok=False)
    physical(work, f"external {fixture_name} evidence directory", directory=True)
    busybox = physical_control_file(Path("/bin/busybox"), "controlled BusyBox")
    loader = pinned_control_loader()
    source = work / f"{fixture_name}-launcher.c"
    source.write_bytes(source_bytes)
    source_record = artifact(source, f"control {fixture_name} launcher source")
    loader_record = artifact(loader, "controlled musl loader")
    oracle_files = oracle.get("files")
    if not isinstance(oracle_files, dict) or loader_record["sha256"] != oracle_files.get("loader", {}).get("sha256"):
        fail(f"controlled {fixture_name} loader differs from the pinned musl runtime")
    control = {
        "busybox": artifact(busybox, "controlled BusyBox"),
        "loader": loader_record,
        "layout": {"busybox": CONTROL_BUSYBOX, "loader": CONTROL_LOADER, "launcher": launcher},
    }
    output = work / f"{fixture_name}-launcher.o"
    trace = work / f"{fixture_name}-launcher.headers.stderr"
    header = run_capture(
        header_command(compiler, product, source, shared_object=False, quote_dirs=(), kind="runtime"),
        cwd=work, environment=compiler_environment,
        stdout=work / f"{fixture_name}-launcher.headers.stdout", stderr=trace,
    )
    paths = header_trace_paths(trace)
    headers = {
        "status": "passed" if header["exit_status"] == 0 and all(
            Path(path).is_absolute() and Path(os.path.abspath(path)).is_relative_to(product / "usr/include")
            for path in paths
        ) else "failed",
        "record": header,
        "trace": artifact(trace, f"control {fixture_name} header trace"),
        "trace_paths": paths,
    }
    command = compile_command(product, source, output, shared_object=False, quote_dirs=(), kind="runtime")
    if not driver_ready:
        return {
            "status": "blocked", "reason": "installed driver lacks required sealed libc-test source inputs",
            "source": source_record, "control": control, "header_translation": headers,
            "candidate_translation": {"status": "blocked", "record": command_record(command, compiler_environment)},
        }
    translation = run_capture(
        command, cwd=work, environment=compiler_environment,
        stdout=work / f"{fixture_name}-launcher.compile.stdout",
        stderr=work / f"{fixture_name}-launcher.compile.stderr",
    )
    if translation["exit_status"] != 0 or not output.is_file() or output.is_symlink():
        return {
            "status": "failed", "reason": f"control {fixture_name} launcher did not translate through the installed driver",
            "source": source_record, "control": control, "header_translation": headers,
            "candidate_translation": {"status": "failed", "record": translation, "object": None},
        }
    object_record = artifact(output, f"control {fixture_name} launcher object")
    candidate_output = work / f"candidate-{fixture_name}-launcher"
    oracle_output = work / f"oracle-{fixture_name}-launcher"
    candidate = candidate_link(
        product=product, environment=link_environment, output=candidate_output,
        evidence=work / f"{fixture_name}-launcher.candidate-link", objects=[output], runpath="/usr/lib",
    )
    oracle_link_result = oracle_link(
        output=oracle_output, evidence=work / f"{fixture_name}-launcher.oracle-link",
        environment=link_environment, objects=[output], runpath="/usr/lib",
    )
    status = "passed" if (
        headers["status"] == "passed" and candidate.get("status") == "passed"
        and oracle_link_result.get("status") == "passed"
    ) else "failed"
    return {
        "status": status, "source": source_record, "control": control, "header_translation": headers,
        "candidate_translation": {"status": "passed", "record": translation, "object": object_record},
        "candidate_link": candidate, "oracle_link": oracle_link_result,
        "candidate_launcher": artifact(candidate_output, f"candidate control {fixture_name} launcher")
        if candidate.get("status") == "passed" else None,
        "oracle_launcher": artifact(oracle_output, f"pinned-musl control {fixture_name} launcher")
        if oracle_link_result.get("status") == "passed" else None,
    }


def shell_fixture(
    work: Path, product: Path, compiler: Path, compiler_environment: dict[str, str],
    link_environment: dict[str, str], driver_ready: bool, oracle: dict[str, Any],
) -> dict[str, Any]:
    """Build the existing source-selected `/bin/sh` control closure."""

    return fixed_control_fixture(
        work, product, compiler, compiler_environment, link_environment, driver_ready, oracle,
        fixture_name="shell", launcher="/bin/sh", source_bytes=CONTROL_SHELL_SOURCE,
    )


def echo_fixture(
    work: Path, product: Path, compiler: Path, compiler_environment: dict[str, str],
    link_environment: dict[str, str], driver_ready: bool, oracle: dict[str, Any],
) -> dict[str, Any]:
    """Build the narrow `/bin/echo` closure required by `functional/spawn`."""

    return fixed_control_fixture(
        work, product, compiler, compiler_environment, link_environment, driver_ready, oracle,
        fixture_name="echo", launcher="/bin/echo", source_bytes=CONTROL_ECHO_SOURCE,
    )


def make_candidate_root(product: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        fail("candidate execution root already exists")
    shutil.copytree(product, destination, symlinks=True)


def copied_oracle_runtime_record(
    *, root: Path, source: Path, destination: Path, source_identity: dict[str, str], description: str,
) -> dict[str, Any]:
    """Copy one raw-runtime file and retain the identity of the copied bytes.

    The private root is deleted after execution, so its artifact pathname would
    be misleading evidence.  Record the source identity, in-root destination,
    and hash observed immediately after the copy instead.
    """

    copied = copy_regular(source, destination, description)
    if copied["sha256"] != source_identity.get("sha256"):
        fail(f"raw runtime copy differs from the pinned musl identity: {description}")
    return {
        "source": dict(source_identity),
        "destination": "/" + destination.relative_to(root).as_posix(),
        "copied_sha256": copied["sha256"],
    }


def make_oracle_root(destination: Path, oracle: dict[str, Any]) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        fail("oracle execution root already exists")
    files = oracle.get("files")
    if not isinstance(files, dict):
        fail("pinned musl identity has no runtime file records")
    loader_identity = files.get("loader")
    libc_identity = files.get("libc")
    if not isinstance(loader_identity, dict) or not isinstance(libc_identity, dict):
        fail("pinned musl identity omits loader or libc")
    destination.mkdir(mode=0o755)
    return {
        "loader": copied_oracle_runtime_record(
            root=destination, source=ORACLE_LIBC, destination=destination / MUSL_INTERPRETER.lstrip("/"),
            source_identity=loader_identity, description="pinned-musl loader",
        ),
        "libc": copied_oracle_runtime_record(
            root=destination, source=ORACLE_LIBC, destination=destination / "usr/lib/libc.so",
            source_identity=libc_identity, description="pinned-musl libc",
        ),
    }


def prepare_execution_root(root: Path) -> None:
    (root / "tmp").mkdir(mode=0o1777, exist_ok=False)
    os.chmod(root / "tmp", 0o1777)
    (root / "dev").mkdir(mode=0o755, exist_ok=False)
    make_char_device(root / "dev/null", 3)
    make_char_device(root / "dev/zero", 5)


def filesystem_fixture_for_unit(unit_id: str) -> list[dict[str, str]]:
    """Return the exact source-required filesystem nodes for one runtime unit.

    The returned JSON-safe records are intentionally separate from copied
    program/control files: directories and a kernel-visible symlink have no
    source byte hash, but their type, mode, target, and absence of undeclared
    children are still part of the observed private-root contract.
    """

    if unit_id in SHARED_MEMORY_RUNTIME_UNITS:
        return [{"path": "/dev/shm", "type": "directory", "mode": "01777"}]
    if unit_id == TLS_ORIGIN_RUNTIME_UNIT:
        return [
            {"path": "/proc", "type": "directory", "mode": "0755"},
            {"path": "/proc/self", "type": "directory", "mode": "0755"},
            {"path": "/proc/self/exe", "type": "symlink", "target": f"/{unit_id}"},
        ]
    return []



def identity_helper_module() -> Any:
    """Load only the small host identity contract, without importing target code."""

    specification = importlib.util.spec_from_file_location("owned_libc_test_identity", EXECUTION_IDENTITY_HELPER)
    if specification is None or specification.loader is None:
        fail("cannot load the fixed execution-identity helper")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def execution_identity_fixture_for_unit(unit_id: str) -> dict[str, Any] | None:
    """The atfork errno test requires a nonroot RLIMIT_NPROC execution identity."""

    if unit_id != EXECUTION_IDENTITY_UNIT:
        return None
    return identity_helper_module().fixture_for_unit(unit_id)


def validate_execution_identity_receipt(
    receipt: dict[str, Any], *, root: Path, unit_id: str, source: dict[str, str],
    parent_before: dict[str, Any],
) -> None:
    """Validate the measured transition; this is not a post-exec observation."""

    fixture = execution_identity_fixture_for_unit(unit_id)
    expected = {
        "schema": "crabc.x86_64-owned-libc-test-execution-identity/v1",
        "unit": unit_id, "root": str(root), "fixture": fixture, "source": source,
        "command": source_runtest_arguments(f"/{unit_id}"), "before_drop": parent_before,
    }
    if fixture is None or not isinstance(receipt, dict) or set(receipt) != {*expected, "before_exec"}:
        fail("execution identity receipt has an undeclared shape or unit")
    if any(receipt.get(name) != value for name, value in expected.items()):
        fail("execution identity receipt differs from its source, parent, or command")
    try:
        identity_helper_module().validate_transition(receipt["before_drop"], receipt["before_exec"])
    except (KeyError, TypeError, ValueError) as error:
        raise EvidenceError(f"execution identity precondition failed: {error}") from error


def retain_identity_control(invoked: Path, work: Path, name: str) -> dict[str, Any]:
    """Retain control bytes so a host-only collector need not execute Python."""

    source = artifact(physical(invoked.resolve(strict=True), f"identity {name} source"), f"identity {name} source")
    retained = work / "execution-controls" / name
    if retained.exists():
        if digest(retained) != source["sha256"]:
            fail(f"retained identity control changed: {name}")
    else:
        copy_regular(Path(source["path"]), retained, f"retained identity {name}")
    return {"invoked_path": str(invoked), "source": source, "retained": artifact(retained, f"retained identity {name}")}


def execute_with_identity(
    *, root: Path, unit_id: str, output: Path, work: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use identical fixed identity controls for raw and candidate observations."""

    fixture = execution_identity_fixture_for_unit(unit_id)
    if fixture is None:
        fail("execution identity requested for an undeclared unit")
    timeout = find_control_tool("timeout")
    python = find_control_tool("python3")
    if timeout != Path("/usr/bin/timeout") or python != Path("/usr/bin/python3"):
        fail("identity control commands differ from the pinned invocation")
    helper = physical(EXECUTION_IDENTITY_HELPER, "fixed execution identity helper")
    controls = {
        "helper": retain_identity_control(helper, work, "owned_libc_test_identity.py"),
        "python": retain_identity_control(python, work, "python3"),
    }
    source_path = work / "source-prepared/src" / f"{unit_id}.c"
    source = artifact(source_path, "fixed execution identity source")
    receipt_path = output.with_suffix(".identity.json")
    parent_before = identity_helper_module().observe_process_identity()
    record = run_capture([
        str(timeout), "20", str(python), "-B", str(helper), "--root", str(root),
        "--receipt", str(receipt_path), "--unit", unit_id,
    ], cwd=output.parent, environment=clean_environment(), stdout=output, stderr=output.with_suffix(".stderr"))
    parent_after = identity_helper_module().observe_process_identity()
    if parent_before != parent_after:
        fail("execution identity control changed the producer parent credentials")
    for name, control in controls.items():
        control["after"] = artifact(Path(control["source"]["path"]), f"identity {name} after execution")
        if control["source"] != control["after"] or digest(Path(control["retained"]["path"])) != control["source"]["sha256"]:
            fail(f"identity control changed during execution: {name}")
    source_after = artifact(source_path, "fixed execution identity source after execution")
    if source != source_after:
        fail("fixed execution identity source changed during execution")
    receipt = read_json(receipt_path, "execution identity receipt")
    validate_execution_identity_receipt(receipt, root=root, unit_id=unit_id, source=source, parent_before=parent_before)
    return record, {
        "fixture": fixture, **controls, "source": source, "source_after": source_after,
        "receipt": artifact(receipt_path, "execution identity receipt"),
        "parent": {"before": parent_before, "after": parent_after, "unchanged": True},
    }


def fixture_relative_path(value: str, description: str) -> Path:
    """Validate one canonical absolute private-root fixture pathname."""

    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"{description} is not an absolute pathname")
    relative = Path(value[1:])
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        fail(f"{description} has a non-canonical pathname")
    canonical = "/" + relative.as_posix()
    if value != canonical:
        fail(f"{description} has a non-canonical pathname")
    return relative


def normalized_filesystem_fixture(entries: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Reject malformed or broad fixtures before a root is populated."""

    normalized: list[dict[str, str]] = []
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("filesystem fixture entry is not an object")
        path = entry.get("path")
        kind = entry.get("type")
        if not isinstance(path, str) or not isinstance(kind, str):
            fail("filesystem fixture entry has no path or type")
        fixture_relative_path(path, "filesystem fixture path")
        if path in paths:
            fail("filesystem fixture repeats a pathname")
        paths.add(path)
        if kind == "directory":
            if set(entry) != {"path", "type", "mode"}:
                fail("filesystem fixture directory fields drifted")
            mode = entry.get("mode")
            if not isinstance(mode, str) or re.fullmatch(r"0[0-7]{3,4}", mode) is None:
                fail("filesystem fixture directory mode is malformed")
            normalized.append({"path": path, "type": kind, "mode": mode})
        elif kind == "symlink":
            if set(entry) != {"path", "type", "target"}:
                fail("filesystem fixture symlink fields drifted")
            target = entry.get("target")
            if not isinstance(target, str):
                fail("filesystem fixture symlink target is malformed")
            fixture_relative_path(target, "filesystem fixture symlink target")
            normalized.append({"path": path, "type": kind, "target": target})
        else:
            fail("filesystem fixture type is unsupported")
    if normalized != sorted(normalized, key=lambda item: item["path"]):
        fail("filesystem fixture paths are not sorted")
    return normalized


def fixture_directory_children(entries: Sequence[dict[str, str]], directory: str) -> list[str]:
    """Return only declared immediate children of a fixture-owned directory."""

    return sorted(
        Path(entry["path"]).name for entry in entries
        if str(Path(entry["path"]).parent) == directory
    )


def materialize_filesystem_fixture(root: Path, entries: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Create one narrow source-selected fixture without replacing root inputs."""

    normalized = normalized_filesystem_fixture(entries)
    for entry in normalized:
        destination = root / fixture_relative_path(entry["path"], "filesystem fixture destination")
        if destination.exists() or destination.is_symlink():
            fail(f"filesystem fixture would replace an existing root path: {entry['path']}")
        physical(destination.parent, "filesystem fixture parent", directory=True)
        if entry["type"] == "directory":
            destination.mkdir(mode=int(entry["mode"], 8), exist_ok=False)
            os.chmod(destination, int(entry["mode"], 8))
        else:
            target = root / fixture_relative_path(entry["target"], "filesystem fixture symlink target")
            physical(target, "filesystem fixture symlink target", executable=True)
            os.symlink(entry["target"], destination)
    return verify_filesystem_fixture(root, normalized)


def verify_filesystem_fixture(root: Path, entries: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Bind type, mode, target, and exact fixture-owned children pre and post run."""

    normalized = normalized_filesystem_fixture(entries)
    for entry in normalized:
        destination = root / fixture_relative_path(entry["path"], "filesystem fixture destination")
        try:
            mode = destination.lstat().st_mode
        except OSError as error:
            raise EvidenceError(f"filesystem fixture path is absent: {entry['path']}") from error
        if entry["type"] == "directory":
            if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
                fail(f"filesystem fixture directory type drifted: {entry['path']}")
            observed_mode = f"0{stat.S_IMODE(mode):o}"
            if observed_mode != entry["mode"]:
                fail(f"filesystem fixture directory mode drifted: {entry['path']}")
            observed_children = sorted(child.name for child in destination.iterdir())
            expected_children = fixture_directory_children(normalized, entry["path"])
            if observed_children != expected_children:
                fail(f"filesystem fixture directory has undeclared child: {entry['path']}")
        else:
            if not stat.S_ISLNK(mode) or os.readlink(destination) != entry["target"]:
                fail(f"filesystem fixture symlink target drifted: {entry['path']}")
    return normalized


def unit_dso_roles(unit_id: str) -> dict[str, Any]:
    """Return the upstream source-specific DSO topology for one runtime unit."""

    if unit_id == "functional/dlopen":
        return {"runtime": [("functional/dlopen_dso", "/functional/dlopen_dso.so")], "initial": (), "runpath": "/usr/lib", "export_dynamic": True}
    if unit_id == "functional/tls_align":
        return {"runtime": (), "initial": ("functional/tls_align_dso",), "runpath": "/usr/lib", "export_dynamic": False}
    if unit_id == "functional/tls_align_dlopen":
        return {"runtime": [("functional/tls_align_dso", "/src/functional/tls_align_dso.so")], "initial": (), "runpath": "/usr/lib", "export_dynamic": False}
    if unit_id == "functional/tls_init_dlopen":
        return {"runtime": [("functional/tls_init_dso", "/src/functional/tls_init_dso.so")], "initial": (), "runpath": "/usr/lib", "export_dynamic": False}
    if unit_id == "regression/tls_get_new-dtv":
        return {"runtime": [("regression/tls_get_new-dtv_dso", "/regression/tls_get_new-dtv_dso.so")], "initial": (), "runpath": "$ORIGIN", "export_dynamic": False}
    return {"runtime": (), "initial": (), "runpath": "/usr/lib", "export_dynamic": False}


def find_control_tool(name: str) -> Path:
    path = shutil.which(name)
    if path is None:
        fail(f"host control-plane command is missing: {name}")
    # The evidence image deliberately exposes BusyBox-compatible tools through
    # conventional `/usr/bin` symlinks.  Resolve that host-only control-plane
    # selection before applying the physical-file rule; target inputs never
    # receive this exception.
    physical(Path(os.path.realpath(path)), f"host control-plane {name}", executable=True)
    # Keep the conventional applet pathname for execution.  BusyBox selects
    # `timeout` versus `chroot` from argv[0], so invoking its resolved
    # multicall inode would turn a validated control tool into a different
    # command.  This exception is limited to the host control-plane discovery
    # above; product and target inputs remain physical-only.
    return Path(path)


def source_runtest_arguments(target: str) -> list[str]:
    """Reproduce the Makefile's normal `RUN_TEST` invocation exactly.

    Upstream always passes `-w '$(RUN_WRAP)'`.  The normal installed execution
    graph has an empty `RUN_WRAP`, so retain the empty argument instead of
    omitting `-w`; the harness then applies its own five-second default.
    """

    return ["/runtest", "-w", SOURCE_RUNTEST_WRAP, target]


def execute_in_root(root: Path, target: str, output: Path) -> dict[str, Any]:
    timeout = find_control_tool("timeout")
    chroot = find_control_tool("chroot")
    return run_capture([str(timeout), "20", str(chroot), str(root), *source_runtest_arguments(target)], cwd=output.parent,
                       environment=clean_environment(), stdout=output, stderr=output.with_suffix(".stderr"))


def blocked(reason: str) -> dict[str, Any]:
    """Use an explicit blocked phase when an earlier observable phase failed.

    A libc-test source is never silently removed from this aggregate.  A
    blocked link or launch means its prerequisite had a retained failure; it
    is deliberately different from an upstream source graph that has no link
    or run edge at all.
    """

    return {"status": "blocked", "reason": reason}


def common_candidate_toolchain_failure(unit_id: str, result: dict[str, Any]) -> dict[str, Any] | None:
    """Recognize the one retained linker defect that blocks every next link.

    The campaign must retain the first real command failure, but re-running
    that same Rust-LLD limitation for each of hundreds of source objects adds
    no independent observation.  Do not classify ordinary unresolved symbols,
    receipt failures, or source-specific link errors as common: those remain
    individual target results.
    """

    if result.get("status") != "failed":
        return None
    record = result.get("record")
    if not isinstance(record, dict):
        return None
    stderr = record.get("stderr")
    if not isinstance(stderr, dict) or not isinstance(stderr.get("path"), str):
        return None
    try:
        path = physical(Path(stderr["path"]), "candidate link stderr")
        text = path.read_text(encoding="utf-8", errors="replace")
    except EvidenceError:
        return None
    if "is compressed with ELFCOMPRESS_ZLIB" not in text:
        return None
    return {
        "kind": "compressed-debug-information",
        "detail": "the installed linker cannot read the candidate object's compressed DWARF",
        "first_unit": unit_id,
        "stderr": artifact(path, "common candidate linker failure"),
    }


def blocked_by_common_candidate_toolchain(blocker: dict[str, Any]) -> dict[str, Any]:
    """Record an unattempted dependent candidate link without inventing a run."""

    return {
        "status": "blocked",
        "reason": "unattempted: retained common candidate toolchain failure",
        "common_toolchain_failure": blocker,
    }


def source_graph_absent(reason: str) -> dict[str, Any]:
    """Describe a phase absent from upstream's finite target graph."""

    return {"status": "not-applicable", "reason": reason}


def output_path(root: Path, unit_id: str, suffix: str) -> Path:
    """Map a fixed upstream identity to a contained evidence output path."""

    relative = Path(unit_id)
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"unsafe upstream unit identity: {unit_id}")
    return root / relative.with_suffix(suffix)


def phase_object(record: dict[str, Any]) -> Path | None:
    candidate = record.get("candidate_translation")
    if not isinstance(candidate, dict) or candidate.get("status") != "passed":
        return None
    artifact_record = candidate.get("object")
    if not isinstance(artifact_record, dict) or not isinstance(artifact_record.get("path"), str):
        return None
    candidate_path = Path(artifact_record["path"])
    try:
        return physical(candidate_path, "candidate object")
    except EvidenceError:
        return None


def candidate_link(
    *, product: Path, environment: dict[str, str], output: Path, evidence: Path,
    objects: Sequence[Path], application_dsos: Sequence[Path] = (), runpath: str = "/usr/lib",
    shared_object: bool = False, export_dynamic: bool = False,
) -> dict[str, Any]:
    """Run and audit one installed-driver dynamic link without ambient inputs."""

    output.parent.mkdir(parents=True, exist_ok=True)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    command = candidate_link_command(
        product, objects, output, shared_object=shared_object,
        application_dsos=application_dsos, runpath=runpath, export_dynamic=export_dynamic,
    )
    executed = run_capture(
        command, cwd=evidence.parent, environment=environment,
        stdout=evidence.with_suffix(".candidate-link.stdout"), stderr=evidence.with_suffix(".candidate-link.stderr"),
    )
    if executed["exit_status"] != 0 or not output.is_file() or output.is_symlink():
        return {"status": "failed", "record": executed, "output": None}
    receipt_path = Path(str(output) + ".crabc-link.json")
    try:
        receipt = verify_candidate_receipt(
            product=product, output=output, receipt_path=receipt_path, objects=objects,
            application_dsos=application_dsos, shared_object=shared_object,
            runpath=runpath, export_dynamic=export_dynamic,
        )
        observations = elf_record(output, evidence.with_suffix(".candidate-elf"), "candidate")
        elf_ok, elf_detail = expected_candidate_elf(
            output, observations, shared_object=shared_object, application_dsos=application_dsos,
        )
    except EvidenceError as error:
        return {
            "status": "failed", "record": executed, "output": artifact(output, "candidate link output"),
            "audit_error": str(error),
        }
    return {
        "status": "passed" if elf_ok else "failed", "record": executed,
        "output": artifact(output, "candidate link output"), "receipt": receipt,
        "elf": {"status": "passed" if elf_ok else "failed", "detail": elf_detail, "observations": observations},
    }


def oracle_link(
    *, output: Path, evidence: Path, environment: dict[str, str], objects: Sequence[Path],
    application_dsos: Sequence[Path] = (), runpath: str = "/usr/lib", shared_object: bool = False,
    export_dynamic: bool = False,
) -> dict[str, Any]:
    """Link the exact installed-driver objects against pinned musl only."""

    output.parent.mkdir(parents=True, exist_ok=True)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    command = oracle_link_command(
        objects, output, shared_object=shared_object, application_dsos=application_dsos,
        runpath=runpath, export_dynamic=export_dynamic,
    )
    executed = run_capture(
        command, cwd=evidence.parent, environment=environment,
        stdout=evidence.with_suffix(".oracle-link.stdout"), stderr=evidence.with_suffix(".oracle-link.stderr"),
    )
    if executed["exit_status"] != 0 or not output.is_file() or output.is_symlink():
        return {"status": "failed", "record": executed, "output": None}
    try:
        observations = elf_record(output, evidence.with_suffix(".oracle-elf"), "oracle")
        elf_ok, elf_detail = expected_oracle_elf(observations, shared_object=shared_object)
    except EvidenceError as error:
        return {
            "status": "failed", "record": executed, "output": artifact(output, "pinned-musl link output"),
            "audit_error": str(error),
        }
    return {
        "status": "passed" if elf_ok else "failed", "record": executed,
        "output": artifact(output, "pinned-musl link output"),
        "elf": {"status": "passed" if elf_ok else "failed", "detail": elf_detail, "observations": observations},
    }


def copied_payload_at_root(root: Path, source: Path, destination: Path, description: str) -> dict[str, Any]:
    """Copy an execution input while retaining its durable source identity.

    Execution roots are deliberately reclaimed after each observation rather
    than retaining hundreds of full product copies.  The executable/DSO source
    file and the immutable product manifest remain in the evidence leaf, so a
    record never points at a discarded copied inode.
    """

    if destination.exists() or destination.is_symlink():
        fail(f"execution fixture would replace an existing root payload: {destination}")
    source_record = artifact(source, description)
    copied = copy_regular(source, destination, description)
    if copied["sha256"] != source_record["sha256"]:
        fail(f"private-root copied payload differs from its source: {description}")
    return {
        "source": source_record,
        "destination": "/" + destination.relative_to(root).as_posix(),
        "copied_sha256": copied["sha256"],
    }


def copy_control_fixture_record(
    root: Path, fixture: dict[str, Any], side: str, *, fixture_name: str, launcher_destination: str,
) -> list[dict[str, Any]]:
    """Install one declared BusyBox closure without changing product aliases."""

    if fixture.get("status") != "passed":
        fail(f"{fixture_name}-dependent source has no complete declared control fixture")
    control = fixture.get("control")
    launcher = fixture.get(f"{side}_launcher")
    if not isinstance(control, dict) or not isinstance(launcher, dict):
        fail(f"{fixture_name} control fixture record is malformed")
    busybox = control.get("busybox")
    loader = control.get("loader")
    if not isinstance(busybox, dict) or not isinstance(loader, dict):
        fail(f"{fixture_name} control fixture lacks BusyBox or loader identity")
    expected_layout = {
        "busybox": CONTROL_BUSYBOX,
        "loader": CONTROL_LOADER,
        "launcher": launcher_destination,
    }
    if control.get("layout") != expected_layout:
        fail(f"{fixture_name} control fixture layout drifted")
    destination = root / launcher_destination.lstrip("/")
    destinations = (root / "control", destination)
    if any(path.exists() or path.is_symlink() for path in destinations):
        fail(f"{fixture_name} control fixture would replace a product payload path")
    return [
        copied_payload_at_root(root, Path(busybox["path"]), root / CONTROL_BUSYBOX.lstrip("/"), "controlled BusyBox"),
        copied_payload_at_root(root, Path(loader["path"]), root / CONTROL_LOADER.lstrip("/"), "controlled musl loader"),
        copied_payload_at_root(root, Path(launcher["path"]), destination, f"{side} control {fixture_name} launcher"),
    ]


def copy_shell_fixture_record(root: Path, fixture: dict[str, Any], side: str) -> list[dict[str, Any]]:
    """Install the source-selected shell control closure."""

    return copy_control_fixture_record(
        root, fixture, side, fixture_name="shell", launcher_destination="/bin/sh",
    )


def copy_echo_fixture_record(root: Path, fixture: dict[str, Any], side: str) -> list[dict[str, Any]]:
    """Install the source-selected `posix_spawnp("echo")` control closure."""

    return copy_control_fixture_record(
        root, fixture, side, fixture_name="echo", launcher_destination="/bin/echo",
    )


def runtime_root_payload_record(
    *, root: Path, runner: Path, executable: Path, unit_id: str, support: dict[str, Path],
    external_shell: dict[str, Any] | None, external_echo: dict[str, Any] | None, side: str,
) -> dict[str, Any]:
    """Populate one private root according to the upstream unit topology."""

    copied = [
        copied_payload_at_root(root, runner, root / "runtest", "runtest executable"),
        copied_payload_at_root(root, executable, root / unit_id, "runtime test executable"),
    ]
    roles = unit_dso_roles(unit_id)
    for dso_id, destination in roles["runtime"]:
        copied.append(copied_payload_at_root(
            root, support[dso_id], root / destination.lstrip("/"), f"runtime-loaded {dso_id} DSO",
        ))
    for dso_id in roles["initial"]:
        copied.append(copied_payload_at_root(
            root, support[dso_id], root / "usr/lib" / f"{Path(dso_id).name}.so",
            f"initial {dso_id} DSO",
        ))
    shell = copy_shell_fixture_record(root, external_shell, side) if external_shell is not None else []
    echo = copy_echo_fixture_record(root, external_echo, side) if external_echo is not None else []
    if shell and echo:
        fail("one runtime unit cannot install two conflicting control closures")
    filesystem_fixture = materialize_filesystem_fixture(root, filesystem_fixture_for_unit(unit_id))
    return {
        "program": copied,
        "control_fixture": [*shell, *echo],
        "filesystem_fixture": filesystem_fixture,
        "execution_identity_fixture": execution_identity_fixture_for_unit(unit_id),
        "topology": roles,
    }


def copied_product_payload_at_root(root: Path, expected: dict[str, Any]) -> dict[str, Any]:
    """Re-hash the product part of an execution root without admitting controls.

    Runtime roots add `/dev`, `/tmp`, programs, and optionally `/control`; those
    declared additions must not make a copied candidate product appear to have
    changed.  This checks every manifest payload byte and every alias directly.
    """

    identity = product_payload_identity(expected)
    manifest = root / "share/crabc/manifest.json"
    if digest(manifest) != identity["manifest_sha256"]:
        fail("candidate execution root manifest differs from its sealed product")
    for relative, expected_hash in identity["files"].items():
        path = root / relative
        if digest(path) != expected_hash:
            fail(f"candidate execution root payload differs: {relative}")
    for relative, expected_target in identity["aliases"].items():
        path = root / relative
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise EvidenceError(f"candidate execution root alias is absent: {relative}") from error
        if not stat.S_ISLNK(mode) or os.readlink(path) != expected_target:
            fail(f"candidate execution root alias differs: {relative}")
    return identity


def copied_root_files(root: Path, entries: Sequence[dict[str, Any]]) -> list[dict[str, str]]:
    """Capture the bytes currently present at declared disposable-root paths."""

    result: list[dict[str, str]] = []
    for entry in entries:
        destination = entry.get("destination")
        expected = entry.get("copied_sha256")
        if not isinstance(destination, str) or not destination.startswith("/") or not isinstance(expected, str):
            fail("execution-root copied-file record is malformed")
        path = root / destination.lstrip("/")
        observed = digest(path)
        if observed != expected:
            fail(f"execution-root copied file changed: {destination}")
        result.append({"destination": destination, "sha256": observed})
    return result


def copied_oracle_runtime_at_root(root: Path, runtime: dict[str, Any]) -> dict[str, Any]:
    """Check the actual raw loader/libc copies before the root is reclaimed."""

    result: dict[str, Any] = {}
    for name in ("loader", "libc"):
        entry = runtime.get(name)
        if not isinstance(entry, dict):
            fail("raw execution root lacks copied runtime identity")
        destination = entry.get("destination")
        expected = entry.get("copied_sha256")
        if not isinstance(destination, str) or not destination.startswith("/") or not isinstance(expected, str):
            fail("raw execution root copied runtime identity is malformed")
        observed = digest(root / destination.lstrip("/"))
        if observed != expected:
            fail(f"raw execution root copied runtime changed: {name}")
        result[name] = {**entry, "observed_sha256": observed}
    return result


def write_root_payload_phase(
    *, roots: Path, root: Path, side: str, phase: str, runtime_base: dict[str, Any],
    payload: dict[str, Any], candidate_product: dict[str, Any], oracle: dict[str, Any],
) -> dict[str, str]:
    """Persist a root phase before its disposable filesystem is removed."""

    entries = [*payload["program"], *payload["control_fixture"]]
    copied = copied_root_files(root, entries)
    filesystem_fixture = verify_filesystem_fixture(root, payload["filesystem_fixture"])
    if side == "candidate":
        runtime = {"candidate_product": copied_product_payload_at_root(root, candidate_product)}
        source_bindings = {
            "candidate_product_manifest": candidate_product["manifest"],
            "candidate_product_payload": product_payload_identity(candidate_product),
        }
    elif side == "oracle":
        base = runtime_base.get("oracle")
        if not isinstance(base, dict):
            fail("raw execution root has no runtime base record")
        runtime = {"oracle_runtime": copied_oracle_runtime_at_root(root, base)}
        source_bindings = {"oracle": oracle}
    else:
        fail(f"unknown execution-root side: {side}")
    record = {
        "schema": "crabc.x86_64-owned-libc-test-root-payload/v1",
        "side": side,
        "phase": phase,
        "runtime": runtime,
        "copied_files": copied,
        "control_fixture": payload["control_fixture"],
        "filesystem_fixture": filesystem_fixture,
        "execution_identity_fixture": payload["execution_identity_fixture"],
        "topology": payload["topology"],
        "canonical_source_bindings": source_bindings,
    }
    path = roots / f"{side}.root-payload-{phase}.json"
    write_json(path, record)
    return artifact(path, f"{side} execution-root {phase} payload")


def remove_execution_root(root: Path, work: Path) -> None:
    """Remove only a per-observation root after all durable bytes were retained."""

    try:
        root.relative_to(work / "execution")
    except ValueError as error:
        raise EvidenceError("execution-root cleanup escaped its evidence owner") from error
    if root.exists() or root.is_symlink():
        shutil.rmtree(root)


def execute_runtime_side(
    *, side: str, work: Path, product: Path, unit_id: str, runner: Path, executable: Path,
    support: dict[str, Path], external_shell: dict[str, Any] | None, external_echo: dict[str, Any] | None,
    oracle: dict[str, Any],
    candidate_product: dict[str, Any],
) -> dict[str, Any]:
    """Observe one candidate or raw runtime independently in a fresh root."""

    roots = work / "execution" / unit_id
    root = roots / side
    roots.mkdir(parents=True, exist_ok=True)
    output = roots / f"{side}.stdout"
    setup_error = roots / f"{side}.setup-error.txt"
    try:
        if side == "candidate":
            make_candidate_root(product, root)
            runtime_base: dict[str, Any] = {"product": product_payload_identity(candidate_product)}
        elif side == "oracle":
            runtime_base = {"oracle": make_oracle_root(root, oracle)}
        else:
            fail(f"unknown runtime side: {side}")
        prepare_execution_root(root)
        payload = runtime_root_payload_record(
            root=root, runner=runner, executable=executable, unit_id=unit_id,
            support=support, external_shell=external_shell, external_echo=external_echo, side=side,
        )
        root_before = write_root_payload_phase(
            roots=roots, root=root, side=side, phase="before", runtime_base=runtime_base,
            payload=payload, candidate_product=candidate_product, oracle=oracle,
        )
        execution_identity = None
        if execution_identity_fixture_for_unit(unit_id) is None:
            record = execute_in_root(root, f"/{unit_id}", output)
        else:
            record, execution_identity = execute_with_identity(root=root, unit_id=unit_id, output=output, work=work)
        root_after = write_root_payload_phase(
            roots=roots, root=root, side=side, phase="after", runtime_base=runtime_base,
            payload=payload, candidate_product=candidate_product, oracle=oracle,
        )
        status_path = roots / f"{side}.status.json"
        write_json(status_path, record)
        result = {
            "status": "passed" if record["exit_status"] == 0 else "failed", "record": record,
            "status_record": artifact(status_path, f"{side} runtime status"),
            "execution_identity": execution_identity,
            "root_payload": {
                "before": root_before,
                "after": root_after,
                "unchanged": True,
            },
            "root_reclaimed": True,
        }
    except (EvidenceError, OSError) as error:
        setup_error.write_text(str(error) + "\n", encoding="utf-8", newline="\n")
        result = {
            "status": "setup-failed", "detail": str(error),
            "setup_error": artifact(setup_error, f"{side} runtime setup error"), "root_reclaimed": True,
            "execution_identity": None,
        }
    finally:
        remove_execution_root(root, work)
    return result


def runtime_observation(
    *, work: Path, product: Path, unit_id: str, candidate_runner: Path | None, oracle_runner: Path | None,
    candidate_executable: Path | None, oracle_executable: Path | None,
    candidate_support: dict[str, Path], oracle_support: dict[str, Path], external_shell: dict[str, Any] | None,
    external_echo: dict[str, Any] | None,
    oracle_identity: dict[str, Any], candidate_product: dict[str, Any],
) -> dict[str, Any]:
    """Run raw and candidate sides independently, then compare exact outputs."""

    if external_shell is not None and external_shell.get("status") != "passed":
        reason = "the declared control shell fixture is incomplete"
        return {
            "oracle": blocked(reason),
            "candidate": blocked(reason),
            "comparison": blocked(reason),
        }
    if external_echo is not None and external_echo.get("status") != "passed":
        reason = "the declared control echo fixture is incomplete"
        return {
            "oracle": blocked(reason),
            "candidate": blocked(reason),
            "comparison": blocked(reason),
        }
    roles = unit_dso_roles(unit_id)
    runtime_names = [name for name, _ in roles["runtime"]]
    initial_names = list(roles["initial"])
    candidate_missing = [name for name in [*runtime_names, *initial_names] if name not in candidate_support]
    oracle_missing = [name for name in [*runtime_names, *initial_names] if name not in oracle_support]
    oracle_run = blocked("pinned-musl runtest link did not produce an executable") if oracle_runner is None else (
        blocked("pinned-musl test link did not produce an executable") if oracle_executable is None else (
            blocked(f"pinned-musl DSO support is unavailable: {', '.join(oracle_missing)}") if oracle_missing else
            execute_runtime_side(
                side="oracle", work=work, product=product, unit_id=unit_id,
                runner=oracle_runner, executable=oracle_executable, support=oracle_support,
                external_shell=external_shell, external_echo=external_echo,
                oracle=oracle_identity, candidate_product=candidate_product,
            )
        )
    )
    candidate = blocked("candidate runtest link did not produce an executable") if candidate_runner is None else (
        blocked("candidate test link did not produce an executable") if candidate_executable is None else (
            blocked(f"candidate DSO support is unavailable: {', '.join(candidate_missing)}") if candidate_missing else
            execute_runtime_side(
                side="candidate", work=work, product=product, unit_id=unit_id,
                runner=candidate_runner, executable=candidate_executable, support=candidate_support,
                external_shell=external_shell, external_echo=external_echo,
                oracle=oracle_identity, candidate_product=candidate_product,
            )
        )
    )
    if oracle_run.get("status") != "passed":
        comparison = blocked("pinned-musl runtime did not pass this prepared root")
    elif candidate.get("status") != "passed":
        comparison = blocked("candidate runtime did not pass this prepared root")
    else:
        oracle_record = oracle_run["record"]
        candidate_record = candidate["record"]
        paths = (
            Path(oracle_record["stdout"]["path"]), Path(candidate_record["stdout"]["path"]),
            Path(oracle_record["stderr"]["path"]), Path(candidate_record["stderr"]["path"]),
        )
        same = (oracle_record["exit_status"] == candidate_record["exit_status"] and
                paths[0].read_bytes() == paths[1].read_bytes() and paths[2].read_bytes() == paths[3].read_bytes())
        comparison = {"status": "passed" if same else "failed",
                      "detail": "passed" if same else "candidate raw status/stdout/stderr differs from pinned musl"}
    return {"oracle": oracle_run, "candidate": candidate, "comparison": comparison}


def compile_all_units(
    *, units: Sequence[dict[str, Any]], product: Path, compiler: Path, environment: dict[str, str],
    prepared: Path, generated: Path, work: Path, driver_ready: bool,
) -> dict[str, dict[str, Any]]:
    """Translate every upstream source, retaining a record even after failures."""

    results: dict[str, dict[str, Any]] = {}
    for unit in units:
        unit_id = unit["id"]
        output = output_path(work / "objects/candidate", unit_id, ".o")
        evidence = output_path(work / "units", unit_id, ".translation")
        try:
            result = compile_candidate(
                product=product, compiler=compiler, environment=environment, prepared=prepared,
                generated=generated, unit=unit, output=output, evidence=evidence,
                driver_ready=driver_ready,
            )
            results[unit_id] = {**unit, **result}
        except (EvidenceError, OSError) as error:
            results[unit_id] = {
                **unit, "source": {"path": str(prepared / unit["source"])},
                "candidate_translation": {"status": "failed", "detail": str(error), "object": None},
                "harness_error": str(error),
            }
    return results


def update_support_links(
    *, records: dict[str, dict[str, Any]], product: Path, environment: dict[str, str], work: Path,
    candidate_blocker: dict[str, Any] | None = None,
) -> tuple[dict[str, Path], dict[str, Path], dict[str, Any] | None]:
    """Link the four source-defined DSOs on both target-runtime sides."""

    candidate_support: dict[str, Path] = {}
    oracle_support: dict[str, Path] = {}
    for unit_id in DSO_UNITS:
        record = records[unit_id]
        object_path = phase_object(record)
        if object_path is None:
            record["candidate_link"] = blocked("candidate DSO translation did not produce an object")
            record["oracle_link"] = blocked("installed-driver DSO translation did not produce an object")
            record["runtime"] = source_graph_absent("upstream helper DSO has no direct runtest edge")
            continue
        candidate_output = output_path(work / "links/candidate", unit_id, ".so")
        oracle_output = output_path(work / "links/oracle", unit_id, ".so")
        if candidate_blocker is None:
            candidate = candidate_link(
                product=product, environment=environment, output=candidate_output,
                evidence=output_path(work / "units", unit_id, ".dso"), objects=[object_path], shared_object=True,
            )
            candidate_blocker = common_candidate_toolchain_failure(unit_id, candidate) or candidate_blocker
        else:
            candidate = blocked_by_common_candidate_toolchain(candidate_blocker)
        oracle = oracle_link(
            output=oracle_output, evidence=output_path(work / "units", unit_id, ".dso"),
            environment=environment, objects=[object_path], shared_object=True,
        )
        record["candidate_link"] = candidate
        record["oracle_link"] = oracle
        record["runtime"] = source_graph_absent("upstream helper DSO has no direct runtest edge")
        if candidate.get("status") == "passed":
            candidate_support[unit_id] = candidate_output
        if oracle.get("status") == "passed":
            oracle_support[unit_id] = oracle_output
    return candidate_support, oracle_support, candidate_blocker


def update_runtest_links(
    *, records: dict[str, dict[str, Any]], product: Path, environment: dict[str, str], work: Path,
    candidate_blocker: dict[str, Any] | None = None,
) -> tuple[Path | None, Path | None, list[Path], dict[str, Any] | None]:
    """Replace the upstream libtest.a link input with its fixed member roster."""

    record = records[RUNTIME_HELPER]
    members = [phase_object(records[name]) for name in COMMON_MEMBERS]
    runner_object = phase_object(record)
    if runner_object is None or any(member is None for member in members):
        record["candidate_link"] = blocked("runtest or a declared libtest.a member did not translate")
        record["oracle_link"] = blocked("runtest or a declared libtest.a member did not translate")
        record["runtime"] = source_graph_absent("upstream runtest is the target-side harness executable")
        return None, None, [], candidate_blocker
    common_objects = [member for member in members if member is not None]
    objects = [runner_object, *common_objects]
    candidate_output = output_path(work / "links/candidate", RUNTIME_HELPER, ".exe")
    oracle_output = output_path(work / "links/oracle", RUNTIME_HELPER, ".exe")
    if candidate_blocker is None:
        record["candidate_link"] = candidate_link(
            product=product, environment=environment, output=candidate_output,
            evidence=output_path(work / "units", RUNTIME_HELPER, ".link"), objects=objects,
        )
        candidate_blocker = common_candidate_toolchain_failure(RUNTIME_HELPER, record["candidate_link"]) or candidate_blocker
    else:
        record["candidate_link"] = blocked_by_common_candidate_toolchain(candidate_blocker)
    record["oracle_link"] = oracle_link(
        output=oracle_output, evidence=output_path(work / "units", RUNTIME_HELPER, ".link"),
        environment=environment, objects=objects,
    )
    record["runtime"] = source_graph_absent("upstream runtest is the target-side harness executable")
    candidate_runner = candidate_output if record["candidate_link"].get("status") == "passed" else None
    oracle_runner = oracle_output if record["oracle_link"].get("status") == "passed" else None
    # `runtest` is the harness executable, never a member of upstream's
    # libtest.a.  Runtime targets link only the nine archive members; adding
    # the harness object would introduce its own `main` beside every test.
    return candidate_runner, oracle_runner, common_objects, candidate_blocker


def update_runtime_links(
    *, records: dict[str, dict[str, Any]], product: Path, environment: dict[str, str], work: Path,
    common_objects: Sequence[Path], candidate_runner: Path | None, oracle_runner: Path | None,
    candidate_support: dict[str, Path], oracle_support: dict[str, Path], shell: dict[str, Any] | None,
    echo: dict[str, Any] | None,
    oracle_identity: dict[str, Any], candidate_product: dict[str, Any],
    candidate_blocker: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Link and run every upstream runtime target after support edges are known."""

    for unit_id, record in records.items():
        if record["kind"] == "api":
            record["candidate_link"] = source_graph_absent("upstream api targets are compilation-only")
            record["oracle_link"] = source_graph_absent("upstream api targets are compilation-only")
            record["runtime"] = source_graph_absent("upstream api targets are compilation-only")
            continue
        if record["kind"] in {"dso", "common"}:
            if unit_id != RUNTIME_HELPER and "candidate_link" not in record:
                record["candidate_link"] = source_graph_absent("upstream support object has no standalone link edge")
                record["oracle_link"] = source_graph_absent("upstream support object has no standalone link edge")
                record["runtime"] = source_graph_absent("upstream support object has no direct runtest edge")
            continue
        object_path = phase_object(record)
        if object_path is None:
            record["candidate_link"] = blocked("candidate runtime translation did not produce an object")
            record["oracle_link"] = blocked("installed-driver runtime translation did not produce an object")
            record["runtime"] = blocked("runtime target has no translated object")
            continue
        roles = unit_dso_roles(unit_id)
        candidate_initial = [candidate_support[name] for name in roles["initial"] if name in candidate_support]
        oracle_initial = [oracle_support[name] for name in roles["initial"] if name in oracle_support]
        candidate_missing = [name for name in roles["initial"] if name not in candidate_support]
        oracle_missing = [name for name in roles["initial"] if name not in oracle_support]
        candidate_output = output_path(work / "links/candidate", unit_id, ".exe")
        oracle_output = output_path(work / "links/oracle", unit_id, ".exe")
        if candidate_blocker is not None:
            candidate = blocked_by_common_candidate_toolchain(candidate_blocker)
        elif candidate_missing:
            candidate = blocked(f"candidate initial DSO support is unavailable: {', '.join(candidate_missing)}")
        else:
            candidate = candidate_link(
                product=product, environment=environment, output=candidate_output,
                evidence=output_path(work / "units", unit_id, ".link"), objects=[object_path, *common_objects],
                application_dsos=candidate_initial, runpath=roles["runpath"], export_dynamic=roles["export_dynamic"],
            )
            candidate_blocker = common_candidate_toolchain_failure(unit_id, candidate) or candidate_blocker
        if oracle_missing:
            oracle_link_result = blocked(f"pinned-musl initial DSO support is unavailable: {', '.join(oracle_missing)}")
        else:
            oracle_link_result = oracle_link(
                output=oracle_output, evidence=output_path(work / "units", unit_id, ".link"),
                environment=environment, objects=[object_path, *common_objects], application_dsos=oracle_initial,
                runpath=roles["runpath"], export_dynamic=roles["export_dynamic"],
            )
        record["candidate_link"] = candidate
        record["oracle_link"] = oracle_link_result
        record["runtime"] = runtime_observation(
            work=work, product=product, unit_id=unit_id, candidate_runner=candidate_runner,
            oracle_runner=oracle_runner,
            candidate_executable=candidate_output if candidate.get("status") == "passed" else None,
            oracle_executable=oracle_output if oracle_link_result.get("status") == "passed" else None,
            candidate_support=candidate_support, oracle_support=oracle_support,
            external_shell=shell if unit_id in SHELL_RUNTIME_UNITS else None,
            external_echo=echo if unit_id in ECHO_RUNTIME_UNITS else None,
            oracle_identity=oracle_identity, candidate_product=candidate_product,
        )
    return candidate_blocker


def classify_unit(record: dict[str, Any]) -> str:
    """Summarize the required source-graph edges without converting failures to skips."""

    header = record.get("header_translation", {})
    translation = record.get("candidate_translation", {})
    if not isinstance(header, dict) or header.get("status") != "passed":
        return "header-failed"
    if not isinstance(translation, dict) or translation.get("status") != "passed":
        return "translation-failed"
    kind = record["kind"]
    if kind == "api":
        return "passed"
    if kind == "common" and record["id"] != RUNTIME_HELPER:
        phases = (record.get("candidate_link"), record.get("oracle_link"), record.get("runtime"))
        if all(isinstance(phase, dict) and phase.get("status") == "not-applicable" for phase in phases):
            return "passed"
        return "source-graph-failed"
    candidate = record.get("candidate_link", {})
    oracle = record.get("oracle_link", {})
    if not isinstance(candidate, dict) or candidate.get("status") != "passed":
        return "candidate-link-failed"
    if not isinstance(oracle, dict) or oracle.get("status") != "passed":
        return "oracle-link-failed"
    runtime = record.get("runtime", {})
    if kind in {"dso", "common"}:
        if isinstance(runtime, dict) and runtime.get("status") == "not-applicable":
            return "passed"
        return "source-graph-failed"
    if not isinstance(runtime, dict):
        return "runtime-failed"
    comparison = runtime.get("comparison", {})
    if not isinstance(comparison, dict) or comparison.get("status") != "passed":
        return "runtime-failed"
    return "passed"


def campaign_counts(records: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records.values():
        status = record["status"]
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def run_campaign(product_input: Path, evidence: Path) -> dict[str, Any]:
    """Run the finite upstream graph and return a non-promoting result object."""

    evidence = physical(evidence, "owned libc-test evidence leaf", directory=True)
    temporary = evidence / "tmp"
    temporary.mkdir(mode=0o700)
    environment = clean_environment()
    environment["TMPDIR"] = str(temporary)
    oracle_before: dict[str, Any] | None = None
    source_product: Path | None = None
    source_product_before: dict[str, Any] | None = None
    sealed_product: Path | None = None
    sealed_product_before: dict[str, Any] | None = None
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "incomplete",
        "campaign_complete": False,
        "public_support": False,
        "target": TARGET,
        "upstream": {},
        "oracle": {},
        "product": {},
        "source_preparation": {},
        "source_graph": {
            "dynamic_runtime_modes": ["dynamic-pie"],
            "dynamic_runtime_entry": "normal installed dynamic PIE through its kernel PT_INTERP entry",
            "dynamic_runtime_mode_scope": (
                "this source-selected libc-test graph does not select non-PIE or direct-loader entries; "
                "the separate 50-case owned dynamic-product qualification owns all-entry product coverage"
            ),
            "archive_translation": "the upstream libtest.a membership is linked as its nine explicit installed-driver objects",
            "runtest": {
                "source": "src/common/runtest.c",
                "child_stack_limit_bytes": 102400,
                "default_timeout_seconds": SOURCE_RUNTEST_TIMEOUT_SECONDS,
                "makefile_invocation": ["runtest.exe", "-w", SOURCE_RUNTEST_WRAP, "TARGET"],
                "execution": (
                    "the upstream harness receives Makefile's explicit empty -w argument, forks, applies its "
                    "fixed child stack limit, then execs each runtime target with its source default timeout"
                ),
            },
            "api": "the upstream API graph is compilation-only; not-applicable link/runtime fields are source-graph facts",
        },
        "units": [],
        "counts": {},
    }
    try:
        source, source_record = ensure_source()
        stage = evidence / "source-stage"
        source_hashes = copy_pinned_source(source, stage)
        prepared = evidence / "source-prepared"
        preparation = prepare_source(stage, prepared)
        preparation["staged_tracked_files"] = source_hashes
        units, inventory = collect_inventory(prepared)
        oracle_before = pinned_musl_identity()
        report["oracle"] = {"before": oracle_before}
        source_product = physical(product_input, "supplied dynamic product", directory=True)
        source_product_before = validate_product(source_product)
        report["product"] = {"source": {"before": source_product_before}}
        sealed_product = evidence / "candidate-product"
        sealed_product_before = seal_candidate_product(source_product, sealed_product, source_product_before)
        source_after_copy = validate_product(source_product)
        require_same_product_payload(source_product_before, source_after_copy, "supplied dynamic product during copy")
        report["product"] = {
            "source": {"before": source_product_before, "after_copy": source_after_copy},
            "copied": {"before": sealed_product_before},
        }
        product = sealed_product
        compiler, compiler_environment, compiler_record = installed_compiler_contract(product)
        compiler_environment["TMPDIR"] = str(temporary)
        support = driver_support(product)
        options = generate_options_header(
            compiler=compiler, environment=compiler_environment, include=product / "usr/include",
            source=prepared / "src/common/options.h.in", output=evidence / "generated/candidate/options.h",
            trace=evidence / "generated/candidate/options.headers.stderr",
        )
        records = compile_all_units(
            units=units, product=product, compiler=compiler, environment=compiler_environment,
            prepared=prepared, generated=evidence / "generated", work=evidence,
            driver_ready=support["complete"],
        )
        candidate_support, oracle_support, candidate_blocker = update_support_links(
            records=records, product=product, environment=environment, work=evidence,
        )
        candidate_runner, oracle_runner, common_objects, candidate_blocker = update_runtest_links(
            records=records, product=product, environment=environment, work=evidence,
            candidate_blocker=candidate_blocker,
        )
        shell = shell_fixture(
            evidence / "external-shell", product, compiler, compiler_environment, environment,
            support["complete"], oracle_before,
        )
        echo = echo_fixture(
            evidence / "external-echo", product, compiler, compiler_environment, environment,
            support["complete"], oracle_before,
        )
        candidate_blocker = update_runtime_links(
            records=records, product=product, environment=environment, work=evidence,
            common_objects=common_objects, candidate_runner=candidate_runner, oracle_runner=oracle_runner,
            candidate_support=candidate_support, oracle_support=oracle_support, shell=shell, echo=echo,
            oracle_identity=oracle_before, candidate_product=sealed_product_before,
            candidate_blocker=candidate_blocker,
        )
        for record in records.values():
            record["status"] = classify_unit(record)
        report.update({
            "upstream": source_record,
            "product": {
                **report["product"],
                "driver": sealed_product_before["driver"],
                "compiler": compiler_record,
                "compiler_helper": sealed_product_before["compiler_helper"],
                "compiler_environment": dict(sorted(compiler_environment.items())),
                "driver_support": support,
            },
            "source_preparation": {"options": options, "api_unistd": preparation},
            "inventory": inventory,
            "candidate_link_blocker": candidate_blocker,
            "external_shell_fixture": shell,
            "external_echo_fixture": echo,
            "units": [records[name] for name in sorted(records)],
            "counts": campaign_counts(records),
        })
        if report["counts"] == {"passed": EXPECTED_COUNTS["declared_total"]}:
            report["status"] = "passed"
    except (EvidenceError, OSError, subprocess.SubprocessError, tomllib.TOMLDecodeError) as error:
        report["fatal_error"] = str(error)
    finally:
        def record_postcondition_error(message: str) -> None:
            if "fatal_error" not in report:
                report["fatal_error"] = message
            else:
                report["postcondition_error"] = message
            report["status"] = "incomplete"

        if oracle_before is not None:
            try:
                oracle_after = pinned_musl_identity()
                report.setdefault("oracle", {})["after"] = oracle_after
                if oracle_after != oracle_before:
                    record_postcondition_error("pinned musl oracle identity changed during aggregate")
            except (EvidenceError, OSError, tomllib.TOMLDecodeError) as error:
                record_postcondition_error(f"cannot bind pinned musl oracle after aggregate: {error}")
        if source_product is not None and source_product_before is not None:
            try:
                source_after_use = validate_product(source_product)
                report.setdefault("product", {}).setdefault("source", {})["after_use"] = source_after_use
                require_same_product_payload(
                    source_product_before, source_after_use, "supplied dynamic product during compiler/link use",
                )
            except (EvidenceError, OSError) as error:
                record_postcondition_error(f"cannot bind supplied dynamic product after aggregate: {error}")
        if sealed_product is not None and sealed_product_before is not None:
            try:
                sealed_after_use = validate_product(sealed_product)
                report.setdefault("product", {}).setdefault("copied", {})["after_use"] = sealed_after_use
                require_same_product_payload(
                    sealed_product_before, sealed_after_use, "sealed candidate product during aggregate",
                )
            except (EvidenceError, OSError) as error:
                record_postcondition_error(f"cannot bind sealed candidate product after aggregate: {error}")
    return report


def parse_arguments(arguments: Sequence[str]) -> tuple[Path, Path]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    selected = parser.parse_args(arguments)
    return selected.product, selected.evidence


def main(arguments: Sequence[str] | None = None) -> int:
    product, evidence = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    report_path = evidence / "libc-test.json"
    try:
        report = run_campaign(product, evidence)
    except (EvidenceError, OSError) as error:
        report = {
            "schema": SCHEMA, "status": "incomplete", "campaign_complete": False,
            "public_support": False, "target": TARGET, "fatal_error": str(error),
        }
    try:
        write_json(report_path, report)
    except EvidenceError as error:
        print(f"owned libc-test: cannot publish final report: {error}", file=sys.stderr)
        return 2
    return 0 if report.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
