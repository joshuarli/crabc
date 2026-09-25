#!/usr/bin/env python3
"""Run the frozen full os-test profile through one supplied dynamic product.

The pinned Makefiles remain the test authority.  This runner supplies a small
CC adapter because os-test's conventional driver spelling has target-input
flags that a sealed installed driver intentionally rejects.  Every adaptation
is recorded, compiled target objects are retained, independently replayed with
the installed compiler, compared byte-for-byte, and every successful target
link is validated before os-test removes its intermediate object.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, Iterable, Sequence

import owned_os_test_aio_suspend_source as aio_suspend_source

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "compat/x86_64"
OS_TEST_REVISION = "5e9456d510612f83b6ec8b1a0c06d6b1303a2512"
OS_TEST_TREE = "68fd4eef88d0e52b55c7cc2a73659b1e439d33fe"
DEFAULT_SUITES = (
    "include", "namespace", "basic", "io", "limits", "malloc", "process", "pty", "signal", "stdio",
)
MUSL_COMPILER = "/usr/local/bin/crabc-x86_64-musl-gcc"
# One whole-suite Make bound, used only as a hang guard: os-test's run.sh has no
# per-case limit. The owned side compiles each case twice, scans dependencies
# and seals every link, so `basic` alone takes ~1100 s at a host load average
# near 60; a 600 s bound timed it out with ~260 outcomes unwritten.
SUITE_TIMEOUT_SECONDS = 3600.0
MUSL_INCLUDE = "/opt/musl-1.2.6/include"
SCHEMA = "crabc.x86_64-owned-os-test/v1"
ADAPTER_SCHEMA = "crabc.x86_64-owned-os-test-adapter/v1"
PRODUCT_INCLUDE = "usr/include"
CONTROL_CHARACTER_DEVICES = (("null", 1, 3), ("zero", 1, 5), ("random", 1, 8), ("urandom", 1, 9), ("tty", 5, 0))
PRIVATE_PROC_SCHEMA = "crabc.x86_64-owned-os-test-private-proc/v1"
PRIVATE_PROC_MOUNT_OPTIONS = "nosuid,nodev,noexec"
PRIVATE_PROC_MOUNT = "/bin/mount"
PRIVATE_PROC_UNMOUNT = "/bin/umount"
PRIVATE_PROC_WITNESS_CHROOT = "/usr/sbin/chroot"
BASIC_SYSTEM_FILES = {
    "passwd": b"root:x:0:0:root:/root:/bin/sh\n",
    "group": b"root:x:0:\n",
    "services": b"http 80/tcp\n",
}

AIO_SUSPEND_PREPARER = HERE / "owned_os_test_aio_suspend_source.py"


class RunnerError(RuntimeError):
    """The supplied product, source pin, or control plane is not sealable."""


class AdapterError(RuntimeError):
    """The source Make invocation lies outside this documented adapter."""


class FixtureError(RunnerError):
    """A disposable execution fixture failed after its evidence began."""

    def __init__(self, message: str, control: dict[str, Any]):
        super().__init__(message)
        self.control = control


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stream_snapshot(value: bytes) -> dict[str, Any]:
    return {
        "byte_length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "text": value.decode("utf-8", errors="replace"),
    }


def artifact_path(work: Path, path: Path) -> str:
    """Name an evidence artifact relative to its single disposable leaf."""
    return path.relative_to(work).as_posix()


def retain_bytes(work: Path, path: Path, value: bytes) -> dict[str, Any]:
    """Retain raw bytes before reporting their digest and size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {"path": artifact_path(work, path), "sha256": hashlib.sha256(value).hexdigest(),
            "byte_length": len(value)}


def retain_json(work: Path, path: Path, value: dict[str, Any]) -> dict[str, Any]:
    """Write one canonical JSON artifact and bind the precise physical bytes."""
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    return retain_bytes(work, path, encoded)


def json_safe(value: Any) -> Any:
    """Serialize adapter plans without changing their Path-bearing execution form."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    return value


def physical_work_directory(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not str(path) or ".." in path.parts:
        raise RunnerError(f"{label} must not contain parent traversal")
    absolute = path.absolute()
    try:
        physical = absolute.resolve(strict=True)
    except OSError as error:
        raise RunnerError(f"{label} is not readable: {path}") from error
    if absolute != physical or not physical.is_dir() or not physical.is_relative_to(ROOT / ".work"):
        raise RunnerError(f"{label} must be a physical checkout .work directory")
    return physical


def require_regular(path: Path, label: str) -> Path:
    try:
        if path.is_symlink() or not path.is_file():
            raise RunnerError(f"{label} is not a physical regular file: {path}")
    except OSError as error:
        raise RunnerError(f"{label} is not readable: {path}") from error
    return path


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RunnerError(f"cannot load installed helper: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def validate_dynamic_product(product: Path) -> dict[str, Any]:
    sys.path.insert(0, str(HERE))
    try:
        import owned_posix_product_evidence as evidence
        evidence._validate_dynamic_product(product)
    except (ImportError, OSError, RuntimeError) as error:
        raise RunnerError(f"supplied dynamic product is invalid: {error}") from error
    manifest = product / "share/crabc/manifest.json"
    return {
        "root": str(product),
        "manifest": str(manifest),
        "manifest_sha256": sha256(manifest),
        "driver": str(product / "bin/crabc-cc-dynamic"),
        "driver_sha256": sha256(product / "bin/crabc-cc-dynamic"),
    }


def validate_source_root(source: Path) -> dict[str, Any]:
    source = physical_work_directory(source, "os-test source")
    if not (source / "GNUmakefile").is_file() or not (source / "misc/suites.list").is_file():
        raise RunnerError(f"os-test source is incomplete: {source}")
    git = shutil.which("git")
    if git is None:
        raise RunnerError("git is required to seal the os-test source revision")
    git_prefix = [git, "-c", f"safe.directory={source}", "-C", str(source)]
    revision = subprocess.run([*git_prefix, "rev-parse", "HEAD"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False, text=True)
    if revision.returncode or revision.stdout.strip() != OS_TEST_REVISION:
        raise RunnerError(f"os-test source is not pinned revision {OS_TEST_REVISION}: {revision.stderr.strip()}")
    tree = subprocess.run([*git_prefix, "rev-parse", "HEAD^{tree}"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False, text=True)
    if tree.returncode or tree.stdout.strip() != OS_TEST_TREE:
        raise RunnerError(f"os-test source does not have pinned tree {OS_TEST_TREE}: {tree.stderr.strip()}")
    status = subprocess.run([*git_prefix, "status", "--porcelain=v1"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, text=True)
    if status.returncode or status.stdout:
        raise RunnerError("os-test source checkout is dirty")
    return {
        "root": str(source),
        "revision": OS_TEST_REVISION,
        "tree": OS_TEST_TREE,
        "gnu_makefile_sha256": sha256(source / "GNUmakefile"),
        "suite_list_sha256": sha256(source / "misc/suites.list"),
    }


def git_command(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    if git is None:
        raise RunnerError("git is required to seal the os-test source revision")
    return subprocess.run([git, "-c", f"safe.directory={root}", "-C", str(root), *arguments],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)


def roster_entry(root: Path, relative: Path) -> dict[str, Any]:
    """Describe one non-followed path with its executable mode and content."""
    path = root / relative
    try:
        details = path.lstat()
    except OSError as error:
        raise RunnerError(f"roster path is unreadable: {path}") from error
    entry: dict[str, Any] = {"path": relative.as_posix(), "mode": stat.S_IMODE(details.st_mode)}
    if stat.S_ISREG(details.st_mode):
        entry.update({"type": "regular", "byte_length": details.st_size, "sha256": sha256(path)})
    elif stat.S_ISLNK(details.st_mode):
        target = os.readlink(path)
        target_bytes = os.fsencode(target)
        entry.update({"type": "symlink", "target": target,
                      "target_byte_length": len(target_bytes), "target_sha256": hashlib.sha256(target_bytes).hexdigest()})
    elif stat.S_ISDIR(details.st_mode):
        entry["type"] = "directory"
    elif stat.S_ISCHR(details.st_mode):
        entry.update({"type": "char-device", "major": os.major(details.st_rdev), "minor": os.minor(details.st_rdev)})
    else:
        raise RunnerError(f"roster has unsupported filesystem object: {path}")
    return entry


def tree_roster(root: Path) -> list[dict[str, Any]]:
    """Record the complete physical payload tree without traversing links."""
    entries: list[dict[str, Any]] = [roster_entry(root, Path("."))]
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        names.sort()
        files.sort()
        for name in [*names, *files]:
            path = current / name
            relative = path.relative_to(root)
            entries.append(roster_entry(root, relative))
    return sorted(entries, key=lambda entry: entry["path"])


def roster_difference(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> dict[str, list[Any]]:
    """Compare path, mode, type, and every content digest in two payload records."""
    left = {entry["path"]: entry for entry in expected}
    right = {entry["path"]: entry for entry in actual}
    return {
        "missing": sorted(set(left) - set(right)),
        "unexpected": sorted(set(right) - set(left)),
        "changed": [{"path": name, "expected": left[name], "actual": right[name]}
                    for name in sorted(set(left) & set(right)) if left[name] != right[name]],
    }


def roster_matches(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> bool:
    difference = roster_difference(expected, actual)
    return not difference["missing"] and not difference["unexpected"] and not difference["changed"]


def product_payload_after_execution(runtime: Path, baseline: list[dict[str, Any]], setup: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[Any]]]:
    """Project a post-run runtime root back onto the supplied product payload.

    The execution root contains deliberately separate control files (the host
    shell, devices, and copied source), so the projection covers every original
    product path and any unplanned addition below an original top-level product
    directory. This catches product writes while allowing os-test's work tree
    to create its ordinary build artifacts.
    """
    actual = tree_roster(runtime)
    expected_by_path = {entry["path"]: entry for entry in baseline}
    setup_by_path = {entry["path"]: entry for entry in setup}
    product_roots = {Path(entry["path"]).parts[0] for entry in baseline if Path(entry["path"]).parts}
    projected: list[dict[str, Any]] = []
    for entry in actual:
        path = entry["path"]
        first = Path(path).parts[0] if Path(path).parts else ""
        if path in expected_by_path:
            projected.append(entry)
        elif first in product_roots and path not in setup_by_path:
            projected.append(entry)
    return projected, roster_difference(baseline, projected)


def tracked_source_roster(source: Path) -> list[dict[str, Any]]:
    """Bind every tracked source file to the verified staged checkout."""
    listed = git_command(source, "ls-files", "-z")
    if listed.returncode:
        raise RunnerError(f"cannot enumerate staged os-test source: {listed.stderr.strip()}")
    paths = [Path(os.fsdecode(name)) for name in listed.stdout.encode().split(b"\0") if name]
    if any(not path.parts or path.is_absolute() or ".." in path.parts for path in paths):
        raise RunnerError("staged os-test source has an unsafe tracked pathname")
    return [roster_entry(source, path) for path in sorted(paths)]


def stage_pristine_source(source: Path, destination: Path, work: Path) -> dict[str, Any]:
    """Clone and freeze the exact checked-out source before either oracle runs."""
    git = shutil.which("git")
    if git is None:
        raise RunnerError("git is required to stage the os-test source")
    cloned = subprocess.run([git, "-c", f"safe.directory={source}", "-c", f"safe.directory={source / '.git'}",
                             "clone", "--no-hardlinks", "--quiet",
                             str(source), str(destination)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if cloned.returncode:
        raise RunnerError(f"cannot stage pinned os-test source: {cloned.stderr.decode(errors='replace').strip()}")
    revision = git_command(destination, "rev-parse", "HEAD")
    tree = git_command(destination, "rev-parse", "HEAD^{tree}")
    status = git_command(destination, "status", "--porcelain=v1")
    if revision.returncode or revision.stdout.strip() != OS_TEST_REVISION or tree.returncode or tree.stdout.strip() != OS_TEST_TREE:
        raise RunnerError("staged os-test source does not reproduce the pinned revision and tree")
    if status.returncode or status.stdout:
        raise RunnerError("newly staged os-test source is unexpectedly dirty")
    roster = tracked_source_roster(destination)
    artifact = retain_json(work, work / "records" / "source-roster.json", {
        "schema": "crabc.x86_64-owned-os-test-source-roster/v1",
        "revision": OS_TEST_REVISION,
        "tree": OS_TEST_TREE,
        "entries": roster,
    })
    freeze_tree(destination)
    return {"stage": artifact_path(work, destination), "revision": OS_TEST_REVISION, "tree": OS_TEST_TREE,
            "tracked_path_count": len(roster), "roster": artifact}


def aio_suspend_preparation(stage: Path) -> tuple[bytes, dict[str, Any]]:
    """Bind the sole lifetime repair to the exact frozen upstream fixture."""
    fixture = stage / aio_suspend_source.SOURCE_PATH
    require_regular(fixture, "pinned os-test aio_suspend source")
    try:
        prepared, replacements = aio_suspend_source.prepare(fixture.read_bytes())
    except aio_suspend_source.SourcePreparationError as error:
        raise RunnerError(str(error)) from error
    preparer = require_regular(AIO_SUSPEND_PREPARER, "os-test aio_suspend preparer")
    return prepared, {
        "schema": aio_suspend_source.SCHEMA,
        "fixture": aio_suspend_source.SOURCE_PATH,
        "source_sha256": aio_suspend_source.ORIGINAL_SHA256,
        "prepared_sha256": aio_suspend_source.PREPARED_SHA256,
        "preparer": {"path": preparer.relative_to(ROOT).as_posix(), "sha256": sha256(preparer)},
        "replacements": replacements,
    }


def prepare_aio_suspend_copy(source: Path, side: str, prepared: bytes, preparation: dict[str, Any],
                             work: Path) -> dict[str, Any]:
    """Apply the sealed fixture derivative to one disposable oracle or target copy."""
    fixture = source / aio_suspend_source.SOURCE_PATH
    require_regular(fixture, f"{side} os-test aio_suspend source")
    try:
        observed, replacements = aio_suspend_source.prepare(fixture.read_bytes())
    except aio_suspend_source.SourcePreparationError as error:
        raise RunnerError(str(error)) from error
    if observed != prepared or replacements != preparation["replacements"]:
        raise RunnerError("os-test aio_suspend preparation differs from its staged source contract")
    fixture.write_bytes(prepared)
    if sha256(fixture) != preparation["prepared_sha256"]:
        raise RunnerError("prepared os-test aio_suspend source bytes differ")
    record = {**preparation, "side": side}
    return retain_json(work, work / "records" / f"basic.{side}.aio-suspend-preparation.json", record)


def musl_oracle_identity(work: Path, label: str) -> dict[str, Any]:
    """Bind the pinned compiler wrapper, specs, libc, marker, and headers."""
    root = Path("/opt/musl-1.2.6")
    wrapper = Path(MUSL_COMPILER)
    marker = root / ".crabc-oracle"
    specs_digest = root / ".crabc-musl-gcc-specs.sha256"
    specs = root / "lib/musl-gcc.specs"
    libc = root / "lib/libc.so"
    for path, name in ((wrapper, "musl compiler wrapper"), (marker, "musl oracle marker"),
                       (specs_digest, "musl specs digest"), (specs, "musl specs"), (libc, "musl libc")):
        require_regular(path, name)
    try:
        listed_digest, listed_path = specs_digest.read_text().strip().split(maxsplit=1)
    except ValueError as error:
        raise RunnerError("musl specs digest marker is malformed") from error
    if listed_path != str(specs) or listed_digest != sha256(specs):
        raise RunnerError("musl specs do not match their pinned digest marker")
    include_roster = tree_roster(root / "include")
    include_artifact = retain_json(work, work / "records" / f"musl-oracle-{label}-include-roster.json", {
        "schema": "crabc.x86_64-owned-os-test-musl-include-roster/v1",
        "entries": include_roster,
    })
    identity = {
        "root": str(root), "wrapper": {"path": str(wrapper), "sha256": sha256(wrapper)},
        "marker": {"path": str(marker), "sha256": sha256(marker)},
        "specs_digest": {"path": str(specs_digest), "sha256": sha256(specs_digest)},
        "specs": {"path": str(specs), "sha256": sha256(specs)},
        "libc": {"path": str(libc), "sha256": sha256(libc)},
        "include": {"path": str(root / "include"), "entry_count": len(include_roster), "roster": include_artifact},
    }
    return identity


def same_musl_oracle(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return (before["wrapper"]["sha256"] == after["wrapper"]["sha256"] and
            before["marker"]["sha256"] == after["marker"]["sha256"] and
            before["specs_digest"]["sha256"] == after["specs_digest"]["sha256"] and
            before["specs"]["sha256"] == after["specs"]["sha256"] and
            before["libc"]["sha256"] == after["libc"]["sha256"] and
            before["include"]["roster"]["sha256"] == after["include"]["roster"]["sha256"])


def freeze_tree(root: Path) -> None:
    """Remove write permission only after the staged source has been verified."""
    for directory, names, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in [*names, *files]:
            path = current / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                continue
            os.chmod(path, stat.S_IMODE(mode) & ~0o222)
        mode = current.lstat().st_mode
        if not stat.S_ISLNK(mode):
            os.chmod(current, stat.S_IMODE(mode) & ~0o222)


def thaw_tree(root: Path) -> None:
    """Make a disposable copy buildable while preserving its existing execute bits."""
    for directory, names, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in [*names, *files]:
            path = current / name
            mode = path.lstat().st_mode
            if not stat.S_ISLNK(mode):
                os.chmod(path, stat.S_IMODE(mode) | stat.S_IWUSR)
        mode = current.lstat().st_mode
        if not stat.S_ISLNK(mode):
            os.chmod(current, stat.S_IMODE(mode) | stat.S_IWUSR | stat.S_IXUSR)


def restore_roster_modes(root: Path, roster: list[dict[str, Any]]) -> None:
    """Restore a frozen copy's product modes without changing any content."""
    for entry in roster:
        if entry["type"] == "symlink":
            continue
        path = root / entry["path"]
        os.chmod(path, entry["mode"])


def split_output(arguments: list[str]) -> tuple[Path, list[str]]:
    output = None
    retained: list[str] = []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item == "-o":
            index += 1
            if index == len(arguments) or arguments[index].startswith("-") or output is not None:
                raise AdapterError("os-test adapter requires one ordinary -o output")
            output = Path(arguments[index])
        else:
            retained.append(item)
        index += 1
    if output is None:
        raise AdapterError("os-test adapter requires an explicit -o output")
    return output, retained


def _drop_product_include(arguments: list[str], include: Path) -> tuple[list[str], list[dict[str, str]]]:
    result: list[str] = []
    changes: list[dict[str, str]] = []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        value = None
        if item == "-I":
            index += 1
            if index == len(arguments):
                raise AdapterError("-I needs an include directory")
            value = arguments[index]
        elif item.startswith("-I"):
            value = item[2:]
        if value is not None:
            candidate = Path(value).absolute()
            if candidate != include:
                raise AdapterError(f"unowned source include directory: {value}")
            changes.append({"raw": ("-I" if item == "-I" else item), "action": "installed-header-directory"})
        else:
            result.append(item)
        index += 1
    return result, changes


def target_plan(arguments: list[str], product: Path) -> dict[str, Any]:
    """Map the exact os-test target subset to the installed driver surface."""
    output, retained = split_output(arguments)
    retained, changes = _drop_product_include(retained, product / PRODUCT_INCLUDE)
    source = [Path(item) for item in retained if item.endswith(".c")]
    objects = [Path(item) for item in retained if item.endswith(".o")]
    preprocessor = any(item in {"-E", "-dM"} for item in retained)
    compile_only = "-c" in retained
    shared = "-shared" in retained
    mode = "shared" if shared else "pie"
    compiler_flags: list[str] = []
    adapted: list[str] = []
    drop = {"-fPIE", "-fpie", "-fPIC", "-fpic", "-pthread", "-pie", "-lm", "-lpthread", "-lrt", "-lc"}
    for item in retained:
        if shared and item == "-pie":
            # os-test's GNU basic shared-object rule combines its ordinary
            # PIE LDFLAGS with -shared. The sealed driver rightly accepts one
            # target mode; do not silently erase the source-level conflict.
            raise AdapterError("os-test requests incompatible -shared and -pie modes")
        if item in drop:
            changes.append({"raw": item, "action": "owned-product-default"})
        elif item in {"-c", "-shared"} or item.endswith(".c") or item.endswith(".o"):
            continue
        elif item.startswith(("-D", "-U", "-O", "-g", "-std=", "-W", "-fno-")):
            compiler_flags.append(item)
        elif item in {"-E", "-dM"}:
            # Namespace preprocessing has an explicit host control plane below.
            continue
        elif item.startswith("-"):
            raise AdapterError(f"unsupported os-test target flag: {item}")
        else:
            raise AdapterError(f"unsupported os-test target input: {item}")
    if preprocessor:
        if compile_only or shared or len(source) != 1 or objects:
            raise AdapterError("namespace preprocessing has an unexpected target form")
        return {"kind": "preprocess", "mode": "preprocess", "source": source[0], "objects": [],
                "output": output, "flags": compiler_flags, "changes": changes,
                "macro_dump": "-dM" in retained}
    if compile_only:
        if shared or len(source) != 1 or objects:
            raise AdapterError("target compilation must name one source")
        return {"kind": "compile", "mode": mode, "source": source[0], "objects": [], "output": output,
                "flags": compiler_flags, "changes": changes}
    if len(source) == 1 and not objects and shared:
        return {"kind": "source-link", "mode": "shared", "source": source[0], "objects": [], "output": output,
                "flags": compiler_flags, "changes": changes}
    if not source and len(objects) == 1 and not shared:
        return {"kind": "link", "mode": "pie", "source": None, "objects": objects, "output": output,
                "flags": compiler_flags, "changes": changes}
    raise AdapterError("os-test adapter only admits one source compile or one object link")


def translation_flags(static: Any) -> tuple[str, ...]:
    """Return the installed helper's own hosted translation flags.

    The replay below must reproduce the driver's object byte for byte, so it
    takes the flags from the installed ``crabc_cc_static.py`` the driver
    imports rather than restating them.
    """

    flags = getattr(static, "HOSTED_TRANSLATION_FLAGS", None)
    if type(flags) is not tuple or not all(type(flag) is str for flag in flags):
        raise AdapterError("installed compiler helper has no hosted translation flags")
    return flags


def compiler_command(compiler: str, product: Path, source: Path, output: Path, flags: Iterable[str], mode: str,
                     translation: Sequence[str]) -> list[str]:
    if mode not in {"pie", "shared"}:
        raise AdapterError(f"unknown compilation mode: {mode}")
    return [compiler, "-nostdinc", "-isystem", str(product / PRODUCT_INCLUDE), *translation,
            *flags, "-fPIC" if mode == "shared" else "-fPIE", "-c", str(source), "-o", str(output)]


def dependency_command(compiler: str, product: Path, source: Path, flags: Iterable[str], mode: str,
                       translation: Sequence[str]) -> list[str]:
    compile = compiler_command(compiler, product, source, Path("/dev/null"), flags, mode, translation)
    # Drop exactly ``-c SOURCE -o OUTPUT``.  Leaving the first source makes
    # GCC emit a second target rule, which is not a header dependency.
    return [*compile[:-4], "-M", str(source)]


def parse_dependencies(raw: bytes, source_root: Path, product: Path) -> dict[str, str]:
    try:
        body = raw.decode("utf-8").replace("\\\n", " ").split(":", 1)[1]
    except (UnicodeDecodeError, IndexError) as error:
        raise AdapterError("dependency audit did not emit a make dependency line") from error
    result: dict[str, str] = {}
    for name in body.split():
        path = Path(name).resolve(strict=True)
        if not (path.is_relative_to(source_root) or path.is_relative_to(product / PRODUCT_INCLUDE)):
            raise AdapterError(f"dependency escapes source and installed headers: {path}")
        result[str(path)] = sha256(path)
    return result


def event_path(root: Path, event_id: str, suffix: str) -> Path:
    path = root / "events" / f"{event_id}.{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def append_event(root: Path, event: dict[str, Any]) -> str:
    """Create one event without a shared counter between parallel headers."""
    event_id = uuid.uuid4().hex
    event_path(root, event_id, "json").write_text(json.dumps(event, indent=2, sort_keys=True) + "\n")
    return event_id


def run_capture(command: list[str], environment: dict[str, str]) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, check=False)
    return completed.returncode, completed.stdout, completed.stderr


def retain_file(source: Path, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return str(destination)


def adapter(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--adapter", action="store_true")
    parser.add_argument("--product", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("remaining", nargs=argparse.REMAINDER)
    values = parser.parse_args(arguments)
    product = values.product.resolve(strict=True)
    source_root = values.source_root.resolve(strict=True)
    evidence_root = values.evidence.resolve(strict=True)
    runtime_root = values.runtime_root.resolve(strict=True)
    raw = values.remaining
    if raw[:1] == ["--"]:
        raw = raw[1:]
    base: dict[str, Any] = {"schema": ADAPTER_SCHEMA, "raw_command": raw, "cwd": str(Path.cwd())}
    try:
        plan = target_plan(raw, product)
        static = load_module("owned_os_test_installed_static", product / "share/crabc/crabc_cc_static.py")
        compiler = static.compiler()
        environment = static.clean_environment()
        translation = translation_flags(static)
        base["plan"] = json_safe(plan)
        base["compiler"] = {"path": compiler, "sha256": sha256(Path(compiler))}
        event_id = append_event(evidence_root, {**base, "state": "started"})
        if plan["kind"] == "preprocess":
            command = [*compiler_command(compiler, product, plan["source"], Path("/dev/null"), plan["flags"], "pie", translation)[:-4],
                       "-E", *(["-dM"] if plan["macro_dump"] else []), str(plan["source"]), "-o", str(plan["output"])]
            status, stdout, stderr = run_capture(command, environment)
            final = {**base, "event_id": event_id, "state": "finished", "command": command, "status": status,
                     "stdout": stream_snapshot(stdout), "stderr": stream_snapshot(stderr), "control_plane": "pinned-host-preprocessor"}
            if status == 0 and plan["output"].is_file():
                output = plan["output"].resolve(strict=True)
                retained = evidence_root / "preprocessed" / f"{event_id}{output.suffix}"
                final["output"] = {"source_path": str(output), "sha256": sha256(output),
                                   "retained": retain_file(output, retained)}
            dependencies = dependency_command(compiler, product, plan["source"], plan["flags"], "pie", translation)
            dependency_status, dependency_stdout, dependency_stderr = run_capture(dependencies, environment)
            final["dependencies"] = {"command": dependencies, "status": dependency_status,
                                       "stdout": stream_snapshot(dependency_stdout), "stderr": stream_snapshot(dependency_stderr),
                                       "headers": parse_dependencies(dependency_stdout, source_root, product) if dependency_status == 0 else {}}
            if status == 0 and dependency_status != 0:
                final["adapter_error"] = "namespace preprocessing did not produce an installed-header dependency closure"
            event_path(evidence_root, event_id, "stdout").write_bytes(stdout)
            event_path(evidence_root, event_id, "stderr").write_bytes(stderr)
            event_path(evidence_root, event_id, "dependencies.stdout").write_bytes(dependency_stdout)
            event_path(evidence_root, event_id, "dependencies.stderr").write_bytes(dependency_stderr)
            event_path(evidence_root, event_id, "json").write_text(json.dumps(final, indent=2, sort_keys=True) + "\n")
            sys.stdout.buffer.write(stdout); sys.stderr.buffer.write(stderr)
            return 0 if status == 0 and "adapter_error" not in final else 1
        source = plan["source"]
        if plan["kind"] == "link":
            object_path = plan["objects"][0].resolve(strict=True)
            command = [str(product / "bin/crabc-cc-dynamic"), "--dynamic-pie", str(object_path), "-o", str(plan["output"])]
            return complete_link(base, event_id, command, object_path, plan, product, evidence_root, runtime_root, source_root, environment)
        object_root = evidence_root / "objects"
        object_root.mkdir(parents=True, exist_ok=True)
        object_path = plan["output"] if plan["kind"] == "compile" else object_root / f"{event_id}.o"
        mode_flag = "--dynamic-shared-object" if plan["mode"] == "shared" else "--dynamic-pie"
        command = [str(product / "bin/crabc-cc-dynamic"), mode_flag, "-c", str(source), "-o", str(object_path), *plan["flags"]]
        status, stdout, stderr = run_capture(command, environment)
        final: dict[str, Any] = {**base, "event_id": event_id, "state": "finished", "command": command, "status": status,
                                 "stdout": stream_snapshot(stdout), "stderr": stream_snapshot(stderr), "control_plane": "installed-driver"}
        event_path(evidence_root, event_id, "stdout").write_bytes(stdout)
        event_path(evidence_root, event_id, "stderr").write_bytes(stderr)
        if status == 0:
            object_path = object_path.resolve(strict=True)
            direct = object_root / f"{event_id}.direct.o"
            replay = compiler_command(compiler, product, source, direct, plan["flags"], plan["mode"], translation)
            replay_status, replay_stdout, replay_stderr = run_capture(replay, environment)
            dependencies = dependency_command(compiler, product, source, plan["flags"], plan["mode"], translation)
            dependency_status, dependency_stdout, dependency_stderr = run_capture(dependencies, environment)
            final["object"] = {"path": str(object_path.absolute()), "sha256": sha256(object_path),
                               "retained": retain_file(object_path, object_root / f"{event_id}.driver.o")}
            final["replay"] = {"command": replay, "status": replay_status, "stdout": stream_snapshot(replay_stdout),
                               "stderr": stream_snapshot(replay_stderr), "object": str(direct),
                               "object_sha256": sha256(direct) if replay_status == 0 and direct.is_file() else None,
                               "byte_equal": replay_status == 0 and direct.is_file() and object_path.read_bytes() == direct.read_bytes()}
            final["dependencies"] = {"command": dependencies, "status": dependency_status,
                                      "stdout": stream_snapshot(dependency_stdout), "stderr": stream_snapshot(dependency_stderr),
                                      "headers": parse_dependencies(dependency_stdout, source_root, product) if dependency_status == 0 else {}}
            if replay_status != 0 or dependency_status != 0 or not final["replay"]["byte_equal"]:
                final["adapter_error"] = "installed driver object did not reproduce exactly under its recorded compiler"
        event_path(evidence_root, event_id, "json").write_text(json.dumps(final, indent=2, sort_keys=True) + "\n")
        sys.stdout.buffer.write(stdout); sys.stderr.buffer.write(stderr)
        if status != 0 or final.get("adapter_error"):
            return 1
        if plan["kind"] == "compile":
            return 0
        link_command = [str(product / "bin/crabc-cc-dynamic"), "--dynamic-shared-object", str(object_path), "-o", str(plan["output"])]
        return complete_link(base, event_id, link_command, object_path, plan, product, evidence_root, runtime_root, source_root, environment, source_event=final)
    except (AdapterError, RunnerError, OSError, ValueError) as error:
        number = append_event(evidence_root, {**base, "state": "adapter-error", "adapter_error": str(error)})
        print(f"owned os-test adapter: {error}", file=sys.stderr)
        return 1


def install_execution_wrapper(output: Path, source_root: Path, runtime_root: Path) -> dict[str, str]:
    """Mirror a sealed target into the private root and replace its host path.

    os-test's ``misc/run.sh`` deliberately executes a relative pathname. The
    host shell cannot execute the product's absolute PT_INTERP spelling, so
    the wrapper enters a product copy that also contains a distinct host-musl
    BusyBox control plane. The link is sealed before this replacement.
    """
    relative = output.relative_to(source_root)
    mirrored = runtime_root / "work" / relative
    retain_file(output, mirrored)
    suite_directory = relative.parts[0]
    # The frozen helper invokes a nested path from the suite directory, e.g.
    # ``basic/dirent/readdir`` from ``basic``. Do not turn that nested pathname
    # into the process cwd: several tests open suite-relative fixtures.
    inside = "cd " + shlex.quote("/work/" + suite_directory) + " && exec " + shlex.quote("/lib/ld-crabc-x86_64.so.1") + " " + shlex.quote("/work/" + str(relative))
    wrapper = "#!/bin/sh\nexec /usr/sbin/chroot " + shlex.quote(str(runtime_root)) + " /control/ld-musl-x86_64.so.1 /control/busybox sh -c " + shlex.quote(inside) + "\n"
    output.write_text(wrapper)
    os.chmod(output, 0o755)
    return {"runtime_path": str(mirrored), "runtime_sha256": sha256(mirrored), "host_wrapper": str(output),
            "runtime_cwd": "/work/" + suite_directory}


def complete_link(base: dict[str, Any], event_id: str, command: list[str], object_path: Path, plan: dict[str, Any], product: Path,
                  evidence_root: Path, runtime_root: Path, source_root: Path, environment: dict[str, str], source_event: dict[str, Any] | None = None) -> int:
    object_path = object_path.resolve(strict=True)
    status, stdout, stderr = run_capture(command, environment)
    output = plan["output"].absolute()
    receipt = Path(str(output) + ".crabc-link.json")
    final: dict[str, Any] = {**base, "event_id": event_id, "state": "link-finished", "command": command, "status": status,
                             "stdout": stream_snapshot(stdout), "stderr": stream_snapshot(stderr), "workload": str(object_path.absolute()),
                             "output": str(output), "receipt": str(receipt), "control_plane": "installed-driver"}
    if source_event is not None:
        final["source_compile_event"] = source_event["event_id"]
    event_path(evidence_root, event_id, "link.stdout").write_bytes(stdout)
    event_path(evidence_root, event_id, "link.stderr").write_bytes(stderr)
    if status == 0:
        try:
            sys.path.insert(0, str(HERE))
            import owned_posix_product_evidence as evidence
            linkage = "pie" if plan["mode"] == "pie" else "shared"
            # Shared objects have no process ELF contract; preserve the receipt
            # separately and validate the dynamic executable links exactly.
            if linkage == "pie":
                final["link_identity"] = evidence.validate_link(product, object_path.absolute(), output, receipt, "pie")
            else:
                final["link_identity"] = {"linkage": "shared", "product_manifest_sha256": sha256(product / "share/crabc/manifest.json"),
                                          "workload_sha256": sha256(object_path), "output_sha256": sha256(output), "receipt_sha256": sha256(receipt)}
            final["retained_output"] = retain_file(output, evidence_root / "links" / f"{event_id}.{output.name}")
            final["retained_receipt"] = retain_file(receipt, evidence_root / "links" / f"{event_id}.{output.name}.crabc-link.json")
            if linkage == "pie":
                final["execution_wrapper"] = install_execution_wrapper(output, source_root, runtime_root)
            else:
                relative = output.relative_to(source_root)
                final["runtime_dso"] = retain_file(output, runtime_root / "work" / relative)
        except (OSError, RuntimeError) as error:
            final["adapter_error"] = f"sealed link validation failed: {error}"
    event_path(evidence_root, event_id, "link.json").write_text(json.dumps(final, indent=2, sort_keys=True) + "\n")
    sys.stdout.buffer.write(stdout); sys.stderr.buffer.write(stderr)
    return 0 if status == 0 and "adapter_error" not in final else 1


def collect_outcomes(root: Path, suite: str) -> dict[str, dict[str, Any]]:
    outcome_root = root / "out/linux" / suite
    if not outcome_root.is_dir():
        return {}
    return {path.relative_to(outcome_root).as_posix(): {"sha256": sha256(path), "text": path.read_text(errors="replace")}
            for path in sorted(outcome_root.rglob("*.out"))}


def expected_outcomes(source: Path, suite: str) -> list[str]:
    """Derive the frozen Make target roster from the staged C case graph."""
    root = source / suite
    if not root.is_dir():
        raise RunnerError(f"staged os-test suite is missing: {suite}")
    return sorted(path.relative_to(root).with_suffix(".out").as_posix() for path in root.rglob("*.c"))


def retain_expected_outcomes(work: Path, source: Path, suite: str) -> tuple[list[str], dict[str, Any]]:
    outcomes = expected_outcomes(source, suite)
    artifact = retain_json(work, work / "records" / f"{suite}.expected-outcomes.json", {
        "schema": "crabc.x86_64-owned-os-test-expected-outcomes/v1",
        "suite": suite,
        "outcomes": outcomes,
    })
    return outcomes, artifact


def copied_tree(source: Path, destination: Path, *, discard_git: bool = False, buildable: bool = False) -> None:
    ignored = shutil.ignore_patterns(".git") if discard_git else None
    shutil.copytree(source, destination, symlinks=True, ignore=ignored)
    if buildable:
        thaw_tree(destination)


def make_command(suite: str, source: Path, adapter_path: Path, product: Path, evidence: Path, runtime: Path, header_jobs: int) -> list[str]:
    adapter = " ".join(shlex.quote(str(argument)) for argument in (
        sys.executable, "-B", adapter_path, "--adapter", "--product", product,
        "--source-root", source, "--evidence", evidence, "--runtime-root", runtime, "--",
    ))
    jobs = header_jobs if suite in {"include", "namespace"} else 1
    return ["make", "-C", str(source), f"-j{jobs}", f"{suite}-test", f"CC={adapter}", "EXTRA_LDFLAGS=", "CC_FOR_BUILD=/usr/bin/cc",
            "CFLAGS_FOR_BUILD=", "CPPFLAGS_FOR_BUILD=", "LDFLAGS_FOR_BUILD="]


def musl_make_command(suite: str, source: Path, header_jobs: int) -> list[str]:
    """Run the untouched suite through its pinned musl 1.2.6 oracle."""
    jobs = header_jobs if suite in {"include", "namespace"} else 1
    return ["make", "-C", str(source), f"-j{jobs}", f"{suite}-test", f"CC={MUSL_COMPILER}", "EXTRA_LDFLAGS=", "CC_FOR_BUILD=/usr/bin/cc",
            "CFLAGS_FOR_BUILD=", "CPPFLAGS_FOR_BUILD=", "LDFLAGS_FOR_BUILD="]


def run_make(command: list[str], timeout: float) -> tuple[int | str, bytes, bytes]:
    environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1"}
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=environment, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        return "TIMEOUT", stdout, stderr


def make_record(work: Path, suite: str, side: str, command: list[str], timeout: float,
                status: int | str, stdout: bytes, stderr: bytes) -> dict[str, Any]:
    """Retain one canonical Make result and its unmodified physical streams."""
    prefix = work / "records" / f"{suite}.{side}.make"
    stdout_artifact = retain_bytes(work, prefix.with_suffix(".stdout"), stdout)
    stderr_artifact = retain_bytes(work, prefix.with_suffix(".stderr"), stderr)
    status_artifact = retain_json(work, prefix.with_suffix(".status.json"), {
        "schema": "crabc.x86_64-owned-os-test-make-status/v1",
        "suite": suite,
        "side": side,
        "command": command,
        "timeout_seconds": timeout,
        "environment": {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1"},
        "make_status": status,
        "stdout": stdout_artifact,
        "stderr": stderr_artifact,
    })
    return {"command": command, "timeout_seconds": timeout, "make_status": status,
            "stdout": stdout_artifact, "stderr": stderr_artifact, "status_record": status_artifact}


def make_evidence_host_readable(work: Path, *, skip_roots: set[Path] | None = None) -> None:
    """Return the complete retained evidence leaf to the invoking workspace user."""
    skipped = {path.absolute() for path in skip_roots or set()}
    paths: list[Path] = []
    for directory, names, files in os.walk(work, topdown=True, followlinks=False):
        current = Path(directory)
        names[:] = [name for name in names if (current / name).absolute() not in skipped]
        paths.extend(current / name for name in [*names, *files])
    for path in reversed(paths):
        if path.absolute() in skipped:
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            continue
        if stat.S_ISDIR(mode):
            os.chmod(path, stat.S_IMODE(mode) | 0o555)
        elif stat.S_ISREG(mode):
            os.chmod(path, stat.S_IMODE(mode) | 0o444)
    mode = work.lstat().st_mode
    if not stat.S_ISLNK(mode):
        os.chmod(work, stat.S_IMODE(mode) | 0o555)


def evidence_events(evidence: Path) -> list[dict[str, Any]]:
    return [json.loads(path.read_text()) for path in sorted((evidence / "events").glob("*.json")) if path.name != "next"]


def suite_passed(status: int | str, outcomes: dict[str, Any], expected: list[str], events: list[dict[str, Any]]) -> bool:
    if status != 0 or sorted(outcomes) != expected:
        return False
    return not any(event.get("state") == "adapter-error" or event.get("adapter_error") for event in events)


def compare_outcomes(reference: dict[str, dict[str, Any]], candidate: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    differences = []
    for name in sorted(set(reference) | set(candidate)):
        left = reference.get(name)
        right = candidate.get(name)
        if left == right:
            continue
        differences.append({"case": name, "musl": left if left is not None else "missing",
                            "dynamic": right if right is not None else "missing"})
    return differences


def mount_private_devpts(destination: Path) -> dict[str, Any]:
    """Mount the one private PTY instance needed by os-test's PTY suite."""
    mount = shutil.which("mount")
    if mount is None:
        raise RunnerError("pinned image lacks mount for the private devpts fixture")
    target = destination / "dev/pts"
    target.mkdir(parents=True, exist_ok=True)
    command = [mount, "-t", "devpts", "-o", "newinstance,ptmxmode=0666,mode=0620", "devpts", str(target)]
    status, stdout, stderr = run_capture(command, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    record = {"command": command, "status": status, "stdout": stream_snapshot(stdout), "stderr": stream_snapshot(stderr),
              "target": str(target)}
    if status != 0:
        raise FixtureError(f"private devpts fixture setup failed: {stderr.decode('utf-8', errors='replace').strip()}",
                           {"private_devpts": record})
    ptmx = destination / "dev/ptmx"
    if ptmx.exists() or ptmx.is_symlink():
        ptmx.unlink()
    ptmx.symlink_to("pts/ptmx")
    return record


def suite_needs_private_devpts(suite: str) -> bool:
    """Both basic and PTY sources open a fresh pseudo-terminal controller."""
    return suite in {"basic", "pty"}


def reserve_private_proc_mountpoint(destination: Path, suite: str) -> dict[str, Any] | None:
    """Reserve basic's empty procfs mountpoint before the control snapshot.

    The product collision check happens before this helper.  Keeping the empty
    directory in the ordinary control roster lets the later procfs mount remain
    a separately attested kernel fixture rather than an unbounded filesystem
    input to either product snapshot.
    """
    if suite != "basic":
        return None
    target = destination / "proc"
    if target.exists() or target.is_symlink():
        raise RunnerError(f"control-plane path collides with supplied product: {target}")
    target.mkdir(mode=0o755)
    # ``mkdir`` is subject to the invoking process's umask.  The reservation
    # is part of the sealed ordinary control tree, so give it one explicit
    # mode before recording the setup roster.
    os.chmod(target, 0o755)
    if any(target.iterdir()):
        raise RunnerError("private procfs mountpoint is not empty before setup snapshot")
    return {
        "schema": PRIVATE_PROC_SCHEMA,
        "mountpoint": str(target),
        "reservation": {"empty": True, "mode": 0o755},
    }


def container_pid_namespace() -> str:
    """Read the pinned container's current PID namespace identity."""
    try:
        identity = os.readlink("/proc/self/ns/pid")
    except OSError as error:
        raise RunnerError("pinned container cannot read its PID namespace identity") from error
    if not identity.startswith("pid:[") or not identity.endswith("]") or not identity[5:-1].isdigit():
        raise RunnerError(f"unexpected PID namespace identity: {identity!r}")
    return identity


def mount_private_proc(destination: Path, private: dict[str, Any]) -> None:
    """Mount and attest basic's procfs only after its root snapshot is sealed."""
    target = destination / "proc"
    if private.get("schema") != PRIVATE_PROC_SCHEMA or private.get("mountpoint") != str(target):
        raise FixtureError("private procfs reservation does not bind this execution root", {"private_proc": private})
    if not target.is_dir() or target.is_symlink() or any(target.iterdir()):
        raise FixtureError("private procfs mountpoint changed after setup snapshot", {"private_proc": private})
    mount = Path(PRIVATE_PROC_MOUNT)
    if not mount.is_file():
        raise FixtureError("pinned image lacks mount for the private procfs fixture", {"private_proc": private})
    command = [str(mount), "-t", "proc", "-o", PRIVATE_PROC_MOUNT_OPTIONS, "proc", str(target)]
    status, stdout, stderr = run_capture(command, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    private["mount"] = {"command": command, "status": status, "stdout": stream_snapshot(stdout),
                        "stderr": stream_snapshot(stderr), "target": str(target)}
    if status != 0:
        raise FixtureError(f"private procfs fixture setup failed: {stderr.decode('utf-8', errors='replace').strip()}",
                           {"private_proc": private})

    outside = container_pid_namespace()
    witness_command = [PRIVATE_PROC_WITNESS_CHROOT, str(destination), "/control/ld-musl-x86_64.so.1",
                       "/control/busybox", "readlink", "/proc/self/ns/pid"]
    witness_status, witness_stdout, witness_stderr = run_capture(
        witness_command, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    inside = witness_stdout.decode("utf-8", errors="replace").strip()
    private["namespace"] = {
        "outside": outside,
        "inside": {"command": witness_command, "status": witness_status,
                   "stdout": stream_snapshot(witness_stdout), "stderr": stream_snapshot(witness_stderr)},
        "matched": witness_status == 0 and witness_stderr == b"" and inside == outside,
    }
    if not private["namespace"]["matched"]:
        raise FixtureError("private procfs PID namespace witness failed", {"private_proc": private})


def unmount_private_proc(private: dict[str, Any]) -> dict[str, Any]:
    """Tear down procfs before any post-run filesystem inspection."""
    unmount = Path(PRIVATE_PROC_UNMOUNT)
    command = [str(unmount), str(private["mountpoint"])]
    if not unmount.is_file():
        return {"command": command, "status": "UNAVAILABLE", "stdout": stream_snapshot(b""),
                "stderr": stream_snapshot(b"pinned image lacks umount\n")}
    try:
        status, stdout, stderr = run_capture(command, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except OSError as error:
        return {"command": command, "status": "EXEC_ERROR", "stdout": stream_snapshot(b""),
                "stderr": stream_snapshot((str(error) + "\n").encode())}
    return {"command": command, "status": status, "stdout": stream_snapshot(stdout), "stderr": stream_snapshot(stderr)}


def private_proc_postwalk_safe(private: dict[str, Any] | None) -> bool:
    """A failed procfs teardown forbids all subsequent walks of its root."""
    if private is None:
        return True
    mount = private.get("mount")
    if not isinstance(mount, dict) or mount.get("status") != 0:
        return True
    unmount = private.get("unmount")
    return isinstance(unmount, dict) and unmount.get("status") == 0


def private_proc_fixture_passed(private: dict[str, Any] | None) -> bool:
    """Require the complete basic-only mount, witness, and teardown lifecycle."""
    if private is None:
        return True
    mount = private.get("mount")
    namespace = private.get("namespace")
    unmount = private.get("unmount")
    return (isinstance(mount, dict) and mount.get("status") == 0 and
            isinstance(namespace, dict) and namespace.get("matched") is True and
            isinstance(unmount, dict) and unmount.get("status") == 0)


def private_proc_lifecycle(private: dict[str, Any]) -> dict[str, Any]:
    """Track a mutable procfs receipt without changing its successful schema.

    A signal can interrupt the mount helper after the kernel has accepted the
    mount but before its successful receipt is stored.  The internal lifecycle
    therefore starts uncertain and only permits a post-run walk after a
    recorded successful teardown.  It is intentionally not serialized into a
    passing suite's execution-control receipt.
    """
    return {"receipt": private, "mount_pending": False, "teardown_pending": False,
            "teardown_succeeded": False}


def private_proc_lifecycle_postwalk_safe(lifecycle: dict[str, Any]) -> bool:
    """Allow a root walk only when every possible procfs mount was removed."""
    private = lifecycle["receipt"]
    mount = private.get("mount")
    mounted = isinstance(mount, dict) and type(mount.get("status")) is int and mount["status"] == 0
    if lifecycle["teardown_pending"]:
        return False
    if lifecycle["mount_pending"] or mounted:
        return lifecycle["teardown_succeeded"] is True
    return True


def mount_private_proc_tracked(destination: Path, lifecycle: dict[str, Any]) -> None:
    """Mark mount uncertainty before calling the kernel-facing procfs helper."""
    private = lifecycle["receipt"]
    lifecycle["mount_pending"] = True
    # A mount utility can report failure after the kernel accepted the mount.
    # Preserve uncertainty for every exceptional result until teardown records
    # a successful unmount, including a completed nonzero command receipt.
    mount_private_proc(destination, private)
    lifecycle["mount_pending"] = False


def unmount_private_proc_tracked(lifecycle: dict[str, Any]) -> None:
    """Attempt teardown for known or uncertain mounts before any root walk."""
    private = lifecycle["receipt"]
    mount = private.get("mount")
    mounted = isinstance(mount, dict) and type(mount.get("status")) is int and mount["status"] == 0
    if not lifecycle["mount_pending"] and not mounted:
        return
    if "unmount" in private:
        status = private["unmount"].get("status")
        lifecycle["teardown_succeeded"] = type(status) is int and status == 0
        return
    lifecycle["teardown_pending"] = True
    try:
        private["unmount"] = unmount_private_proc(private)
    except Exception:
        raise
    else:
        lifecycle["teardown_pending"] = False
        status = private["unmount"].get("status")
        lifecycle["teardown_succeeded"] = type(status) is int and status == 0


def install_basic_runtime_fixtures(destination: Path, suite: str) -> dict[str, Any] | None:
    """Supply only the conventional files that frozen basic cases explicitly read.

    These are test-root inputs, not libc providers: basic's passwd/group cases
    look up the chroot's uid/gid zero, its netdb cases look up http/tcp, and its
    POSIX shared-memory/named-semaphore cases require a writable `/dev/shm`.
    """
    if suite != "basic":
        return None
    shm = destination / "dev/shm"
    shm.mkdir(parents=True)
    os.chmod(shm, 0o1777)
    etc = destination / "etc"
    etc.mkdir(exist_ok=True)
    files: dict[str, dict[str, Any]] = {}
    for name, contents in BASIC_SYSTEM_FILES.items():
        path = etc / name
        path.write_bytes(contents)
        os.chmod(path, 0o644)
        files[f"/etc/{name}"] = {"sha256": hashlib.sha256(contents).hexdigest(), "byte_length": len(contents)}
    return {"kind": "basic-system-files", "/dev/shm": {"mode": 0o1777}, "files": files}


def control_shell_launcher_source() -> str:
    """Return the candidate-visible `/bin/sh` control fixture source.

    The fixture begins under the candidate loader, then explicitly execs the
    separate host-musl loader and BusyBox beneath `/control`. It therefore
    preserves the selected product's `/lib/ld-musl-x86_64.so.1` alias while
    allowing libc APIs such as `popen`, `system`, and `wordexp` to execute the
    conventional shell pathname inside the disposable root.
    """
    return """#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
    char *command[argc + 3];
    command[0] = \"/control/ld-musl-x86_64.so.1\";
    command[1] = \"/control/busybox\";
    command[2] = \"sh\";
    for (int index = 1; index < argc; index++)
        command[index + 2] = argv[index];
    command[argc + 2] = NULL;
    execve(command[0], command, environ);
    return 127;
}
"""


def install_candidate_shell_launcher(product: Path, destination: Path) -> dict[str, Any]:
    """Build and attest the explicit candidate-side `/bin/sh` control fixture."""
    control = destination / "control"
    source = control / "candidate-shell-launcher.c"
    object_path = control / "candidate-shell-launcher.o"
    launcher = control / "candidate-shell-launcher"
    receipt = Path(str(launcher) + ".crabc-link.json")
    source_text = control_shell_launcher_source()
    source.write_text(source_text)
    os.chmod(source, 0o644)
    static = load_module("owned_os_test_shell_static", product / "share/crabc/crabc_cc_static.py")
    environment = static.clean_environment()
    driver = str(product / "bin/crabc-cc-dynamic")
    compile_command = [driver, "--dynamic-pie", "-c", str(source), "-o", str(object_path)]
    compile_status, compile_stdout, compile_stderr = run_capture(compile_command, environment)
    record: dict[str, Any] = {
        "kind": "candidate-shell-launcher/v1",
        "source": {"path": "/control/candidate-shell-launcher.c", "sha256": hashlib.sha256(source_text.encode()).hexdigest()},
        "compile": {"command": compile_command, "status": compile_status,
                    "stdout": stream_snapshot(compile_stdout), "stderr": stream_snapshot(compile_stderr)},
    }
    if compile_status != 0 or not object_path.is_file():
        raise FixtureError("candidate-visible shell fixture did not compile", {"shell_launcher": record})
    record["object"] = {"path": "/control/candidate-shell-launcher.o", "sha256": sha256(object_path)}
    link_command = [driver, "--dynamic-pie", str(object_path), "-o", str(launcher)]
    link_status, link_stdout, link_stderr = run_capture(link_command, environment)
    record["link"] = {"command": link_command, "status": link_status,
                      "stdout": stream_snapshot(link_stdout), "stderr": stream_snapshot(link_stderr)}
    if link_status != 0 or not launcher.is_file() or not receipt.is_file():
        raise FixtureError("candidate-visible shell fixture did not link", {"shell_launcher": record})
    try:
        sys.path.insert(0, str(HERE))
        import owned_posix_product_evidence as evidence
        record["link_identity"] = evidence.validate_link(product, object_path.absolute(), launcher.absolute(), receipt, "pie")
    except (OSError, RuntimeError) as error:
        raise FixtureError(f"candidate-visible shell fixture receipt is invalid: {error}", {"shell_launcher": record}) from error
    installed = destination / "bin/sh"
    retain_file(launcher, installed)
    record["launcher"] = {"path": "/control/candidate-shell-launcher", "sha256": sha256(launcher),
                          "receipt_sha256": sha256(receipt), "candidate_path": "/bin/sh",
                          "candidate_sha256": sha256(installed),
                          "argv": ["/control/ld-musl-x86_64.so.1", "/control/busybox", "sh", "<original argv[1..]>"]}
    return record


def unmount_private_devpts(record: dict[str, Any]) -> dict[str, Any]:
    """Unmount a successful fixture before the evidence leaf is returned."""
    unmount = shutil.which("umount")
    if unmount is None:
        return {"command": None, "status": "UNAVAILABLE", "stdout": stream_snapshot(b""),
                "stderr": stream_snapshot(b"pinned image lacks umount\n")}
    command = [unmount, str(record["target"])]
    status, stdout, stderr = run_capture(command, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    return {"command": command, "status": status, "stdout": stream_snapshot(stdout), "stderr": stream_snapshot(stderr)}


def install_control_character_devices(destination: Path) -> None:
    """Create only the root-local Linux character devices the sealed fixture uses."""
    for name, major, minor in CONTROL_CHARACTER_DEVICES:
        path = destination / "dev" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(major, minor))


def prepare_compile_product(product: Path, destination: Path, product_roster: list[dict[str, Any]]) -> dict[str, Any]:
    """Copy and bind one per-suite compiler/linker product before Make invokes it.

    Unlike the frozen source stage, an installed product has source-bound file
    modes. In particular, the dynamic link validator requires its CRT objects
    and archives to remain ``0644`` and its shared libc to remain ``0755``.
    The copied product is bound to the supplied roster before use and retained
    for the collector's exact post-run comparison; do not relabel those roles
    merely to make this disposable copy read-only.
    """
    copied_tree(product, destination)
    copied_payload = tree_roster(destination)
    difference = roster_difference(product_roster, copied_payload)
    if not roster_matches(product_roster, copied_payload):
        raise FixtureError("per-suite compiler product differs from the sealed supplied-product roster",
                           {"product_copy_difference": difference})
    identity = validate_dynamic_product(destination)
    return {"root": str(destination), "identity": identity, "payload": copied_payload,
            "copy_difference": difference}


def prepare_execution_root(product: Path, source: Path, destination: Path, suite: str, private_devpts: bool,
                           product_roster: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the candidate-only root plus an explicitly separate musl shell."""
    copied_tree(product, destination)
    restore_roster_modes(destination, product_roster)
    copied_payload = tree_roster(destination)
    copied_difference = roster_difference(product_roster, copied_payload)
    if not roster_matches(product_roster, copied_payload):
        raise RunnerError("per-suite product copy differs from the sealed supplied-product roster")
    # The per-suite compiler product is the source of this runtime copy. Its
    # original source-bound roster was recorded before Make began; the
    # collector compares the retained compiler copy to that roster after the
    # suite, and runtime controls live outside this payload.
    copied_identity = validate_dynamic_product(destination)
    busybox = Path("/bin/busybox")
    loader = Path("/lib/ld-musl-x86_64.so.1")
    if not busybox.is_file() or not loader.is_file():
        raise RunnerError("pinned image lacks BusyBox or its musl control loader")
    control_paths = [destination / "control",
                 destination / "dev/null", destination / "dev/zero", destination / "dev/random",
                 destination / "dev/urandom", destination / "dev/tty", destination / "etc/hosts",
                 destination / "etc/resolv.conf", destination / "dev/pts", destination / "dev/ptmx",
                 destination / "tmp", destination / "work"]
    if suite == "basic":
        control_paths.extend(destination / path for path in ("dev/shm", "etc/passwd", "etc/group", "etc/services", "bin/sh", "proc"))
    for path in control_paths:
        if path.exists() or path.is_symlink():
            raise RunnerError(f"control-plane path collides with supplied product: {path}")
    copied_tree(source, destination / "work", discard_git=True)
    (destination / "control").mkdir(exist_ok=True)
    retain_file(busybox, destination / "control/busybox")
    retain_file(loader, destination / "control/ld-musl-x86_64.so.1")
    shell_launcher = install_candidate_shell_launcher(product, destination) if suite == "basic" else None
    install_control_character_devices(destination)
    (destination / "tmp").mkdir(exist_ok=True)
    os.chmod(destination / "tmp", 0o1777)
    etc = destination / "etc"
    etc.mkdir(exist_ok=True)
    (etc / "hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    (etc / "resolv.conf").write_text("nameserver 127.0.0.1\n")
    basic_fixtures = install_basic_runtime_fixtures(destination, suite)
    devpts = None
    private_proc = None
    try:
        private_proc = reserve_private_proc_mountpoint(destination, suite)
        devpts = mount_private_devpts(destination) if private_devpts else None
        setup_roster = tree_roster(destination)
        control_delta = roster_difference(product_roster, setup_roster)
        if control_delta["missing"] or control_delta["changed"]:
            raise RunnerError("execution control plane modified the copied product payload")
        return {"root": str(destination), "product": copied_identity, "product_copy_difference": copied_difference,
                "product_payload_before": product_roster, "execution_root_after_setup": setup_roster,
                "control_additions": control_delta["unexpected"],
                "product_manifest_sha256": sha256(destination / "share/crabc/manifest.json"),
                "basic_runtime_fixtures": basic_fixtures,
                "shell_launcher": shell_launcher,
                "busybox": {"path": str(busybox), "sha256": sha256(busybox)},
                "musl_control_loader": {"path": str(loader), "sha256": sha256(loader)},
                "candidate_loader_sha256": sha256(destination / "lib/ld-crabc-x86_64.so.1"), "private_devpts": devpts,
                "private_proc": private_proc}
    except BaseException as error:
        if devpts is not None:
            devpts["unmount"] = unmount_private_devpts(devpts)
        if isinstance(error, FixtureError):
            raise
        if isinstance(error, (RunnerError, OSError)):
            control = {"private_proc": private_proc}
            if devpts is not None:
                control["private_devpts"] = devpts
            raise FixtureError(str(error), control) from error
        raise


def retain_execution_integrity(work: Path, suite: str, control: dict[str, Any], *, inspect_payload: bool = True) -> tuple[dict[str, Any], bool]:
    """Store product pre/post payloads separately from disposable controls."""
    before = control.pop("product_payload_before")
    setup = control.pop("execution_root_after_setup")
    baseline_paths = {entry["path"] for entry in before}
    control_entries = [entry for entry in setup if entry["path"] not in baseline_paths]
    before_artifact = retain_json(work, work / "records" / f"{suite}.dynamic-product-payload-before.json", {
        "schema": "crabc.x86_64-owned-os-test-product-payload/v1", "phase": "before-execution", "entries": before,
    })
    controls_artifact = retain_json(work, work / "records" / f"{suite}.execution-control-additions.json", {
        "schema": "crabc.x86_64-owned-os-test-execution-controls/v1", "entries": control_entries,
    })
    if not inspect_payload:
        integrity: dict[str, Any] = {"before": before_artifact, "after": None,
                                     "difference": {"error": "private procfs teardown failed before post-run payload inspection"},
                                     "passed": False}
        intact = False
    else:
        try:
            after, difference = product_payload_after_execution(Path(control["root"]), before, setup)
            after_artifact = retain_json(work, work / "records" / f"{suite}.dynamic-product-payload-after.json", {
                "schema": "crabc.x86_64-owned-os-test-product-payload/v1", "phase": "after-execution", "entries": after,
            })
            intact = not difference["missing"] and not difference["unexpected"] and not difference["changed"]
            integrity: dict[str, Any] = {"before": before_artifact, "after": after_artifact,
                                         "difference": difference, "passed": intact}
        except (OSError, RunnerError) as error:
            integrity = {"before": before_artifact, "after": None,
                         "difference": {"error": str(error)}, "passed": False}
            intact = False
    control["control_additions"] = controls_artifact
    control["product_payload"] = integrity
    return control, intact


def run_profile(values: argparse.Namespace) -> int:
    if values.timeout <= 0:
        raise RunnerError("--timeout must be positive")
    if values.header_jobs <= 0:
        raise RunnerError("--header-jobs must be positive")
    temporary = physical_work_directory(os.environ.get("TMPDIR", ""), "TMPDIR")
    product = physical_work_directory(values.dynamic_sysroot, "dynamic product")
    product_identity = validate_dynamic_product(product)
    source = physical_work_directory(values.os_test_root, "os-test source")
    source_identity = validate_source_root(source)
    work = Path(tempfile.mkdtemp(prefix="owned-os-test.", dir=temporary))
    report: dict[str, Any] = {"schema": SCHEMA, "passed": False, "profile": list(DEFAULT_SUITES),
                              "timeout_seconds": values.timeout, "work": str(work), "suites": []}
    # Keep each receipt by object identity before its mount call.  A suite is
    # appended only after outcome collection and payload inspection, while a
    # signal may arrive earlier with a live or uncertain procfs mount.
    private_proc_lifecycles: list[dict[str, Any]] = []
    try:
        product_roster = tree_roster(product)
        product_roster_artifact = retain_json(work, work / "records" / "supplied-product-roster.json", {
            "schema": "crabc.x86_64-owned-os-test-product-roster/v1", "entries": product_roster,
        })
        source_stage = work / "source-stage"
        staged_source = stage_pristine_source(source, source_stage, work)
        prepared_aio_suspend, aio_suspend_map = aio_suspend_preparation(source_stage)
        musl_before = musl_oracle_identity(work, "before")
        report["product"] = {**product_identity, "payload_roster": product_roster_artifact}
        report["source"] = {**source_identity, "stage": staged_source}
        report["source_preparation"] = {"aio_suspend_lifetime": {**aio_suspend_map, "sides": {}}}
        report["musl_oracle"] = {"before": musl_before, "after": None, "unchanged": False}
        for suite in DEFAULT_SUITES:
            expected, expected_artifact = retain_expected_outcomes(work, source_stage, suite)
            musl_root = work / "musl" / suite
            copied_tree(source_stage, musl_root, discard_git=True, buildable=True)
            if suite == "basic":
                report["source_preparation"]["aio_suspend_lifetime"]["sides"]["musl"] = prepare_aio_suspend_copy(
                    musl_root, "musl", prepared_aio_suspend, aio_suspend_map, work
                )
            musl_command = musl_make_command(suite, musl_root, values.header_jobs)
            musl_started = time.monotonic()
            musl_status, musl_stdout, musl_stderr = run_make(musl_command, values.timeout)
            musl_elapsed = round(time.monotonic() - musl_started, 3)
            musl_record = make_record(work, suite, "musl", musl_command, values.timeout, musl_status, musl_stdout, musl_stderr)
            musl_outcomes = collect_outcomes(musl_root, suite)
            musl_passed = suite_passed(musl_status, musl_outcomes, expected, [])
            suite_root = work / "suites" / suite
            copied_tree(source_stage, suite_root, discard_git=True, buildable=True)
            if suite == "basic":
                report["source_preparation"]["aio_suspend_lifetime"]["sides"]["dynamic"] = prepare_aio_suspend_copy(
                    suite_root, "dynamic", prepared_aio_suspend, aio_suspend_map, work
                )
            evidence = work / "evidence" / suite
            evidence.mkdir(parents=True)
            runtime = work / "runtime" / suite
            compile_product = work / "products" / suite
            command: list[str] | None = None
            status: int | str = "SETUP_ERROR"
            stdout = b""
            stderr = b""
            dynamic_record: dict[str, Any] | None = None
            control: dict[str, Any] = {"root": str(runtime), "setup_status": "ERROR"}
            proc_lifecycle: dict[str, Any] | None = None
            started = time.monotonic()
            try:
                compile_control = prepare_compile_product(product, compile_product, product_roster)
                compiler_payload = retain_json(work, work / "records" / f"{suite}.compiler-product-payload.json", {
                    "schema": "crabc.x86_64-owned-os-test-product-payload/v1", "phase": "compiler-and-linker",
                    "entries": compile_control["payload"],
                })
                control = prepare_execution_root(compile_product, suite_root, runtime, suite, suite_needs_private_devpts(suite), product_roster)
                control["compiler_product"] = {"root": compile_control["root"], "identity": compile_control["identity"],
                                                "copy_difference": compile_control["copy_difference"], "payload": compiler_payload}
                private_proc = control.get("private_proc")
                if private_proc is not None:
                    proc_lifecycle = private_proc_lifecycle(private_proc)
                    private_proc_lifecycles.append(proc_lifecycle)
                    mount_private_proc_tracked(runtime, proc_lifecycle)
                command = make_command(suite, suite_root, Path(__file__).resolve(), compile_product, evidence, runtime, values.header_jobs)
                status, stdout, stderr = run_make(command, values.timeout)
                dynamic_record = make_record(work, suite, "dynamic", command, values.timeout, status, stdout, stderr)
            except (FixtureError, RunnerError, OSError) as error:
                fixture = error.control if isinstance(error, FixtureError) else {}
                control = {**control, **fixture, "setup_status": "ERROR", "setup_error": str(error)}
                dynamic_record = retain_json(work, work / "records" / f"{suite}.dynamic.setup-error.json", {
                    "schema": "crabc.x86_64-owned-os-test-setup-error/v1", "suite": suite, "error": str(error),
                    "control": control,
                })
            finally:
                try:
                    if proc_lifecycle is not None:
                        unmount_private_proc_tracked(proc_lifecycle)
                finally:
                    private_devpts = control.get("private_devpts")
                    if private_devpts is not None and private_devpts.get("status") == 0 and "unmount" not in private_devpts:
                        private_devpts["unmount"] = unmount_private_devpts(private_devpts)
            events = evidence_events(evidence) if (evidence / "events").is_dir() else []
            outcomes = collect_outcomes(suite_root, suite)
            differences = compare_outcomes(musl_outcomes, outcomes)
            fixture_passed = (control.get("setup_status") != "ERROR" and
                              (control.get("private_devpts") is None or control["private_devpts"].get("unmount", {}).get("status") == 0) and
                              private_proc_fixture_passed(control.get("private_proc")))
            product_intact = False
            if "product_payload_before" in control and "execution_root_after_setup" in control:
                control, product_intact = retain_execution_integrity(
                    work, suite, control,
                    inspect_payload=(private_proc_lifecycle_postwalk_safe(proc_lifecycle)
                                     if proc_lifecycle is not None else private_proc_postwalk_safe(control.get("private_proc"))),
                )
            candidate_passed = suite_passed(status, outcomes, expected, events) and fixture_passed and product_intact
            report["suites"].append({"suite": suite,
                                      "expected_outcomes": expected_artifact,
                                      "musl": {**musl_record,
                                               "elapsed_seconds": musl_elapsed,
                                               "outcomes": musl_outcomes, "outcome_count": len(musl_outcomes), "passed": musl_passed},
                                      "dynamic": {"make": dynamic_record, "elapsed_seconds": round(time.monotonic() - started, 3),
                                                  "outcomes": outcomes, "outcome_count": len(outcomes), "execution_control": control,
                                                  "adapter_event_count": len(events), "adapter_errors": [event for event in events if event.get("adapter_error") or event.get("state") == "adapter-error"],
                                                  "passed": candidate_passed},
                                      "difference_count": len(differences), "differences": differences,
                                      "passed": musl_passed and candidate_passed and not differences})
        musl_after = musl_oracle_identity(work, "after")
        report["musl_oracle"] = {"before": musl_before, "after": musl_after,
                                  "unchanged": same_musl_oracle(musl_before, musl_after)}
        report["passed"] = report["musl_oracle"]["unchanged"] and all(suite["passed"] for suite in report["suites"])
    finally:
        report_path = work / "os-test.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        live_proc_mounts = {
            Path(lifecycle["receipt"]["mountpoint"])
            for lifecycle in private_proc_lifecycles
            if not private_proc_lifecycle_postwalk_safe(lifecycle)
        }
        make_evidence_host_readable(work, skip_roots=live_proc_mounts)
        print(f"owned os-test evidence: {work}")
    return 0 if report["passed"] else 1


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--product", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--source-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--evidence", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--runtime-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=SUITE_TIMEOUT_SECONDS)
    parser.add_argument("--header-jobs", type=int, default=8,
                        help="bounded parallel jobs for compile-only include and namespace suites (default: 8)")
    parser.add_argument("--os-test-root", type=Path,
                        default=ROOT / ".work/x86_64/source-oracles" / f"os-test-{OS_TEST_REVISION}")
    parser.add_argument("dynamic_sysroot", nargs="?")
    values, remainder = parser.parse_known_args(arguments)
    if values.adapter:
        values.remaining = remainder
        if not (values.product and values.source_root and values.evidence and values.runtime_root):
            parser.error("internal adapter arguments are incomplete")
    elif remainder or values.dynamic_sysroot is None:
        parser.error("one supplied dynamic sysroot is required")
    return values


def main(arguments: list[str]) -> int:
    values = parse_arguments(arguments)
    try:
        return adapter(arguments) if values.adapter else run_profile(values)
    except RunnerError as error:
        print(f"owned os-test: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
