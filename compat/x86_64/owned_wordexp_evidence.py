#!/usr/bin/env python3
"""Collect and replay bounded installed-product wordexp evidence.

The controlled shell is a sealed external execution fixture.  It is never an
owned runtime input or a claim that crabc implements shell semantics.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_crypt_runtime_evidence as copies
import owned_dynamic_qualification as qualification
import owned_posix_product_evidence as products
import run_qualification_manifest as native_qualification

SCHEMA = "crabc.x86_64-owned-wordexp-products/v1"
SOURCE_MOUNT = "/workspace"
TARGET = "x86_64-unknown-linux-musl"
PROBE = "compat/x86_64/owned_wordexp_probe.c"
DOC = "compat/x86_64/owned-wordexp.md"
RUNNER = "compat/x86_64/run_owned_wordexp.sh"
LEGACY_RUNNER = "compat/x86_64/run_libc_owned_wordexp.sh"
HEADERS = ("errno.h", "wordexp.h", "stdio.h", "stdlib.h", "string.h", "features.h", "bits/alltypes.h")
SOURCES = (PROBE, DOC, RUNNER, LEGACY_RUNNER, "compat/x86_64/owned_wordexp_evidence.py",
           "compat/x86_64/owned_posix_product_evidence.py", "compat/x86_64/owned_crypt_runtime_evidence.py",
           "compat/x86_64/owned_dynamic_qualification.py", "compat/x86_64/run_qualification_manifest.py",
           "compat/upstreams.toml", "docker/x86_64-musl-oracle-gcc")
SHELL_CASES = ("normal", "missing", "inaccessible", "invalid")
MODE_SPECS = {
    "static-et-exec": ("static", "static", "consumer-static-et-exec"),
    "static-pie": ("static-pie", "static", "consumer-static-pie"),
    "dynamic-pie-kernel": ("pie", "dynamic", "consumer-pie"),
    "dynamic-pie-direct": ("pie", "dynamic", "consumer-pie"),
    "dynamic-non-pie-kernel": ("non-pie", "dynamic", "consumer-non-pie"),
    "dynamic-non-pie-direct": ("non-pie", "dynamic", "consumer-non-pie"),
}


class EvidenceError(RuntimeError):
    """A retained wordexp product record is incomplete or has changed."""


def fail(message: str) -> None:
    raise EvidenceError(message)


def _physical(path: Path, description: str, *, directory: bool | None = None) -> Path:
    if ".." in path.parts:
        fail(f"{description} has lexical parent traversal: {path}")
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    try:
        for component in path.parts[1:-1]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                fail(f"{description} traverses a symlink: {path}")
        mode = path.lstat().st_mode
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {path}") from error
    if directory is True and not stat.S_ISDIR(mode):
        fail(f"{description} is not a physical directory: {path}")
    if directory is False and not stat.S_ISREG(mode):
        fail(f"{description} is not a physical regular file: {path}")
    return path


def _relative(value: str, description: str) -> str:
    if not isinstance(value, str):
        fail(f"{description} must be a string")
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{description} is unsafe: {value}")
    return path.as_posix()


def _sha(path: Path) -> str:
    path = _physical(path, "hashed artifact", directory=False)
    result = sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(block)
    except OSError as error:
        raise EvidenceError(f"cannot hash artifact: {path}") from error
    return result.hexdigest()


def _mode(path: Path) -> int:
    return stat.S_IMODE(_physical(path, "mode-recorded artifact").lstat().st_mode)


def _file_identity(root: Path, relative: str, description: str) -> dict[str, Any]:
    relative = _relative(relative, description)
    path = _physical(root / relative, description, directory=False)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise EvidenceError(f"{description} escapes execution root") from error
    return {"path": relative, "sha256": _sha(path), "mode": _mode(path)}


def _alias_identity(root: Path, relative: str, description: str) -> dict[str, str]:
    relative = _relative(relative, description)
    path = _physical(root / relative, description)
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISLNK(mode):
            fail(f"{description} is not a symbolic link: {relative}")
        target = os.readlink(path)
    except OSError as error:
        raise EvidenceError(f"{description} is unreadable: {relative}") from error
    return {"path": relative, "target": target}


def _walk_root(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    aliases: set[str] = set()
    try:
        entries = sorted(root.rglob("*"))
    except OSError as error:
        raise EvidenceError(f"cannot enumerate execution root: {root}") from error
    for path in entries:
        relative = path.relative_to(root).as_posix()
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise EvidenceError(f"cannot inspect execution root entry: {path}") from error
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISREG(mode):
            files.add(relative)
        elif stat.S_ISLNK(mode):
            aliases.add(relative)
        else:
            fail(f"execution root contains non-file entry: {relative}")
    return files, aliases


def _exact_dict(value: object, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{description} fields drifted")
    return value


def record_execution_root(
    execution_root: Path,
    *,
    product_files: Mapping[str, str],
    product_aliases: Mapping[str, str],
    consumers: Mapping[str, str],
    fixture_files: Mapping[str, str],
) -> dict[str, Any]:
    """Seal every regular file and alias in an actually executed root.

    Callers supply the product manifest's exact file/alias roster.  Consumers
    and external fixture files are explicitly named, so no unrecorded loader,
    shell, or library file can enter an execution root unnoticed.
    """
    root = _physical(execution_root, "execution root", directory=True)
    def roster(values: Mapping[str, str], description: str) -> dict[str, dict[str, Any]]:
        if not isinstance(values, Mapping) or not values:
            fail(f"{description} roster is empty or malformed")
        result: dict[str, dict[str, Any]] = {}
        for name, relative in values.items():
            if not isinstance(name, str) or not name:
                fail(f"{description} has an invalid name")
            if name in result:
                fail(f"{description} duplicates a name")
            result[name] = _file_identity(root, relative, f"{description} {name}")
        return result

    product = roster(product_files, "execution product file") if product_files else {}
    consumer = roster(consumers, "execution consumer")
    fixture = roster(fixture_files, "execution fixture")
    relative_files = [entry["path"] for values in (product, consumer, fixture) for entry in values.values()]
    if len(relative_files) != len(set(relative_files)):
        fail("execution file rosters overlap")
    aliases: dict[str, dict[str, str]] = {}
    for name, relative in product_aliases.items():
        if not isinstance(name, str) or not name or name in aliases:
            fail("execution product alias roster is malformed")
        aliases[name] = _alias_identity(root, relative, f"execution product alias {name}")
    alias_paths = [entry["path"] for entry in aliases.values()]
    if len(alias_paths) != len(set(alias_paths)) or set(alias_paths) & set(relative_files):
        fail("execution alias roster overlaps or duplicates a file")
    observed_files, observed_aliases = _walk_root(root)
    if observed_files != set(relative_files):
        fail("execution root file roster drifted")
    if observed_aliases != set(alias_paths):
        fail("execution root alias roster drifted")
    return {
        "root": str(root),
        "product_files": product,
        "product_aliases": aliases,
        "consumers": consumer,
        "fixtures": fixture,
    }


def validate_execution_root(execution_root: Path, record: object) -> dict[str, Any]:
    root = _physical(execution_root, "execution root", directory=True)
    record = _exact_dict(record, {"root", "product_files", "product_aliases", "consumers", "fixtures"},
                         "execution root record")
    if record["root"] != str(root):
        fail("execution root path drifted")
    for key in ("product_files", "consumers", "fixtures"):
        if not isinstance(record[key], dict):
            fail(f"execution root {key} roster is malformed")
    if not isinstance(record["product_aliases"], dict):
        fail("execution root product aliases roster is malformed")
    replay = record_execution_root(
        root,
        product_files={name: entry.get("path") if isinstance(entry, dict) else "" for name, entry in record["product_files"].items()},
        product_aliases={name: entry.get("path") if isinstance(entry, dict) else "" for name, entry in record["product_aliases"].items()},
        consumers={name: entry.get("path") if isinstance(entry, dict) else "" for name, entry in record["consumers"].items()},
        fixture_files={name: entry.get("path") if isinstance(entry, dict) else "" for name, entry in record["fixtures"].items()},
    )
    if replay != record:
        fail("execution root bytes, modes, aliases, or roster drifted")
    return replay


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        fail(f"refusing to replace evidence artifact: {path}")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise EvidenceError(f"cannot write evidence artifact: {path}") from error


def _mounted(root: Path, path: Path) -> str:
    path = _physical(path, "recorded checkout artifact")
    try:
        return str(Path(SOURCE_MOUNT) / path.relative_to(root))
    except ValueError as error:
        raise EvidenceError(f"recorded artifact escapes checkout: {path}") from error


def _checkout_identity(root: Path, path: Path, description: str) -> dict[str, Any]:
    path = _physical(path, description, directory=False)
    return {"path": _mounted(root, path), "sha256": _sha(path), "mode": _mode(path)}


def _tool_identity(path: Path, description: str) -> dict[str, Any]:
    # Command names such as /usr/sbin/chroot can be pinned-image symlinks.
    # Seal their resolved regular executable, while command argv retains the
    # executable spelling that was actually invoked.
    path = _physical(Path(os.path.realpath(path)), description, directory=False)
    return {"path": str(path), "sha256": _sha(path), "mode": _mode(path)}


def _run(work: Path, label: str, argv: list[str], *, environment: Mapping[str, str] | None = None,
         cwd: Path | None = None, required: bool = True) -> dict[str, Any]:
    """Run exactly one producer or execution command and retain all streams."""
    if not argv or not all(isinstance(argument, str) for argument in argv):
        fail(f"{label} command is malformed")
    if environment is None or not isinstance(environment, Mapping) or not all(isinstance(key, str) and isinstance(item, str)
                                      for key, item in environment.items()):
        fail(f"{label} command environment must be explicit")
    directory = work / "commands"
    directory.mkdir(parents=True, exist_ok=True)
    command_path = directory / f"{label}.argv.json"
    environment_path = directory / f"{label}.environment.json"
    stdout_path = directory / f"{label}.stdout"
    stderr_path = directory / f"{label}.stderr"
    status_path = directory / f"{label}.status"
    _write_json(command_path, argv)
    env = dict(environment)
    _write_json(environment_path, env)
    try:
        completed = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as error:
        raise EvidenceError(f"cannot execute {label}: {error}") from error
    stdout_path.write_bytes(completed.stdout)
    stderr_path.write_bytes(completed.stderr)
    status_path.write_text(f"{completed.returncode}\n", encoding="ascii")
    record = {
        "argv": _checkout_identity(ROOT, command_path, f"{label} argv"),
        "environment": _checkout_identity(ROOT, environment_path, f"{label} environment"),
        "stdout": _checkout_identity(ROOT, stdout_path, f"{label} stdout"),
        "stderr": _checkout_identity(ROOT, stderr_path, f"{label} stderr"),
        "status": _checkout_identity(ROOT, status_path, f"{label} status"),
    }
    if required and completed.returncode != 0:
        fail(f"{label} failed with status {completed.returncode}; retained output is {directory}")
    return record


def require_exact_command(argv_path: Path, expected_argv: list[str], expected_environment: Mapping[str, str],
                          description: str) -> None:
    """Reject an arbitrary successful command record at a named seam."""
    try:
        argv = json.loads(_physical(argv_path, f"{description} argv", directory=False).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{description} argv is not valid JSON") from error
    if argv != expected_argv:
        fail(f"{description} argv differs from its canonical command")
    if not isinstance(expected_environment, Mapping) or not all(isinstance(key, str) and isinstance(value, str)
                                                                  for key, value in expected_environment.items()):
        fail(f"{description} expected environment is malformed")


def evidence_environment(work: Path) -> dict[str, str]:
    """Return the complete non-producer environment for retained commands."""
    work = _physical(work, "wordexp command work", directory=True)
    return {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1", "TZ": "UTC", "TMPDIR": str(work)}


def producer_environment(work: Path) -> dict[str, str]:
    """Keep the build invocation explicit without opening ambient C inputs."""
    result = evidence_environment(work)
    # Git's safe-directory configuration is source-control plumbing only.  The
    # builders themselves choose pinned Cargo/Rust state and target inputs.
    for name in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"):
        if name in os.environ:
            result[name] = os.environ[name]
    return result


def _mounted_environment(root: Path, work: Path) -> dict[str, str]:
    return {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1", "TZ": "UTC",
            "TMPDIR": _mounted(root, work)}


def _native_requirements() -> None:
    if os.uname().sysname != "Linux" or os.uname().machine not in {"x86_64", "amd64"}:
        fail("requires native Linux/x86-64")
    if os.geteuid() != 0:
        fail("requires root for private chroot execution roots")
    if ROOT != Path(SOURCE_MOUNT):
        fail("native wordexp evidence must run from the fixed /workspace source mount")


def _work_directory() -> Path:
    raw = os.environ.get("TMPDIR")
    if not raw:
        fail("requires repository-local TMPDIR")
    parent = _physical(Path(raw), "TMPDIR", directory=True)
    checkout = _physical(ROOT, "checkout", directory=True)
    if not parent.is_relative_to(checkout / ".work"):
        fail(f"TMPDIR physically escapes checkout .work: {parent}")
    return Path(tempfile.mkdtemp(prefix="owned-wordexp-products.", dir=parent))


def _copy_regular(source: Path, destination: Path, description: str) -> None:
    source = _physical(source, f"{description} source", directory=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        fail(f"{description} destination already exists: {destination}")
    try:
        shutil.copyfile(source, destination, follow_symlinks=True)
        shutil.copymode(source, destination, follow_symlinks=True)
    except OSError as error:
        raise EvidenceError(f"cannot copy {description}: {source}") from error
    if _sha(source) != _sha(destination) or _mode(source) != _mode(destination):
        fail(f"{description} copy differs from its source")


def _copy_dynamic_product(product: Path, execution_root: Path) -> tuple[dict[str, str], dict[str, str]]:
    product, manifest, files, aliases = copies.dynamic_product(product)
    if execution_root.exists() or execution_root.is_symlink():
        fail(f"execution root already exists: {execution_root}")
    try:
        shutil.copytree(product, execution_root, symlinks=True, copy_function=shutil.copy2)
    except OSError as error:
        raise EvidenceError(f"cannot copy dynamic product into execution root") from error
    # The shared manifest checker must accept the untouched product copy before
    # a consumer or external fixture enters the root.  Do not recover from a
    # failed exact-tree assertion: a product copy mismatch is fatal evidence.
    try:
        copies.assert_execution_tree(execution_root, files, aliases, execution_root / "share/crabc/manifest.json")
        copies.copied_file(manifest, execution_root / "share/crabc/manifest.json", "wordexp copied manifest")
        for name in files:
            copies.copied_file(product / name, execution_root / name, f"wordexp copied product {name}")
        for name, target in aliases.items():
            copies.copied_alias(product / name, execution_root / name, target, f"wordexp copied alias {name}")
    except copies.CryptRuntimeEvidenceError as error:
        raise EvidenceError(str(error)) from error
    product_files = {"manifest": "share/crabc/manifest.json"}
    product_files.update({f"product:{name}": name for name in files})
    product_aliases = {f"product:{name}": name for name in aliases}
    return product_files, product_aliases


def _ldd_closure_candidates(text: str) -> tuple[Path, ...]:
    """Parse every physical library path advertised by the sealed ``ldd`` run."""
    result: list[Path] = []
    for line in text.splitlines():
        fields = line.split()
        candidate = fields[0] if fields and fields[0].startswith("/") else (
            fields[2] if len(fields) >= 3 and fields[1] == "=>" and fields[2].startswith("/") else None
        )
        if candidate is None:
            # The virtual VDSO has no copied filesystem input. Any other line
            # would make the actual shell closure ambiguous.
            if fields and fields[0].startswith("linux-vdso"):
                continue
            fail(f"controlled shell ldd line is not a physical dependency: {line!r}")
        path = Path(candidate)
        if not path.is_absolute() or ".." in path.parts:
            fail("controlled shell ldd dependency path is unsafe")
        if path not in result:
            result.append(path)
    if not result:
        fail("controlled shell ldd closure is empty")
    return tuple(result)


def _shell_dependencies(work: Path, shell: Path, ldd: str) -> tuple[list[tuple[str, Path]], dict[str, Any]]:
    record = _run(work, "controlled-shell-ldd", [ldd, str(shell)], environment=evidence_environment(work))
    output = _local_mounted(ROOT, record["stdout"]["path"], "controlled shell ldd stdout")
    try:
        text = output.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError("controlled shell ldd output is not text") from error
    closure = _ldd_closure_candidates(text)
    if closure != (Path("/lib/ld-musl-x86_64.so.1"),):
        fail("controlled shell ldd closure differs from the one pinned loader fixture")
    # ``ldd`` establishes the shell's required in-root pathname. The pinned
    # qualification loader supplies those bytes, so the fixture never imports
    # Alpine's bootstrap loader just because it ran the observation command.
    loader = _physical(Path(os.path.realpath(native_qualification.MUSL_RUNTIME_PATHS["loader"])),
                       "pinned musl shell loader", directory=False)
    return [("lib/ld-musl-x86_64.so.1", loader)], record


def _prepare_fixture_source(work: Path, ldd: str) -> tuple[Path, dict[str, str], dict[str, Any], dict[str, Any]]:
    shell = Path(os.path.realpath("/bin/sh"))
    shell = _physical(shell, "controlled /bin/sh", directory=False)
    if not os.access(shell, os.X_OK):
        fail("controlled /bin/sh is not executable")
    source = work / "external-shell-fixture"
    source.mkdir()
    _copy_regular(shell, source / "bin/sh", "controlled shell")
    files = {"shell": "bin/sh"}
    source_records = {"shell": _checkout_identity(ROOT, source / "bin/sh", "retained controlled shell")}
    dependencies, ldd_record = _shell_dependencies(work, shell, ldd)
    for index, (relative, dependency) in enumerate(dependencies):
        # Preserve absolute fixture names inside the chroot while the retained
        # source copy gives host readers a path that never needs ambient /lib.
        _copy_regular(dependency, source / relative, f"controlled shell dependency {dependency}")
        name = f"dependency:{index}"
        files[name] = relative
        source_records[name] = _checkout_identity(ROOT, source / relative, f"retained shell dependency {dependency}")
    (source / "dev").mkdir(exist_ok=True)
    null = source / "dev/null"
    null.write_bytes(b"")
    null.chmod(0o666)
    files["null"] = "dev/null"
    source_records["null"] = _checkout_identity(ROOT, null, "retained private null fixture")
    return source, files, source_records, ldd_record


def _copy_fixture(source: Path, files: Mapping[str, str], execution_root: Path, shell_case: str) -> tuple[dict[str, str], tuple[str, ...]]:
    copied: dict[str, str] = {}
    replaced_aliases: list[str] = []
    for name, relative in files.items():
        if shell_case == "missing" and name == "shell":
            continue
        input_path = source / relative
        output_path = execution_root / relative
        if output_path.is_symlink():
            # The pinned image's /bin/sh is musl-linked and its external
            # loader path overlaps the product's compatibility alias.  The
            # candidate always enters through /lib/ld-crabc-x86_64.so.1;
            # replace only that alias with a fully sealed external fixture.
            replaced_aliases.append(relative)
            output_path.unlink()
        _copy_regular(input_path, output_path, f"execution shell fixture {name}")
        copied[name] = relative
    shell = execution_root / "bin/sh"
    if shell_case == "normal":
        pass
    elif shell_case == "missing":
        if shell.exists() or shell.is_symlink():
            fail("missing shell fixture unexpectedly has /bin/sh")
    elif shell_case == "inaccessible":
        shell.chmod(0o644)
    elif shell_case == "invalid":
        shell.write_bytes(b"not an executable shell image\n")
        shell.chmod(0o755)
    else:
        fail(f"unknown controlled shell case: {shell_case}")
    return copied, tuple(sorted(replaced_aliases))


def _status_zero(root: Path, record: Mapping[str, Any], description: str) -> None:
    value = record.get("status")
    if not isinstance(value, dict):
        fail(f"{description} has no status record")
    path = _local_mounted(root, value.get("path"), f"{description} status")
    if path.read_bytes() != b"0\n":
        fail(f"{description} did not succeed")


def _local_mounted(root: Path, value: object, description: str) -> Path:
    if not isinstance(value, str) or not value.startswith(SOURCE_MOUNT + "/"):
        fail(f"{description} does not use the fixed source mount")
    relative = Path(value).relative_to(SOURCE_MOUNT)
    if any(part in {"", ".", ".."} for part in relative.parts):
        fail(f"{description} has an unsafe mounted path")
    return _physical(root / relative, description)


def _identity_current(root: Path, value: object, description: str) -> Path:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "mode"}:
        fail(f"{description} identity fields drifted")
    path = _local_mounted(root, value["path"], description)
    if not stat.S_ISREG(path.lstat().st_mode) or value != _checkout_identity(root, path, description):
        fail(f"{description} identity drifted")
    return path


def _installed_tool_roster(dynamic: Path, static: Path | None) -> dict[str, dict[str, Any]]:
    """Resolve source compiler/LLD before the first installed consumption."""
    helper = _physical(dynamic / "share/crabc/crabc_cc_static.py", "installed compiler helper", directory=False)
    specification = importlib.util.spec_from_file_location("owned_wordexp_installed_compiler", helper)
    if specification is None or specification.loader is None:
        fail("installed compiler helper cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    try:
        specification.loader.exec_module(module)
        compiler = Path(module.compiler())
        linker = Path(module.linker())
    except (AttributeError, OSError, RuntimeError) as error:
        raise EvidenceError("installed compiler helper cannot resolve fixed tools") from error
    finally:
        sys.modules.pop(specification.name, None)
    roster = {
        "dynamic-driver": _tool_identity(dynamic / "bin/crabc-cc-dynamic", "installed dynamic driver"),
        "compiler": _tool_identity(compiler, "pinned source compiler"),
        "linker": _tool_identity(linker, "installed linker"),
        "oracle-compiler": _tool_identity(Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl oracle compiler"),
        "chroot": _tool_identity(Path("/usr/sbin/chroot"), "chroot"),
        "timeout": _tool_identity(Path("/usr/bin/timeout"), "timeout"),
        "ldd": _tool_identity(Path("/usr/bin/ldd"), "ldd"),
        "shell": _tool_identity(Path(os.path.realpath("/bin/sh")), "controlled shell"),
    }
    if static is not None:
        roster["static-driver"] = _tool_identity(static / "bin/crabc-cc", "installed static driver")
    return roster


def _fixture_record(root: Path, fixture_root: Path, files: Mapping[str, str], records: Mapping[str, Any],
                    ldd_record: Mapping[str, Any]) -> dict[str, Any]:
    fixture_root = _physical(fixture_root, "sealed external shell fixture root", directory=True)
    expected = set(files.values())
    observed, aliases = _walk_root(fixture_root)
    if observed != expected or aliases:
        fail("sealed external shell fixture roster differs")
    current = {name: _checkout_identity(root, fixture_root / relative, f"sealed fixture {name}")
               for name, relative in files.items()}
    if dict(records) != current:
        fail("sealed external shell fixture records differ")
    return {"root": _mounted(root, fixture_root), "files": current, "ldd": dict(ldd_record)}


def _input_seal(root: Path, dynamic: Path, static: Path | None, tools: Mapping[str, Any],
                oracle: Mapping[str, Any], fixture: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sources": {source: _checkout_identity(root, root / source, f"wordexp source {source}") for source in SOURCES},
        "products": {"dynamic": _product_record(root, dynamic, "dynamic"),
                     "static": _product_record(root, static, "static") if static is not None else None},
        "tools": dict(tools), "oracle": dict(oracle), "fixture": dict(fixture),
    }


def _products(dynamic: Path | None, static: Path | None, work: Path) -> tuple[Path, Path | None, bool]:
    built = dynamic is None
    if dynamic is None:
        dynamic = work / "owned-dynamic-product"
        _run(work, "build-dynamic", [sys.executable, str(ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"),
                                      "--output", str(dynamic)], environment=producer_environment(work))
    dynamic = _physical(dynamic, "selected dynamic product", directory=True)
    try:
        products._validate_dynamic_product(dynamic)
    except products.ProductEvidenceError as error:
        raise EvidenceError(f"selected dynamic product is invalid: {error}") from error
    if static is None and built:
        static = work / "owned-static-product"
        _run(work, "build-static", [sys.executable, str(ROOT / "scripts/build_x86_64_owned_sysroot.py"),
                                     "--output", str(static)], environment=producer_environment(work))
    if static is not None:
        static = _physical(static, "selected static product", directory=True)
        try:
            products._validate_static_product(static)
        except products.ProductEvidenceError as error:
            raise EvidenceError(f"selected static product is invalid: {error}") from error
    return dynamic, static, built


def _product_record(root: Path, product: Path, kind: str) -> dict[str, Any]:
    try:
        manifest, files = (products._validate_dynamic_product(product) if kind == "dynamic"
                           else products._validate_static_product(product))
    except products.ProductEvidenceError as error:
        raise EvidenceError(f"{kind} product validation failed: {error}") from error
    return {"root": _mounted(root, product), "manifest": _checkout_identity(root, manifest, f"{kind} manifest"),
            "files": dict(sorted(files.items()))}


def _link_validate(root: Path, work: Path, product: Path, workload: Path, executable: Path,
                   linkage: str, label: str) -> dict[str, Any]:
    receipt = Path(str(executable) + ".crabc-link.json")
    try:
        validated = products.validate_link(product, workload, executable, receipt, linkage)
    except products.ProductEvidenceError as error:
        raise EvidenceError(f"{label} installed link validation failed: {error}") from error
    path = work / "links" / f"{label}.validated.json"
    _write_json(path, validated)
    try:
        receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} link receipt is not JSON") from error
    linker = receipt_value.get("resolved_linker")
    if not isinstance(linker, dict) or set(linker) != {"path", "sha256"}:
        fail(f"{label} link receipt linker is malformed")
    linker_path = _physical(Path(linker["path"]), f"{label} resolved linker", directory=False)
    if linker != {"path": str(linker_path), "sha256": _sha(linker_path)}:
        fail(f"{label} resolved linker identity differs")
    return {"linkage": linkage, "executable": _checkout_identity(root, executable, f"{label} executable"),
            "receipt": _checkout_identity(root, receipt, f"{label} link receipt"),
            "validated": _checkout_identity(root, path, f"{label} retained link validation"),
            "linker": linker}


def _run_shell_case(work: Path, root: Path, *, label: str, mode: str, candidate: Path, oracle: Path,
                    dynamic_product: Path | None, fixture_source: Path, fixture_files: Mapping[str, str],
                    fixture_records: Mapping[str, Any]) -> dict[str, Any]:
    execution = work / "execution" / label
    if dynamic_product is not None:
        product_files, product_aliases = _copy_dynamic_product(dynamic_product, execution)
    else:
        execution.mkdir(parents=True)
        product_files, product_aliases = {}, {}
    consumer_name = MODE_SPECS[mode][2]
    _copy_regular(candidate, execution / consumer_name, "execution candidate")
    _copy_regular(oracle, execution / "oracle", "execution pinned-musl oracle")
    copied_fixture, replaced_aliases = _copy_fixture(fixture_source, fixture_files, execution, label.rsplit("-", 1)[1])
    for alias_name, alias_path in tuple(product_aliases.items()):
        if alias_path in replaced_aliases:
            del product_aliases[alias_name]
    if replaced_aliases and set(replaced_aliases) != {"lib/ld-musl-x86_64.so.1"}:
        fail("external shell fixture replaced an unexpected product alias")
    execution_record = record_execution_root(
        execution, product_files=product_files, product_aliases=product_aliases,
        consumers={"candidate": consumer_name, "oracle": "oracle"}, fixture_files=copied_fixture,
    )
    shell_case = label.rsplit("-", 1)[1]
    argument = [] if shell_case == "normal" else ["--shell-unavailable"]
    command_environment = {"CRABC_WORDEXP": "bar baz"}
    def invocation(program: str, direct: bool) -> list[str]:
        prefix = ["/usr/bin/timeout", "20", "/usr/sbin/chroot", str(execution)]
        if direct:
            prefix += ["/lib/ld-crabc-x86_64.so.1", f"/{program}"]
        else:
            prefix += [f"/{program}"]
        return prefix + argument
    direct = mode.endswith("-direct")
    oracle_result = _run(work, f"{label}-oracle", invocation("oracle", False), environment=command_environment)
    candidate_result = _run(work, f"{label}-candidate", invocation(consumer_name, direct), environment=command_environment)
    _status_zero(root, oracle_result, f"{label} pinned-musl oracle")
    _status_zero(root, candidate_result, f"{label} candidate")
    oracle_stdout = _identity_current(root, oracle_result["stdout"], f"{label} oracle stdout")
    candidate_stdout = _identity_current(root, candidate_result["stdout"], f"{label} candidate stdout")
    oracle_stderr = _identity_current(root, oracle_result["stderr"], f"{label} oracle stderr")
    candidate_stderr = _identity_current(root, candidate_result["stderr"], f"{label} candidate stderr")
    expected = b"owned-wordexp: PASS\n" if shell_case == "normal" else b"owned-wordexp-shell-unavailable: PASS\n"
    if oracle_stdout.read_bytes() != expected or candidate_stdout.read_bytes() != expected:
        fail(f"{label} did not produce its exact expected transcript")
    if oracle_stdout.read_bytes() != candidate_stdout.read_bytes() or oracle_stderr.read_bytes() != candidate_stderr.read_bytes():
        fail(f"{label} candidate differs from pinned-musl oracle")
    execution_record["root"] = _mounted(root, execution)
    return {"mode": mode, "shell_case": shell_case, "execution": execution_record,
            "consumer_sources": {"candidate": _checkout_identity(root, candidate, "candidate consumer source"),
                                 "oracle": _checkout_identity(root, oracle, "oracle consumer source")},
            "external_alias_overrides": list(replaced_aliases), "oracle": oracle_result,
            "candidate": candidate_result, "expected_stdout": expected.decode("ascii")}


def _validate_header_trace(root: Path, trace: Path, dynamic: Path) -> dict[str, Any]:
    text = trace.read_text(encoding="utf-8", errors="strict")
    for header in HEADERS:
        expected = _mounted(root, dynamic / "usr/include" / header)
        if expected not in text:
            fail(f"installed header trace omitted {header}")
    return _checkout_identity(root, trace, "installed wordexp header trace")


def _capture_oracle_inputs(work: Path) -> dict[str, Any]:
    """Capture the shared independently pinned musl oracle before linking."""
    try:
        qualified = qualification.capture_oracle(work)
        qualification.require_live_oracle(work, qualified)
    except qualification.QualificationError as error:
        raise EvidenceError(f"pinned musl qualification input is unavailable: {error}") from error
    source = _physical(Path("/opt/musl-1.2.6/lib/libc.a"), "pinned musl static libc", directory=False)
    loader_path = Path(native_qualification.MUSL_RUNTIME_PATHS["loader"])
    loader = {"source_path": str(loader_path), "identity": _tool_identity(loader_path, "pinned musl loader")}
    retained = work / "pinned-musl-static-libc.a"
    _copy_regular(source, retained, "pinned musl static libc")
    return {"qualification": qualified, "loader": loader,
            "static_libc": {"native": _tool_identity(source, "pinned musl static libc"),
                            "retained": _checkout_identity(ROOT, retained, "retained pinned musl static libc")}}


def collect(dynamic: Path | None, static: Path | None) -> Path:
    _native_requirements()
    work = _work_directory()
    try:
        dynamic, static, built = _products(dynamic, static, work)
        tools_before = _installed_tool_roster(dynamic, static)
        oracle_inputs = _capture_oracle_inputs(work)
        fixture_source, fixture_files, fixture_records, fixture_ldd = _prepare_fixture_source(work, tools_before["ldd"]["path"])
        fixture = _fixture_record(ROOT, fixture_source, fixture_files, fixture_records, fixture_ldd)
        before = _input_seal(ROOT, dynamic, static, tools_before, oracle_inputs, fixture)

        dynamic_driver = dynamic / "bin/crabc-cc-dynamic"
        static_driver = static / "bin/crabc-cc" if static else None
        oracle_compiler = Path(tools_before["oracle-compiler"]["path"])
        header_trace = _run(work, "installed-header-trace", [tools_before["compiler"]["path"], "-nostdinc", "-isystem",
                            str(dynamic / "usr/include"), "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
                            "-fPIE", "-std=c11", "-D_GNU_SOURCE", "-E", "-H", str(ROOT / PROBE)],
                            environment=evidence_environment(work))
        header_trace_path = _local_mounted(ROOT, header_trace["stderr"]["path"], "installed header trace stderr")
        header = _validate_header_trace(ROOT, header_trace_path, dynamic)
        workload = work / "workload.o"
        compile_record = _run(work, "compile-workload", [str(dynamic_driver), "--dynamic-pie", "-std=c11",
                              "-D_GNU_SOURCE", "-fno-builtin", "-c", str(ROOT / PROBE), "-o", str(workload)],
                              environment=evidence_environment(work))
        _physical(workload, "installed wordexp workload", directory=False)
        oracle = work / "pinned-musl-static-et-exec"
        oracle_link = _run(work, "pinned-musl-link", [str(oracle_compiler), "-static", "-fno-pie", "-no-pie",
                           str(workload), "-o", str(oracle)], environment=evidence_environment(work))
        _physical(oracle, "pinned-musl wordexp oracle", directory=False)
        links: dict[str, Any] = {}
        candidates: dict[str, tuple[Path, Path | None]] = {}
        if static is not None and static_driver is not None:
            for mode, flag, linkage in (("static-et-exec", "-static", "static"), ("static-pie", "-static-pie", "static-pie")):
                binary = work / MODE_SPECS[mode][2]
                command = _run(work, f"link-{mode}", [str(static_driver), flag, "--link-receipt",
                               f"{binary.name}.crabc-link.json", str(workload), "-o", str(binary)], cwd=work,
                               environment=evidence_environment(work))
                links[mode] = _link_validate(ROOT, work, static, workload, binary, linkage, mode)
                links[mode]["command"] = command
                candidates[mode] = (binary, None)
        for mode, flag, linkage in (("dynamic-pie-kernel", "--dynamic-pie", "pie"),
                                    ("dynamic-non-pie-kernel", "--dynamic-non-pie", "non-pie")):
            base = "dynamic-pie" if linkage == "pie" else "dynamic-non-pie"
            binary = work / base
            command = _run(work, f"link-{base}", [str(dynamic_driver), flag, str(workload), "-o", str(binary)],
                           environment=evidence_environment(work))
            links[base] = _link_validate(ROOT, work, dynamic, workload, binary, linkage, base)
            links[base]["command"] = command
            for entry in (f"{base}-kernel", f"{base}-direct"):
                candidates[entry] = (binary, dynamic)
        sealed_linker = {"path": tools_before["linker"]["path"], "sha256": tools_before["linker"]["sha256"]}
        if any(link["linker"] != sealed_linker for link in links.values()):
            fail("installed link receipt differs from the pre-sealed linker")
        cells: dict[str, Any] = {}
        for mode, (candidate, dynamic_root) in candidates.items():
            for shell_case in SHELL_CASES:
                label = f"{mode}-{shell_case}"
                cells[label] = _run_shell_case(work, ROOT, label=label, mode=mode, candidate=candidate, oracle=oracle,
                                                dynamic_product=dynamic_root, fixture_source=fixture_source,
                                                fixture_files=fixture_files, fixture_records=fixture_records)
        try:
            qualification.require_live_oracle(work, oracle_inputs["qualification"])
        except qualification.QualificationError as error:
            raise EvidenceError(f"pinned musl oracle changed during collection: {error}") from error
        if _tool_identity(Path("/opt/musl-1.2.6/lib/libc.a"), "post-run pinned musl static libc") != oracle_inputs["static_libc"]["native"]:
            fail("pinned musl static libc changed during collection")
        if _tool_identity(Path(native_qualification.MUSL_RUNTIME_PATHS["loader"]), "post-run pinned musl loader") != oracle_inputs["loader"]["identity"]:
            fail("pinned musl loader changed during collection")
        after = _input_seal(ROOT, dynamic, static, _installed_tool_roster(dynamic, static), oracle_inputs,
                            _fixture_record(ROOT, fixture_source, fixture_files, fixture_records, fixture_ldd))
        if before != after:
            fail("source, product, tool, oracle, or fixture input changed during wordexp collection")
        report = {
            "schema": SCHEMA, "source_mount": SOURCE_MOUNT, "status": "component-verified-not-family-qualified",
            "inputs": {"before": before, "after": after, "built_products": built},
            "header_trace": {"command": header_trace, "trace": header},
            "workload": _checkout_identity(ROOT, workload, "installed wordexp workload"),
            "compile": compile_record, "oracle_link": oracle_link,
            "oracle": _checkout_identity(ROOT, oracle, "pinned-musl wordexp oracle"),
            "links": links, "cells": cells,
        }
        report_path = work / "owned-wordexp-products.json"
        _write_json(report_path, report)
        validate_report(ROOT, report_path)
        print(report_path)
        return report_path
    except Exception:
        print(f"owned wordexp products: retained failure evidence at {work}", file=sys.stderr)
        raise


def _validate_tool_record(value: object, description: str) -> dict[str, Any]:
    value = _exact_dict(value, {"path", "sha256", "mode"}, description)
    if not isinstance(value["path"], str) or not Path(value["path"]).is_absolute() or ".." in Path(value["path"]).parts:
        fail(f"{description} path is malformed")
    if not isinstance(value["sha256"], str) or len(value["sha256"]) != 64 or type(value["mode"]) is not int:
        fail(f"{description} identity is malformed")
    return value


def _validate_retained_oracle(root: Path, work: Path, value: object) -> dict[str, Any]:
    """Validate the retained musl oracle against the caller's checked source.

    ``owned_dynamic_qualification.validate_oracle`` is intentionally tied to
    that module's checkout-global path. A retained-wordexp reader instead gets
    its checkout explicitly, so an integration reader can replay a worker
    receipt without accidentally consulting the worker module's source tree.
    """
    oracle = _exact_dict(value, {"version", "runtime_sha256", "compiler_wrapper_sha256", "pins_sha256", "files"},
                         "wordexp retained pinned oracle")
    files = oracle["files"]
    if oracle["version"] != "musl-1.2.6" or not isinstance(files, dict) or set(files) != set(qualification.ORACLE_FILES):
        fail("wordexp retained pinned oracle roster differs")
    pins_path = _physical(root / "compat/upstreams.toml", "wordexp caller upstream pins", directory=False)
    wrapper_path = _physical(root / "docker/x86_64-musl-oracle-gcc", "wordexp caller oracle wrapper", directory=False)
    if oracle["pins_sha256"] != _sha(pins_path):
        fail("wordexp retained pinned oracle pin identity differs")
    directory = _physical(work / "qualification-oracle", "wordexp retained pinned oracle directory", directory=True)
    if {path.name for path in directory.iterdir()} != set(files):
        fail("wordexp retained pinned oracle file roster differs")
    for name, digest in files.items():
        if not isinstance(digest, str) or len(digest) != 64 or _sha(directory / name) != digest:
            fail("wordexp retained pinned oracle file identity differs")
    if oracle["runtime_sha256"] != files["runtime"] or oracle["compiler_wrapper_sha256"] != files["compiler_wrapper"]:
        fail("wordexp retained pinned oracle summary differs")
    if files["compiler_wrapper"] != _sha(wrapper_path):
        fail("wordexp retained oracle compiler differs from the caller pin")
    try:
        pins = tomllib.loads(pins_path.read_text(encoding="utf-8"))["musl"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError) as error:
        raise EvidenceError("wordexp caller upstream pins are malformed") from error
    expected_manifest = ("format=crabc-pinned-musl-oracle-v1\n"
                         f"version={pins['version']}\nsource_sha256={pins['sha256']}\n"
                         f"fallback_revision={pins['fallback_revision']}\narchitecture=x86_64\n")
    if (directory / "source_manifest").read_text(encoding="utf-8") != expected_manifest:
        fail("wordexp retained oracle source manifest differs")
    if (directory / "specs_manifest").read_text(encoding="utf-8") != f"{files['specs']}  /opt/musl-1.2.6/lib/musl-gcc.specs\n":
        fail("wordexp retained oracle specs manifest differs")
    return oracle


def _command_record(root: Path, work: Path, label: str, record: object, expected_argv: list[str],
                    expected_environment: Mapping[str, str], description: str) -> dict[str, Any]:
    record = _exact_dict(record, {"argv", "environment", "stdout", "stderr", "status"}, description)
    expected_paths = {
        "argv": work / "commands" / f"{label}.argv.json",
        "environment": work / "commands" / f"{label}.environment.json",
        "stdout": work / "commands" / f"{label}.stdout",
        "stderr": work / "commands" / f"{label}.stderr",
        "status": work / "commands" / f"{label}.status",
    }
    paths = {name: _identity_current(root, record[name], f"{description} {name}") for name in expected_paths}
    for name, expected_path in expected_paths.items():
        if paths[name] != _physical(expected_path, f"{description} expected {name}", directory=False):
            fail(f"{description} {name} path differs")
    require_exact_command(paths["argv"], expected_argv, expected_environment, description)
    try:
        environment = json.loads(paths["environment"].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{description} environment is not JSON") from error
    if environment != dict(expected_environment):
        fail(f"{description} environment differs from its canonical command")
    if paths["status"].read_bytes() != b"0\n":
        fail(f"{description} status is not zero")
    return record


def _fixture_from_seal(root: Path, work: Path, value: object, tools: Mapping[str, dict[str, Any]],
                       oracle: Mapping[str, Any]) -> tuple[Path, dict[str, str], dict[str, dict[str, Any]]]:
    value = _exact_dict(value, {"root", "files", "ldd"}, "wordexp external fixture")
    fixture_root = _local_mounted(root, value["root"], "wordexp external fixture root")
    expected_root = _physical(work / "external-shell-fixture", "wordexp expected external fixture root", directory=True)
    if fixture_root != expected_root:
        fail("wordexp external fixture root differs")
    files = value["files"]
    if not isinstance(files, dict) or not files:
        fail("wordexp external fixture files are malformed")
    paths: dict[str, str] = {}
    for name, identity in files.items():
        if not isinstance(name, str) or not name:
            fail("wordexp external fixture name differs")
        path = _identity_current(root, identity, f"wordexp external fixture {name}")
        try:
            relative = path.relative_to(fixture_root).as_posix()
        except ValueError as error:
            raise EvidenceError("wordexp external fixture file escapes its root") from error
        paths[name] = relative
    observed, aliases = _walk_root(fixture_root)
    if aliases or observed != set(paths.values()) or len(set(paths.values())) != len(paths):
        fail("wordexp external fixture roster differs")
    if paths.get("shell") != "bin/sh" or paths.get("null") != "dev/null":
        fail("wordexp external fixture roles differ")
    dependencies = sorted((name for name in paths if name.startswith("dependency:")),
                          key=lambda name: int(name.removeprefix("dependency:")) if name.removeprefix("dependency:").isdigit() else -1)
    if dependencies != [f"dependency:{index}" for index in range(len(dependencies))]:
        fail("wordexp external fixture dependency roster differs")
    shell = files["shell"]
    if shell["sha256"] != tools["shell"]["sha256"] or shell["mode"] != tools["shell"]["mode"]:
        fail("wordexp retained fixture shell differs from its sealed source tool")
    loader_record = _exact_dict(oracle["loader"], {"source_path", "identity"}, "wordexp pinned musl loader")
    loader = _validate_tool_record(loader_record["identity"], "wordexp pinned musl loader identity")
    expected_loader = Path(native_qualification.MUSL_RUNTIME_PATHS["loader"])
    if loader_record["source_path"] != str(expected_loader):
        fail("wordexp retained fixture loader source path differs")
    if dependencies != ["dependency:0"] or paths["dependency:0"] != "lib/ld-musl-x86_64.so.1":
        fail("wordexp retained fixture loader closure differs")
    dependency = files["dependency:0"]
    if dependency["sha256"] != loader["sha256"] or dependency["mode"] != loader["mode"]:
        fail("wordexp retained fixture loader differs from the pinned musl loader")
    ldd = _command_record(root, work, "controlled-shell-ldd", value["ldd"],
                          [tools["ldd"]["path"], tools["shell"]["path"]], _mounted_environment(root, work),
                          "wordexp controlled shell ldd")
    ldd_stdout = _identity_current(root, ldd["stdout"], "wordexp controlled shell ldd stdout")
    try:
        closure = _ldd_closure_candidates(ldd_stdout.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError("wordexp controlled shell ldd output is not text") from error
    if tuple(path.as_posix().lstrip("/") for path in closure) != tuple(paths[name] for name in dependencies):
        fail("wordexp retained fixture differs from the sealed ldd closure")
    return fixture_root, paths, {name: files[name] for name in paths}


def _validate_input_seal(root: Path, work: Path, value: object) -> tuple[Path, Path | None, dict[str, Any], tuple[Path, dict[str, str], dict[str, dict[str, Any]]]]:
    value = _exact_dict(value, {"sources", "products", "tools", "oracle", "fixture"}, "wordexp input seal")
    sources = value["sources"]
    if not isinstance(sources, dict) or set(sources) != set(SOURCES):
        fail("wordexp source input roster differs")
    for source in SOURCES:
        path = _identity_current(root, sources[source], f"wordexp source {source}")
        if path != _physical(root / source, f"wordexp named source {source}", directory=False):
            fail("wordexp source identity uses the wrong path")
    product_value = _exact_dict(value["products"], {"dynamic", "static"}, "wordexp product input seal")
    dynamic_record = _exact_dict(product_value["dynamic"], {"root", "manifest", "files"}, "wordexp dynamic input")
    dynamic = _local_mounted(root, dynamic_record["root"], "wordexp dynamic product")
    if dynamic_record != _product_record(root, dynamic, "dynamic"):
        fail("wordexp dynamic product input drifted")
    static = None
    if product_value["static"] is not None:
        static_record = _exact_dict(product_value["static"], {"root", "manifest", "files"}, "wordexp static input")
        static = _local_mounted(root, static_record["root"], "wordexp static product")
        if static_record != _product_record(root, static, "static"):
            fail("wordexp static product input drifted")
    tools = value["tools"]
    expected_tools = {"dynamic-driver", "compiler", "linker", "oracle-compiler", "chroot", "timeout", "ldd", "shell"}
    if static is not None:
        expected_tools.add("static-driver")
    if not isinstance(tools, dict) or set(tools) != expected_tools:
        fail("wordexp pre-sealed tool roster differs")
    tools = {name: _validate_tool_record(item, f"wordexp pre-sealed tool {name}") for name, item in tools.items()}
    dynamic_driver = dynamic / "bin/crabc-cc-dynamic"
    expected_dynamic_driver = {"path": _mounted(root, dynamic_driver), "sha256": _sha(dynamic_driver), "mode": _mode(dynamic_driver)}
    if tools["dynamic-driver"] != expected_dynamic_driver:
        fail("wordexp dynamic driver pre-seal differs")
    if static is not None:
        static_driver = static / "bin/crabc-cc"
        expected_static_driver = {"path": _mounted(root, static_driver), "sha256": _sha(static_driver), "mode": _mode(static_driver)}
        if tools["static-driver"] != expected_static_driver:
            fail("wordexp static driver pre-seal differs")
    oracle = _exact_dict(value["oracle"], {"qualification", "loader", "static_libc"}, "wordexp pinned oracle input")
    _validate_retained_oracle(root, work, oracle["qualification"])
    oracle_compiler = tools["oracle-compiler"]
    expected_wrapper = native_qualification.MUSL_RUNTIME_PATHS["compiler_wrapper"]
    if oracle_compiler["path"] != expected_wrapper or oracle_compiler["sha256"] != oracle["qualification"]["compiler_wrapper_sha256"]:
        fail("wordexp oracle compiler differs from the independently pinned wrapper")
    loader_record = _exact_dict(oracle["loader"], {"source_path", "identity"}, "wordexp pinned musl loader")
    loader = _validate_tool_record(loader_record["identity"], "wordexp pinned musl loader identity")
    if (loader_record["source_path"] != native_qualification.MUSL_RUNTIME_PATHS["loader"]
            or loader["path"] != native_qualification.MUSL_RUNTIME_PATHS["libc"]
            or loader["sha256"] != oracle["qualification"]["runtime_sha256"]):
        fail("wordexp pinned loader differs from the qualified musl runtime")
    static_libc = _exact_dict(oracle["static_libc"], {"native", "retained"}, "wordexp static oracle libc")
    native = _validate_tool_record(static_libc["native"], "wordexp static oracle libc native")
    if native["path"] != "/opt/musl-1.2.6/lib/libc.a":
        fail("wordexp static oracle libc source path differs")
    retained = _identity_current(root, static_libc["retained"], "wordexp retained static oracle libc")
    if retained != _physical(work / "pinned-musl-static-libc.a", "wordexp retained static oracle libc path", directory=False) or native["sha256"] != _sha(retained):
        fail("wordexp static oracle libc retention differs")
    return dynamic, static, tools, _fixture_from_seal(root, work, value["fixture"], tools, oracle)


def _expected_execution_maps(dynamic: Path | None, fixture_paths: Mapping[str, str], shell_case: str,
                             overrides: object) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    if shell_case not in SHELL_CASES:
        fail("wordexp shell case differs")
    fixture = {name: relative for name, relative in fixture_paths.items() if not (shell_case == "missing" and name == "shell")}
    product_files: dict[str, str] = {}
    product_aliases: dict[str, str] = {}
    if dynamic is not None:
        try:
            _, _, files, aliases = copies.dynamic_product(dynamic)
        except copies.CryptRuntimeEvidenceError as error:
            raise EvidenceError(str(error)) from error
        product_files = {"manifest": "share/crabc/manifest.json", **{f"product:{name}": name for name in files}}
        product_aliases = {f"product:{name}": name for name in aliases}
        expected_override = ["lib/ld-musl-x86_64.so.1"]
        if overrides != expected_override:
            fail("wordexp dynamic external alias override differs")
        for name, relative in tuple(product_aliases.items()):
            if relative == expected_override[0]:
                del product_aliases[name]
                break
        else:
            fail("wordexp dynamic product has no expected shell-loader alias")
    elif overrides != []:
        fail("wordexp static execution has an external alias override")
    return product_files, product_aliases, fixture


def _validate_execution_binding(root: Path, work: Path, label: str, mode: str, shell_case: str, execution: object,
                                dynamic_product: Path | None, candidate: Path, oracle: Path,
                                fixture: tuple[Path, dict[str, str], dict[str, dict[str, Any]]], overrides: object) -> Path:
    execution = _exact_dict(execution, {"root", "product_files", "product_aliases", "consumers", "fixtures"},
                            f"wordexp cell {label} execution")
    execution_root = _local_mounted(root, execution["root"], f"wordexp cell {label} execution root")
    expected_root = _physical(work / "execution" / label, f"wordexp cell {label} expected execution root", directory=True)
    if execution_root != expected_root:
        fail("wordexp execution root path differs")
    fixture_root, fixture_paths, fixture_records = fixture
    product_files, product_aliases, fixture_expected = _expected_execution_maps(dynamic_product, fixture_paths, shell_case, overrides)
    consumer = MODE_SPECS[mode][2]
    if execution.get("product_files") != {name: {"path": relative, "sha256": _sha(dynamic_product / relative),
                                                        "mode": _mode(dynamic_product / relative)}
                                          for name, relative in product_files.items()}:
        fail("wordexp execution product file binding differs")
    expected_aliases = {name: {"path": relative, "target": os.readlink(dynamic_product / relative)}
                        for name, relative in product_aliases.items()} if dynamic_product is not None else {}
    if execution.get("product_aliases") != expected_aliases:
        fail("wordexp execution product alias binding differs")
    expected_consumers = {
        "candidate": {"path": consumer, "sha256": _sha(candidate), "mode": _mode(candidate)},
        "oracle": {"path": "oracle", "sha256": _sha(oracle), "mode": _mode(oracle)},
    }
    if execution.get("consumers") != expected_consumers:
        fail("wordexp execution consumer binding differs")
    expected_fixtures: dict[str, dict[str, Any]] = {}
    for name, relative in fixture_expected.items():
        source = fixture_root / relative
        digest = _sha(source)
        mode_value = _mode(source)
        if name == "shell" and shell_case == "inaccessible":
            mode_value = 0o644
        elif name == "shell" and shell_case == "invalid":
            digest = sha256(b"not an executable shell image\n").hexdigest()
            mode_value = 0o755
        expected_fixtures[name] = {"path": relative, "sha256": digest, "mode": mode_value}
    if execution.get("fixtures") != expected_fixtures:
        fail("wordexp execution external fixture binding differs")
    local = dict(execution)
    local["root"] = str(execution_root)
    validate_execution_root(execution_root, local)
    return execution_root


def validate_report(root: Path, report_path: Path) -> dict[str, Any]:
    root = _physical(root, "checkout root", directory=True)
    report_path = _physical(report_path, "wordexp report", directory=False)
    try:
        value = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("wordexp report is not valid JSON") from error
    report = _exact_dict(value, {"schema", "source_mount", "status", "inputs", "header_trace", "workload", "compile",
                                 "oracle_link", "oracle", "links", "cells"}, "wordexp report")
    if report["schema"] != SCHEMA or report["source_mount"] != SOURCE_MOUNT or report["status"] != "component-verified-not-family-qualified":
        fail("wordexp report contract differs")
    work = report_path.parent
    inputs = _exact_dict(report["inputs"], {"before", "after", "built_products"}, "wordexp input seals")
    if type(inputs["built_products"]) is not bool:
        fail("wordexp product materialization marker differs")
    dynamic, static, tools, fixture = _validate_input_seal(root, work, inputs["before"])
    after_dynamic, after_static, after_tools, after_fixture = _validate_input_seal(root, work, inputs["after"])
    if (dynamic, static, tools, fixture) != (after_dynamic, after_static, after_tools, after_fixture) or inputs["before"] != inputs["after"]:
        fail("wordexp inputs changed after collection")

    workload = _identity_current(root, report["workload"], "wordexp workload")
    if workload != _physical(work / "workload.o", "wordexp canonical workload", directory=False):
        fail("wordexp workload path differs")
    header = _exact_dict(report["header_trace"], {"command", "trace"}, "wordexp header trace")
    expected_header = [tools["compiler"]["path"], "-nostdinc", "-isystem", _mounted(root, dynamic / "usr/include"),
                       "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-fPIE", "-std=c11",
                       "-D_GNU_SOURCE", "-E", "-H", _mounted(root, root / PROBE)]
    command_environment = _mounted_environment(root, work)
    header_command = _command_record(root, work, "installed-header-trace", header["command"], expected_header, command_environment,
                                     "wordexp installed header trace")
    trace = _identity_current(root, header["trace"], "wordexp installed header trace bytes")
    if header_command["stderr"] != header["trace"] or trace != _physical(work / "commands/installed-header-trace.stderr",
                                                                              "wordexp installed header trace path", directory=False):
        fail("wordexp installed header trace record differs")
    _validate_header_trace(root, trace, dynamic)
    expected_compile = [tools["dynamic-driver"]["path"], "--dynamic-pie", "-std=c11", "-D_GNU_SOURCE", "-fno-builtin",
                        "-c", _mounted(root, root / PROBE), "-o", _mounted(root, workload)]
    _command_record(root, work, "compile-workload", report["compile"], expected_compile, command_environment, "wordexp compile")
    oracle = _identity_current(root, report["oracle"], "wordexp static oracle")
    if oracle != _physical(work / "pinned-musl-static-et-exec", "wordexp canonical static oracle", directory=False):
        fail("wordexp static oracle path differs")
    expected_oracle_link = [tools["oracle-compiler"]["path"], "-static", "-fno-pie", "-no-pie",
                            _mounted(root, workload), "-o", _mounted(root, oracle)]
    _command_record(root, work, "pinned-musl-link", report["oracle_link"], expected_oracle_link, command_environment,
                    "wordexp pinned-musl link")

    links = report["links"]
    expected_links = {"dynamic-pie", "dynamic-non-pie"} | ({"static-et-exec", "static-pie"} if static else set())
    if not isinstance(links, dict) or set(links) != expected_links:
        fail("wordexp link roster differs")
    link_specs = {"dynamic-pie": (dynamic, "pie", "--dynamic-pie"), "dynamic-non-pie": (dynamic, "non-pie", "--dynamic-non-pie"),
                  "static-et-exec": (static, "static", "-static"), "static-pie": (static, "static-pie", "-static-pie")}
    for name in sorted(links):
        item = _exact_dict(links[name], {"linkage", "executable", "receipt", "validated", "linker", "command"}, f"wordexp {name} link")
        executable = _identity_current(root, item["executable"], f"wordexp {name} executable")
        receipt = _identity_current(root, item["receipt"], f"wordexp {name} receipt")
        validated_path = _identity_current(root, item["validated"], f"wordexp {name} validation")
        product, linkage, mode_flag = link_specs[name]
        if product is None or item["linkage"] != linkage:
            fail("wordexp link product or mode differs")
        if linkage.startswith("static"):
            expected_link = [tools["static-driver"]["path"], mode_flag, "--link-receipt", f"{executable.name}.crabc-link.json",
                             _mounted(root, workload), "-o", _mounted(root, executable)]
        else:
            expected_link = [tools["dynamic-driver"]["path"], mode_flag, _mounted(root, workload), "-o", _mounted(root, executable)]
        _command_record(root, work, f"link-{name}", item["command"], expected_link, command_environment,
                        f"wordexp {name} link")
        sealed_linker = {"path": tools["linker"]["path"], "sha256": tools["linker"]["sha256"]}
        try:
            receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
            actual_linker = receipt_value.get("resolved_linker")
            if item["linker"] != sealed_linker or actual_linker != sealed_linker:
                fail("wordexp retained link selected an unsealed linker")
            observed = products.validate_retained_link(root, SOURCE_MOUNT, product, workload, executable, receipt, linkage, actual_linker)
        except (products.ProductEvidenceError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"wordexp retained {name} link is invalid: {error}") from error
        try:
            retained_validation = json.loads(validated_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"wordexp retained {name} validation is invalid") from error
        expected_validation = dict(observed)
        expected_validation["product"] = _mounted(root, product)
        if retained_validation != expected_validation:
            fail(f"wordexp retained {name} link validation drifted")

    expected_modes = set(MODE_SPECS)
    if static is None:
        expected_modes -= {"static-et-exec", "static-pie"}
    cells = report["cells"]
    expected_cell_labels = {f"{mode}-{shell}" for mode in expected_modes for shell in SHELL_CASES}
    if not isinstance(cells, dict) or set(cells) != expected_cell_labels:
        fail("wordexp execution cell roster differs")
    for mode in sorted(expected_modes):
        link_name = mode if mode.startswith("static") else mode.rsplit("-", 1)[0]
        candidate = _identity_current(root, links[link_name]["executable"], f"wordexp {mode} linked consumer")
        dynamic_product = None if mode.startswith("static") else dynamic
        for shell_case in SHELL_CASES:
            label = f"{mode}-{shell_case}"
            item = _exact_dict(cells[label], {"mode", "shell_case", "execution", "consumer_sources", "external_alias_overrides",
                                               "oracle", "candidate", "expected_stdout"}, f"wordexp cell {label}")
            if item["mode"] != mode or item["shell_case"] != shell_case:
                fail("wordexp cell mode or shell case differs")
            source_consumers = _exact_dict(item["consumer_sources"], {"candidate", "oracle"}, f"wordexp cell {label} source consumers")
            if source_consumers["candidate"] != links[link_name]["executable"] or source_consumers["oracle"] != report["oracle"]:
                fail("wordexp cell consumers are not bound to sealed links")
            execution_root = _validate_execution_binding(root, work, label, mode, shell_case, item["execution"], dynamic_product,
                                                         candidate, oracle, fixture, item["external_alias_overrides"])
            suffix = [] if shell_case == "normal" else ["--shell-unavailable"]
            environment = {"CRABC_WORDEXP": "bar baz"}
            mounted_execution = _mounted(root, execution_root)
            expected_oracle = ["/usr/bin/timeout", "20", "/usr/sbin/chroot", mounted_execution, "/oracle", *suffix]
            program = "/" + MODE_SPECS[mode][2]
            expected_candidate = ["/usr/bin/timeout", "20", "/usr/sbin/chroot", mounted_execution]
            if mode.endswith("-direct"):
                expected_candidate += ["/lib/ld-crabc-x86_64.so.1", program]
            else:
                expected_candidate += [program]
            expected_candidate += suffix
            oracle_command = _command_record(root, work, f"{label}-oracle", item["oracle"], expected_oracle, environment,
                                             f"wordexp cell {label} oracle")
            candidate_command = _command_record(root, work, f"{label}-candidate", item["candidate"], expected_candidate, environment,
                                                f"wordexp cell {label} candidate")
            expected_stdout = b"owned-wordexp: PASS\n" if shell_case == "normal" else b"owned-wordexp-shell-unavailable: PASS\n"
            if item["expected_stdout"] != expected_stdout.decode("ascii"):
                fail("wordexp expected transcript differs")
            oracle_stdout = _identity_current(root, oracle_command["stdout"], f"wordexp cell {label} oracle stdout")
            candidate_stdout = _identity_current(root, candidate_command["stdout"], f"wordexp cell {label} candidate stdout")
            oracle_stderr = _identity_current(root, oracle_command["stderr"], f"wordexp cell {label} oracle stderr")
            candidate_stderr = _identity_current(root, candidate_command["stderr"], f"wordexp cell {label} candidate stderr")
            if oracle_stdout.read_bytes() != expected_stdout or candidate_stdout.read_bytes() != expected_stdout:
                fail("wordexp cell transcript differs")
            if oracle_stderr.read_bytes() != candidate_stderr.read_bytes():
                fail("wordexp cell oracle/candidate stderr differs")
    return report

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    run = commands.add_parser("run", help="build or consume products and retain the wordexp execution evidence")
    run.add_argument("--static-sysroot", type=Path, help="optional supplied static product; requires dynamic product")
    run.add_argument("dynamic_sysroot", type=Path, nargs="?", help="supplied dynamic product")
    validate = commands.add_parser("validate", help="replay retained evidence without executing native tools")
    validate.add_argument("--report", type=Path, required=True)
    parsed = parser.parse_args()
    try:
        if parsed.action == "run":
            if parsed.static_sysroot is not None and parsed.dynamic_sysroot is None:
                fail("--static-sysroot requires a supplied dynamic product")
            collect(parsed.dynamic_sysroot, parsed.static_sysroot)
        else:
            validate_report(ROOT, parsed.report)
    except EvidenceError as error:
        print(f"owned wordexp evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
