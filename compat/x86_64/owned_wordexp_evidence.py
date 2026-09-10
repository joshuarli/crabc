#!/usr/bin/env python3
"""Collect and replay bounded installed-product wordexp evidence.

The controlled shell is a sealed external execution fixture.  It is never an
owned runtime input or a claim that crabc implements shell semantics.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import owned_crypt_runtime_evidence as copies
import owned_posix_product_evidence as products

SCHEMA = "crabc.x86_64-owned-wordexp-products/v1"
SOURCE_MOUNT = "/workspace"
TARGET = "x86_64-unknown-linux-musl"
PROBE = "compat/x86_64/owned_wordexp_probe.c"
DOC = "compat/x86_64/owned-wordexp.md"
RUNNER = "compat/x86_64/run_owned_wordexp.sh"
LEGACY_RUNNER = "compat/x86_64/run_libc_owned_wordexp.sh"
HEADERS = ("errno.h", "wordexp.h", "stdio.h", "stdlib.h", "string.h", "features.h", "bits/alltypes.h")
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
    directory = work / "commands"
    directory.mkdir(parents=True, exist_ok=True)
    command_path = directory / f"{label}.argv.json"
    stdout_path = directory / f"{label}.stdout"
    stderr_path = directory / f"{label}.stderr"
    status_path = directory / f"{label}.status"
    _write_json(command_path, argv)
    env = dict(environment) if environment is not None else None
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
        "stdout": _checkout_identity(ROOT, stdout_path, f"{label} stdout"),
        "stderr": _checkout_identity(ROOT, stderr_path, f"{label} stderr"),
        "status": _checkout_identity(ROOT, status_path, f"{label} status"),
    }
    if required and completed.returncode != 0:
        fail(f"{label} failed with status {completed.returncode}; retained output is {directory}")
    return record


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
    # Bind through the shared product manifest contract before adding consumers
    # and the explicitly non-owned shell fixture.
    try:
        copies.assert_execution_tree(execution_root, files, aliases, execution_root / "share/crabc/manifest.json")
    except copies.CryptRuntimeEvidenceError as error:
        # assert_execution_tree treats the manifest as a consumer, which is
        # valid for its exact tree check but reports a duplicate expected path.
        # Recreate the shared manifest/file/alias comparisons explicitly.
        try:
            copies.copied_file(manifest, execution_root / "share/crabc/manifest.json", "wordexp copied manifest")
            for name in files:
                copies.copied_file(product / name, execution_root / name, f"wordexp copied product {name}")
            for name, target in aliases.items():
                copies.copied_alias(product / name, execution_root / name, target, f"wordexp copied alias {name}")
        except copies.CryptRuntimeEvidenceError as nested:
            raise EvidenceError(str(nested)) from nested
    product_files = {"manifest": "share/crabc/manifest.json"}
    product_files.update({f"product:{name}": name for name in files})
    product_aliases = {f"product:{name}": name for name in aliases}
    return product_files, product_aliases


def _shell_dependencies(shell: Path) -> list[Path]:
    completed = subprocess.run(["/usr/bin/ldd", str(shell)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True,
                               env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    if completed.returncode != 0:
        fail("controlled shell ldd failed")
    names: list[Path] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        candidate = fields[0] if fields and fields[0].startswith("/") else (
            fields[2] if len(fields) >= 3 and fields[1] == "=>" and fields[2].startswith("/") else None
        )
        if candidate is not None:
            resolved = Path(os.path.realpath(candidate))
            _physical(resolved, "controlled shell dependency", directory=False)
            if resolved not in names:
                names.append(resolved)
    if not names:
        fail("controlled shell has no copied loader closure")
    return names


def _prepare_fixture_source(work: Path) -> tuple[Path, dict[str, str], dict[str, Any]]:
    shell = Path(os.path.realpath("/bin/sh"))
    shell = _physical(shell, "controlled /bin/sh", directory=False)
    if not os.access(shell, os.X_OK):
        fail("controlled /bin/sh is not executable")
    source = work / "external-shell-fixture"
    source.mkdir()
    _copy_regular(shell, source / "bin/sh", "controlled shell")
    files = {"shell": "bin/sh"}
    source_records = {"shell": _checkout_identity(ROOT, source / "bin/sh", "retained controlled shell")}
    for index, dependency in enumerate(_shell_dependencies(shell)):
        # Preserve absolute fixture names inside the chroot while the retained
        # source copy gives host readers a path that never needs ambient /lib.
        relative = dependency.as_posix().lstrip("/")
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
    return source, files, source_records


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


def _copy_oracle_inputs(work: Path, oracle_compiler: Path) -> dict[str, Any]:
    root = Path("/opt/musl-1.2.6")
    inputs: list[tuple[str, Path]] = [
        ("compiler", oracle_compiler), ("source-manifest", root / ".crabc-oracle"),
        ("shared-libc", root / "lib/libc.so"), ("static-libc", root / "lib/libc.a"),
        ("gcc-specs", root / "lib/musl-gcc.specs"),
    ]
    retained = work / "pinned-musl-inputs"
    retained.mkdir()
    records: dict[str, Any] = {}
    for name, source in inputs:
        source = _physical(source, f"pinned musl {name}", directory=False)
        destination = retained / name
        _copy_regular(source, destination, f"pinned musl {name}")
        records[name] = {
            "native": _tool_identity(source, f"pinned musl {name}"),
            "retained": _checkout_identity(ROOT, destination, f"retained pinned musl {name}"),
        }
    return records


def _products(dynamic: Path | None, static: Path | None, work: Path) -> tuple[Path, Path | None, bool]:
    built = dynamic is None
    if dynamic is None:
        dynamic = work / "owned-dynamic-product"
        _run(work, "build-dynamic", [sys.executable, str(ROOT / "scripts/build_x86_64_owned_dynamic_sysroot.py"),
                                      "--output", str(dynamic)])
    dynamic = _physical(dynamic, "selected dynamic product", directory=True)
    try:
        products._validate_dynamic_product(dynamic)
    except products.ProductEvidenceError as error:
        raise EvidenceError(f"selected dynamic product is invalid: {error}") from error
    if static is None and built:
        static = work / "owned-static-product"
        _run(work, "build-static", [sys.executable, str(ROOT / "scripts/build_x86_64_owned_sysroot.py"),
                                     "--output", str(static)])
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
    return {"shell_case": shell_case, "execution": execution_record,
            "fixture_source": dict(fixture_records), "external_alias_overrides": list(replaced_aliases),
            "oracle": oracle_result, "candidate": candidate_result, "expected_stdout": expected.decode("ascii")}


def _validate_header_trace(root: Path, trace: Path, dynamic: Path) -> dict[str, Any]:
    text = trace.read_text(encoding="utf-8", errors="strict")
    for header in HEADERS:
        expected = _mounted(root, dynamic / "usr/include" / header)
        if expected not in text:
            fail(f"installed header trace omitted {header}")
    return _checkout_identity(root, trace, "installed wordexp header trace")


def collect(dynamic: Path | None, static: Path | None) -> Path:
    _native_requirements()
    work = _work_directory()
    try:
        dynamic, static, built = _products(dynamic, static, work)
        dynamic_driver = _physical(dynamic / "bin/crabc-cc-dynamic", "installed dynamic driver", directory=False)
        static_driver = _physical(static / "bin/crabc-cc", "installed static driver", directory=False) if static else None
        oracle_compiler = _physical(Path("/usr/local/bin/crabc-x86_64-musl-gcc"), "pinned musl oracle compiler", directory=False)
        for source in (ROOT / PROBE, ROOT / DOC, ROOT / RUNNER, ROOT / LEGACY_RUNNER):
            _physical(source, "wordexp source", directory=False)
        tool_before = {
            "dynamic-driver": _tool_identity(dynamic_driver, "installed dynamic driver"),
            "compiler": _tool_identity(Path("/usr/bin/gcc"), "pinned source compiler"),
            "oracle-compiler": _tool_identity(oracle_compiler, "pinned musl oracle compiler"),
            "chroot": _tool_identity(Path("/usr/sbin/chroot"), "chroot"),
            "timeout": _tool_identity(Path("/usr/bin/timeout"), "timeout"),
            "ldd": _tool_identity(Path("/usr/bin/ldd"), "ldd"),
            "shell": _tool_identity(Path(os.path.realpath("/bin/sh")), "controlled shell"),
        }
        if static_driver:
            tool_before["static-driver"] = _tool_identity(static_driver, "installed static driver")
        source_records = {item: _checkout_identity(ROOT, ROOT / item, f"wordexp source {item}")
                          for item in (PROBE, DOC, RUNNER, LEGACY_RUNNER, "compat/x86_64/owned_wordexp_evidence.py")}
        header_trace = _run(work, "installed-header-trace", ["/usr/bin/gcc", "-nostdinc", "-isystem",
                            str(dynamic / "usr/include"), "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
                            "-fPIE", "-std=c11", "-D_GNU_SOURCE", "-E", "-H", str(ROOT / PROBE)], required=True)
        header_trace_path = _local_mounted(ROOT, header_trace["stderr"]["path"], "installed header trace stderr")
        header = _validate_header_trace(ROOT, header_trace_path, dynamic)
        workload = work / "workload.o"
        compile_record = _run(work, "compile-workload", [str(dynamic_driver), "--dynamic-pie", "-std=c11",
                              "-D_GNU_SOURCE", "-fno-builtin", "-c", str(ROOT / PROBE), "-o", str(workload)])
        _physical(workload, "installed wordexp workload", directory=False)
        oracle = work / "pinned-musl-static-et-exec"
        oracle_link = _run(work, "pinned-musl-link", [str(oracle_compiler), "-static", "-fno-pie", "-no-pie",
                           str(workload), "-o", str(oracle)])
        _physical(oracle, "pinned-musl wordexp oracle", directory=False)
        oracle_inputs = _copy_oracle_inputs(work, oracle_compiler)
        fixture_source, fixture_files, fixture_records = _prepare_fixture_source(work)
        links: dict[str, Any] = {}
        candidates: dict[str, tuple[Path, Path | None]] = {}
        if static is not None and static_driver is not None:
            for mode, flag, linkage in (("static-et-exec", "-static", "static"), ("static-pie", "-static-pie", "static-pie")):
                binary = work / MODE_SPECS[mode][2]
                _run(work, f"link-{mode}", [str(static_driver), flag, "--link-receipt",
                      f"{binary.name}.crabc-link.json", str(workload), "-o", str(binary)], cwd=work)
                links[mode] = _link_validate(ROOT, work, static, workload, binary, linkage, mode)
                candidates[mode] = (binary, None)
        for mode, flag, linkage in (("dynamic-pie-kernel", "--dynamic-pie", "pie"),
                                    ("dynamic-non-pie-kernel", "--dynamic-non-pie", "non-pie")):
            base = "dynamic-pie" if linkage == "pie" else "dynamic-non-pie"
            binary = work / base
            _run(work, f"link-{base}", [str(dynamic_driver), flag, str(workload), "-o", str(binary)])
            link_record = _link_validate(ROOT, work, dynamic, workload, binary, linkage, base)
            links[base] = link_record
            for entry in (f"{base}-kernel", f"{base}-direct"):
                candidates[entry] = (binary, dynamic)
        cells: dict[str, Any] = {}
        for mode, (candidate, dynamic_root) in candidates.items():
            for shell_case in SHELL_CASES:
                label = f"{mode}-{shell_case}"
                cells[label] = _run_shell_case(work, ROOT, label=label, mode=mode, candidate=candidate, oracle=oracle,
                                                dynamic_product=dynamic_root, fixture_source=fixture_source,
                                                fixture_files=fixture_files, fixture_records=fixture_records)
        resolved_linkers = {json.dumps(item["linker"], sort_keys=True) for item in links.values()}
        if len(resolved_linkers) != 1:
            fail("installed wordexp links selected different resolved linkers")
        selected_linker = json.loads(next(iter(resolved_linkers)))
        tool_before["linker"] = _tool_identity(Path(selected_linker["path"]), "selected installed linker")
        if {"path": tool_before["linker"]["path"], "sha256": tool_before["linker"]["sha256"]} != selected_linker:
            fail("selected installed linker seal differs from the link receipt")
        tool_after = {
            name: _tool_identity(Path(value["path"]), f"retained tool {name}") for name, value in tool_before.items()
        }
        if tool_before != tool_after:
            fail("tool identity changed during wordexp evidence collection")
        report = {
            "schema": SCHEMA, "source_mount": SOURCE_MOUNT, "status": "component-verified-not-family-qualified",
            "products": {"dynamic": _product_record(ROOT, dynamic, "dynamic"),
                         "static": _product_record(ROOT, static, "static") if static is not None else None,
                         "built_products": built},
            "sources": source_records, "header_trace": header,
            "workload": _checkout_identity(ROOT, workload, "installed wordexp workload"),
            "compile": compile_record, "oracle_link": oracle_link,
            "oracle_inputs": oracle_inputs,
            "tools": {"before": tool_before, "after": tool_after},
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


def _validate_command(root: Path, record: object, description: str) -> dict[str, Any]:
    record = _exact_dict(record, {"argv", "stdout", "stderr", "status"}, description)
    argv = _identity_current(root, record["argv"], f"{description} argv")
    try:
        value = json.loads(argv.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{description} argv is not JSON") from error
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        fail(f"{description} argv is malformed")
    _identity_current(root, record["stdout"], f"{description} stdout")
    _identity_current(root, record["stderr"], f"{description} stderr")
    status = _identity_current(root, record["status"], f"{description} status")
    if status.read_bytes() != b"0\n":
        fail(f"{description} status is not zero")
    return record


def validate_report(root: Path, report_path: Path) -> dict[str, Any]:
    root = _physical(root, "checkout root", directory=True)
    report_path = _physical(report_path, "wordexp report", directory=False)
    try:
        value = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("wordexp report is not valid JSON") from error
    report = _exact_dict(value, {"schema", "source_mount", "status", "products", "sources", "header_trace", "workload",
                                 "compile", "oracle_link", "oracle_inputs", "tools", "links", "cells"}, "wordexp report")
    if report["schema"] != SCHEMA or report["source_mount"] != SOURCE_MOUNT or report["status"] != "component-verified-not-family-qualified":
        fail("wordexp report contract differs")
    sources = report["sources"]
    expected_sources = {PROBE, DOC, RUNNER, LEGACY_RUNNER, "compat/x86_64/owned_wordexp_evidence.py"}
    if not isinstance(sources, dict) or set(sources) != expected_sources:
        fail("wordexp source roster differs")
    for source in expected_sources:
        _identity_current(root, sources[source], f"wordexp source {source}")
    products_record = _exact_dict(report["products"], {"dynamic", "static", "built_products"}, "wordexp products")
    dynamic_record = _exact_dict(products_record["dynamic"], {"root", "manifest", "files"}, "wordexp dynamic product")
    dynamic = _local_mounted(root, dynamic_record["root"], "wordexp dynamic product")
    if not isinstance(dynamic_record["files"], dict):
        fail("wordexp dynamic product files are malformed")
    current_dynamic = _product_record(root, dynamic, "dynamic")
    if dynamic_record != current_dynamic:
        fail("wordexp dynamic product identity drifted")
    static = None
    if products_record["static"] is not None:
        static_record = _exact_dict(products_record["static"], {"root", "manifest", "files"}, "wordexp static product")
        static = _local_mounted(root, static_record["root"], "wordexp static product")
        if static_record != _product_record(root, static, "static"):
            fail("wordexp static product identity drifted")
    if type(products_record["built_products"]) is not bool:
        fail("wordexp built product marker differs")
    header_trace = _identity_current(root, report["header_trace"], "wordexp installed header trace")
    _validate_header_trace(root, header_trace, dynamic)
    workload = _identity_current(root, report["workload"], "wordexp workload")
    _validate_command(root, report["compile"], "wordexp compile")
    _validate_command(root, report["oracle_link"], "wordexp pinned-musl link")
    tools = _exact_dict(report["tools"], {"before", "after"}, "wordexp tools")
    if not isinstance(tools["before"], dict) or not isinstance(tools["after"], dict) or set(tools["before"]) != set(tools["after"]):
        fail("wordexp tool roster differs")
    before = {name: _validate_tool_record(item, f"wordexp tool {name}") for name, item in tools["before"].items()}
    after = {name: _validate_tool_record(item, f"wordexp retained tool {name}") for name, item in tools["after"].items()}
    if before != after or set(before) != ({"dynamic-driver", "compiler", "oracle-compiler", "chroot", "timeout", "ldd", "shell", "linker"} | ({"static-driver"} if static else set())):
        fail("wordexp tools changed or have the wrong roster")
    dynamic_driver = dynamic / "bin/crabc-cc-dynamic"
    expected_dynamic_driver = {"path": _mounted(root, dynamic_driver), "sha256": _sha(dynamic_driver),
                               "mode": _mode(dynamic_driver)}
    if before["dynamic-driver"] != expected_dynamic_driver:
        fail("wordexp dynamic driver seal drifted")
    if static:
        static_driver = static / "bin/crabc-cc"
        expected_static_driver = {"path": _mounted(root, static_driver), "sha256": _sha(static_driver),
                                  "mode": _mode(static_driver)}
        if before["static-driver"] != expected_static_driver:
            fail("wordexp static driver seal drifted")
    if not isinstance(report["oracle_inputs"], dict) or set(report["oracle_inputs"]) != {"compiler", "source-manifest", "shared-libc", "static-libc", "gcc-specs"}:
        fail("wordexp pinned-musl input roster differs")
    for name, item in report["oracle_inputs"].items():
        item = _exact_dict(item, {"native", "retained"}, f"wordexp oracle input {name}")
        native = _validate_tool_record(item["native"], f"wordexp oracle native {name}")
        retained = _identity_current(root, item["retained"], f"wordexp retained oracle {name}")
        if native["sha256"] != retained.read_bytes() and False:
            fail("unreachable")
        if native["sha256"] != _sha(retained):
            fail(f"wordexp retained oracle {name} bytes differ from native seal")
    if report["oracle_inputs"]["compiler"]["native"] != before["oracle-compiler"]:
        fail("wordexp oracle compiler seal differs")
    links = report["links"]
    expected_links = {"dynamic-pie", "dynamic-non-pie"} | ({"static-et-exec", "static-pie"} if static else set())
    if not isinstance(links, dict) or set(links) != expected_links:
        fail("wordexp link roster differs")
    link_specs = {"dynamic-pie": (dynamic, "pie"), "dynamic-non-pie": (dynamic, "non-pie"),
                  "static-et-exec": (static, "static"), "static-pie": (static, "static-pie")}
    for name, item in links.items():
        item = _exact_dict(item, {"linkage", "executable", "receipt", "validated", "linker"}, f"wordexp {name} link")
        executable = _identity_current(root, item["executable"], f"wordexp {name} executable")
        receipt = _identity_current(root, item["receipt"], f"wordexp {name} receipt")
        validated_path = _identity_current(root, item["validated"], f"wordexp {name} validation")
        product, linkage = link_specs[name]
        if product is None or item["linkage"] != linkage:
            fail("wordexp linkage selection differs")
        # The retained reader validates the receipt's full actual linker
        # identity.  It must also equal the native before/after tool seal.
        try:
            receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
            actual_linker = receipt_value.get("resolved_linker")
            sealed_linker = {"path": before["linker"]["path"], "sha256": before["linker"]["sha256"]}
            if item["linker"] != sealed_linker or actual_linker != sealed_linker:
                fail("wordexp retained link selected an unsealed linker")
            observed = products.validate_retained_link(root, SOURCE_MOUNT, product, workload, executable, receipt,
                                                       linkage, actual_linker)
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
    if not isinstance(cells, dict) or set(cells) != {f"{mode}-{shell}" for mode in expected_modes for shell in SHELL_CASES}:
        fail("wordexp execution cell roster differs")
    for label, item in cells.items():
        item = _exact_dict(item, {"shell_case", "execution", "fixture_source", "external_alias_overrides", "oracle", "candidate", "expected_stdout"},
                           f"wordexp cell {label}")
        shell_case = label.rsplit("-", 1)[1]
        if item["shell_case"] != shell_case or shell_case not in SHELL_CASES:
            fail("wordexp shell case differs")
        execution = _exact_dict(item["execution"], {"root", "product_files", "product_aliases", "consumers", "fixtures"},
                                f"wordexp cell {label} execution")
        execution_root = _local_mounted(root, execution["root"], f"wordexp cell {label} execution root")
        local_execution = dict(execution)
        local_execution["root"] = str(execution_root)
        validate_execution_root(execution_root, local_execution)
        if item["fixture_source"] != report_cell_fixture(item["fixture_source"], root):
            fail("wordexp fixture source identities drifted")
        if item["external_alias_overrides"] not in ([], ["lib/ld-musl-x86_64.so.1"]):
            fail("wordexp external shell alias override differs")
        oracle = _validate_command(root, item["oracle"], f"wordexp cell {label} oracle")
        candidate = _validate_command(root, item["candidate"], f"wordexp cell {label} candidate")
        expected = b"owned-wordexp: PASS\n" if shell_case == "normal" else b"owned-wordexp-shell-unavailable: PASS\n"
        if item["expected_stdout"] != expected.decode("ascii"):
            fail("wordexp expected transcript differs")
        for stream in (oracle["stdout"], candidate["stdout"]):
            if _identity_current(root, stream, f"wordexp cell {label} stdout").read_bytes() != expected:
                fail("wordexp actual transcript differs")
        oracle_stderr = _identity_current(root, oracle["stderr"], f"wordexp cell {label} oracle stderr")
        candidate_stderr = _identity_current(root, candidate["stderr"], f"wordexp cell {label} candidate stderr")
        if oracle_stderr.read_bytes() != candidate_stderr.read_bytes():
            fail("wordexp actual oracle/candidate stderr differs")
    return report


def report_cell_fixture(value: object, root: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        fail("wordexp fixture source roster differs")
    return {name: _checkout_identity(root, _local_mounted(root, item.get("path") if isinstance(item, dict) else None,
                                                             f"wordexp fixture {name}"), f"wordexp fixture {name}")
            for name, item in value.items()}


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
