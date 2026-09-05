#!/usr/bin/env python3
"""Prepare reproducible static products; this is never runtime qualification.

The existing owned-static producer selects and records the pinned tools. The
existing package owner validates installed payloads and performs bounded safe
extraction. This coordinator only binds those operations to one clean source
revision and the POSIX catalog's primary/reproduction/extracted product names.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

import owned_static_sysroot_package as package

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-posix-static-preparation/v1"
PRODUCER = "scripts/build_x86_64_owned_sysroot.py"
PACKAGER = "compat/x86_64/owned_static_sysroot_package.py"


class PreparationError(RuntimeError):
    """Preparation artifacts do not identify the complete frozen product set."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def physical(root: Path, path: Path) -> Path:
    path = path.absolute()
    require(path.resolve() == path and path.is_relative_to(root / ".work")
            and path != root / ".work", "evidence must be a physical checkout .work child")
    return path


def relative(root: Path, path: Path) -> str:
    return physical(root, path).relative_to(root).as_posix()


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


def read(path: Path) -> object:
    package.require_regular_file(path, "preparation record")
    return json.loads(path.read_text())


def source_identity(root: Path) -> dict:
    """Use the dynamic coordinator's content/mode hashing, without its contracts.

    Cleanliness is mandatory here, rather than only at publication. Hash actual
    files as well as HEAD so a receipt cannot survive a source-content change.
    """
    def git(*arguments: str) -> bytes:
        return subprocess.check_output(["git", *arguments], cwd=root)
    require(not git("status", "--porcelain", "--untracked-files=all").strip(),
            "static preparation requires clean committed source")
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    content = hashlib.sha256()
    for name in names:
        path = root / os.fsdecode(name)
        mode = path.lstat().st_mode
        data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        content.update(name + b"\0" + str(stat.S_IMODE(mode)).encode() + b"\0")
        content.update(hashlib.sha256(data).digest())
    return {"revision": git("rev-parse", "HEAD").decode().strip(),
            "content_sha256": content.hexdigest()}


def product_paths(work: Path) -> dict[str, Path]:
    return {"primary": work / "products/primary",
            "reproduction": work / "products/reproduction",
            "extracted": work / "products/extracted" / package.ARCHIVE_ROOT}


def commands(root: Path, work: Path) -> dict[str, list[str]]:
    base = relative(root, work)
    result = {}
    for label in ("primary", "reproduction"):
        result[f"{label}-build"] = ["python3", "-B", PRODUCER, "--output", f"{base}/products/{label}"]
    for label in ("primary", "reproduction"):
        result[f"{label}-package"] = ["python3", "-B", PACKAGER, "create", "--source",
            f"{base}/products/{label}", "--archive", f"{base}/archives/{label}.tar.xz"]
    result["extract"] = ["python3", "-B", PACKAGER, "extract", "--archive",
        f"{base}/archives/primary.tar.xz", "--destination", f"{base}/products/extracted"]
    return result


def run_step(root: Path, work: Path, step: str, command: list[str]) -> None:
    prefix = work / "steps" / step
    write_new(prefix.with_suffix(".command.json"), command)
    with prefix.with_suffix(".stdout").open("xb") as output, prefix.with_suffix(".stderr").open("xb") as errors:
        try:
            result = subprocess.run(command, cwd=root, stdout=output, stderr=errors, check=False)
            status = result.returncode
        except OSError as error:
            errors.write((str(error) + "\n").encode())
            status = 127
    with prefix.with_suffix(".status").open("x") as output:
        output.write(f"{status}\n")
    require(status == 0, f"{step} exited {status}; retained diagnostics: {prefix}")


def file_identity(root: Path, path: Path) -> dict:
    physical(root, path)
    package.require_regular_file(path, "preparation artifact")
    return {"path": relative(root, path), "sha256": package.sha256_file(path), "size": path.stat().st_size}


def tree_identity(product: Path) -> dict:
    """Compare the package owner's normalized modes, including directories."""
    entries = package.source_entries(product)
    package.validate_installed_tree(product, entries)
    return {name.as_posix(): ({"kind": "directory", "mode": 0o755} if path.is_dir() else
            {"kind": "file", "mode": package.normalized_mode(path),
             "sha256": package.sha256_file(path), "size": path.stat().st_size})
            for name, path in entries}


def exact_children(path: Path, expected: set[str]) -> None:
    require(path.is_dir() and not path.is_symlink(), f"missing or unsafe directory: {path}")
    require({entry.name for entry in path.iterdir()} == expected, f"missing or extra entries: {path}")


def collect(root: Path, work: Path) -> dict:
    """Recompute a preparation record from live source, products and raw steps.

    Extraction verification delegates to the existing bounded package parser.
    Its temporary materialization stays below this run and is removed before
    returning; no product, command log, or successful receipt is rewritten.
    """
    work = physical(root, work)
    source = source_identity(root)
    for name in ("source-before.json", "source-after.json"):
        require(read(work / name) == source, f"source seal changed: {name}")
    exact_children(work / "products", {"primary", "reproduction", "extracted"})
    exact_children(work / "products/extracted", {package.ARCHIVE_ROOT})
    exact_children(work / "archives", {"primary.tar.xz", "reproduction.tar.xz"})
    expected_commands = commands(root, work)
    exact_children(work / "steps", {f"{step}.{suffix}" for step in expected_commands
                   for suffix in ("command.json", "stdout", "stderr", "status")})
    steps = {}
    for step, command in expected_commands.items():
        prefix = work / "steps" / step
        require(read(prefix.with_suffix(".command.json")) == command, f"command changed: {step}")
        require(prefix.with_suffix(".status").read_bytes() == b"0\n", f"unsuccessful step: {step}")
        steps[step] = {"command": command, "exit_status": 0,
            "artifacts": {suffix: file_identity(root, prefix.with_suffix(f".{suffix}"))
                          for suffix in ("command.json", "stdout", "stderr", "status")}}
    products = {}
    for label, product in product_paths(work).items():
        physical(root, product)
        tree = tree_identity(product)
        manifest_path = product / package.MANIFEST_RELATIVE_PATH
        manifest = read(manifest_path)
        require(isinstance(manifest.get("producer_tools"), dict) and manifest["producer_tools"],
                f"producer tool provenance absent: {label}")
        require(isinstance(manifest.get("toolchain"), str), f"toolchain provenance absent: {label}")
        products[label] = {"path": relative(root, product), "manifest": file_identity(root, manifest_path),
                           "tree": tree, "producer_tools": manifest["producer_tools"], "toolchain": manifest["toolchain"]}
    primary = products["primary"]
    for label in ("reproduction", "extracted"):
        require(products[label]["tree"] == primary["tree"], f"product differs from primary: {label}")
    archives = {label: file_identity(root, work / "archives" / f"{label}.tar.xz")
                for label in ("primary", "reproduction")}
    require(filecmp.cmp(work / "archives/primary.tar.xz", work / "archives/reproduction.tar.xz", shallow=False),
            "independent package archive bytes differ")
    with tempfile.TemporaryDirectory(prefix=".verify-static-package.", dir=work) as temporary:
        extracted = package.extract_archive(work / "archives/primary.tar.xz", Path(temporary) / "extraction")
        require(tree_identity(extracted) == primary["tree"], "archive payload differs from primary")
    require(source_identity(root) == source, "source changed during preparation validation")
    return {"schema": SCHEMA, "status": "prepared-unqualified", "work": relative(root, work),
            "source": source, "source_seals": {name: file_identity(root, work / name)
                for name in ("source-before.json", "source-after.json")},
            "pins": {name: package.sha256_file(root / name)
                for name in ("compat/upstreams.toml", "rust-toolchain.toml")},
            "products": products, "archives": archives, "steps": steps}


def prepare(root: Path, work: Path) -> Path:
    work = physical(root, work)
    source = source_identity(root)
    require(not work.exists(), "preparation requires a fresh run directory")
    work.mkdir(parents=True)
    for name in ("products", "archives", "steps"):
        (work / name).mkdir()
    write_new(work / "source-before.json", source)
    try:
        for step, command in commands(root, work).items():
            run_step(root, work, step, command)
    finally:
        # Even a failed producer leaves its command/status/log files. A dirty
        # final source cannot acquire a success seal or preparation receipt.
        try:
            write_new(work / "source-after.json", source_identity(root))
        except PreparationError as error:
            write_new(work / "source-after-error.json", {"error": str(error)})
    record = collect(root, work)
    destination = work / "preparation.json"
    write_new(destination, record)
    return destination


def validate_receipt(root: Path, path: Path) -> dict:
    path = physical(root, path)
    require(path.name == "preparation.json", "expected preparation.json receipt")
    record = read(path)
    observed = collect(root, path.parent)
    require(record == observed, "preparation receipt differs from recomputed evidence")
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "validate"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            print(prepare(ROOT, args.path))
        else:
            validate_receipt(ROOT, args.path)
            print("owned POSIX static preparation: valid; runtime unqualified")
    except (PreparationError, package.PackageError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"owned POSIX static preparation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
