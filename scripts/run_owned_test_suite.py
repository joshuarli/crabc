#!/usr/bin/env python3
"""Run Cargo tests with an owned canonical-loader execution boundary.

The installed `crabc-cc` driver intentionally emits the fixed normal-kernel
interpreter `/lib/ld-crabc-aarch64.so.1`. The development container is
disposable and does not preinstall that loader, so this test-only launcher
copies the already-built debug crabc loader there for the duration of one
Cargo invocation. It refuses to replace an existing path and verifies the
copy before removing it, keeping the staging operation explicit and bounded.

This launcher does not set `LD_LIBRARY_PATH`: Rust test binaries continue to
use their normal host runtime, while individual C fixture tests retain their
explicit crabc debug-library search paths.  Cargo emits only `libc.so` in that
debug directory, so the launcher temporarily supplies the deliberate installed
libc aliases there as well.  This keeps those fixtures on one debug runtime
rather than falling through to a second, installed libc just to resolve
`libdl.so` or `libpthread.so`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence


CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")


class TestSuiteError(RuntimeError):
    """A violated owned-test execution boundary."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular_file(path: Path, description: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise TestSuiteError(f"{description} must be a regular file: {path}")
    return resolved


def installed_libc_aliases(sysroot: Path) -> tuple[str, ...]:
    """Return only installed library aliases that resolve to the owned libc."""

    library_directory = sysroot / "usr/lib"
    libc = require_regular_file(library_directory / "libc.so", "installed libc")
    if not library_directory.is_dir():
        raise TestSuiteError(f"installed library directory is unavailable: {library_directory}")
    aliases: list[str] = []
    for path in sorted(library_directory.iterdir()):
        if path.name == "libc.so" or not path.is_symlink():
            continue
        try:
            target = path.resolve(strict=True)
        except OSError as error:
            raise TestSuiteError(f"installed library alias is not resolvable: {path}") from error
        if target == libc:
            aliases.append(path.name)
    if not aliases:
        raise TestSuiteError(f"installed sysroot has no deliberate libc aliases: {library_directory}")
    return tuple(aliases)


@contextmanager
def staged_debug_runtime_aliases(sysroot: Path, loader: Path) -> Iterator[None]:
    """Temporarily mirror installed libc aliases next to the debug runtime."""

    runtime_directory = loader.parent
    libc = require_regular_file(runtime_directory / "libc.so", "owned debug libc")
    staged: list[Path] = []
    try:
        for name in installed_libc_aliases(sysroot):
            alias = runtime_directory / name
            if alias.exists() or alias.is_symlink():
                raise TestSuiteError(f"refusing to replace existing debug runtime alias: {alias}")
            alias.symlink_to("libc.so")
            staged.append(alias)
        yield
    finally:
        unexpected: list[Path] = []
        for alias in reversed(staged):
            try:
                expected = (
                    alias.is_symlink()
                    and alias.readlink() == Path("libc.so")
                    and alias.resolve(strict=True) == libc
                )
            except OSError:
                expected = False
            if expected:
                alias.unlink()
            else:
                unexpected.append(alias)
        if unexpected:
            paths = ", ".join(str(path) for path in unexpected)
            raise TestSuiteError(f"staged debug runtime aliases changed unexpectedly and were retained: {paths}")


@contextmanager
def staged_owned_loader(loader: Path) -> Iterator[None]:
    """Make exactly one absent canonical loader available to the kernel."""

    if os.geteuid() != 0:
        raise TestSuiteError("owned C fixture execution requires root in the disposable Linux container")
    if CANONICAL_LOADER.exists() or CANONICAL_LOADER.is_symlink():
        raise TestSuiteError(f"refusing to replace existing canonical loader: {CANONICAL_LOADER}")
    CANONICAL_LOADER.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(loader, CANONICAL_LOADER)
    try:
        yield
    finally:
        if CANONICAL_LOADER.exists() and sha256_file(CANONICAL_LOADER) == sha256_file(loader):
            CANONICAL_LOADER.unlink()
        elif CANONICAL_LOADER.exists():
            raise TestSuiteError(
                f"staged canonical loader changed unexpectedly and was retained: {CANONICAL_LOADER}"
            )


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sysroot", type=Path, required=True, help="installed owned crabc sysroot")
    parser.add_argument("--loader", type=Path, required=True, help="owned debug loader copied to the canonical path")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Cargo command after --")
    args = parser.parse_args(arguments)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a Cargo command is required after --")
    return args


def main(arguments: Sequence[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        sysroot = args.sysroot.expanduser().resolve()
        manifest = require_regular_file(sysroot / "share/crabc/manifest.json", "owned sysroot manifest")
        del manifest
        loader = require_regular_file(args.loader, "owned debug loader")
        environment = dict(os.environ)
        environment["CRABC_TEST_SYSROOT"] = str(sysroot)
        with staged_debug_runtime_aliases(sysroot, loader):
            with staged_owned_loader(loader):
                return subprocess.run(args.command, env=environment, check=False).returncode
    except TestSuiteError as error:
        print(f"owned-test-suite: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
