#!/usr/bin/env python3
"""Product-scoped source identity for the native x86-64 products.

The products are the bytes that `PRODUCT_BUILDERS` write. Their source
identity is the names, modes and bytes of the product-input set:

- every tracked or untracked non-ignored file below `PRODUCT_TREES`, so an
  added file there changes the digest;
- `PRODUCT_FILES`, the other repository files a product build reads,
  including the Cargo workspace members outside the product trees and the
  two loader case runners whose presence the TLS contract checks;
- `PRODUCT_BUILDERS`, `PRODUCT_LAZY_MODULES` and the module-level Python
  import closure of both, resolved the way the builders resolve imports.

A commit outside this set keeps products, and evidence bound to them, valid.
The revision is informational: it is recorded, never compared for validity.
`guard` runs one product build under strace and fails when the build touches a
repository file outside the set; every product build in qualification runs
under it, so a product never depends on a file the digest does not cover.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_TREES = (
    ".cargo", "builtins", "crabc-core", "crabc-mimalloc", "crabc-rs", "crt", "docker", "include", "ldso",
    "libc", "unwinder",
)
PRODUCT_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "compat/allocator/native-mi-adapter/Cargo.toml",
    "compat/allocator/native-mi-adapter/src/lib.rs",
    "compat/allocator/runtime-ticket-zero-adapter/Cargo.toml",
    "compat/allocator/runtime-ticket-zero-adapter/src/lib.rs",
    "compat/allocator/test-adapter/Cargo.toml",
    "compat/allocator/test-adapter/src/lib.rs",
    "compat/upstreams.toml",
    "compat/x86_64/dynamic-product-state.json",
    "compat/x86_64/dynamic-product.toml",
    "compat/x86_64/header_callable_inventory.toml",
    "compat/x86_64/loader-libc-tls-runtime-v1.toml",
    "compat/x86_64/run_owned_ldso_initial_tls_cases.sh",
    "compat/x86_64/run_owned_ldso_runtime_v1_cases.sh",
    "rust-toolchain.toml",
)
PRODUCT_BUILDERS = (
    "compat/x86_64/owned_dynamic_package.py",
    "compat/x86_64/owned_static_sysroot_package.py",
    "scripts/build_x86_64_owned_dynamic_sysroot.py",
    "scripts/build_x86_64_owned_sysroot.py",
)
PRODUCT_LAZY_MODULES = (
    "compat/allocator/perf_x86_64.py",
    "compat/x86_64/compiler_helper_evidence.py",
    "compat/x86_64/header_callable_inventory.py",
    "compat/x86_64/validate_loader_libc_tls_runtime_v1.py",
)
PYTHON_SEARCH = ("compat/x86_64", "scripts", "")
GUARD_EXCLUDED_TOP = frozenset({".git", ".work", "target"})
GUARD_PINNED_CACHES = ("compat/allocator/.cache",)
GUARD_SCRATCH = ".work/x86_64/tmp"


class SourceSealError(RuntimeError):
    """The checkout cannot provide a product source identity."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceSealError(message)


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(["git", "-c", f"safe.directory={root}", *arguments], cwd=root,
                                       env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.CalledProcessError) as error:
        raise SourceSealError(f"git {arguments[0]} failed in {root}: {error}") from error


def _module_level_imports(tree: ast.Module) -> Iterable[tuple[int, str, tuple[str, ...]]]:
    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield 0, alias.name, ()
        elif isinstance(node, ast.ImportFrom):
            yield node.level, node.module or "", tuple(alias.name for alias in node.names)
        else:
            pending.extend(ast.iter_child_nodes(node))


def _resolve(names: frozenset[str], importer: str, level: int, name: str) -> str | None:
    parent = importer.rpartition("/")[0]
    if level:
        for _ in range(level - 1):
            parent = parent.rpartition("/")[0]
        directories = [parent]
    else:
        directories = [parent, *PYTHON_SEARCH]
    parts = [part for part in name.split(".") if part]
    for directory in directories:
        stem = "/".join(part for part in (directory, *parts) if part)
        for candidate in ((stem + ".py") if parts else None, (stem + "/__init__.py") if stem else "__init__.py"):
            if candidate in names:
                return candidate
    return None


def _python_closure(names: frozenset[str], read: Callable[[str], bytes]) -> frozenset[str]:
    seen: set[str] = set()
    pending = []
    for relative in (*PRODUCT_BUILDERS, *PRODUCT_LAZY_MODULES):
        require(relative in names, f"product builder module is missing: {relative}")
        pending.append(relative)
    while pending:
        relative = pending.pop()
        if relative in seen:
            continue
        seen.add(relative)
        try:
            tree = ast.parse(read(relative), filename=relative)
        except (OSError, SyntaxError, ValueError) as error:
            raise SourceSealError(f"product module cannot be parsed: {relative}: {error}") from error
        for level, module, members in _module_level_imports(tree):
            for name in (module, *(f"{module}.{member}" if module else member for member in members)):
                resolved = _resolve(names, relative, level, name)
                if resolved is not None:
                    pending.append(resolved)
    return frozenset(seen)


def select_product_files(names: Iterable[str], read: Callable[[str], bytes]) -> tuple[str, ...]:
    """Return the sorted product-input subset of one complete checkout listing."""

    names = frozenset(names)
    for relative in PRODUCT_FILES:
        require(relative in names, f"product input is missing: {relative}")
    trees = {name for name in names if name.split("/", 1)[0] in PRODUCT_TREES}
    return tuple(sorted(trees | set(PRODUCT_FILES) | _python_closure(names, read)))


def product_files(root: Path) -> tuple[str, ...]:
    """Return the checkout's sorted repository-relative product-input set."""

    listed = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    names = {os.fsdecode(name) for name in listed.split(b"\0") if name}
    return select_product_files(names, lambda name: (root / name).read_bytes())


def digest_entries(entries: Iterable[tuple[str, int, bytes]]) -> str:
    """Hash sorted `(name, permission bits, bytes or symlink target)` entries."""

    result = hashlib.sha256()
    for name, mode, data in sorted(entries):
        result.update(os.fsencode(name) + b"\0" + str(mode).encode() + b"\0")
        result.update(hashlib.sha256(data).digest())
    return result.hexdigest()


def product_source_digest(root: Path) -> str:
    """Hash the checkout's product-input names, modes and bytes."""

    def entry(name: str) -> tuple[str, int, bytes]:
        path = root / name
        try:
            mode = path.lstat().st_mode
            data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        except OSError as error:
            raise SourceSealError(f"product input cannot be read: {name}: {error}") from error
        return name, stat.S_IMODE(mode), data

    return digest_entries(entry(name) for name in product_files(root))


def product_source_digest_of(files: Mapping[str, tuple[int, bytes]]) -> str:
    """Hash the product inputs of a complete tree given as `{name: (mode, bytes)}`."""

    selected = select_product_files(files, lambda name: files[name][1])
    return digest_entries((name, *files[name]) for name in selected)


def require_clean(root: Path) -> None:
    require(not _git(root, "status", "--porcelain", "--untracked-files=all").strip(),
            "qualification requires clean committed source")


def revision(root: Path) -> str:
    """The checked-out commit; informational, never a validity input."""

    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def seal(root: Path) -> dict[str, str]:
    """Return a clean checkout's `{revision, content_sha256}` source seal.

    `content_sha256` is the product source digest. `revision` records where
    the seal was taken; compare seals with `same_product`, never by revision.
    """

    require_clean(root)
    return {"revision": revision(root), "content_sha256": product_source_digest(root)}


def same_product(left: object, right: object) -> bool:
    """Whether two source seals name the same product source."""

    def digest(value: object) -> str | None:
        content = value.get("content_sha256") if isinstance(value, Mapping) else None
        return content if isinstance(content, str) and re.fullmatch(r"[0-9a-f]{64}", content) else None

    return digest(left) is not None and digest(left) == digest(right)


# ---------------------------------------------------------------------------
# Runtime completeness guard


PATH_ARGUMENTS = {
    **dict.fromkeys(("access", "acct", "chdir", "chmod", "chown", "chroot", "creat", "execve", "getxattr",
                     "lchown", "lgetxattr", "listxattr", "llistxattr", "lremovexattr", "lsetxattr", "lstat",
                     "mkdir", "mknod", "open", "readlink", "removexattr", "rmdir", "setxattr", "stat",
                     "statfs", "swapoff", "swapon", "truncate", "umount2", "unlink", "uselib", "utime",
                     "utimes"), ((None, 0),)),
    **dict.fromkeys(("link", "rename"), ((None, 0), (None, 1))),
    "symlink": ((None, 1),),
    "mount": ((None, 1),),
    "inotify_add_watch": ((None, 1),),
    **dict.fromkeys(("execveat", "faccessat", "faccessat2", "fchmodat", "fchmodat2", "fchownat", "fstatat64",
                     "futimesat", "mkdirat", "mknodat", "name_to_handle_at", "newfstatat", "open_tree",
                     "openat", "openat2", "readlinkat", "statx", "unlinkat", "utimensat", "getxattrat",
                     "listxattrat", "removexattrat", "setxattrat"), ((0, 1),)),
    **dict.fromkeys(("linkat", "renameat", "renameat2"), ((0, 1), (2, 3))),
    "symlinkat": ((1, 2),),
    "fanotify_mark": ((3, 4),),
}
FORKS = frozenset({"clone", "clone3", "fork", "vfork"})
PATHLESS = frozenset({"exit", "exit_group", "getcwd", "kill", "pidfd_open", "pidfd_send_signal", "setns",
                      "rt_sigqueueinfo", "rt_tgsigqueueinfo", "tgkill", "tkill", "unshare", "wait4", "waitid"})
OPENS = frozenset({"creat", "open", "openat", "openat2"})
LINE = re.compile(r"^(?P<name>[a-z0-9_]+)\((?P<arguments>.*)\)\s+=\s+(?P<result>-?\d+|0x[0-9a-f]+)"
                  r"(?:<(?P<path>(?:[^>\\]|\\.)*)>)?")
DESCRIPTOR = re.compile(r"^(?:AT_FDCWD|-?\d+)(?:<(?P<path>(?:[^>\\]|\\.)*)>)?$")
ESCAPE = re.compile(rb"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)")
SIMPLE_ESCAPES = {b"n": b"\n", b"t": b"\t", b"r": b"\r", b"v": b"\v", b"f": b"\f", b"a": b"\a", b"b": b"\b"}


@dataclass(frozen=True)
class Access:
    """One successful traced syscall that named a repository path."""

    path: str
    syscall: str
    program: str


def _split_arguments(text: str) -> list[str]:
    arguments, depth, start, index, quoted = [], 0, 0, 0, False
    while index < len(text):
        character = text[index]
        if quoted:
            if character == "\\":
                index += 1
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{(":
            depth += 1
        elif character in "]})":
            depth -= 1
        elif character == "," and depth == 0:
            arguments.append(text[start:index].strip())
            start = index + 1
        index += 1
    arguments.append(text[start:].strip())
    return arguments


def _unescape(text: str) -> str:
    def replace(match: re.Match[bytes]) -> bytes:
        token = match.group(1)
        if token[:1] == b"x" and len(token) == 3:
            return bytes([int(token[1:], 16)])
        if token[:1].isdigit():
            return bytes([int(token, 8)])
        return SIMPLE_ESCAPES.get(token, token)

    return os.fsdecode(ESCAPE.sub(replace, os.fsencode(text)))


def _string(argument: str) -> str | None:
    if len(argument) < 2 or argument[0] != '"':
        return None
    end = argument.rfind('"')
    require(end > 0, f"unterminated traced string: {argument}")
    return _unescape(argument[1:end])


def _descriptor_path(argument: str, cwd: str) -> str | None:
    match = DESCRIPTOR.match(argument)
    if match is None:
        return None
    if match.group("path") is not None:
        return _unescape(match.group("path"))
    return cwd if argument.startswith("AT_FDCWD") else None


def _join(base: str | None, path: str) -> str | None:
    if path.startswith("/"):
        return os.path.normpath(path)
    if base is None:
        return None
    return os.path.normpath(os.path.join(base, path)) if path else base


def _is_git(program: str) -> bool:
    return os.path.basename(program) == "git" or "/git-core/" in program


def traced_accesses(trace: Path, root_cwd: str) -> list[Access]:
    """Replay a `strace -ff -y -z` trace and return each successful path access.

    Each process starts with its parent's program and working directory at
    the fork that created it; a process whose fork the trace does not show
    starts in `root_cwd`. A git process's own accesses are its metadata walk,
    not build inputs, and are omitted.
    """

    files = {int(path.name.rsplit(".", 1)[1]): path for path in trace.parent.glob(trace.name + ".*")}
    require(bool(files), f"strace wrote no trace: {trace}")
    children: set[int] = set()
    lines = {}
    for pid, path in files.items():
        lines[pid] = path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
        for line in lines[pid]:
            match = LINE.match(line)
            if match is not None and match.group("name") in FORKS:
                children.add(int(match.group("result"), 0))
    roots = sorted(pid for pid in files if pid not in children)
    require(bool(roots), "trace has no root process")
    state = {pid: ("", root_cwd) for pid in roots}
    order = list(reversed(roots))
    accesses: list[Access] = []
    while order:
        pid = order.pop()
        program, cwd = state[pid]
        for line in lines.get(pid, ()):
            match = LINE.match(line)
            if match is None:
                continue
            name, result = match.group("name"), match.group("result")
            arguments = _split_arguments(match.group("arguments"))
            if name in FORKS:
                child = int(result, 0)
                state[child] = (program, cwd)
                order.append(child)
                continue
            if name in PATHLESS:
                continue
            if name == "fchdir":
                cwd = _descriptor_path(arguments[0], cwd) or cwd
                continue
            require(name in PATH_ARGUMENTS, f"trace has an unclassified path syscall: {line}")
            paths = []
            for descriptor, position in PATH_ARGUMENTS[name]:
                value = _string(arguments[position]) if position < len(arguments) else None
                if value is None:
                    continue
                base = cwd if descriptor is None else _descriptor_path(arguments[descriptor], cwd)
                paths.append(_join(base, value))
            if name in OPENS and match.group("path") is not None:
                paths = [_unescape(match.group("path"))]
            if name in ("execve", "execveat") and paths and paths[0] is not None:
                program = paths[0]
            if name == "chdir" and paths and paths[0] is not None:
                cwd = paths[0]
            if _is_git(program):
                continue
            accesses.extend(Access(path, name, program) for path in paths if path is not None)
    return accesses


def out_of_set(root: Path, accesses: Iterable[Access], allowed: Iterable[str]) -> dict[str, Access]:
    """Return each repository file the accesses touched outside `allowed`.

    A directory contributes only its listing, and a product tree's listing is
    already in the digest through its file names, so directories are skipped.
    `GUARD_PINNED_CACHES` hold ignored downloads that the builder checks
    against a digest pinned in `compat/upstreams.toml` before use.
    """

    allowed = frozenset(allowed)
    prefix = str(root).rstrip("/") + "/"
    result: dict[str, Access] = {}
    for access in accesses:
        if not access.path.startswith(prefix) or os.path.isdir(access.path):
            continue
        name = access.path[len(prefix):]
        parts = name.split("/")
        if (parts[0] in GUARD_EXCLUDED_TOP or "__pycache__" in parts
                or any(name.startswith(cache + "/") for cache in GUARD_PINNED_CACHES)):
            continue
        if name not in allowed:
            result.setdefault(name, access)
    return result


def guard(root: Path, command: Sequence[str]) -> int:
    """Run one product build from `root` under strace; fail on an out-of-set access."""

    require(bool(command), "guard requires a product build command")
    scratch = root / GUARD_SCRATCH
    scratch.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="product-guard.", dir=scratch))
    try:
        trace = directory / "trace"
        status = subprocess.run(
            ["strace", "-ff", "-qq", "-z", "--seccomp-bpf", "-y", "-s", "65535",
             "-e", "trace=%file,%process,fchdir", "-e", "signal=none", "-o", str(trace), "--", *command],
            cwd=root, check=False,
        ).returncode
        if status != 0:
            return status
        violations = out_of_set(root, traced_accesses(trace, str(root)), product_files(root))
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    if violations:
        print("product build touched repository files outside the product-input set:", file=sys.stderr)
        for name, access in sorted(violations.items()):
            print(f"  {name or '.'} ({access.syscall} by {access.program})", file=sys.stderr)
        return 1
    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("digest", help="print the product source digest")
    commands.add_parser("files", help="print the product-input set")
    run = commands.add_parser("guard", help="run one product build under the completeness guard")
    run.add_argument("build", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(arguments)
    try:
        if parsed.operation == "digest":
            print(product_source_digest(ROOT))
        elif parsed.operation == "files":
            print("\n".join(product_files(ROOT)))
        else:
            build = parsed.build[1:] if parsed.build[:1] == ["--"] else parsed.build
            return guard(ROOT, build)
    except SourceSealError as error:
        print(f"product source seal: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
