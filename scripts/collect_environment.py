#!/usr/bin/env python3
"""Write the reproducibility metadata required beside compatibility reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def command_output(*command: str) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    """Hash public headers by names and contents, independent of host paths."""

    digest = hashlib.sha256()
    for member in sorted(root.rglob("*")):
        if not member.is_file():
            continue
        relative = member.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(member.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def artifact_record(path: Path) -> dict[str, str | None]:
    """Describe one required build input or artifact without inventing a hash."""

    relative = path.relative_to(ROOT_DIR).as_posix()
    return {
        "path": relative,
        "sha256": sha256_file(path) if path.is_file() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT_DIR / "compat/reports/environment.json",
        help="JSON report path (default: %(default)s)",
    )
    arguments = parser.parse_args()

    with (ROOT_DIR / "compat/upstreams.toml").open("rb") as stream:
        upstreams = tomllib.load(stream)

    report = {
        "crabc_git_sha": command_output("git", "-C", str(ROOT_DIR), "rev-parse", "HEAD"),
        # A commit alone is insufficient provenance when an evidence run could
        # have incorporated uncommitted source. Keep this explicit so the
        # final dashboard can distinguish its tested source parent from its
        # generated evidence-only child.
        "crabc_git_dirty": bool(
            command_output("git", "-C", str(ROOT_DIR), "status", "--porcelain")
        ),
        "target": "aarch64-unknown-linux-musl",
        "linux_kernel": command_output("uname", "-a"),
        "rustc_vv": command_output("rustc", "-Vv"),
        "clang_version": command_output("clang", "--version").splitlines()[0],
        "lld_version": command_output("ld.lld", "--version").splitlines()[0],
        "readelf_version": command_output("readelf", "--version").splitlines()[0],
        "environment": upstreams["environment"],
        "musl": upstreams["musl"],
        "libc_test": upstreams["libc_test"],
        "os_test": upstreams["os_test"],
        "libc_bench": upstreams["libc_bench"],
        "artifacts": {
            "libc_shared": artifact_record(ROOT_DIR / "target" / "debug" / "libc.so"),
            "libc_static": artifact_record(ROOT_DIR / "target" / "release" / "libc.a"),
            "ldso_shared": artifact_record(ROOT_DIR / "target" / "debug" / "libldso.so"),
            "public_headers": {
                "path": "include",
                "sha256": sha256_tree(ROOT_DIR / "include"),
            },
            "workspace_lock": artifact_record(ROOT_DIR / "Cargo.lock"),
            "oracle_pins": artifact_record(ROOT_DIR / "compat" / "upstreams.toml"),
        },
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(arguments.output)


if __name__ == "__main__":
    main()
