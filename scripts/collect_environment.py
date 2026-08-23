#!/usr/bin/env python3
"""Write the reproducibility metadata required beside compatibility reports."""

from __future__ import annotations

import argparse
import json
import subprocess
import tomllib
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def command_output(*command: str) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.strip()


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
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(arguments.output)


if __name__ == "__main__":
    main()
