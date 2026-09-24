#!/usr/bin/env python3
"""Fetch the finite native x86_64 corpus input into the runner's default boundary.

Downloads exactly the manifest's repository index and its 59 `archive_roster`
APK URLs into `.work/x86_64/owned-package-corpus-input`, which is where
`run_x86.py` reads them by default. Every archive must match its pinned
SHA-256 before it is kept; an existing matching archive is not refetched. The
index is a mutable upstream snapshot: an existing one is kept unless
`--refresh-index` is given, and its signature is verified by the runner, not
here. This helper runs on the host (the runner's container has no network) and
never extracts or executes package content.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("manifest-x86_64.toml")
INPUT = ROOT / ".work/x86_64/owned-package-corpus-input"
ARCHIVES = INPUT / "apks"
INDEX = INPUT / "index/main-x86_64.APKINDEX.tar.gz"


def download(url: str, destination: Path, expected_sha256: str | None) -> str:
    """Write `url` to `destination` atomically, returning the observed digest."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=destination.parent, prefix=f".{destination.name}.")
    try:
        digest = hashlib.sha256()
        with os.fdopen(handle, "wb") as output, urllib.request.urlopen(url, timeout=60) as response:
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                output.write(chunk)
        observed = digest.hexdigest()
        if expected_sha256 is not None and observed != expected_sha256:
            raise SystemExit(f"{url}: SHA-256 {observed} differs from pinned {expected_sha256}")
        os.replace(temporary, destination)
        return observed
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh-index", action="store_true", help="replace an existing index snapshot")
    arguments = parser.parse_args()
    with MANIFEST.open("rb") as stream:
        manifest = tomllib.load(stream)
    base = manifest["repository"]["base_url"].rstrip("/")
    for name, expected in sorted(manifest["archive_roster"].items()):
        archive = ARCHIVES / name
        if archive.is_file() and not archive.is_symlink() \
                and hashlib.sha256(archive.read_bytes()).hexdigest() == expected:
            continue
        download(f"{base}/{name}", archive, expected)
    if arguments.refresh_index or not INDEX.is_file():
        download(f"{base}/{manifest['repository']['index_filename']}", INDEX, None)
    observed = hashlib.sha256(INDEX.read_bytes()).hexdigest()
    print(f"x86 corpus input: {len(manifest['archive_roster'])} pinned archives; index snapshot {observed}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
