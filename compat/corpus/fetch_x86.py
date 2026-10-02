#!/usr/bin/env python3
"""Materialize the native x86_64 corpus input in this checkout.

Produces `.work/x86_64/owned-package-corpus-input/{apks,index}`, the default
`--archive-dir`/`--index` of `run_x86.py`: exactly the manifest's 59
`archive_roster` APKs and one repository index snapshot.

Each archive must match its pinned SHA-256 before it is kept. A matching file
already present is kept; otherwise it is copied from the primary checkout's
same input directory when that copy matches (lane worktrees share one primary
checkout), and only then downloaded from the manifest's exact repository URL.
Explicit `--mirror-base-url` repositories may recover unavailable archives at
the same exact filenames; their bytes must still match the pinned SHA-256.
Unavailable files are all reported after the remaining inputs are collected.

The index is a mutable upstream snapshot and is not digest-pinned. An existing
snapshot is kept unless `--refresh-index` is given; otherwise the primary
checkout's snapshot is copied when present, else the current index is
downloaded. The runner authenticates it inside the pinned native image with
the manifest's signing key alone and retains its observed digest. This host
helper only moves and hashes bytes; it never extracts or executes packages.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("manifest-x86_64.toml")
INPUT = Path(".work/x86_64/owned-package-corpus-input")
INDEX_NAME = "index/main-x86_64.APKINDEX.tar.gz"


class FetchError(RuntimeError):
    pass


def sha256(path: Path) -> str | None:
    if not path.is_file() or path.is_symlink():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def primary_input() -> Path | None:
    """Return the primary checkout's input directory when this is a worktree."""
    try:
        common = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=ROOT,
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    primary = Path(common).parent
    return None if primary == ROOT else primary / INPUT


def install(relative: str, expected: str | None, url: str, seed: Path | None, refresh: bool = False,
            mirrors: tuple[str, ...] = ()) -> str:
    """Place one file at INPUT/relative, returning how it was obtained.

    `expected=None` admits any bytes (the unpinned index); otherwise the file
    must match `expected` and a mismatching copy or download is never kept.
    """
    destination = ROOT / INPUT / relative
    present = sha256(destination)
    if not refresh and present is not None and (expected is None or present == expected):
        return "present"
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(dir=destination.parent, prefix=f".{destination.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(handle, "wb") as output:
            seeded = None if seed is None or refresh else sha256(seed / relative)
            if seeded is not None and (expected is None or seeded == expected):
                with (seed / relative).open("rb") as source:
                    shutil.copyfileobj(source, output)
                origin = "primary checkout"
            else:
                if expected is None and mirrors:
                    raise FetchError("unpinned index snapshots cannot use archive mirrors")
                candidates = (url, *mirrors)
                for position, candidate in enumerate(candidates):
                    try:
                        response = urllib.request.urlopen(candidate, timeout=60)
                    except OSError:
                        if position + 1 == len(candidates):
                            raise
                        continue
                    with response:
                        shutil.copyfileobj(response, output)
                    origin = "download" if candidate == url else f"mirror {candidate}"
                    url = candidate
                    break
        observed = sha256(temporary)
        if expected is not None and observed != expected:
            raise FetchError(f"{url}: SHA-256 {observed} differs from pinned {expected}")
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
        return origin
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh-index", action="store_true", help="download a new index snapshot")
    parser.add_argument("--mirror-base-url", action="append", default=[],
                        help="HTTPS repository containing the same exact pinned APK filenames; repeatable")
    arguments = parser.parse_args(argv)
    mirrors = tuple(base.rstrip("/") for base in arguments.mirror_base_url)
    for base in mirrors:
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            parser.error("--mirror-base-url must be an HTTPS repository URL without query or fragment")
    with MANIFEST.open("rb") as stream:
        manifest = tomllib.load(stream)
    repository = manifest["repository"]
    base = repository["base_url"].rstrip("/")
    seed = primary_input()
    origins: dict[str, int] = {}
    errors: list[str] = []
    for name, expected in sorted(manifest["archive_roster"].items()):
        try:
            origin = install(f"apks/{name}", expected, f"{base}/{name}", seed,
                             mirrors=tuple(f"{mirror}/{name}" for mirror in mirrors))
            origins[origin] = origins.get(origin, 0) + 1
        except (FetchError, OSError) as error:
            errors.append(f"{name}: {error}")
    try:
        index_origin = install(INDEX_NAME, None, f"{base}/{repository['index_filename']}", seed,
                               refresh=arguments.refresh_index)
    except (FetchError, OSError) as error:
        errors.append(f"{INDEX_NAME}: {error}")
    archive_directory = ROOT / INPUT / "apks"
    extra = sorted(set(os.listdir(archive_directory)) - set(manifest["archive_roster"])) if archive_directory.is_dir() else []
    if extra:
        errors.append(f"unpinned archives present: {', '.join(extra)}")
    if errors:
        for error in errors:
            print(f"x86 corpus input: FAIL: {error}", file=sys.stderr)
        return 1
    summary = ", ".join(f"{count} {origin}" for origin, count in sorted(origins.items()))
    print(f"x86 corpus input: PASS ({len(manifest['archive_roster'])} pinned archives: {summary}; "
          f"index snapshot {sha256(ROOT / INPUT / INDEX_NAME)} from {index_origin}); input: {INPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
