#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
import urllib.request

HTTPS_URL = re.compile(r"https://[^\s]+")
SHA256 = re.compile(r"[0-9a-f]{64}")


def install(pins: Path, archive: Path, destination: Path,
            source: str | None = None, sha256: str | None = None) -> None:
    pin = tomllib.loads(pins.read_text(encoding="utf-8"))["kache_native"]
    source = source if source is not None else pin["source"]
    sha256 = sha256 if sha256 is not None else pin["sha256"]
    if HTTPS_URL.fullmatch(source) is None:
        raise RuntimeError("kache source is not an https URL")
    if SHA256.fullmatch(sha256) is None:
        raise RuntimeError("kache archive sha256 is invalid")
    with urllib.request.urlopen(source, timeout=120) as response:
        with archive.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != sha256:
        raise RuntimeError("pinned native kache archive checksum differs")
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("kache")
        if not member.isfile():
            raise RuntimeError("pinned native kache is not a regular archive member")
        source_stream = bundle.extractfile(member)
        if source_stream is None:
            raise RuntimeError("pinned native kache archive member is unreadable")
        destination.write_bytes(source_stream.read())
    destination.chmod(0o755)
    actual = subprocess.check_output([str(destination), "--version"], text=True).strip()
    if actual != f"kache {pin['version']}":
        raise RuntimeError(f"pinned native kache version differs: {actual}")
    subprocess.run(["/usr/bin/mold", "--version"], check=True)
    archive.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", help="override the [kache_native] source URL (default: the pin)")
    parser.add_argument("--sha256", help="override the [kache_native] archive sha256 (default: the pin)")
    args = parser.parse_args()
    install(Path("/tmp/upstreams.toml"), Path("/tmp/kache.tar.gz"), Path("/usr/local/bin/kache"),
            source=args.source, sha256=args.sha256)
