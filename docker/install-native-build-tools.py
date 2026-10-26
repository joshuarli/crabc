#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tarfile
import tomllib
import urllib.request


def install(pins: Path, archive: Path, destination: Path) -> None:
    pin = tomllib.loads(pins.read_text(encoding="utf-8"))["kache_native"]
    with urllib.request.urlopen(pin["source"], timeout=120) as response:
        with archive.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin["sha256"]:
        raise RuntimeError("pinned native kache archive checksum differs")
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("kache")
        if not member.isfile():
            raise RuntimeError("pinned native kache is not a regular archive member")
        source = bundle.extractfile(member)
        if source is None:
            raise RuntimeError("pinned native kache archive member is unreadable")
        destination.write_bytes(source.read())
    destination.chmod(0o755)
    actual = subprocess.check_output([str(destination), "--version"], text=True).strip()
    if actual != f"kache {pin['version']}":
        raise RuntimeError(f"pinned native kache version differs: {actual}")
    subprocess.run(["/usr/bin/mold", "--version"], check=True)
    archive.unlink()


if __name__ == "__main__":
    install(Path("/tmp/upstreams.toml"), Path("/tmp/kache.tar.gz"), Path("/usr/local/bin/kache"))
