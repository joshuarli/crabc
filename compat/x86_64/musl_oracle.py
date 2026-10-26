from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib


def load_pin(path: Path) -> dict[str, str]:
    pin = tomllib.loads(path.read_text(encoding="utf-8"))["musl_native"]
    if set(pin) != {"version", "source", "sha256", "fallback_repository", "fallback_revision"}:
        raise ValueError("native musl pin fields differ")
    if pin["version"] != "1.2.6":
        raise ValueError("native musl base version differs")
    for key, length in (("sha256", 64), ("fallback_revision", 40)):
        if not isinstance(pin[key], str) or re.fullmatch(f"[0-9a-f]{{{length}}}", pin[key]) is None:
            raise ValueError(f"native musl {key} is invalid")
    revision = pin["fallback_revision"]
    if pin["source"] != f"https://codeload.github.com/ifduyue/musl/tar.gz/{revision}":
        raise ValueError("native musl archive must select the exact source revision")
    if pin["fallback_repository"] != "https://github.com/ifduyue/musl.git":
        raise ValueError("native musl fallback repository differs")
    return pin


def manifest(pin: dict[str, str]) -> str:
    return ("format=crabc-pinned-musl-oracle-v1\n"
            f"version={pin['version']}\nsource_sha256={pin['sha256']}\n"
            f"fallback_revision={pin['fallback_revision']}\narchitecture=x86_64\n")


def extract_archive(archive: Path, destination: Path, pin: dict[str, str]) -> None:
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != pin["sha256"]:
        raise ValueError("native musl source archive digest differs")
    root = f"musl-{pin['fallback_revision']}"
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        for member in members:
            parts = Path(member.name).parts
            if not parts or parts[0] != root or ".." in parts or Path(member.name).is_absolute():
                raise ValueError("native musl archive root differs")
        destination.mkdir()
        source.extractall(destination, members=members, filter="data")
    extracted = destination / root
    for child in extracted.iterdir():
        child.rename(destination / child.name)
    extracted.rmdir()


def acquire_source(pin: dict[str, str], destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("native musl source destination already exists")
    archive = destination.with_name(destination.name + ".tar.gz")
    if archive.exists() or archive.is_symlink():
        raise ValueError("native musl source archive destination already exists")
    result = subprocess.run(["curl", "--fail", "--location", "--connect-timeout", "20", "--max-time", "120",
                             "--retry", "3", "--output", str(archive), pin["source"]], check=False)
    if result.returncode == 0:
        extract_archive(archive, destination, pin)
    else:
        archive.unlink(missing_ok=True)
        subprocess.run(["git", "init", str(destination)], check=True)
        subprocess.run(["git", "-C", str(destination), "fetch", "--depth", "1", pin["fallback_repository"],
                        pin["fallback_revision"]], check=True)
        subprocess.run(["git", "-C", str(destination), "checkout", "--detach", "FETCH_HEAD"], check=True)
        actual = subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"], text=True).strip()
        if actual != pin["fallback_revision"]:
            raise ValueError("native musl checkout revision differs")
        shutil.rmtree(destination / ".git")
    if (destination / "VERSION").read_text().strip() != pin["version"]:
        raise ValueError("native musl source base version differs")
    (destination / ".crabc-oracle").write_text(manifest(pin), encoding="utf-8")
    archive.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("operation", choices=("version", "manifest", "acquire"))
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    pin = load_pin(args.pins)
    if args.operation == "version":
        print(pin["version"])
    elif args.operation == "manifest":
        print(manifest(pin), end="")
    else:
        if args.destination is None:
            parser.error("acquire requires a destination")
        acquire_source(pin, args.destination)


if __name__ == "__main__":
    main()
