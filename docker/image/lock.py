"""Regenerate docker/image/sources.lock.json and the mirror staging tree.

The lock pins every byte the x86-64 core-evidence image consumes: the Alpine
minirootfs for each stage, every .apk in each stage's resolved closure, the Rust
channel manifest and selected component archives, the native musl oracle
source, kache, and the Linux 5.10 UAPI source. The builder image digest is
recorded so the launcher reads it from the lock instead of hard-coding it.

Regeneration is a deliberate network act. Each stage's closure is resolved by
running the digest-pinned Alpine base with `apk fetch --recursive`; each
package's exact URL is then confirmed by content, so a package served by a
different mirror than expected fails loudly instead of pinning a guess.

The document follows the shared build-repository contract (buildlib
schema_version 1). Every input carries `urls`: optional mirror templates from
docker/image/mirrors.json followed by the upstream URL that served the bytes.

Usage: lock.py [--output docker/image/sources.lock.json] [--mirror DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIRRORS = ROOT / "docker/image/mirrors.json"
UPSTREAMS = ROOT / "compat/upstreams.toml"
TOOLCHAIN = ROOT / "rust-toolchain.toml"

MAIN_BASE = "alpine:3.24.1@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f"
MAIN_RELEASE = "v3.24"
MAIN_VERSION = "3.24.1"
CLANG_BASE = "alpine@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000"
CLANG_RELEASE = "edge"
CLANG_VERSION = "20260805"
BUILDER = "python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd"

ALPINE_CDN = "https://dl-cdn.alpinelinux.org/alpine"
RUST_STATIC = "https://static.rust-lang.org"
BUILDLIB_URL = ("https://pypi.17166969.xyz/current/wheels/"
                "laputa_buildlib-0.1.0-py3-none-any.whl")
BUILDLIB_SHA256 = "edd102a1713c903f93e19b10036983d123dd76fa1b04a0e5f3c5070f00a95383"
BUILDLIB_VERSION = "0.1.0"

MAIN_WORLD = ["bash", "binutils", "build-base", "clang", "ca-certificates",
              "coreutils", "curl", "git", "perf", "python3", "mold", "rsync",
              "rustup", "strace", "tar", "xz"]
CLANG_WORLD = ["clang", "binutils", "make", "python3", "curl", "git"]
RUST_COMPONENTS = [("rustc", "x86_64-unknown-linux-musl"),
                   ("cargo", "x86_64-unknown-linux-musl"),
                   ("rust-std", "x86_64-unknown-linux-musl"),
                   ("rust-src", "*"),
                   ("llvm-tools-preview", "x86_64-unknown-linux-musl")]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, destination: Path, *, user_agent: str = "crabc-lock/1") -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(request, timeout=300) as response, destination.open("wb") as out:
        shutil.copyfileobj(response, out, 1 << 20)
    return destination


def mirror_urls(sha256: str, filename: str) -> list[str]:
    templates = json.loads(MIRRORS.read_text(encoding="utf-8")).get("templates", [])
    if not isinstance(templates, list):
        raise SystemExit("mirrors templates must be a list")
    urls = []
    for template in templates:
        if not isinstance(template, str) or "{filename}" not in template:
            raise SystemExit(f"mirror template must contain {{filename}}: {template!r}")
        urls.append(template.replace("{filename}", filename).replace("{sha256}", sha256))
    return urls


def make_entry(name: str, version: str, url: str, path: Path, *, role: str,
               purpose: str | None = None, extra: dict | None = None) -> dict:
    digest = sha256_file(path)
    item = {
        "name": name,
        "version": version,
        "sha256": digest,
        "size": path.stat().st_size,
        "urls": mirror_urls(digest, path.name) + [url],
        "filename": path.name,
        "role": role,
    }
    if purpose:
        item["purpose"] = purpose
    if extra:
        item.update(extra)
    return item


def docker_run(image: str, mount: Path, script: str) -> None:
    subprocess.run(
        ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "bridge",
         "-v", f"{mount}:{mount}", "--entrypoint", "/bin/sh", image, "-c", script],
        check=True)


def index_versions(release: str, repos: list[str], scratch: Path) -> dict[str, str]:
    """Map `name-version` to its repository base URL from the signed APKINDEX files."""
    scratch.mkdir(parents=True, exist_ok=True)
    versions: dict[str, str] = {}
    for repo in repos:
        base = f"{ALPINE_CDN}/{release}/{repo}"
        index = download(f"{base}/x86_64/APKINDEX.tar.gz", scratch / f"APKINDEX-{repo}.tar.gz",
                         user_agent="apk-tools")
        with tarfile.open(index, "r:gz") as archive:
            member = archive.getmember("APKINDEX")
            stream = archive.extractfile(member)
            if stream is None:
                raise SystemExit(f"{index}: APKINDEX member is unreadable")
            name = None
            for raw in stream.read().decode("utf-8").splitlines():
                if raw.startswith("P:"):
                    name = raw[2:].strip()
                elif raw.startswith("V:") and name is not None:
                    versions[f"{name}-{raw[2:].strip()}"] = base
                    name = None
    return versions


def fetch_closure(base: str, release: str, world: list[str], seed_rootfs: Path,
                  repos: list[str], scratch: Path) -> list[dict]:
    scratch.mkdir(parents=True, exist_ok=True)
    local_repos = index_versions(release, repos, scratch / "index")
    mount = scratch.resolve()
    seed = mount / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    with tarfile.open(seed_rootfs, "r:gz") as archive:
        archive.extractall(seed, filter="tar")
    apks = mount / "apks"
    apks.mkdir(exist_ok=True)
    docker_run(base, mount, (
        f"apk --root {mount}/seed --repositories-file {mount}/seed/etc/apk/repositories "
        f"--keys-dir {mount}/seed/etc/apk/keys update >/dev/null 2>&1; "
        f"apk --root {mount}/seed --repositories-file {mount}/seed/etc/apk/repositories "
        f"--keys-dir {mount}/seed/etc/apk/keys fetch --recursive -o {mount}/apks "
        f"{' '.join(world)} >/dev/null 2>&1"))

    entries = []
    for apk in sorted(apks.glob("*.apk")):
        package, version = split_package(apk.name[:-4])
        repository = local_repos.get(f"{package}-{version}")
        if repository is None:
            raise SystemExit(f"no {release} index advertises {apk.name}")
        entries.append(make_entry(f"apk-{release}-{apk.name}", version,
                                  f"{repository}/x86_64/{apk.name}", apk,
                                  role="apk", purpose=f"{package} for the {release} stage"))
    return entries


def split_package(name_version: str) -> tuple[str, str]:
    head, separator, tail = name_version.rpartition("-r")
    if not separator:
        raise SystemExit(f"cannot split package version from {name_version!r}")
    package, _, version = head.rpartition("-")
    return package, f"{version}-r{tail}"


def pinned_dist_date(channel: str) -> str:
    """Return the ISO release date a nightly channel pins, e.g. nightly-2026-09-15."""
    try:
        return date.fromisoformat(channel[-10:]).isoformat()
    except ValueError as error:
        raise SystemExit(f"rust-toolchain channel pins no release date: {channel}") from error


def resolve_rust(channel: str, dist_date: str, scratch: Path) -> list[dict]:
    scratch.mkdir(parents=True, exist_ok=True)
    manifest_name = f"channel-rust-{channel.split('-', 1)[0]}.toml"
    manifest_url = f"{RUST_STATIC}/dist/{dist_date}/{manifest_name}"
    manifest = download(manifest_url, scratch / manifest_name)
    sidecar_url = f"{manifest_url}.sha256"
    sidecar = download(sidecar_url, scratch / f"{manifest_name}.sha256")
    if sidecar.read_text(encoding="utf-8").split()[0] != sha256_file(manifest):
        raise SystemExit("pinned channel manifest does not match its upstream checksum")
    document = tomllib.loads(manifest.read_text(encoding="utf-8"))

    entries = [
        make_entry("rust-channel-manifest", channel, manifest_url, manifest,
                   role="rust-dist", purpose="pinned Rust channel manifest",
                   extra={"channel": channel, "dist_date": dist_date}),
        make_entry("rust-channel-manifest-sha256", channel, sidecar_url, sidecar,
                   role="rust-dist", purpose="pinned channel manifest checksum",
                   extra={"channel": channel, "dist_date": dist_date}),
    ]
    seen = set()
    for package, target in RUST_COMPONENTS:
        node = document["pkg"][package]["target"][target]
        url = node["xz_url"]
        filename = url.rsplit("/", 1)[1]
        if filename in seen:
            continue
        seen.add(filename)
        blob = download(url, scratch / filename)
        if sha256_file(blob) != node["xz_hash"]:
            raise SystemExit(f"{filename}: served digest differs from the manifest hash")
        suffix = "" if target == "*" else f"-{target}"
        entries.append(make_entry(f"rust-{package}{suffix}", dist_date, url, blob,
                                  role="rust-dist", purpose=f"{package} component for {target}"))
    return entries


def resolve_upstreams(scratch: Path) -> list[dict]:
    pins = tomllib.loads(UPSTREAMS.read_text(encoding="utf-8"))
    scratch.mkdir(parents=True, exist_ok=True)
    musl = pins["musl_native"]
    musl_archive = download(musl["source"], scratch / "musl.tar.gz")
    kache = pins["kache_native"]
    kache_archive = download(kache["source"], scratch / "kache.tar.gz")
    uapi = pins["linux_5_10_uapi"]
    uapi_archive = download(uapi["source"], scratch / "linux.tar.xz")
    return [
        make_entry("musl", musl["version"], musl["source"], musl_archive,
                   role="source", purpose="pinned musl oracle source",
                   extra={"revision": musl["fallback_revision"]}),
        make_entry("kache", kache["version"], kache["source"], kache_archive,
                   role="tool", purpose="native Rust compile cache"),
        make_entry("linux-uapi", uapi["version"], uapi["source"], uapi_archive,
                   role="source", purpose="Linux 5.10 x86 UAPI headers",
                   extra={"install_arch": uapi["headers_install_arch"],
                          "header_count": uapi["exported_header_count"],
                          "header_manifest_sha256": uapi["exported_header_manifest_sha256"]}),
    ]


def rootfs_entries(scratch: Path) -> tuple[list[dict], Path, Path]:
    scratch.mkdir(parents=True, exist_ok=True)
    main_url = (f"{ALPINE_CDN}/{MAIN_RELEASE}/releases/x86_64/"
                f"alpine-minirootfs-{MAIN_VERSION}-x86_64.tar.gz")
    clang_url = (f"{ALPINE_CDN}/{CLANG_RELEASE}/releases/x86_64/"
                 f"alpine-minirootfs-{CLANG_VERSION}-x86_64.tar.gz")
    main = download(main_url, scratch / "main-rootfs.tar.gz")
    clang = download(clang_url, scratch / "clang-rootfs.tar.gz")
    return ([
        make_entry("alpine-minirootfs", MAIN_VERSION, main_url, main,
                   role="rootfs", purpose="main stage Alpine root filesystem"),
        make_entry("alpine-minirootfs-clang", CLANG_VERSION, clang_url, clang,
                   role="rootfs", purpose="clang stage Alpine root filesystem"),
    ], main, clang)


def builder_entry() -> dict:
    digest = BUILDER.split("@", 1)[1].split(":", 1)[1]
    return {
        "name": "python-builder",
        "version": "3.15-alpine",
        "sha256": digest,
        "urls": [f"https://registry-1.docker.io/v2/library/python/manifests/3.15-alpine"],
        "role": "builder",
        "purpose": "digest-pinned builder that runs build.py",
        "image": BUILDER,
    }


def wheel_entry(scratch: Path) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    wheel = download(BUILDLIB_URL, scratch / "laputa_buildlib-0.1.0-py3-none-any.whl")
    item = make_entry("laputa-buildlib", BUILDLIB_VERSION, BUILDLIB_URL, wheel,
                      role="tool", purpose="lock reader and verified fetch helpers")
    if item["sha256"] != BUILDLIB_SHA256:
        raise SystemExit("buildlib wheel digest differs from the reviewed pin")
    return item


def build_lock(scratch: Path) -> dict:
    inputs = [wheel_entry(scratch), builder_entry()]
    rootfs, main_rootfs, clang_rootfs = rootfs_entries(scratch)
    inputs += rootfs
    inputs += fetch_closure(MAIN_BASE, MAIN_RELEASE, MAIN_WORLD, main_rootfs,
                            ["main", "community"], scratch / "main")
    inputs += fetch_closure(CLANG_BASE, CLANG_RELEASE, CLANG_WORLD, clang_rootfs,
                            ["main", "community"], scratch / "clang")
    channel = tomllib.loads(TOOLCHAIN.read_text(encoding="utf-8"))["toolchain"]["channel"]
    inputs += resolve_rust(channel, pinned_dist_date(channel), scratch / "rust")
    inputs += resolve_upstreams(scratch / "upstreams")
    names = [item["name"] for item in inputs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SystemExit(f"duplicate lock input names: {duplicates}")
    return {"schema_version": 1, "inputs": inputs}


def stage_mirror(lock: dict, scratch: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for item in lock["inputs"]:
        if "filename" not in item:
            continue
        found = next(scratch.rglob(item["filename"]), None)
        if found is None:
            raise SystemExit(f"cannot stage {item['filename']} into the mirror tree")
        shutil.copy2(found, destination / item["filename"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "docker/image/sources.lock.json")
    # Staged bytes are disposable and large; keep them under the ignored .work
    # tree for the parent to publish, never in the checkout.
    parser.add_argument("--mirror", type=Path, default=ROOT / ".work/image-mirror")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="crabc-lock-") as directory:
        scratch = Path(directory)
        lock = build_lock(scratch)
        args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.mirror:
            stage_mirror(lock, scratch, args.mirror)
    print(f"wrote {args.output} ({len(lock['inputs'])} inputs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
