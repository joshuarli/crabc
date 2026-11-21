"""Build the pinned x86-64 core-evidence image reproducibly from the sources lock.

Every input comes from docker/image/sources.lock.json: the Alpine minirootfs and
each stage's exact .apk closure, the Rust channel manifest and component
archives, the native musl oracle, kache, and the Linux 5.10 UAPI source. This
script runs as root inside the digest-pinned builder image recorded in the lock.

It installs the locked .apk files into a chroot offline, letting apk verify each
package signature against the rootfs's own /etc/apk/keys; installs Rust through
rustup-init against a loopback dist server that serves only locked files; builds
musl and the UAPI tree as the former Dockerfile did; writes the image-owned
manifests; and emits a normalized rootfs tar plus a single-layer OCI layout.

The image ID is the OCI manifest digest, computed here and printed. The layout is
then loaded through the Docker socket, so rebuilding from the same lock yields
the same ID.

Usage: build.py --lock PATH --work DIR --staging DIR --out DIR \
    --mold-gcc PATH --musl-oracle-gcc PATH --load
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import http.server
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
from datetime import datetime, timezone
from pathlib import Path

SOURCE_DATE_EPOCH = 1794873600
OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TAR_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
BUILDLIB_INPUT = "laputa-buildlib"

IMAGE_ENV = [
    "PATH=/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "RUSTUP_HOME=/opt/rustup",
    "CARGO_HOME=/opt/cargo",
    "RUSTC_WRAPPER=/usr/local/bin/kache",
    "KACHE_CONFIG=/dev/null",
    "KACHE_HOST_CONFIG=",
    "KACHE_LOCAL_ONLY=1",
    "KACHE_CACHE_DIR=/workspace/.work/x86_64/kache",
    "KACHE_AUTO_CLEAN_ORPHANED_TARGETS=0",
    "KACHE_AUTO_CLEAN_UNUSED_UNITS_DAYS=0",
    "KACHE_AUTO_SHARE_TARGET_FILES=0",
    "KACHE_SEED_NEW_TARGETS=0",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/usr/local/bin/crabc-x86_64-mold-gcc",
]
APK_WORLD = ["bash", "binutils", "build-base", "clang", "ca-certificates",
             "coreutils", "curl", "git", "perf", "python3", "mold", "rsync",
             "rustup", "strace", "tar", "xz"]
CLANG_WORLD = ["clang", "binutils", "make", "python3", "curl", "git"]
DEVICES = {"null": (1, 3), "zero": (1, 5), "full": (1, 7), "random": (1, 8), "urandom": (1, 9)}
RUST_TARGET = "x86_64-unknown-linux-musl"
MUSL_VERSION = "1.2.6"
MUSL_REVISION = "7813e9119eb5fe681b6750b8a033a0490bca0941"
UAPI_VERSION = "5.10"
UAPI_HEADER_COUNT = 935
UAPI_HEADER_MANIFEST_SHA256 = "00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e"


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return "sha256:" + digest.hexdigest(), size


def bootstrap_buildlib(lock: Path, cache: Path):
    """Import buildlib from the wheel pinned in the lock, fetching it on first use."""
    document = json.loads(lock.read_text(encoding="utf-8"))
    pin = next((item for item in document.get("inputs", [])
                if isinstance(item, dict) and item.get("name") == BUILDLIB_INPUT), None)
    if pin is None:
        raise SystemExit(f"{lock}: sources lock has no {BUILDLIB_INPUT} input")
    wheel = cache / pin["name"] / pin["filename"]
    if not wheel.is_file() or digest_file(wheel)[0] != "sha256:" + pin["sha256"]:
        import urllib.request

        wheel.parent.mkdir(parents=True, exist_ok=True)
        part = wheel.with_name(wheel.name + ".part")
        try:
            for url in pin["urls"]:
                try:
                    with urllib.request.urlopen(url, timeout=120) as response:
                        part.write_bytes(response.read())
                except OSError:
                    continue
                if digest_file(part)[0] == "sha256:" + pin["sha256"]:
                    part.replace(wheel)
                    break
            else:
                raise SystemExit(f"no URL served the {BUILDLIB_INPUT} wheel pinned in {lock}")
        finally:
            part.unlink(missing_ok=True)
    sys.path.insert(0, str(wheel))
    from buildlib import locks

    return locks


def read_lock(locks, path: Path) -> tuple[list[dict], dict]:
    """Validate the lock with buildlib; return its raw entries and its Inputs by name."""
    try:
        sources = locks.load_sources(path)
    except locks.LockError as error:
        raise SystemExit(str(error)) from error
    document = json.loads(path.read_text(encoding="utf-8"))
    return document["inputs"], {item.name: item for item in sources.inputs}


def lock_entry(inputs: list[dict], name: str) -> dict:
    for item in inputs:
        if item.get("name") == name:
            return item
    raise SystemExit(f"sources lock has no input named {name!r}")


def entry_filename(item: dict) -> str:
    return item["filename"]


def cache_path(cache: Path, item: dict) -> Path:
    # Namespace the cache by input name: two stages may ship the same .apk file
    # name with different bytes, so a flat cache would collide.
    return cache / item["name"] / entry_filename(item)


def fetch(args: argparse.Namespace) -> None:
    """Download and verify every lock input; the only phase allowed to use the network."""
    cache = Path(args.cache)
    locks = bootstrap_buildlib(Path(args.lock), cache)
    inputs, pinned = read_lock(locks, Path(args.lock))
    for item in inputs:
        if item.get("role") == "builder":
            continue
        try:
            locks.fetch_input(pinned[item["name"]], cache_path(cache, item), timeout=300)
        except locks.FetchError as error:
            raise SystemExit(str(error)) from error


def verify_cache(locks, inputs: list[dict], pinned: dict, cache: Path) -> dict[str, Path]:
    """Re-verify the staged cache after network isolation; no fetching happens here."""
    resolved = {}
    for item in inputs:
        if item.get("role") == "builder":
            continue
        path = cache_path(cache, item)
        try:
            locks.verify_file(path, pinned[item["name"]])
        except locks.FetchError as error:
            raise SystemExit(f"staged input differs from the lock: {error}") from error
        resolved[item["name"]] = path
    return resolved


def chroot(root: Path, script: str) -> None:
    environment = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                   "LC_ALL": "C", "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH)}
    subprocess.run(["chroot", str(root), "/bin/sh", "-c", script], check=True,
                   env=environment, stdin=subprocess.DEVNULL, stdout=sys.stderr)


def extract_rootfs(archive: Path, root: Path) -> None:
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(root, filter="tar")
    devices = root / "dev"
    devices.mkdir(exist_ok=True)
    for name, (major, minor) in DEVICES.items():
        path = devices / name
        if path.exists():
            continue
        try:
            os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(major, minor))
        except OSError:
            if name == "null":
                path.write_bytes(b"")
                path.chmod(0o666)


def install_apks(root: Path, apk_prefix: str, inputs: list[dict], cache: Path,
                 world: list[str]) -> None:
    staged = root / "var/cache/locked"
    shutil.rmtree(staged, ignore_errors=True)
    staged.mkdir(parents=True)
    packages = [item for item in inputs
                if item.get("role") == "apk" and item["name"].startswith(apk_prefix)]
    if not packages:
        raise SystemExit(f"sources lock has no {apk_prefix} inputs")
    for item in packages:
        shutil.copy2(cache_path(cache, item), staged / entry_filename(item))
    chroot(root, "set -eu\n"
                 "apk --arch x86_64 --keys-dir /etc/apk/keys --repositories-file /dev/null "
                 "--no-network add --force-non-repository /var/cache/locked/*.apk\n")
    (root / "etc/apk/world").write_text("\n".join(world) + "\n", encoding="utf-8")
    shutil.rmtree(staged, ignore_errors=True)
    (root / "var/log/apk.log").unlink(missing_ok=True)


class _LockedDist:
    def __init__(self, files: dict[str, Path]) -> None:
        self._files = dict(files)

    def serve(self) -> tuple[http.server.ThreadingHTTPServer, int]:
        files = self._files

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                source = files.get(self.path.split("?", 1)[0].rsplit("/", 1)[-1])
                if source is None or not source.is_file():
                    self.send_error(404)
                    return
                data = source.read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *arguments: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, server.server_address[1]


def install_rust(root: Path, dist: dict[str, Path], channel: str) -> None:
    proc = root / "proc/self"
    proc.mkdir(parents=True, exist_ok=True)
    # rustup-init resolves itself through /proc/self/exe, which a chroot lacks
    # without a mounted procfs; bind the installer to a fixed path instead.
    (proc / "exe").unlink(missing_ok=True)
    os.symlink("/usr/bin/rustup-init", proc / "exe")
    server, port = _LockedDist(dist).serve()
    try:
        chroot(root, (
            "set -eu\n"
            "export HOME=/root RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo\n"
            "export PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"export RUSTUP_DIST_SERVER=http://127.0.0.1:{port}\n"
            "export RUSTUP_IO_THREADS=1\n"
            f"/usr/bin/rustup-init -y --profile minimal --default-toolchain {channel}\n"
            f"rustup target add {RUST_TARGET}\n"
            "rustup component add rust-src llvm-tools\n"
            "rustc --version\n"
        ))
    finally:
        server.shutdown()
    components = root / f"opt/rustup/toolchains/{channel}-{RUST_TARGET}/lib/rustlib/components"
    if components.is_file():
        lines = sorted(line for line in components.read_text().splitlines() if line)
        components.write_text("\n".join(lines) + "\n", encoding="utf-8")
    shutil.rmtree(root / "proc/self", ignore_errors=True)
    for scratch in ("opt/rustup/tmp", "opt/rustup/downloads"):
        directory = root / scratch
        if directory.is_dir():
            for child in directory.iterdir():
                shutil.rmtree(child) if child.is_dir() else child.unlink()


def build_musl(root: Path, archive: Path, prefix: str, cc: str, extra: str) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(root / "tmp", filter="tar")
    source = root / "tmp" / f"musl-{MUSL_REVISION}"
    if not source.is_dir():
        raise SystemExit(f"musl archive did not extract musl-{MUSL_REVISION}")
    chroot(root, (
        "set -eu\n"
        f"cd /tmp/musl-{MUSL_REVISION}\n"
        f"CC={cc} ./configure --prefix={prefix} --syslibdir={prefix}/lib\n"
        "make -s -j\"$(getconf _NPROCESSORS_ONLN)\"\n"
        "make -s install\n"
        f"{extra}"
    ))
    shutil.rmtree(source, ignore_errors=True)


def build_musl_clang(clang_root: Path, archive: Path, destination: Path) -> None:
    prefix = f"/opt/musl-clang-{MUSL_VERSION}"
    build_musl(clang_root, archive, prefix, "clang", (
        f"cp config.mak {prefix}/config.mak\n"
        f"clang --version | head -1 > {prefix}/.clang-version\n"
        f"test -f {prefix}/lib/libc.so\n"
        f"test -f {prefix}/lib/ld-musl-x86_64.so.1\n"
        f"test \"$(readlink -f {prefix}/lib/ld-musl-x86_64.so.1)\" = \"{prefix}/lib/libc.so\"\n"
    ))
    target = destination / "opt" / f"musl-clang-{MUSL_VERSION}"
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(clang_root / f"opt/musl-clang-{MUSL_VERSION}", target, symlinks=True)


def build_musl_oracle(root: Path, archive: Path, oracle_manifest: str) -> None:
    prefix = f"/opt/musl-{MUSL_VERSION}"
    build_musl(root, archive, prefix, "/usr/local/bin/crabc-x86_64-mold-gcc", (
        f"sh tools/musl-gcc.specs.sh {prefix}/include {prefix}/lib "
        f"{prefix}/lib/ld-musl-x86_64.so.1 > {prefix}/lib/musl-gcc.specs\n"
        "test -f " + prefix + "/lib/libc.so\n"
        "test -f " + prefix + "/lib/ld-musl-x86_64.so.1\n"
        f"test \"$(readlink -f {prefix}/lib/ld-musl-x86_64.so.1)\" = \"{prefix}/lib/libc.so\"\n"
        f"cp /usr/lib/libssp_nonshared.a {prefix}/lib/\n"
        f"sha256sum {prefix}/lib/musl-gcc.specs > {prefix}/.crabc-musl-gcc-specs.sha256\n"
    ))
    (root / f"opt/musl-{MUSL_VERSION}/.crabc-oracle").write_text(oracle_manifest, encoding="utf-8")


def build_uapi(root: Path, archive: Path) -> None:
    with tarfile.open(archive, "r:xz") as bundle:
        bundle.extractall(root / "tmp", filter="tar")
    prefix = f"/opt/linux-{UAPI_VERSION}-uapi"
    chroot(root, (
        "set -eu\n"
        f"make -C /tmp/linux-{UAPI_VERSION} ARCH=x86 headers_install INSTALL_HDR_PATH={prefix}\n"
        f"test -f {prefix}/include/linux/kd.h\n"
        f"test -f {prefix}/include/linux/soundcard.h\n"
        f"test -f {prefix}/include/linux/vt.h\n"
        f"(cd {prefix}/include && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) "
        f"> {prefix}/.crabc-linux-uapi.headers.sha256\n"
    ))
    shutil.rmtree(root / "tmp" / f"linux-{UAPI_VERSION}", ignore_errors=True)


def verify_uapi(root: Path, source_sha256: str) -> None:
    prefix = f"/opt/linux-{UAPI_VERSION}-uapi"
    manifest = root / f"opt/linux-{UAPI_VERSION}-uapi/.crabc-linux-uapi.headers.sha256"
    count = len(manifest.read_text().splitlines())
    if count != UAPI_HEADER_COUNT:
        raise SystemExit(f"UAPI header count {count} != pinned {UAPI_HEADER_COUNT}")
    if digest_file(manifest)[0] != "sha256:" + UAPI_HEADER_MANIFEST_SHA256:
        raise SystemExit("UAPI header manifest digest differs from the pin")
    (root / prefix.lstrip("/") / ".crabc-linux-uapi").write_text(
        "format=crabc-linux-uapi-v1\n"
        f"version={UAPI_VERSION}\n"
        f"source_sha256={source_sha256}\n"
        "architecture=x86_64\n"
        "install_arch=x86\n"
        f"header_count={UAPI_HEADER_COUNT}\n"
        f"header_manifest_sha256={UAPI_HEADER_MANIFEST_SHA256}\n", encoding="utf-8")


def install_kache(archive: Path, destination: Path, version: str) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("kache")
        stream = bundle.extractfile(member)
        if stream is None:
            raise SystemExit("kache archive member is unreadable")
        destination.write_bytes(stream.read())
    destination.chmod(0o755)
    actual = subprocess.check_output([str(destination), "--version"], text=True).strip()
    if actual != f"kache {version}":
        raise SystemExit(f"pinned kache version differs: {actual}")


def install_wrappers(root: Path, mold_gcc: Path, musl_oracle_gcc: Path) -> None:
    for source, name in ((mold_gcc, "crabc-x86_64-mold-gcc"),
                         (musl_oracle_gcc, "crabc-x86_64-musl-gcc")):
        destination = root / "usr/local/bin" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        destination.chmod(0o755)


def rootfs_resolve(root: Path, absolute: str) -> Path:
    """Resolve an in-image absolute path through the rootfs, not the host."""
    path = root / absolute.lstrip("/")
    for _ in range(40):
        if not path.is_symlink():
            return path
        target = os.readlink(path)
        path = (root / target.lstrip("/")) if target.startswith("/") else (path.parent / target)
    raise SystemExit(f"symlink loop resolving {absolute}")


def write_performance_manifest(root: Path) -> None:
    tools = ["/usr/local/bin/crabc-x86_64-musl-gcc", "/usr/bin/readelf", "/usr/bin/strace",
             f"/opt/musl-{MUSL_VERSION}/lib/ld-musl-x86_64.so.1",
             f"/opt/musl-{MUSL_VERSION}/lib/libc.so"]
    lines = ["format=crabc-x86_64-performance-image-tools/v2"]
    for tool in tools:
        digest, _ = digest_file(rootfs_resolve(root, tool))
        lines.append(f"{tool} {digest.split(':', 1)[1]}")
    destination = root / "usr/local/share/crabc-x86_64-performance-image-tools.manifest"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    destination.chmod(0o444)


def normalize_rootfs(root: Path, epoch: int) -> bytes:
    entries: list[tuple[str, os.stat_result]] = []

    def walk(relative: str) -> None:
        base = root / relative if relative else root
        for child in sorted(os.scandir(base), key=lambda entry: os.fsencode(entry.name)):
            child_relative = f"{relative}/{child.name}" if relative else child.name
            info = child.stat(follow_symlinks=False)
            entries.append((child_relative, info))
            if stat.S_ISDIR(info.st_mode):
                walk(child_relative)

    walk("")
    output = io.BytesIO()
    seen: dict[tuple[int, int], str] = {}
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for relative, info in entries:
            member = tarfile.TarInfo(relative)
            member.mtime = epoch
            member.uid = info.st_uid
            member.gid = info.st_gid
            member.uname = member.gname = ""
            member.mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                member.type = tarfile.SYMTYPE
                member.linkname = os.readlink(root / relative)
                archive.addfile(member)
            elif stat.S_ISDIR(info.st_mode):
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif stat.S_ISREG(info.st_mode):
                key = (info.st_dev, info.st_ino)
                if info.st_nlink > 1 and key in seen:
                    member.type = tarfile.LNKTYPE
                    member.linkname = seen[key]
                    archive.addfile(member)
                    continue
                seen[key] = relative
                member.type = tarfile.REGTYPE
                member.size = info.st_size
                with (root / relative).open("rb") as handle:
                    archive.addfile(member, handle)
            elif stat.S_ISCHR(info.st_mode):
                member.type = tarfile.CHRTYPE
                member.devmajor = os.major(info.st_rdev)
                member.devminor = os.minor(info.st_rdev)
                archive.addfile(member)
            elif stat.S_ISBLK(info.st_mode):
                member.type = tarfile.BLKTYPE
                member.devmajor = os.major(info.st_rdev)
                member.devminor = os.minor(info.st_rdev)
                archive.addfile(member)
            else:
                raise SystemExit(f"unexpected file type in rootfs: {relative}")
    return output.getvalue()


def drop_build_devices(root: Path) -> None:
    # The devices were created only so apk triggers and the musl/KB builds could
    # open /dev/null. A container runtime supplies its own /dev, and the pinned
    # image's layer carries only the empty directory, so remove them before the
    # rootfs is captured.
    devices = root / "dev"
    for name in DEVICES:
        (devices / name).unlink(missing_ok=True)


def image_config(epoch: int, diff_id: str) -> bytes:
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return canonical_json({
        "architecture": "amd64",
        "config": {"Env": IMAGE_ENV, "Cmd": ["bash"], "WorkingDir": "/workspace"},
        "created": created,
        "history": [{"created": created, "created_by": "crabc docker/image/build.py"}],
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
    })


def write_oci(out: Path, rootfs_tar: bytes, epoch: int) -> tuple[str, str]:
    # The diff_id names the uncompressed tar; the layer blob is that tar gzipped
    # with a fixed header (mtime 0, no name) so the layer digest is reproducible.
    layer = gzip.compress(rootfs_tar, compresslevel=9, mtime=0)
    config = image_config(epoch, digest_bytes(rootfs_tar))
    manifest = canonical_json({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": {"mediaType": OCI_IMAGE_CONFIG, "size": len(config), "digest": digest_bytes(config)},
        "layers": [{"mediaType": OCI_LAYER_TAR_GZIP, "size": len(layer),
                    "digest": digest_bytes(layer)}],
    })
    index = canonical_json({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [{
            "mediaType": OCI_IMAGE_MANIFEST,
            "digest": digest_bytes(manifest),
            "size": len(manifest),
            "platform": {"architecture": "amd64", "os": "linux"},
        }],
    })
    layout = out / "oci"
    shutil.rmtree(layout, ignore_errors=True)
    blobs = layout / "blobs/sha256"
    blobs.mkdir(parents=True)
    for data in (layer, config, manifest):
        (blobs / hashlib.sha256(data).hexdigest()).write_bytes(data)
    (layout / "index.json").write_bytes(index)
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
    archive_path = out / "image.tar"
    entries = ["index.json", "oci-layout"]
    entries += sorted(f"blobs/sha256/{path.name}" for path in blobs.iterdir())
    with tarfile.open(archive_path, "w", format=tarfile.GNU_FORMAT) as archive:
        for relative in sorted(entries):
            data = (layout / relative).read_bytes()
            member = tarfile.TarInfo(relative)
            member.size = len(data)
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    return digest_bytes(manifest), digest_bytes(config)


def load_image(archive: Path, socket_path: str) -> None:
    data = archive.read_bytes()
    _socket_request(socket_path, "POST", "/v1.44/images/load", data,
                    {"Content-Type": "application/x-tar", "Content-Length": str(len(data))})


def _socket_request(socket_path: str, method: str, path: str, body: bytes,
                    headers: dict[str, str]) -> bytes:
    import http.client
    import socket as socket_module

    class UnixConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
            self.sock.connect(socket_path)

    connection = UnixConnection("localhost")
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    if response.status != 200:
        raise SystemExit(f"{method} {path} failed: {response.status} {payload.decode('utf-8', 'replace')}")
    return payload


def musl_oracle_manifest(inputs: list[dict]) -> str:
    """The manifest recorded beneath the pinned musl tree, derived from the lock."""
    musl = lock_entry(inputs, "musl")
    revision = musl.get("revision")
    if not revision:
        raise SystemExit("musl lock input records no revision")
    return ("format=crabc-pinned-musl-oracle-v1\n"
            f"version={musl['version']}\nsource_sha256={musl['sha256']}\n"
            f"fallback_revision={revision}\narchitecture=x86_64\n")


def assemble(args: argparse.Namespace) -> None:
    cache = Path(args.cache)
    locks = bootstrap_buildlib(Path(args.lock), cache)
    inputs, pinned = read_lock(locks, Path(args.lock))
    resolved = verify_cache(locks, inputs, pinned, cache)
    channel = lock_entry(inputs, "rust-channel-manifest").get("channel")
    if not channel:
        raise SystemExit("rust-channel-manifest records no channel")
    staging = Path(args.staging)
    shutil.rmtree(staging, ignore_errors=True)
    root = staging / "root"
    clang_root = staging / "clang"
    extract_rootfs(resolved["alpine-minirootfs"], root)
    extract_rootfs(resolved["alpine-minirootfs-clang"], clang_root)

    install_apks(root, "apk-v3.24-", inputs, cache, APK_WORLD)
    install_apks(clang_root, "apk-edge-", inputs, cache, CLANG_WORLD)

    install_wrappers(root, Path(args.mold_gcc), Path(args.musl_oracle_gcc))

    dist = {}
    for item in inputs:
        if item.get("role") == "rust-dist" and item["name"].startswith("rust-") and \
                item["name"] not in {"rust-channel-manifest", "rust-channel-manifest-sha256"}:
            dist[entry_filename(item)] = resolved[item["name"]]
    dist["channel-rust-nightly.toml"] = resolved["rust-channel-manifest"]
    dist["channel-rust-nightly.toml.sha256"] = resolved["rust-channel-manifest-sha256"]
    install_rust(root, dist, channel)

    install_kache(resolved["kache"], root / "usr/local/bin/kache",
                  lock_entry(inputs, "kache")["version"])

    # musl-clang first, so its tree can be copied into the main root exactly as
    # the former multi-stage Dockerfile did.
    build_musl_clang(clang_root, resolved["musl"], root)

    oracle_manifest = musl_oracle_manifest(inputs)
    build_musl_oracle(root, resolved["musl"], oracle_manifest)
    build_uapi(root, resolved["linux-uapi"])
    verify_uapi(root, lock_entry(inputs, "linux-uapi")["sha256"])
    write_performance_manifest(root)
    drop_build_devices(root)

    rootfs_tar = normalize_rootfs(root, SOURCE_DATE_EPOCH)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rootfs.tar").write_bytes(rootfs_tar)
    image_id, config_id = write_oci(out, rootfs_tar, SOURCE_DATE_EPOCH)
    print(f"IMAGE_ID {image_id}")
    print(f"CONFIG_ID {config_id}")
    if args.load:
        load_image(out / "image.tar", args.load_socket)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default=str(Path(__file__).resolve().parent / "sources.lock.json"))
    parser.add_argument("--cache", required=True)
    phases = parser.add_subparsers(dest="phase", required=True)
    phases.add_parser("fetch")
    assemble_parser = phases.add_parser("assemble")
    assemble_parser.add_argument("--staging", required=True)
    assemble_parser.add_argument("--out", required=True)
    assemble_parser.add_argument("--mold-gcc", required=True)
    assemble_parser.add_argument("--musl-oracle-gcc", required=True)
    assemble_parser.add_argument("--load", action="store_true")
    assemble_parser.add_argument("--load-socket", default="/var/run/docker.sock")
    args = parser.parse_args()
    if args.phase == "fetch":
        if os.geteuid() != 0:
            raise SystemExit("fetch must run as root inside the pinned builder image")
        fetch(args)
    else:
        if os.geteuid() != 0:
            raise SystemExit("assemble must run as root inside the pinned builder image")
        assemble(args)


if __name__ == "__main__":
    main()
