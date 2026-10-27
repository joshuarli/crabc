#!/bin/sh
# Prepare a fresh lane worktree for offline native runs: fetch and vendor the
# locked Cargo closures, seed the pinned source oracles and Lua archive, and
# write the qualification inputs. Pinned allocator and corpus caches are also
# copied from the primary checkout when available; their consumers recheck
# archive hashes and authenticate the package index before use.
set -eu
root=$(git rev-parse --show-toplevel)
common=$(cd "$(git rev-parse --git-common-dir)" && pwd)
primary=$(dirname "$common")
here=$root/scripts/lanes
if [ -L "$root/.work" ] || [ -L "$root/.work/tmp" ] ||
    [ -L "$root/.work/x86_64" ] || [ -L "$root/.work/x86_64/tmp" ] ||
    [ -L "$root/.work/x86_64/cargo" ] || [ -L "$root/.work/x86_64/target-check" ]; then
    printf 'prepare-worktree: work or temporary directory is a symlink\n' >&2
    exit 1
fi
mkdir -p "$root/.work/tmp"
TMPDIR=$root/.work/tmp
export TMPDIR
"$here/rust-check.sh" cargo fetch --locked
vendor=.work/x86_64/cargo/native-static-source-runtime-vendor
if [ ! -d "$root/$vendor" ]; then
    "$here/rust-check.sh" cargo vendor --locked --offline --versioned-dirs \
        "/workspace/$vendor" >/dev/null
fi
# The host runner caches under .work/allocator-cache (with its tag record);
# the x86 container launcher caches under .work/allocator-x86_64.
for cache in .work/allocator-cache .work/allocator-x86_64/allocator-cache; do
    if [ ! -f "$root/$cache/mimalloc-3.5.0.tar.gz" ] && [ "$primary" != "$root" ] &&
        [ -f "$primary/$cache/mimalloc-3.5.0.tar.gz" ]; then
        mkdir -p "$root/$cache"
        for file in "$primary/$cache"/mimalloc-3.5.0.*; do
            cp "$file" "$root/$cache/"
        done
    fi
done
# Qualification inputs are prepared before the native container runs without
# network access. Reuse exact local caches when present; their consumers still
# authenticate the pinned bytes and source revisions.
python3 -B - "$root" "$primary" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import urllib.request

root, primary = (Path(value).resolve() for value in sys.argv[1:])


def require(condition, message):
    if not condition:
        raise SystemExit(f"prepare-worktree: {message}")


def physical_directory(path, label):
    require(not path.is_symlink(), f"{label} is a symlink: {path}")
    require(path.is_dir(), f"{label} is not a directory: {path}")
    require(path.resolve(strict=True) == path.absolute(), f"{label} traverses a symlink: {path}")


def copy_missing_tree(source, destination, label, source_description):
    if not source.exists() and not source.is_symlink():
        if destination.exists() or destination.is_symlink():
            physical_directory(destination, label)
        return
    physical_directory(source, source_description)
    for item in source.rglob("*"):
        mode = item.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode),
                f"primary {label} contains a link or special file: {item}")
    if not destination.exists() and not destination.is_symlink():
        destination.mkdir(parents=True)
    physical_directory(destination, label)
    for item in destination.rglob("*"):
        mode = item.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode),
                f"{label} contains a link or special file: {item}")
    for item in source.rglob("*"):
        relative = item.relative_to(source)
        target = destination / relative
        mode = item.lstat().st_mode
        if stat.S_ISDIR(mode):
            if target.is_symlink():
                raise SystemExit(f"prepare-worktree: {label} destination is a symlink: {target}")
            target.mkdir(parents=True, exist_ok=True)
        elif target.is_symlink():
            raise SystemExit(f"prepare-worktree: {label} destination is a symlink: {target}")
        elif not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def git(source, *arguments):
    result = subprocess.run(
        ["git", "-c", f"safe.directory={source}", "-C", str(source), *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False,
    )
    require(result.returncode == 0,
            f"cannot verify pinned source {source}: {result.stderr.strip()}")
    return result.stdout.strip()


def verify_source(source, revision, label):
    physical_directory(source, label)
    require(git(source, "rev-parse", "HEAD") == revision,
            f"{label} revision differs from its pin: {source}")
    require(not git(source, "status", "--porcelain=v1", "--untracked-files=all"),
            f"{label} checkout is dirty: {source}")


def ensure_source(record, path, label):
    revision = record["revision"]
    destination = root / path
    if destination.exists() or destination.is_symlink():
        verify_source(destination, revision, label)
        return
    source = primary / path
    if source.exists() or source.is_symlink():
        verify_source(source, revision, f"primary {label}")
        clone_source = str(source)
        clone_git = ["git", "-c", f"safe.directory={source / '.git'}"]
    else:
        clone_source = record["repository"]
        clone_git = ["git"]

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.clone-", dir=destination.parent))
    checkout = staging / "checkout"
    try:
        result = subprocess.run([*clone_git, "clone", "--no-checkout", "--no-hardlinks", clone_source, str(checkout)],
                                cwd=root, stdin=subprocess.DEVNULL, check=False)
        require(result.returncode == 0, f"cannot fetch pinned {label} from {clone_source}")
        result = subprocess.run(["git", "-C", str(checkout), "checkout", "--detach", revision],
                                cwd=root, stdin=subprocess.DEVNULL, check=False)
        require(result.returncode == 0, f"cannot check out pinned {label} revision {revision}")
        verify_source(checkout, revision, label)
        os.replace(checkout, destination)
    finally:
        shutil.rmtree(staging)


core_registry = root / ".work/x86_64/cargo/registry"
require(core_registry.exists() or core_registry.is_symlink(),
        "fetched core Cargo registry is missing")
allocator_work = root / ".work/allocator-x86_64"
allocator_cargo = allocator_work / "cargo"
for directory, label in ((allocator_work, "allocator work directory"),
                         (allocator_cargo, "allocator Cargo home")):
    if not directory.exists() and not directory.is_symlink():
        directory.mkdir()
    physical_directory(directory, label)
copy_missing_tree(core_registry, allocator_cargo / "registry", "allocator Cargo registry",
                  "fetched core Cargo registry")

pins = tomllib.loads((root / "compat/upstreams.toml").read_text(encoding="utf-8"))
source_oracles = (
    (pins["os_test"], f".work/x86_64/source-oracles/os-test-{pins['os_test']['revision']}", "os-test oracle"),
    (pins["libc_test"], f".work/x86_64/source-oracles/laputa-libc-test-{pins['libc_test']['revision']}",
     "libc-test oracle"),
)
for record, path, label in source_oracles:
    ensure_source(record, path, label)

# Cache trees are merged without replacing worktree-local entries. Corpus
# archive checks remain the responsibility of fetch_x86.py and its manifest.
for relative, label in (("compat/lua/.cache", "Lua source cache"),
                        ("compat/corpus/.cache", "package corpus cache"),
                        (".work/x86_64/rust-std-lto", "Rust std/LTO vendors")):
    copy_missing_tree(primary / relative, root / relative, label, f"primary {label}")

lua_manifest = tomllib.loads((root / "compat/lua/manifest.toml").read_text(encoding="utf-8"))["lua"]
lua_archive = root / "compat/lua/.cache" / f"lua-{lua_manifest['version']}.tar.gz"
lua_cache = lua_archive.parent
if not lua_cache.exists() and not lua_cache.is_symlink():
    lua_cache.mkdir(parents=True)
physical_directory(lua_cache, "Lua source cache")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


if lua_archive.exists() or lua_archive.is_symlink():
    require(not lua_archive.is_symlink() and lua_archive.is_file(),
            f"Lua archive seed is not a regular file: {lua_archive}")
    require(digest(lua_archive) == lua_manifest["sha256"],
            f"Lua archive seed differs from its pin: {lua_archive}")
else:
    staging = lua_cache / f".{lua_archive.name}.part-{os.getpid()}"
    try:
        with urllib.request.urlopen(lua_manifest["source_url"], timeout=30) as response, staging.open("xb") as output:
            shutil.copyfileobj(response, output)
        require(digest(staging) == lua_manifest["sha256"], "downloaded Lua archive differs from its pin")
        os.replace(staging, lua_archive)
    finally:
        staging.unlink(missing_ok=True)

# The dispatcher admits only physical `.work` seed files; keep the verified
# source cache intact and pass a worktree-local copy to both Lua consumers.
lua_seed_relative = ".work/x86_64/lua-source-build-seed/" + lua_archive.name
lua_seed_directory = root / ".work/x86_64/lua-source-build-seed"
if not lua_seed_directory.exists() and not lua_seed_directory.is_symlink():
    lua_seed_directory.mkdir(parents=True)
physical_directory(lua_seed_directory, "worktree Lua source seed directory")
lua_seed = root / lua_seed_relative
require(not lua_seed.is_symlink() and (not lua_seed.exists() or lua_seed.is_file()),
        f"worktree Lua source seed is not a regular file: {lua_seed}")
staging = None
try:
    with tempfile.NamedTemporaryFile("wb", dir=lua_seed_directory, prefix=f".{lua_seed.name}.",
                                     delete=False) as output:
        staging = Path(output.name)
        with lua_archive.open("rb") as source:
            shutil.copyfileobj(source, output)
    require(digest(staging) == lua_manifest["sha256"],
            "staged Lua archive differs from its pin")
    os.replace(staging, lua_seed)
finally:
    if staging is not None:
        staging.unlink(missing_ok=True)

vendor_paths = {
    "provider_vendor": ".work/x86_64/rust-std-lto/provider-vendor",
    "dependency_vendor": ".work/x86_64/rust-std-lto/dependency-vendor",
}
inputs_path = root / ".work/x86_64/inputs.json"
inputs_path.parent.mkdir(parents=True, exist_ok=True)
if inputs_path.exists() or inputs_path.is_symlink():
    require(not inputs_path.is_symlink() and inputs_path.is_file(),
            f"candidate inputs are not a regular file: {inputs_path}")
    try:
        inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"prepare-worktree: candidate inputs are unreadable: {error}")
else:
    inputs = {}
require(isinstance(inputs, dict), "candidate inputs must be a JSON object")
sys.path.insert(0, str(root / "compat/x86_64"))
import qualification_candidate
require(set(inputs) <= set(qualification_candidate.INPUT_KEYS), "candidate inputs name an unknown group")
for group, fields in inputs.items():
    require(isinstance(fields, dict) and set(fields) == set(qualification_candidate.INPUT_KEYS[group]),
            f"candidate input {group} fields differ")
inputs["lua_source_build"] = {"archive_seed": lua_seed_relative}
inputs["rust_std_lto"] = vendor_paths
with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=inputs_path.parent,
                                 prefix=".inputs.json.", delete=False) as output:
    json.dump(inputs, output, indent=2, sort_keys=True)
    output.write("\n")
    temporary = Path(output.name)
try:
    os.replace(temporary, inputs_path)
except BaseException:
    temporary.unlink(missing_ok=True)
    raise
PY

provider_vendor=.work/x86_64/rust-std-lto/provider-vendor
dependency_vendor=.work/x86_64/rust-std-lto/dependency-vendor
if [ -L "$root/$provider_vendor" ] || [ -L "$root/$dependency_vendor" ]; then
    printf 'prepare-worktree: Rust std/LTO vendor path is a symlink\n' >&2
    exit 1
fi
if [ ! -d "$root/$provider_vendor" ]; then
    "$here/rust-check.sh" cargo vendor --locked --manifest-path unwinder/Cargo.toml \
        --versioned-dirs "/workspace/$provider_vendor" >/dev/null
fi
if [ ! -d "$root/$dependency_vendor" ]; then
    "$root/scripts/dev-x86_64.sh" consumer-rust-std-lto-vendor "$dependency_vendor" >/dev/null
fi
python3 -B - "$root" "$provider_vendor" "$dependency_vendor" <<'PY'
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1]).resolve()
for relative in sys.argv[2:]:
    path = root / relative
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path.absolute():
        raise SystemExit(f"prepare-worktree: Rust std/LTO vendor is not a physical directory: {path}")
    for item in path.rglob("*"):
        mode = item.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise SystemExit(f"prepare-worktree: Rust std/LTO vendor contains a link or special file: {item}")
PY
corpus=.work/x86_64/owned-package-corpus-input
if [ ! -d "$root/$corpus/apks" ]; then
    python3 -B "$root/compat/corpus/fetch_x86.py" ||
        printf 'prepare-worktree: x86 package-corpus input unavailable; run ./scripts/dev-x86_64.sh owned-package-corpus-input\n' >&2
fi
