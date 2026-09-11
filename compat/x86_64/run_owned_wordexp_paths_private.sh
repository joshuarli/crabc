#!/usr/bin/env bash
# Private native witness for the unselected wordexp pathname adapter.
# Run inside the pinned Linux/x86-64 image. The cfg-only bridge belongs to a
# disposable archive linked directly with the owned CRT and builtins. The
# sealed sysroot remains intact; this witness does not select the candidate.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly TARGET="x86_64-unknown-linux-musl"
readonly TOOLCHAIN="nightly-2026-07-24"
readonly LLD="/opt/rustup/toolchains/$TOOLCHAIN-x86_64-unknown-linux-musl/lib/rustlib/$TARGET/bin/gcc-ld/ld.lld"

if [ -z "${TMPDIR:-}" ] || [[ "$TMPDIR" != "$ROOT_DIR/.work/x86_64/"* ]]; then
    printf 'ERROR: pinned native execution requires a contained .work/x86_64 TMPDIR\n' >&2
    exit 2
fi

readonly work="$(mktemp -d "$TMPDIR/owned-wordexp-paths-private.XXXXXX")"
printf 'private evidence: %s\n' "$work"

python3 -B "$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py" \
    --output "$work/static-product" >"$work/static-build.json"
nm -g --defined-only "$work/static-product/usr/lib/libc.a" \
    >"$work/normal-archive.symbols" 2>"$work/normal-archive.stderr"
if awk '$NF == "__crabc_test_wordexp_paths" { found = 1 } END { exit(found ? 0 : 1) }' \
        "$work/normal-archive.symbols"; then
    printf 'ERROR: normal runtime archive contains the private pathname bridge\n' >&2
    exit 1
fi

# Use the same complete producer environment as the normal builder, including
# the checkout's populated Cargo cache. An ambient Cargo home is not a pinned
# producer input and could try to fetch registry metadata into external state.
python3 -B - "$ROOT_DIR" "$work" \
    >"$work/bridge-build.stdout" 2>"$work/bridge-build.stderr" <<'PY'
from pathlib import Path
import shlex
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
work = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(root / "scripts"))
import build_x86_64_owned_sysroot as builder

environment = builder.deterministic_environment()
environment.update({
    "CC_x86_64_unknown_linux_musl": "/usr/bin/gcc",
    "CFLAGS_x86_64_unknown_linux_musl": shlex.join([
        "-nostdinc", "-isystem", str(root / "include"),
        "-fPIC", "-ftls-model=initial-exec", "-fstack-protector-strong",
        builder.MIMALLOC_LIFECYCLE_C_FLAG,
        f"-ffile-prefix-map={root}=/crabc", "-MD", "-MF", str(work / "allocator.d"),
    ]),
    "CC_SHELL_ESCAPED_FLAGS": "1",
})
subprocess.run([
    str(builder.pinned_rustup()), "run", builder.PINNED_TOOLCHAIN,
    "cargo", "rustc", "--locked", "--offline", "-p", "crabc-libc", "--lib",
    "--release", "--features", "x86-owned-static-runtime", "--target", builder.TARGET,
    "--target-dir", str(work / "cargo"), "--",
    "--cfg", "crabc_owned_static_sysroot",
    "--cfg", builder.MIMALLOC_LIFECYCLE_RUST_CFG,
    "--cfg", "crabc_owned_wordexp_paths_private_test",
    "--check-cfg", "cfg(crabc_owned_wordexp_paths_private_test)",
    "-C", "relocation-model=pic", "-C", "code-model=small", "-C", "panic=abort",
    "-Ztls-model=initial-exec", "--remap-path-prefix", f"{root}=/crabc",
], cwd=root, env=environment, stdin=subprocess.DEVNULL, check=True)
PY

/usr/bin/gcc -nostdinc -isystem "$work/static-product/usr/include" \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -std=c11 -c \
    "$ROOT_DIR/compat/x86_64/owned_wordexp_paths_private_probe.c" \
    -o "$work/owned-wordexp-paths-private.o" \
    >"$work/consumer-build.stdout" 2>"$work/consumer-build.stderr"
"$LLD" -static --no-dynamic-linker --no-undefined --gc-sections \
    -z relro -z now -e _start \
    "$work/static-product/usr/lib/crt1.o" \
    "$work/static-product/usr/lib/crti.o" \
    "$work/owned-wordexp-paths-private.o" \
    "$work/cargo/$TARGET/release/libc.a" \
    "$work/static-product/usr/lib/libcrabc-builtins.a" \
    "$work/static-product/usr/lib/crtn.o" \
    -o "$work/owned-wordexp-paths-private" \
    >"$work/consumer-link.stdout" 2>"$work/consumer-link.stderr"

mkdir "$work/fixture"
if TMPDIR="$work/fixture" timeout 30 "$work/owned-wordexp-paths-private" \
    >"$work/consumer.stdout" 2>"$work/consumer.stderr"; then
    printf '0\n' >"$work/consumer.status"
    cat "$work/consumer.stdout"
else
    result=$?
    printf '%s\n' "$result" >"$work/consumer.status"
    cat "$work/consumer.stderr" >&2
    exit "$result"
fi
