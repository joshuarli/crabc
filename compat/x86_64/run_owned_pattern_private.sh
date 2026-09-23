#!/usr/bin/env bash
# Focused real-owner witness for the unselected shell quote-map boundary.
#
# The normal owned-pattern product must not contain a fixture bridge. This
# runner builds a disposable static archive with one private Rust cfg, links a
# C consumer that declares no installed API, and discards the product. It uses
# the same x86-owned-static-runtime owner, C allocator, locale, directory
# traversal, and glob result lifecycle that a later wordexp adapter consumes.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly TARGET="x86_64-unknown-linux-musl"
readonly TOOLCHAIN="$(python3 "$ROOT_DIR/scripts/rust_toolchain.py")"
readonly LLD="/opt/rustup/toolchains/$TOOLCHAIN-x86_64-unknown-linux-musl/lib/rustlib/$TARGET/bin/gcc-ld/ld.lld"
readonly PROBE="$ROOT_DIR/compat/x86_64/owned_pattern_private_probe.c"

if [ -z "${TMPDIR:-}" ] || [[ "$TMPDIR" != "$ROOT_DIR/.work/x86_64/"* ]]; then
    printf 'ERROR: run through the pinned x86 dispatcher with TMPDIR below .work/x86_64\n' >&2
    exit 2
fi

readonly work="$(mktemp -d "$TMPDIR/owned-pattern-private.XXXXXX")"
# Keep this deliberately unqualified fixture product for review on both PASS
# and FAIL. It contains only a cfg-gated bridge and never replaces a sealed
# installed sysroot payload.
trap 'status=$?; trap - EXIT; printf "owned-pattern-private evidence: %s\\n" "$work"; exit "$status"' EXIT

python3 -B "$ROOT_DIR/scripts/build_x86_64_owned_sysroot.py" \
    --output "$work/static-product" >"$work/static-build.json"

# This ordinary sealed archive must remain free of every fixture-only symbol.
# Keep the table in the retained evidence leaf so review can inspect the exact
# normal-product boundary that the cfg-gated archive below does not replace.
nm -g --defined-only "$work/static-product/usr/lib/libc.a" >"$work/normal-symbols.txt"
if awk '$NF ~ /^__crabc_test_shell_/' "$work/normal-symbols.txt" | grep -q .; then
    printf 'private pattern bridge leaked into normal static product\n' >&2
    exit 1
fi

# Match the static-product owner's allocator and compilation profile, adding
# only the cfg that admits the private C witness symbol.
readonly c_flags="-nostdinc -isystem $ROOT_DIR/include -fPIC -ftls-model=initial-exec -fstack-protector-strong -DMI_PRIM_HAS_PROCESS_ATTACH=1 -ffile-prefix-map=$ROOT_DIR=/crabc -MD -MF $work/allocator.d"
CC_x86_64_unknown_linux_musl=/usr/bin/gcc \
CFLAGS_x86_64_unknown_linux_musl="$c_flags" \
CC_SHELL_ESCAPED_FLAGS=1 \
rustup run "$TOOLCHAIN" cargo rustc --locked -p crabc-libc --lib --release \
    --features x86-owned-static-runtime --target "$TARGET" --target-dir "$work/cargo" -- \
    --cfg crabc_owned_static_sysroot \
    --cfg crabc_owned_mimalloc_lifecycle \
    --cfg crabc_owned_pattern_private_test \
    --check-cfg 'cfg(crabc_owned_pattern_private_test)' \
    -C relocation-model=pic -C code-model=small -C panic=abort -Ztls-model=initial-exec \
    --remap-path-prefix "$ROOT_DIR=/crabc"

# The sealed driver correctly rejects a modified installed archive. Keep its
# manifest and normal product payload intact; this fixture-only link instead
# compiles one C object and uses the same installed CRT/builtins with the raw
# cfg-gated archive that contains the otherwise absent private bridge.
/usr/bin/gcc -nostdinc -isystem "$work/static-product/usr/include" \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -std=c11 \
    -c "$PROBE" -o "$work/owned-pattern-private.o"
"$LLD" -static --no-dynamic-linker --no-undefined --gc-sections \
    -z relro -z now -e _start \
    "$work/static-product/usr/lib/crt1.o" \
    "$work/static-product/usr/lib/crti.o" \
    "$work/owned-pattern-private.o" \
    "$work/cargo/$TARGET/release/libc.a" \
    "$work/static-product/usr/lib/libcrabc-builtins.a" \
    "$work/static-product/usr/lib/crtn.o" \
    -o "$work/owned-pattern-private"

fixture="$work/fixture"
mkdir "$fixture" "$fixture/dir" "$fixture/dir\\"
touch "$fixture/*" "$fixture/*file" "$fixture/[file" "$fixture/\\file" \
    "$fixture/-" "$fixture/a" "$fixture/z" "$fixture/m" "$fixture/]" \
    "$fixture/!" "$fixture/7" "$fixture/d]" "$fixture/.hidden" \
    "$fixture/dir/leaf" "$fixture/dir/.hidden" "$fixture/dir\\/leaf"

"$work/owned-pattern-private" "$fixture"
