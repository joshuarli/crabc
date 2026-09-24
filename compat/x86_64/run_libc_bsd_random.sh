#!/usr/bin/env bash
# Pinned-musl/x86 static BSD random-state provider differential.
#
# `--expect-missing` is the pre-provider red-regression mechanism: one
# project-header C fixture first executes against pinned musl, then its static
# link must expose all four absent providers. The historical pre-provider
# receipt captured archive-symbol absence only; this runner does not relabel it
# as an unexecuted link receipt. Once the provider exists, the same fixture
# compares musl and an extracted provider object in a true -nostdlib static
# executable.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_bsd_random_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_bsd_random_start.S"
readonly -a SYMBOLS=(random srandom initstate setstate)

fail() { printf 'ERROR: x86 BSD random: %s\n' "$*" >&2; exit 1; }
[ "$(uname -sm)" = 'Linux x86_64' ] || fail 'requires native Linux/x86-64'
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ "${TMPDIR:-}" != '' ] && [ -d "$TMPDIR" ] || fail 'TMPDIR must be checkout-local .work storage'

expect_missing=0
if [ "${1:-}" = --expect-missing ]; then
    expect_missing=1
    shift
fi
[ "$#" -eq 0 ] || fail 'usage: run_libc_bsd_random.sh [--expect-missing]'

for tool in ar awk cargo cmp grep mkdir nm readelf rustup sort timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done

work_dir="$(mktemp -d "$TMPDIR/libc-bsd-random.XXXXXX")"
chmod a+rx "$work_dir"
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/crabc-candidate"

"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" "$PROBE" -o "$reference"
timeout 10s "$reference" >"$work_dir/reference.trace" || fail 'pinned-musl fixture failed'

build_source_runtime_libc "$target_dir/x86_64-unknown-linux-musl/debug/libc.a" \
    --features x86-owned-static-runtime
[ -f "$archive" ] || fail 'cargo did not emit feature-selected x86 archive'

nm -A --defined-only "$archive" >"$work_dir/archive.symbols"
if [ "$expect_missing" -eq 1 ]; then
    for symbol in "${SYMBOLS[@]}"; do
        if grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$work_dir/archive.symbols"; then
            fail "retained red archive unexpectedly defines ${symbol}"
        fi
    done
    if "$ORACLE_CC" -std=c11 -D_BSD_SOURCE -DCRABC_BSD_RANDOM_FREESTANDING \
        -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
        -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
        "$PROBE" "$START" "$archive" -o "$work_dir/red-candidate" \
        >"$work_dir/red-link.stdout" 2>"$work_dir/red-link.stderr"; then
        fail 'retained red fixture unexpectedly linked through the owned archive'
    fi
    for symbol in "${SYMBOLS[@]}"; do
        grep -Eq "undefined reference to .*${symbol}|undefined symbol: ${symbol}" \
            "$work_dir/red-link.stderr" || fail "red link did not expose missing ${symbol}"
    done
    chmod -R a+rX "$work_dir"
    printf 'x86 BSD random: expected red PASS (pinned-musl fixture passed; the feature-selected owned archive link exposes all four absent providers); evidence: %s\n' "$work_dir"
    exit 0
fi

owner="$(awk '$NF == "random" { member = $1; sub(/^.*\.a:/, "", member); sub(/:.*$/, "", member); print member }' "$work_dir/archive.symbols" | sort -u)"
[ "$(printf '%s\n' "$owner" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ] || fail 'random must have one archive owner'
raw_owner="$(awk '$NF ~ /raw_syscall.*syscall3/ { member = $1; sub(/^.*\.a:/, "", member); sub(/:.*$/, "", member); print member }' "$work_dir/archive.symbols" | sort -u)"
# The optimizer may inline the private raw-syscall closure into its caller;
# otherwise the closure has exactly one out-of-line archive owner.
[ "$(printf '%s\n' "$raw_owner" | awk 'NF { count++ } END { print count + 0 }')" -le 1 ] || fail 'private raw-syscall closure has more than one archive owner'
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "$owner" ${raw_owner:+"$raw_owner"}
    ar crs "$work_dir/provider.a" "$owner" ${raw_owner:+"$raw_owner"}
)
object="$work_dir/owner/$owner"
for symbol in "${SYMBOLS[@]}"; do
    nm -g --defined-only "$object" | grep -E "[[:space:]]${symbol}$" >/dev/null ||
        fail "provider omits ${symbol}"
done
# The selected owner intentionally uses the established private raw-syscall
# closure for musl's blocking `__lock` protocol. Keep that one closure in the
# extracted artifact; do not require an artificial stand-alone object or
# reject compiler-private symbols.

"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -DCRABC_BSD_RANDOM_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections \
    "$PROBE" "$START" "$work_dir/provider.a" -o "$candidate"
readelf -lW "$candidate" >"$work_dir/candidate.headers"
readelf -dW "$candidate" >"$work_dir/candidate.dynamic" || true
grep -Eq 'INTERP|NEEDED|[[:space:]]TLS[[:space:]]' "$work_dir/candidate.headers" "$work_dir/candidate.dynamic" &&
    fail 'candidate has an interpreter, dependency, or TLS'
timeout 10s "$candidate" >"$work_dir/candidate.trace" || fail 'static candidate fixture failed'
cmp "$work_dir/reference.trace" "$work_dir/candidate.trace" || fail 'static trace differs from pinned musl'
chmod -R a+rX "$work_dir"
printf 'x86 BSD random: PASS (pinned-musl differential; default/reseed, all state-size boundaries, state restoration, returned pointers, and extracted static provider); evidence: %s\n' "$work_dir"
