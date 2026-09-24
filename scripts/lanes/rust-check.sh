#!/bin/sh
# Type-check the runtime crates across their owned feature profiles inside the
# pinned x86 image, with a separate target directory under .work/x86_64. Run
# `scripts/lanes/rust-check.sh cargo fetch --locked` once in a fresh checkout.
set -u
root=$(git rev-parse --show-toplevel)
work=$root/.work/x86_64
mkdir -p "$work/target-check" "$work/tmp"
in_image() {
    docker run --rm --init --platform linux/amd64 --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CARGO_TARGET_DIR=/workspace/.work/x86_64/target-check \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --volume "$root:/workspace" --volume "$work:/workspace/.work/x86_64" \
        crabc-core-evidence:x86_64 "$@"
}
if [ "$#" -gt 0 ]; then in_image "$@"; exit; fi
status=0
check() {
    if in_image cargo check -q --locked "$@" >"$work/tmp/rust-check.log" 2>&1; then
        echo "ok   $*"
    else
        echo "FAIL $*"; grep -E '^error' "$work/tmp/rust-check.log" | head -5; status=1
    fi
}
check -p crabc-libc
check -p crabc-libc --features x86-owned-static-runtime
check -p crabc-libc --features x86-owned-dynamic-runtime
check -p crabc-libc --features x86-owned-static-native-shadow
check -p crabc-libc --features x86-owned-dynamic-native-shadow
check -p crabc-mimalloc --all-targets
check -p crabc-ldso --features x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter
check -p crabc-core
check -p crabc-rs
exit $status
