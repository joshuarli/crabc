#!/bin/sh
# Type-check the runtime crates across their owned feature profiles inside
# the pinned native image for this host's architecture, with a separate
# target directory under .work/<arch>. x86-64 keeps crabc-x86_64-mold-gcc and
# the x86 feature-profile list; aarch64 builds for aarch64-unknown-linux-musl.
# Run `scripts/lanes/rust-check.sh cargo fetch --locked` once in a fresh
# checkout.
set -u
root=$(git rev-parse --show-toplevel)
arch_config=$(python3 -B "$root/compat/x86_64/native_arch.py" "$(uname -m)") || exit
eval "$arch_config"
expected_identity=$platform
mold_gcc=$linker
work=$root/.work/$work_name
if [ "$arch" = x86_64 ]; then
    image=${CRABC_X86_64_CORE_IMAGE:-$image}
else
    image=${CRABC_AARCH64_CORE_IMAGE:-$image}
fi
if docker image inspect "$image" >/dev/null; then
    :
else
    inspect_status=$?
    printf 'ERROR: could not inspect native Rust-check image %s (docker image inspect exited %s)\n' \
        "$image" "$inspect_status" >&2
    exit 1
fi
identity=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image") || exit
if [ "$identity" != "$expected_identity" ]; then
    printf 'ERROR: native Rust-check image %s is %s; expected %s\n' "$image" "$identity" "$expected_identity" >&2
    exit 1
fi
mkdir -p "$work/target-check" "$work/tmp"
common_directory=
if [ -f "$root/.git" ]; then
    # Linked checkouts retain absolute paths to their own index and HEAD.
    # Shared metadata is read-only so commands cannot retire host checkouts.
    common_directory=$(GIT_OPTIONAL_LOCKS=0 git -C "$root" rev-parse --path-format=absolute --git-common-dir) || exit
fi
in_image() {
    set -- "$image" "$@"
    if [ -n "$common_directory" ]; then
        set -- --volume "$common_directory:$common_directory:ro" "$@"
    fi
    # Arena tests lock their complete 32-MiB caller-owned reservation.
    # Expected aborts retain status and stderr; core dumps can copy large mappings.
    docker run --rm --init --platform "$platform" --workdir /workspace \
        --ulimit core=0:0 \
        --ulimit memlock=67108864:67108864 \
        --env CARGO_INCREMENTAL=0 \
        --env RUSTC_WRAPPER=/usr/local/bin/kache \
        --env "$linker_variable=$mold_gcc" \
        --env CARGO_HOME="/workspace/.work/$arch/cargo" \
        --env CARGO_TARGET_DIR="/workspace/.work/$arch/target-check" \
        --env TMPDIR="/workspace/.work/$arch/tmp" \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$root:/workspace" --volume "$work:/workspace/.work/$arch" \
        "$@"
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
if [ "$arch" = x86_64 ]; then
    check -p crabc-libc
    check -p crabc-libc --features x86-owned-static-runtime
    check -p crabc-libc --features x86-owned-dynamic-runtime
    check -p crabc-libc --features x86-owned-static-native-shadow
    check -p crabc-libc --features x86-owned-dynamic-native-shadow
    check -p crabc-mimalloc --all-targets
    check -p crabc-ldso --features x86_64-owned-dynamic-runtime
    check -p crabc-core
    check -p crabc-rs
else
    check --target "$target_triple" -p crabc-core
fi
exit $status
