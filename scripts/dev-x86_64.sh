#!/usr/bin/env bash
# Native Linux/x86-64 staged foundation evidence entry point.
#
# This is a deliberately closed foundation lane. It proves only crabc-core
# under the native musl target; it does not select libc, ldso, CRT, sysroot,
# crabc-rs, or allocator evidence commands.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PLATFORM="linux/amd64"
readonly IMAGE="${CRABC_X86_64_CORE_IMAGE:-crabc-core-evidence:x86_64}"
readonly TARGET_VOLUME="${CRABC_X86_64_CORE_TARGET_VOLUME:-crabc-core-evidence-target-x86_64}"
readonly CARGO_VOLUME="${CRABC_X86_64_CORE_CARGO_VOLUME:-crabc-core-evidence-cargo-x86_64}"
readonly DOCKERFILE="$ROOT_DIR/docker/Dockerfile.x86_64"

usage() {
    cat <<'EOF'
Usage: ./scripts/dev-x86_64.sh <command>

Native Linux/x86-64 staged-foundation evidence commands:
  image  build the pinned Linux/amd64 core-evidence image
  core   run the native x86_64-unknown-linux-musl crabc-core lib tests
  libc-syscall  run the isolated x86 C-ABI syscall register probe

This closed runner rejects non-native Linux/x86-64 hosts and does not provide
an x86 libc artifact, ldso, CRT, sysroot, crabc-rs, allocator, generic Cargo,
or shell command. `libc-syscall` compiles only the unintegrated raw syscall
module; it is not a crabc-libc build or C ABI support claim.
EOF
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

require_native_linux_x86_64_host() {
    local host_system
    local host_machine
    host_system="$(uname -s)"
    host_machine="$(uname -m)"

    if [ "$host_system" != "Linux" ]; then
        fail "native x86-64 core evidence requires a Linux host (host: $host_system/$host_machine)"
    fi

    case "$host_machine" in
        x86_64|amd64) ;;
        *) fail "native x86-64 core evidence refuses emulation (host: $host_system/$host_machine)" ;;
    esac
}

build_image() {
    docker build \
        --platform "$PLATFORM" \
        --tag "$IMAGE" \
        --file "$DOCKERFILE" \
        "$ROOT_DIR"
}

ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        build_image
    fi

    local identity
    identity="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")"
    if [ "$identity" != "linux/amd64" ]; then
        fail "$IMAGE is $identity; rebuild it with ./scripts/dev-x86_64.sh image"
    fi
}

run_in_container() {
    docker run --rm --init \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CARGO_HOME=/opt/cargo \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/opt/cargo" \
        "$IMAGE" "$@"
}

run_libc_syscall_probe() {
    run_in_container bash -ceu '
        probe=/tmp/crabc-x86-libc-syscall-probe
        rustc --edition=2021 --target x86_64-unknown-linux-musl \
            /workspace/compat/x86_64/libc_syscall_probe.rs -o "$probe"
        "$probe"
    '
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

case "$command" in
    image|core|libc-syscall) ;;
    *)
        usage >&2
        exit 2
        ;;
esac

require_native_linux_x86_64_host

case "$command" in
    image)
        [ "$#" -eq 0 ] || fail "image takes no arguments"
        build_image
        ;;
    core)
        [ "$#" -eq 0 ] || fail "core takes no arguments"
        ensure_image
        run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
            -p crabc-core --lib --no-default-features -- --test-threads=1
        ;;
    libc-syscall)
        [ "$#" -eq 0 ] || fail "libc-syscall takes no arguments"
        ensure_image
        run_libc_syscall_probe
        ;;
esac
