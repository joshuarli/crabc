#!/usr/bin/env bash
# Native Linux/x86-64 staged foundation evidence entry point.
#
# This is a deliberately closed foundation lane. It proves explicitly named
# native core, direct-facade, raw-C-syscall, and source-only relocation slices;
# it does not select a libc, ldso artifact, CRT, sysroot, or allocator build.
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
  facade run the bounded native x86_64 crabc-rs direct-facade tests
  libc-syscall  run the isolated x86 C-ABI syscall register probe
  ldso-relocation  run the source-only checked x86 RELA/RELR foundation tests

This closed runner rejects non-native Linux/x86-64 hosts and does not provide
an x86 libc artifact, ldso, CRT, sysroot, allocator, generic Cargo, or shell
command. `facade` covers only the separately admitted direct `crabc-rs`
subset; `libc-syscall` compiles only the unintegrated raw syscall module.
`ldso-relocation` compiles only the unintegrated checked relocation source.
None is a crabc-libc or crabc-ldso build, general facade admission, or C ABI
support claim.
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

run_core_tests() {
    run_in_container bash -ceu '
        target_dir="$(mktemp -d /tmp/crabc-x86-64-core.XXXXXX)"
        CARGO_TARGET_DIR="$target_dir" cargo test --locked --target x86_64-unknown-linux-musl \
            -p crabc-core --lib --no-default-features -- --test-threads=1

        mapfile -d "" -t test_binaries < <(
            find "$target_dir/x86_64-unknown-linux-musl/debug/deps" -maxdepth 1 \
                -type f -name "crabc_core-*" -perm -111 -print0
        )
        if [ "${#test_binaries[@]}" -ne 1 ]; then
            printf "ERROR: expected one crabc-core test binary, found %s\\n" \
                "${#test_binaries[@]}" >&2
            exit 1
        fi

        test_binary="${test_binaries[0]}"
        command -v objdump >/dev/null || {
            printf "ERROR: x86 fenv codegen gate requires objdump\\n" >&2
            exit 1
        }
        if objdump -d -- "$test_binary" | grep -Eqi "[[:space:]]fxrstor(64)?[[:space:]]"; then
            printf "ERROR: x86 fenv codegen must not reload XMM state with fxrstor: %s\\n" \
                "$test_binary" >&2
            exit 1
        fi
        printf "x86 fenv codegen gate: PASS (no fxrstor in %s)\\n" "$test_binary"
    '
}

run_libc_syscall_probe() {
    run_in_container bash -ceu '
        probe=/tmp/crabc-x86-libc-syscall-probe
        rustc --edition=2021 --target x86_64-unknown-linux-musl \
            /workspace/compat/x86_64/libc_syscall_probe.rs -o "$probe"
        "$probe"
    '
}

run_ldso_relocation_tests() {
    run_in_container bash -ceu '
        test_binary=/tmp/crabc-x86-64-ldso-relocation
        rustup run nightly-2026-07-24 rustc --edition=2021 --test \
            /workspace/ldso/src/x86_64_relocation.rs -o "$test_binary"
        "$test_binary" --test-threads=1
    '
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

case "$command" in
    image|core|facade|libc-syscall|ldso-relocation) ;;
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
        run_core_tests
        ;;
    facade)
        [ "$#" -eq 0 ] || fail "facade takes no arguments"
        ensure_image
        run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
            -p crabc-rs --lib --no-default-features --test fenv --test x86_64_foundation \
            -- --test-threads=1
        ;;
    libc-syscall)
        [ "$#" -eq 0 ] || fail "libc-syscall takes no arguments"
        ensure_image
        run_libc_syscall_probe
        ;;
    ldso-relocation)
        [ "$#" -eq 0 ] || fail "ldso-relocation takes no arguments"
        ensure_image
        run_ldso_relocation_tests
        ;;
esac
