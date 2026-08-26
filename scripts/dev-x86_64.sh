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
  musl-oracle  verify the pinned musl-1.2.6 x86 C/POSIX oracle toolchain
  header-abi-reference  verify the pinned x86 SysV LP64/x87 header baseline
  header-abi-project  compile the staged crabc x86 fenv/float header slice
  sys-reg-header-abi  compile the staged crabc x86 ptrace-register header slice
  types-header-abi  compile the staged crabc x86 C/C++ type-layout header slice
  stat-header-abi  compile the staged x86 C/C++ sys/stat header layouts
  time-header-abi  compile the staged x86 C/C++ time header layouts
  poll-header-abi  compile the staged x86 C/C++ poll header layouts
  fcntl-header-abi compile the staged x86 C/C++ fcntl header layouts
  unistd-header-abi  compile the staged x86 C/C++ unistd header declarations
  system-header-abi  compile the staged x86 C/C++ system header layouts
  syscall-header-abi  compare the staged x86 syscall macro surface with musl
  signal-header-abi  compile the staged x86 GNU/POSIX signal-header layouts
  mman-header-abi  compile the staged x86 C/C++ mapping-header declarations
  mm-abi-reference  verify pinned-musl x86 mapping syscall and flag constants
  mlock-reference  verify pinned-musl x86 memory-locking ABI and behavior
  msync-reference  verify pinned-musl x86 mapping-synchronization ABI and behavior
  madvise-reference  verify pinned-musl x86 mapping-advice ABI and behavior
  mincore-reference  verify pinned-musl x86 mapping-residency ABI and behavior
  rand-reference  verify pinned-musl x86 getrandom ABI and behavior reference
  time-abi-reference  verify pinned-musl x86 timespec and clock ABI constants
  time-observation-reference  verify pinned-musl x86 realtime observation behavior
  relative-sleep-reference  verify pinned-musl x86 nanosleep behavior
  poll-reference  verify pinned-musl x86 poll ABI and behavior reference
  ppoll-reference  verify pinned-musl x86 ppoll/pause signal-mask behavior
  process-identity-reference  verify pinned-musl x86 process-identity behavior
  process-session-reference  verify pinned-musl x86 process group/session behavior
  pidfd-open-reference  verify pinned-musl x86 pidfd_open behavior
  fcntl-getlk-reference  verify pinned-musl x86 fcntl lock-query behavior
  scheduler-priority-bounds-reference  verify pinned-musl x86 scheduler-priority bounds
  fstat-reference  verify pinned-musl x86 fstat ABI and behavior reference
  system-reference  verify pinned-musl x86 uname/sysinfo ABI and behavior reference
  thread-reference  verify pinned-musl x86 thread observation/yield behavior
  core   run the native x86_64-unknown-linux-musl crabc-core lib tests
  facade run the bounded native x86_64 crabc-rs direct-facade tests
  libc-syscall  run the isolated x86 C-ABI syscall register probe
  libc-errno-tls  run the source-only x86 C errno/initial-TLS probe
  libc-setjmp  run the source-only x86 C setjmp/signal-mask ABI probe
  ldso-relocation  run the source-only checked x86 RELA/RELR foundation tests
  ldso-image  run the source-only checked x86 ELF image parser tests

This closed runner rejects non-native Linux/x86-64 hosts and does not provide
an x86 libc artifact, ldso, CRT, sysroot, allocator, generic Cargo, or shell
command. `facade` covers only the separately admitted direct `crabc-rs`
subset; `musl-oracle` proves only C/POSIX oracle provenance, and
`header-abi-reference` proves only its pinned reference baseline.
`header-abi-project` compiles only the staged public fenv/float/fundamental
type declarations and does not link an x86 libc artifact.
`sys-reg-header-abi` compiles only the staged ptrace register-index header.
`types-header-abi` compiles only staged C/C++ type declarations and opaque
pthread object layouts. `stat-header-abi`, `time-header-abi`, `poll-header-abi`,
`fcntl-header-abi`, `unistd-header-abi`, and `system-header-abi` compile only
their named C/C++ layout/declaration slices.
`syscall-header-abi` compares only staged syscall number macros.
`signal-header-abi` and `mman-header-abi` compile only staged signal-frame and
mapping declarations. `mm-abi-reference` establishes only the pinned-musl
constants used by the separately admitted Rust mapping facade.
`mlock-reference` establishes only the pinned-musl x86 per-range memory-locking
boundary used by that facade.
`msync-reference`, `madvise-reference`, and `mincore-reference` establish only
their named mapping-synchronization, Linux/POSIX advisory, and page-residency
boundaries used by the typed Rust facade.
`rand-reference`, `time-abi-reference`, `time-observation-reference`,
`relative-sleep-reference`, `poll-reference`, `ppoll-reference`,
`process-identity-reference`, `process-session-reference`,
`pidfd-open-reference`, `fcntl-getlk-reference`,
`scheduler-priority-bounds-reference`, `fstat-reference`,
`system-reference`, and `thread-reference` establish only their named
pinned-musl kernel boundaries for separately admitted Rust slices.
`libc-syscall` compiles only the unintegrated raw syscall module.
`libc-errno-tls` compiles only the unintegrated errno source and its C fixture.
`libc-setjmp` compiles only the unintegrated control-transfer assembly leaf.
`ldso-relocation` compiles only the unintegrated checked relocation source.
`ldso-image` compiles only the unintegrated checked ELF image parser.
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
        disassembly="$target_dir/fenv-disassembly"
        command -v objdump >/dev/null || {
            printf "ERROR: x86 fenv codegen gate requires objdump\\n" >&2
            exit 1
        }
        # Save output before searching it: with pipefail, grep -q can close
        # early and turn a harmless SIGPIPE from objdump into a flaky failure.
        objdump -d -- "$test_binary" > "$disassembly"
        if grep -Eqi "[[:space:]]fxrstor(64)?[[:space:]]" "$disassembly"; then
            printf "ERROR: x86 fenv codegen must not reload XMM state with fxrstor: %s\\n" \
                "$test_binary" >&2
            exit 1
        fi
        printf "x86 fenv codegen gate: PASS (no fxrstor in %s)\\n" "$test_binary"
    '
}

run_musl_oracle() {
    run_in_container bash /workspace/compat/x86_64/run_musl_oracle.sh
}

run_header_abi_reference() {
    run_in_container bash /workspace/compat/x86_64/run_header_abi_reference.sh
}

run_header_abi_project() {
    run_in_container bash /workspace/compat/x86_64/run_project_header_abi.sh
}

run_sys_reg_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sys_reg_header_abi.sh
}

run_types_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_types_header_abi.sh
}

run_stat_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_stat_header_abi.sh
}

run_time_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_time_header_abi.sh
}

run_poll_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_poll_header_abi.sh
}

run_fcntl_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_fcntl_header_abi.sh
}

run_unistd_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_unistd_header_abi.sh
}

run_system_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_system_header_abi.sh
}

run_syscall_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_x86_syscall_header.sh
}

run_signal_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_signal_header_abi.sh
}

run_mman_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mman_header_abi.sh
}

run_mm_abi_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_mm_reference.sh
}

run_mlock_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_mlock_reference.sh
}

run_msync_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_msync_reference.sh
}

run_madvise_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_madvise_reference.sh
}

run_mincore_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_mincore_reference.sh
}

run_rand_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_rand_reference.sh
}

run_time_abi_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_time_reference.sh
}

run_time_observation_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_time_observation_reference.sh
}

run_relative_sleep_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_relative_sleep_reference.sh
}

run_poll_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_poll_reference.sh
}

run_ppoll_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_ppoll_reference.sh
}

run_process_identity_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_process_identity_reference.sh
}

run_process_session_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_process_session_reference.sh
}

run_pidfd_open_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_pidfd_open_reference.sh
}

run_fcntl_getlk_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fcntl_getlk_reference.sh
}

run_scheduler_priority_bounds_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_scheduler_priority_bounds_reference.sh
}

run_fstat_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fstat_reference.sh
}

run_system_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_system_reference.sh
}

run_thread_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_thread_reference.sh
}

run_libc_syscall_probe() {
    run_in_container bash -ceu '
        probe=/tmp/crabc-x86-libc-syscall-probe
        rustc --edition=2021 --target x86_64-unknown-linux-musl \
            /workspace/compat/x86_64/libc_syscall_probe.rs -o "$probe"
        "$probe"
    '
}

run_libc_errno_tls_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_errno_tls.sh
}

run_libc_setjmp_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_setjmp.sh
}

run_ldso_relocation_tests() {
    run_in_container bash -ceu '
        test_binary=/tmp/crabc-x86-64-ldso-relocation
        rustup run nightly-2026-07-24 rustc --edition=2021 --test \
            /workspace/ldso/src/x86_64_relocation.rs -o "$test_binary"
        "$test_binary" --test-threads=1
    '
}

run_ldso_image_tests() {
    run_in_container bash /workspace/ldso/run-x86_64-image.sh test
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

case "$command" in
    image|musl-oracle|header-abi-reference|header-abi-project|sys-reg-header-abi|types-header-abi|stat-header-abi|time-header-abi|poll-header-abi|fcntl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|mman-header-abi|mm-abi-reference|mlock-reference|msync-reference|madvise-reference|mincore-reference|rand-reference|time-abi-reference|time-observation-reference|relative-sleep-reference|poll-reference|ppoll-reference|process-identity-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|scheduler-priority-bounds-reference|fstat-reference|system-reference|thread-reference|core|facade|libc-syscall|libc-errno-tls|libc-setjmp|ldso-relocation|ldso-image) ;;
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
    musl-oracle)
        [ "$#" -eq 0 ] || fail "musl-oracle takes no arguments"
        ensure_image
        run_musl_oracle
        ;;
    header-abi-reference)
        [ "$#" -eq 0 ] || fail "header-abi-reference takes no arguments"
        ensure_image
        run_header_abi_reference
        ;;
    header-abi-project)
        [ "$#" -eq 0 ] || fail "header-abi-project takes no arguments"
        ensure_image
        run_header_abi_project
        ;;
    sys-reg-header-abi)
        [ "$#" -eq 0 ] || fail "sys-reg-header-abi takes no arguments"
        ensure_image
        run_sys_reg_header_abi
        ;;
    types-header-abi)
        [ "$#" -eq 0 ] || fail "types-header-abi takes no arguments"
        ensure_image
        run_types_header_abi
        ;;
    stat-header-abi)
        [ "$#" -eq 0 ] || fail "stat-header-abi takes no arguments"
        ensure_image
        run_stat_header_abi
        ;;
    time-header-abi)
        [ "$#" -eq 0 ] || fail "time-header-abi takes no arguments"
        ensure_image
        run_time_header_abi
        ;;
    poll-header-abi)
        [ "$#" -eq 0 ] || fail "poll-header-abi takes no arguments"
        ensure_image
        run_poll_header_abi
        ;;
    fcntl-header-abi)
        [ "$#" -eq 0 ] || fail "fcntl-header-abi takes no arguments"
        ensure_image
        run_fcntl_header_abi
        ;;
    unistd-header-abi)
        [ "$#" -eq 0 ] || fail "unistd-header-abi takes no arguments"
        ensure_image
        run_unistd_header_abi
        ;;
    system-header-abi)
        [ "$#" -eq 0 ] || fail "system-header-abi takes no arguments"
        ensure_image
        run_system_header_abi
        ;;
    syscall-header-abi)
        [ "$#" -eq 0 ] || fail "syscall-header-abi takes no arguments"
        ensure_image
        run_syscall_header_abi
        ;;
    signal-header-abi)
        [ "$#" -eq 0 ] || fail "signal-header-abi takes no arguments"
        ensure_image
        run_signal_header_abi
        ;;
    mman-header-abi)
        [ "$#" -eq 0 ] || fail "mman-header-abi takes no arguments"
        ensure_image
        run_mman_header_abi
        ;;
    mm-abi-reference)
        [ "$#" -eq 0 ] || fail "mm-abi-reference takes no arguments"
        ensure_image
        run_mm_abi_reference
        ;;
    mlock-reference)
        [ "$#" -eq 0 ] || fail "mlock-reference takes no arguments"
        ensure_image
        run_mlock_reference
        ;;
    msync-reference)
        [ "$#" -eq 0 ] || fail "msync-reference takes no arguments"
        ensure_image
        run_msync_reference
        ;;
    madvise-reference)
        [ "$#" -eq 0 ] || fail "madvise-reference takes no arguments"
        ensure_image
        run_madvise_reference
        ;;
    mincore-reference)
        [ "$#" -eq 0 ] || fail "mincore-reference takes no arguments"
        ensure_image
        run_mincore_reference
        ;;
    rand-reference)
        [ "$#" -eq 0 ] || fail "rand-reference takes no arguments"
        ensure_image
        run_rand_reference
        ;;
    time-abi-reference)
        [ "$#" -eq 0 ] || fail "time-abi-reference takes no arguments"
        ensure_image
        run_time_abi_reference
        ;;
    time-observation-reference)
        [ "$#" -eq 0 ] || fail "time-observation-reference takes no arguments"
        ensure_image
        run_time_observation_reference
        ;;
    relative-sleep-reference)
        [ "$#" -eq 0 ] || fail "relative-sleep-reference takes no arguments"
        ensure_image
        run_relative_sleep_reference
        ;;
    poll-reference)
        [ "$#" -eq 0 ] || fail "poll-reference takes no arguments"
        ensure_image
        run_poll_reference
        ;;
    ppoll-reference)
        [ "$#" -eq 0 ] || fail "ppoll-reference takes no arguments"
        ensure_image
        run_ppoll_reference
        ;;
    process-identity-reference)
        [ "$#" -eq 0 ] || fail "process-identity-reference takes no arguments"
        ensure_image
        run_process_identity_reference
        ;;
    process-session-reference)
        [ "$#" -eq 0 ] || fail "process-session-reference takes no arguments"
        ensure_image
        run_process_session_reference
        ;;
    pidfd-open-reference)
        [ "$#" -eq 0 ] || fail "pidfd-open-reference takes no arguments"
        ensure_image
        run_pidfd_open_reference
        ;;
    fcntl-getlk-reference)
        [ "$#" -eq 0 ] || fail "fcntl-getlk-reference takes no arguments"
        ensure_image
        run_fcntl_getlk_reference
        ;;
    scheduler-priority-bounds-reference)
        [ "$#" -eq 0 ] || fail "scheduler-priority-bounds-reference takes no arguments"
        ensure_image
        run_scheduler_priority_bounds_reference
        ;;
    fstat-reference)
        [ "$#" -eq 0 ] || fail "fstat-reference takes no arguments"
        ensure_image
        run_fstat_reference
        ;;
    system-reference)
        [ "$#" -eq 0 ] || fail "system-reference takes no arguments"
        ensure_image
        run_system_reference
        ;;
    thread-reference)
        [ "$#" -eq 0 ] || fail "thread-reference takes no arguments"
        ensure_image
        run_thread_reference
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
            --test x86_64_eventfd --test x86_64_fcntl_getlk --test x86_64_fs --test x86_64_io --test x86_64_mm --test x86_64_param --test x86_64_pipe --test x86_64_poll --test x86_64_process_identity --test x86_64_process_session --test x86_64_pidfd_open --test x86_64_rand --test x86_64_scheduler_priority_bounds --test x86_64_sleep --test x86_64_system --test x86_64_thread --test x86_64_time \
            -- --test-threads=1
        ;;
    libc-syscall)
        [ "$#" -eq 0 ] || fail "libc-syscall takes no arguments"
        ensure_image
        run_libc_syscall_probe
        ;;
    libc-errno-tls)
        [ "$#" -eq 0 ] || fail "libc-errno-tls takes no arguments"
        ensure_image
        run_libc_errno_tls_probe
        ;;
    libc-setjmp)
        [ "$#" -eq 0 ] || fail "libc-setjmp takes no arguments"
        ensure_image
        run_libc_setjmp_probe
        ;;
    ldso-relocation)
        [ "$#" -eq 0 ] || fail "ldso-relocation takes no arguments"
        ensure_image
        run_ldso_relocation_tests
        ;;
    ldso-image)
        [ "$#" -eq 0 ] || fail "ldso-image takes no arguments"
        ensure_image
        run_ldso_image_tests
        ;;
esac
