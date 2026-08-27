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
  fs-advice-reference  verify pinned-musl x86 fadvise64/readahead ABI and behavior
  memfd-reference  verify direct typed x86 memfd/sealing ABI and lifecycle
  ftruncate-reference  verify pinned-musl x86 descriptor-length ABI and lifecycle
  file-position-reference  verify pinned-musl x86 lseek/fsync/fdatasync ABI and behavior
  rand-reference  verify pinned-musl x86 getrandom ABI and behavior reference
  time-abi-reference  verify pinned-musl x86 timespec and clock ABI constants
  time-observation-reference  verify pinned-musl x86 realtime observation behavior
  relative-sleep-reference  verify pinned-musl x86 nanosleep behavior
  clock-nanosleep-reference  verify pinned-musl x86 clock_nanosleep behavior
  getitimer-reference  verify pinned-musl x86 read-only interval-timer ABI and behavior
  setitimer-reference  verify pinned-musl x86 contained interval-timer behavior
  timerfd-reference  verify pinned-musl x86 timerfd ABI and lifecycle
  pselect-reference  verify pinned-musl/raw x86 direct select/pselect ABI and behavior
  poll-reference  verify pinned-musl x86 poll ABI and behavior reference
  ppoll-reference  verify pinned-musl x86 ppoll/pause signal-mask behavior
  epoll-reference  verify pinned-musl/raw x86 direct typed epoll ABI and behavior
  process-identity-reference  verify pinned-musl x86 process-identity behavior
  getgroups-reference  verify pinned-musl x86 supplementary-group ABI and behavior
  process-session-reference  verify pinned-musl x86 process group/session behavior
  pidfd-open-reference  verify pinned-musl x86 pidfd_open behavior
  fcntl-getlk-reference  verify pinned-musl x86 fcntl lock-query behavior
  scheduler-priority-bounds-reference  verify pinned-musl x86 scheduler-priority bounds
  rr-interval-reference  verify pinned-musl x86 read-only round-robin interval behavior
  sched-affinity-reference  verify pinned-musl x86 direct typed CPU-affinity observation
  sched-affinity-set-reference  verify pinned-musl x86 direct typed CPU-affinity mutation
  priority-reference  verify pinned-musl x86 getpriority ABI and behavior
  setpriority-reference  verify pinned-musl x86 contained scheduling-priority mutation
  rlimit-reference  verify pinned-musl x86 read-only resource-limit ABI and behavior
  rlimit-targeted-reference  verify pinned-musl/raw x86 targeted-resource-limit behavior
  setrlimit-reference  verify pinned-musl x86 contained resource-limit mutation
  umask-reference  verify pinned-musl x86 process-mask exchange ABI and behavior
  rusage-reference  verify pinned-musl x86 read-only resource-usage ABI and behavior
  times-reference  verify pinned-musl x86 process-accounting ABI and behavior
  fstat-reference  verify pinned-musl x86 fstat ABI and behavior reference
  statat-reference  verify pinned-musl x86 private statat ABI and behavior reference
  getcwd-reference  verify pinned-musl/raw x86 direct typed getcwd behavior
  readlinkat-reference  verify pinned-musl x86 private caller-buffer readlinkat behavior reference
  system-reference  verify pinned-musl x86 uname/sysinfo ABI and behavior reference
  thread-reference  verify pinned-musl x86 thread observation/yield behavior
  thread-credentials-reference  verify pinned-musl x86 calling-thread credential ABI and behavior
  fs-credentials-reference  verify pinned-musl x86 filesystem-credential ABI and behavior
  core   run the native x86_64-unknown-linux-musl crabc-core lib tests
  facade run the bounded native x86_64 crabc-rs direct-facade tests
  libc-syscall  run the isolated x86 C-ABI syscall register probe
  libc-errno-tls  run the source-only x86 C errno/initial-TLS probe
  libc-thread-pointer  run the source-only x86 opaque %fs:0 thread-pointer probe
  libc-foundation  run the source-only x86 C runtime primitive-composition probe
  libc-fenv  run the source-only x86 C x87/MXCSR floating-point-environment probe
  libc-memory  run the source-only x86 C memcpy/memmove/memset probe
  libc-setjmp  run the source-only x86 C setjmp/signal-mask ABI probe
  libc-atomic  run the source-only x86 atomic-helper probe
  libc-clone-raw  run the source-only x86 musl-shaped raw clone probe
  libc-signal-foundation  run the source-only x86 signal-action packing probe
  ldso-relocation  run the source-only checked x86 RELA/RELR foundation tests
  ldso-image  run the source-only checked x86 ELF image parser tests

This closed runner rejects non-native Linux/x86-64 hosts and does not provide
an x86 libc artifact, ldso, CRT, sysroot, allocator, generic Cargo, or shell
command. `facade` covers only the separately admitted direct `crabc-rs`
subset, including borrowed-atomic futex wait/wake and the complete typed
`seek`/`tell`/`ftruncate`/`fsync`/`fdatasync` file-position family, typed
anonymous memory-file creation plus bounded seal observation/mutation,
calling-process `getrlimit`/`setrlimit`, typed supplementary-group query/fill,
typed read-only `getrusage` observations, typed read-only `times` accounting,
typed read-only interval-timer and round-robin interval, plus direct typed
CPU-affinity observation/mutation, and typed
process-global `umask` exchange,
calling-thread `setresuid`/`setresgid` transitions with typed no-change
sentinels, and typed scheduling-priority mutation,
plus bounded typed clock-nanosleep with its relative-remainder and
absolute-no-remainder modes, direct select/pselect and packed epoll readiness
with masked waits, and caller-buffer current-working-directory observation. The
dedicated `getcwd-reference` gate also covers its alloc-gated retry; contained
interval-timer control, timerfd, private statat path-metadata, and
caller-buffer-only readlinkat remain privately evidenced. None makes the
record-owning family selectable.
`musl-oracle` proves only C/POSIX oracle provenance, and
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
`fs-advice-reference` establishes only the typed Rust file-access advice and
readahead boundary; it does not select a C filesystem API.
`memfd-reference` establishes the direct typed x86 `memfd_create` plus
`F_GET_SEALS`/`F_ADD_SEALS` boundary: descriptor ownership/CLOEXEC, the
249-byte kernel versus 256-byte facade name limit, Linux-5.10 seal effects
including `F_SEAL_WRITE`'s live-mapping `EBUSY` guard and
`F_SEAL_FUTURE_WRITE` preserving preexisting writable shared mappings while
rejecting direct writes and new writable shared mappings, and direct descriptor
errors. It excludes a C `fcntl`/header ABI,
`memfd_secret`, huge-page size selection, executable policy, and broader
filesystem behavior; the Linux-6.3 `F_SEAL_EXEC` bit is forwarded but not
proved on the Linux-5.10 baseline.
`ftruncate-reference` establishes the `ftruncate` component of the
admitted typed x86 file-position family: syscall 77, the signed 64-bit
`loff_t` maximum, extend-with-zero-fill and shrink behavior for a fresh
memfd-backed fixture, unchanged file position, and direct `EINVAL`/`EBADF`
errors. It
does not select a C filesystem API, pathname truncation, allocation, or
durability policy.
`file-position-reference` establishes the remaining admitted typed x86
`lseek`/`fsync`/`fdatasync` boundary: signed 64-bit `off_t`, syscall numbers
8/74/75, `SEEK_SET`/`SEEK_CUR`/`SEEK_END` positions, accepted descriptor-sync
requests, and direct `EINVAL`/`ESPIPE`/`EBADF` errors. Its fresh memfd
avoids host-filesystem durability claims. It does not select a C filesystem
API, pathname behavior, or broader filesystem semantics.
`rand-reference`, `time-abi-reference`, `time-observation-reference`,
`relative-sleep-reference`, `clock-nanosleep-reference`,
`getitimer-reference`, `setitimer-reference`, `timerfd-reference`, `pselect-reference`,
`poll-reference`, `ppoll-reference`, and `epoll-reference`,
`process-identity-reference`, `getgroups-reference`, `process-session-reference`,
`setpriority-reference`, `rlimit-targeted-reference`, `setrlimit-reference`, `umask-reference`,
`pidfd-open-reference`, `fcntl-getlk-reference`,
`scheduler-priority-bounds-reference`, `rlimit-reference`, `rusage-reference`,
`times-reference`,
`fstat-reference`, `statat-reference`, `getcwd-reference`,
`readlinkat-reference`, `system-reference`, and
`thread-reference` establish only their named
pinned-musl kernel boundaries for separately admitted Rust slices.
`thread-credentials-reference` establishes only the typed direct
calling-thread `setresuid`/`setresgid` no-change boundary: it does not
emulate musl's process-wide credential synchronization or select C credential
APIs.
`fs-credentials-reference` establishes only the typed direct
calling-task `setfsuid`/`setfsgid` query/current-effective-ID boundary. Linux
returns the previous identity even when a requested change is denied, so it
does not claim ordinary failure reporting, process-wide synchronization, or a
C credential API.
`epoll-reference` proves the direct typed x86 packed epoll lifecycle:
close-on-exec and legacy creation, null and borrowed eight-byte signal masks,
future-bit forwarding for Linux validation, add/modify/delete, initialized-prefix
readiness output, and temporary mask installation/restoration through raw and
pinned-musl waits. C facades and errno TLS remain excluded.
`timerfd-reference` proves only the x86 `itimerspec` record and focused
timer-descriptor lifecycle; it does not promote the broader record-owning
facade family.
`getitimer-reference` proves the direct typed read-only interval-timer query:
the x86 `itimerval` record, closed selectors, canonical transient output, and
invalid-selector `EINVAL`. It does not select `setitimer`, `alarm`/`ualarm`,
C time APIs, timer/signal delivery policy, or a broader process API.
`setitimer-reference` proves only the private x86 contained interval-timer
control boundary: syscall 38, validated microsecond settings, old-setting
exchange, and malformed-`timeval` `EINVAL` behavior in short-lived child
processes. It does not select `alarm`, `ualarm`, C time APIs, or promote the
broader record-owning facade family.
`statat-reference` proves only the x86 `newfstatat` record with CWD and
`AT_SYMLINK_NOFOLLOW`; it does not select `AT_EMPTY_PATH`, general path APIs,
filesystem mutation, or promote the broader record-owning facade family.
`getcwd-reference` proves the direct x86 typed `process::{getcwd,getcwd_alloc}`
boundary: raw/pinned-musl `getcwd=79` prefix and `ERANGE` behavior, the
intentional musl zero-size `EINVAL` versus raw-kernel `ERANGE` difference, and
an alloc-gated native Rust long-current-directory retry that returns a
`CString`. It excludes `chdir`/`fchdir`, filesystem mutation, general path
APIs, C APIs, errno TLS, and the broader record-owning facade family.
`readlinkat-reference` proves only the private x86 caller-buffer-only
`readlinkat` target query: the caller owns writable storage, the result is a
non-NUL-terminated initialized prefix, and a short output buffer succeeds with
its truncated prefix. Its direct raw kernel boundary rejects a zero-length
buffer with `EINVAL`, unlike musl's empty successful C-wrapper result. It does
not select allocation-backed path APIs, path mutation, or promote the broader
record-owning facade family.
`rr-interval-reference` proves the direct typed x86 read-only
`sched_rr_get_interval` query: PID zero and an explicit `gettid` select the
calling task, and that explicit task ID remains addressable from the initial
task while the worker is live; a missing task returns `ESRCH`. Its pinned-musl
C oracle uses the worker only as harness machinery. It excludes scheduler
policy selection/mutation and parameter-query APIs, a C API or pthread facade,
errno TLS, affinity, and a broader thread API.
`clock-nanosleep-reference` proves only the direct typed x86 clock-sleep
boundary: syscall 230 with a 16-byte timespec, relative zero completion and
signal interruption with a positive remainder, plus absolute past-deadline
completion and signal-interrupted deadlines with a null remainder pointer. Pinned musl's C
function returns direct positive errors, while the raw syscall uses `-1` plus
`errno`; neither form selects a C sleep ABI, clock mutation, POSIX timers, or
broader time policy.
`sched-affinity-reference` proves the direct typed x86 read-only
CPU-affinity observation: PID zero, explicit calling and live non-leader task
IDs, raw dynamic-length/untouched-tail behavior, and musl's
zero-success/zero-tail C wrapper. Its pinned-musl pthread worker is oracle
harness machinery only; this observation gate excludes scheduler policy, C or
pthread facades, errno TLS, and the broader record-owning family.
`sched-affinity-set-reference` proves the direct typed x86 explicit affinity
mutation: PID zero and a live non-leader task ID, raw and musl success, current
mask reapplication without broadening, and a contained worker singleton. It
also records empty-mask `EINVAL` and missing-task `ESRCH`. Its pinned-musl
pthread worker is oracle harness machinery only; wider scheduler policy, C or
pthread facades, errno TLS, and the broader record-owning family remain
excluded.
`pselect-reference` proves direct x86 `event::{select, pselect}` behavior:
the 1024-bit descriptor-bit-vector ABI, empty/readable readiness, invalid
`nfds`, raw `pselect6` argument-six mask-pointer/size placement, copied
timeouts, and raw/pinned-musl temporary signal-mask restoration. C facades and
errno TLS remain excluded.
`priority-reference` establishes only the typed Rust read-only getpriority
boundary; it does not by itself select scheduling mutation or a C process API.
`setpriority-reference` proves only typed scheduling-priority mutation:
`setpriority=141` over the existing closed `PRIO_*` and nice-value vocabulary,
with child-contained raw/musl set/read/no-op exchange plus invalid-selector
`EINVAL` and missing process/group/user target `ESRCH`. It does not select scheduler-policy
mutation or a C process API.
`rlimit-reference` proves the direct typed calling-process `getrlimit`
boundary: `prlimit64=302`, a 16-byte `rlimit64`, PID zero/null-new-limit
query placement, closed selectors, and infinity mapping. It does not select
target-resource mutation or a C process API.
`rlimit-targeted-reference` proves the direct typed read-only
`process::getrlimit_for` boundary: a forked live child holds a distinct
`RLIMIT_NOFILE` soft limit while both pinned-musl `prlimit` and raw
`prlimit64=302` reads agree with its reported 16-byte `rlimit64` record; the
native Rust regression makes the same live-child query and retains missing-PID
`ESRCH`. It excludes target-resource mutation, C process APIs, errno TLS, and
the broader record-owning family.
`setrlimit-reference` proves only typed calling-process resource-limit
mutation: `prlimit64=302`, a 16-byte `rlimit64`, child-contained raw/musl
set/query/restore exchange, and pre-syscall inverted-limit `EINVAL`. It does
not select target-process mutation or a C process API.
`umask-reference` proves only the typed x86 process-mask exchange: syscall 95,
unsigned 32-bit `mode_t`, and child-contained raw/musl exchange/restoration.
It does not select a C process API or pathname-creation support.
`rusage-reference` proves the direct typed read-only `process::getrusage`
boundary: the x86 initialized `rusage` kernel prefix, closed selectors, and
focused canonical observations. It copies only initialized fields into the
typed Rust value and does not select C `struct rusage` storage, musl's
uninitialized reserved tail, or broader process-accounting policy.
`times-reference` proves the direct typed read-only `process::times` boundary:
the x86 `tms` record, nonnegative process-accounting fields, and a separately
preserved signed elapsed-tick return. It does not select a C `times`/`struct
tms` API, tick-rate conversion, or broader process-accounting policy.
`getgroups-reference` proves the direct typed supplementary-group query/fill
boundary: x86 `gid_t`, the null count query, caller-owned initialized-prefix
output, and the retry-after-`EINVAL` count-to-fill snapshot race. It does not
select C `getgroups`/`setgroups`, credential mutation or synchronization, or a
broader process API.
`libc-syscall` compiles only the unintegrated raw syscall module.
`libc-errno-tls` compiles only the unintegrated errno source and its C fixture.
`libc-thread-pointer` compiles only the private musl-shaped `%fs:0` identity
leaf and a pinned-musl C fixture. It establishes neither a C runtime artifact,
public C ABI, pthread/TLS lifecycle, loader TLS, nor an FS-base setup path.
`libc-foundation` composes only a private fixed-six-word raw x86 syscall-to-errno bridge
with the separately proved memory and fenv leaves in one source-only object.
It is not a selected C runtime artifact or general x86 C support.
`libc-fenv` compiles only the fixed-musl x86 x87/MXCSR fenv leaf and its C
fixture. It is not a selected C `fenv_t` artifact or general x86 C support.
`libc-memory` compiles only the fixed-musl x86 memcpy/memmove/memset leaf and
its C fixture. It is not a selected C string/runtime artifact or general x86
C support.
`libc-setjmp` compiles only the unintegrated control-transfer assembly leaf.
`libc-atomic` compiles only the unintegrated x86 atomic-helper leaf.
`libc-clone-raw` compiles only the private musl-shaped x86 process-clone
machine-boundary leaf. It does not provide public `clone`, pthread, or TLS
support.
`libc-signal-foundation` compiles only the private musl-shaped x86 public-to-
kernel signal-action record packer and syscall-15 restorer. It does not install
or deliver a handler or provide public C signal support.
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

run_fs_advice_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fs_advice_reference.sh
}

run_memfd_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_memfd_reference.sh
}

run_ftruncate_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_ftruncate_reference.sh
}

run_file_position_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_file_position_reference.sh
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

run_clock_nanosleep_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_clock_nanosleep_reference.sh
}

run_getitimer_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_getitimer_reference.sh
}

run_setitimer_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_setitimer_reference.sh
}

run_timerfd_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_timerfd_reference.sh
}

run_pselect_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_pselect_reference.sh
}

run_poll_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_poll_reference.sh
}

run_ppoll_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_ppoll_reference.sh
}

run_epoll_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_epoll_reference.sh
}

run_process_identity_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_process_identity_reference.sh
}

run_getgroups_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_getgroups_reference.sh
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

run_priority_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_priority_reference.sh
}

run_setpriority_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_setpriority_reference.sh
}

run_rlimit_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_rlimit_reference.sh
}

run_rlimit_targeted_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_rlimit_targeted_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_rlimit_targeted -- --test-threads=1
}

run_setrlimit_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_setrlimit_reference.sh
}

run_umask_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_umask_reference.sh
}

run_rusage_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_rusage_reference.sh
}

run_times_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_times_reference.sh
}

run_fstat_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fstat_reference.sh
}

run_statat_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_statat_reference.sh
}

run_getcwd_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_getcwd_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc --test x86_64_getcwd -- --test-threads=1
}

run_readlinkat_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_readlinkat_reference.sh
}

run_rr_interval_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_sched_rr_interval_reference.sh
}

run_sched_affinity_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_sched_affinity_reference.sh
}

run_sched_affinity_set_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_sched_setaffinity_reference.sh
}

run_system_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_system_reference.sh
}

run_thread_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_thread_reference.sh
}

run_thread_credentials_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_thread_credentials_reference.sh
}

run_fs_credentials_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fs_credentials_reference.sh
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

run_libc_thread_pointer_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_thread_pointer.sh
}

run_libc_foundation_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_foundation.sh
}

run_libc_fenv_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_fenv.sh
}

run_libc_memory_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_memory.sh
}

run_libc_setjmp_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_setjmp.sh
}

run_libc_atomic_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_atomic.sh
}

run_libc_clone_raw_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_clone_raw.sh
}

run_libc_signal_foundation_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_foundation.sh
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
    image|musl-oracle|header-abi-reference|header-abi-project|sys-reg-header-abi|types-header-abi|stat-header-abi|time-header-abi|poll-header-abi|fcntl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|mman-header-abi|mm-abi-reference|mlock-reference|msync-reference|madvise-reference|mincore-reference|fs-advice-reference|memfd-reference|ftruncate-reference|file-position-reference|rand-reference|time-abi-reference|time-observation-reference|relative-sleep-reference|clock-nanosleep-reference|getitimer-reference|setitimer-reference|timerfd-reference|pselect-reference|poll-reference|ppoll-reference|epoll-reference|process-identity-reference|getgroups-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|scheduler-priority-bounds-reference|rr-interval-reference|sched-affinity-reference|sched-affinity-set-reference|priority-reference|setpriority-reference|rlimit-reference|rlimit-targeted-reference|setrlimit-reference|umask-reference|rusage-reference|times-reference|fstat-reference|statat-reference|getcwd-reference|readlinkat-reference|system-reference|thread-reference|thread-credentials-reference|fs-credentials-reference|core|facade|libc-syscall|libc-errno-tls|libc-thread-pointer|libc-foundation|libc-fenv|libc-memory|libc-setjmp|libc-atomic|libc-clone-raw|libc-signal-foundation|ldso-relocation|ldso-image) ;;
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
    fs-advice-reference)
        [ "$#" -eq 0 ] || fail "fs-advice-reference takes no arguments"
        ensure_image
        run_fs_advice_reference
        ;;
    memfd-reference)
        [ "$#" -eq 0 ] || fail "memfd-reference takes no arguments"
        ensure_image
        run_memfd_reference
        ;;
    ftruncate-reference)
        [ "$#" -eq 0 ] || fail "ftruncate-reference takes no arguments"
        ensure_image
        run_ftruncate_reference
        ;;
    file-position-reference)
        [ "$#" -eq 0 ] || fail "file-position-reference takes no arguments"
        ensure_image
        run_file_position_reference
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
    clock-nanosleep-reference)
        [ "$#" -eq 0 ] || fail "clock-nanosleep-reference takes no arguments"
        ensure_image
        run_clock_nanosleep_reference
        ;;
    getitimer-reference)
        [ "$#" -eq 0 ] || fail "getitimer-reference takes no arguments"
        ensure_image
        run_getitimer_reference
        ;;
    setitimer-reference)
        [ "$#" -eq 0 ] || fail "setitimer-reference takes no arguments"
        ensure_image
        run_setitimer_reference
        ;;
    timerfd-reference)
        [ "$#" -eq 0 ] || fail "timerfd-reference takes no arguments"
        ensure_image
        run_timerfd_reference
        ;;
    pselect-reference)
        [ "$#" -eq 0 ] || fail "pselect-reference takes no arguments"
        ensure_image
        run_pselect_reference
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
    epoll-reference)
        [ "$#" -eq 0 ] || fail "epoll-reference takes no arguments"
        ensure_image
        run_epoll_reference
        ;;
    process-identity-reference)
        [ "$#" -eq 0 ] || fail "process-identity-reference takes no arguments"
        ensure_image
        run_process_identity_reference
        ;;
    getgroups-reference)
        [ "$#" -eq 0 ] || fail "getgroups-reference takes no arguments"
        ensure_image
        run_getgroups_reference
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
    priority-reference)
        [ "$#" -eq 0 ] || fail "priority-reference takes no arguments"
        ensure_image
        run_priority_reference
        ;;
    setpriority-reference)
        [ "$#" -eq 0 ] || fail "setpriority-reference takes no arguments"
        ensure_image
        run_setpriority_reference
        ;;
    rlimit-reference)
        [ "$#" -eq 0 ] || fail "rlimit-reference takes no arguments"
        ensure_image
        run_rlimit_reference
        ;;
    rlimit-targeted-reference)
        [ "$#" -eq 0 ] || fail "rlimit-targeted-reference takes no arguments"
        ensure_image
        run_rlimit_targeted_reference
        ;;
    setrlimit-reference)
        [ "$#" -eq 0 ] || fail "setrlimit-reference takes no arguments"
        ensure_image
        run_setrlimit_reference
        ;;
    umask-reference)
        [ "$#" -eq 0 ] || fail "umask-reference takes no arguments"
        ensure_image
        run_umask_reference
        ;;
    rusage-reference)
        [ "$#" -eq 0 ] || fail "rusage-reference takes no arguments"
        ensure_image
        run_rusage_reference
        ;;
    times-reference)
        [ "$#" -eq 0 ] || fail "times-reference takes no arguments"
        ensure_image
        run_times_reference
        ;;
    fstat-reference)
        [ "$#" -eq 0 ] || fail "fstat-reference takes no arguments"
        ensure_image
        run_fstat_reference
        ;;
    statat-reference)
        [ "$#" -eq 0 ] || fail "statat-reference takes no arguments"
        ensure_image
        run_statat_reference
        ;;
    getcwd-reference)
        [ "$#" -eq 0 ] || fail "getcwd-reference takes no arguments"
        ensure_image
        run_getcwd_reference
        ;;
    readlinkat-reference)
        [ "$#" -eq 0 ] || fail "readlinkat-reference takes no arguments"
        ensure_image
        run_readlinkat_reference
        ;;
    rr-interval-reference)
        [ "$#" -eq 0 ] || fail "rr-interval-reference takes no arguments"
        ensure_image
        run_rr_interval_reference
        ;;
    sched-affinity-reference)
        [ "$#" -eq 0 ] || fail "sched-affinity-reference takes no arguments"
        ensure_image
        run_sched_affinity_reference
        ;;
    sched-affinity-set-reference)
        [ "$#" -eq 0 ] || fail "sched-affinity-set-reference takes no arguments"
        ensure_image
        run_sched_affinity_set_reference
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
    thread-credentials-reference)
        [ "$#" -eq 0 ] || fail "thread-credentials-reference takes no arguments"
        ensure_image
        run_thread_credentials_reference
        ;;
    fs-credentials-reference)
        [ "$#" -eq 0 ] || fail "fs-credentials-reference takes no arguments"
        ensure_image
        run_fs_credentials_reference
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
            -p crabc-rs --lib --no-default-features --test fenv --test futex --test x86_64_foundation \
            --test x86_64_epoll --test x86_64_eventfd --test x86_64_fcntl_getlk --test x86_64_fs --test x86_64_fs_advice --test x86_64_file_position --test x86_64_ftruncate --test x86_64_fs_credentials --test x86_64_getgroups --test x86_64_getitimer --test x86_64_setitimer --test x86_64_io --test x86_64_memfd --test x86_64_mm --test x86_64_param --test x86_64_pipe --test x86_64_poll --test x86_64_pselect --test x86_64_priority --test x86_64_setpriority --test x86_64_process_identity --test x86_64_process_session --test x86_64_pidfd_open --test x86_64_rand --test x86_64_rlimit --test x86_64_rlimit_targeted --test x86_64_setrlimit --test x86_64_umask --test x86_64_rusage --test x86_64_scheduler_priority_bounds --test x86_64_sleep --test x86_64_clock_nanosleep --test x86_64_statat --test x86_64_getcwd --test x86_64_readlink --test x86_64_sched_rr_interval --test x86_64_sched_affinity --test x86_64_sched_setaffinity --test x86_64_system --test x86_64_thread --test x86_64_thread_credentials --test x86_64_time --test x86_64_timerfd --test x86_64_times \
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
    libc-thread-pointer)
        [ "$#" -eq 0 ] || fail "libc-thread-pointer takes no arguments"
        ensure_image
        run_libc_thread_pointer_probe
        ;;
    libc-foundation)
        [ "$#" -eq 0 ] || fail "libc-foundation takes no arguments"
        ensure_image
        run_libc_foundation_probe
        ;;
    libc-fenv)
        [ "$#" -eq 0 ] || fail "libc-fenv takes no arguments"
        ensure_image
        run_libc_fenv_probe
        ;;
    libc-memory)
        [ "$#" -eq 0 ] || fail "libc-memory takes no arguments"
        ensure_image
        run_libc_memory_probe
        ;;
    libc-setjmp)
        [ "$#" -eq 0 ] || fail "libc-setjmp takes no arguments"
        ensure_image
        run_libc_setjmp_probe
        ;;
    libc-atomic)
        [ "$#" -eq 0 ] || fail "libc-atomic takes no arguments"
        ensure_image
        run_libc_atomic_probe
        ;;
    libc-clone-raw)
        [ "$#" -eq 0 ] || fail "libc-clone-raw takes no arguments"
        ensure_image
        run_libc_clone_raw_probe
        ;;
    libc-signal-foundation)
        [ "$#" -eq 0 ] || fail "libc-signal-foundation takes no arguments"
        ensure_image
        run_libc_signal_foundation_probe
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
