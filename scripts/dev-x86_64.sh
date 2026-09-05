#!/usr/bin/env bash
# Native Linux/x86-64 development and evidence dispatcher.
# Routes focused core/facade/C ABI tests, loader/CRT gates, and installed
# sysroot consumers through the pinned native container. Mutable host state
# stays under the checkout's .work boundary; each runner owns its child state.
# See compat/x86_64/README.md for commands and their evidence contracts.
# A passing command proves its named boundary, not public-platform promotion.
# Native mimalloc has its separate contained compat/allocator/run-x86_64.sh.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PLATFORM="linux/amd64"
readonly IMAGE="${CRABC_X86_64_CORE_IMAGE:-crabc-core-evidence:x86_64}"
readonly DOCKERFILE="$ROOT_DIR/docker/Dockerfile.x86_64"
readonly WORK_BOUNDARY="$ROOT_DIR/.work/x86_64"
normalize_absolute_path() {
    local path="${1#/}"
    local component
    local last_index
    local normalized=""
    local -a components=()

    while [ -n "$path" ]; do
        if [[ "$path" == */* ]]; then
            component="${path%%/*}"
            path="${path#*/}"
        else
            component="$path"
            path=""
        fi
        case "$component" in
            ""|.)
                ;;
            ..)
                if [ "${#components[@]}" -gt 0 ]; then
                    last_index=$((${#components[@]} - 1))
                    unset "components[$last_index]"
                fi
                ;;
            *)
                components+=("$component")
                ;;
        esac
    done

    for component in "${components[@]}"; do
        normalized="$normalized/$component"
    done
    printf '%s\n' "${normalized:-/}"
}

resolve_existing_directory() {
    local candidate="$1"
    local existing="$candidate"
    local missing_component
    local missing_suffix=""
    local physical_existing

    # Resolve every existing prefix physically before making the missing tail.
    # This catches a symlink below .work before `mkdir -p` could follow it.
    while [ ! -e "$existing" ] && [ ! -L "$existing" ]; do
        missing_component="${existing##*/}"
        missing_suffix="/$missing_component$missing_suffix"
        existing="${existing%/*}"
        if [ -z "$existing" ]; then
            existing="/"
        fi
    done
    if ! physical_existing="$(cd -P "$existing" 2>/dev/null && pwd)"; then
        return 1
    fi
    if [ -z "$missing_suffix" ]; then
        printf '%s\n' "$physical_existing"
    elif [ "$physical_existing" = "/" ]; then
        printf '%s\n' "$missing_suffix"
    else
        printf '%s%s\n' "$physical_existing" "$missing_suffix"
    fi
}

path_is_within_work_boundary() {
    [ "$1" = "$WORK_BOUNDARY" ] || [[ "$1" == "$WORK_BOUNDARY/"* ]]
}

configuration_error() {
    printf 'ERROR: %s\n' "$*" >&2
    return 1
}

resolve_bounded_directory() {
    local name="$1"
    local configured_path="$2"
    local relative_base="$3"
    local candidate
    local resolved

    if [[ "/$configured_path/" == */../* ]]; then
        configuration_error "$name must not contain '..' path components: $configured_path"
        return 1
    fi
    if [[ "$configured_path" == *:* ]]; then
        configuration_error "$name must be a host directory path, not Docker mount syntax: $configured_path"
        return 1
    fi
    if [[ "$configured_path" = /* ]]; then
        candidate="$configured_path"
    else
        candidate="$relative_base/$configured_path"
    fi
    candidate="$(normalize_absolute_path "$candidate")"
    if ! resolved="$(resolve_existing_directory "$candidate")"; then
        configuration_error "$name must name a directory: $candidate"
        return 1
    fi
    if ! path_is_within_work_boundary "$resolved"; then
        configuration_error "$name must resolve below $WORK_BOUNDARY: $resolved"
        return 1
    fi
    printf '%s\n' "$resolved"
}

resolve_container_bind_directory() {
    local name="$1"
    local configured_path="$2"
    local relative_base="$3"

    # A bare word is Docker's named-volume syntax. Require an explicit host
    # path marker for overrides, then apply the same physical boundary check.
    if [[ "$configured_path" != /* && "$configured_path" != .* ]]; then
        configuration_error "$name must be an explicit host path; named Docker volumes are not allowed: $configured_path"
        return 1
    fi
    resolve_bounded_directory "$name" "$configured_path" "$relative_base"
}

if ! resolved_work_boundary="$(resolve_existing_directory "$WORK_BOUNDARY")"; then
    exit 2
fi
if [ "$resolved_work_boundary" != "$WORK_BOUNDARY" ]; then
    configuration_error "x86 work boundary must be a physical checkout directory"
    exit 2
fi
WORK_DIR="$(resolve_bounded_directory CRABC_X86_64_WORK_DIR "${CRABC_X86_64_WORK_DIR:-$WORK_BOUNDARY}" "$ROOT_DIR")" || exit 2
TARGET_VOLUME="$(resolve_container_bind_directory CRABC_X86_64_CORE_TARGET_VOLUME "${CRABC_X86_64_CORE_TARGET_VOLUME:-$WORK_DIR/target}" "$WORK_DIR")" || exit 2
CARGO_VOLUME="$(resolve_container_bind_directory CRABC_X86_64_CORE_CARGO_VOLUME "${CRABC_X86_64_CORE_CARGO_VOLUME:-$WORK_DIR/cargo}" "$WORK_DIR")" || exit 2
readonly WORK_DIR TARGET_VOLUME CARGO_VOLUME
TMP_DIR="$(resolve_bounded_directory TMPDIR "$WORK_DIR/tmp" "$WORK_DIR")" || exit 2
REPORT_DIR="$(resolve_bounded_directory REPORT_DIR "$WORK_DIR/reports" "$WORK_DIR")" || exit 2
readonly TMP_DIR REPORT_DIR

# Linked worktrees contain an absolute host gitdir pointer. Preserve that
# pointer inside the container so source-bound builders can read their own
# index and HEAD. Mount only shared Git metadata, read-only; the worktree
# itself remains at /workspace and mutable build state remains below .work.
GIT_METADATA_MOUNT=()
if [ -f "$ROOT_DIR/.git" ]; then
    git_common_directory="$(GIT_OPTIONAL_LOCKS=0 git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)" || exit 2
    git_common_directory="$(resolve_existing_directory "$git_common_directory")" || exit 2
    if [[ "$git_common_directory" == *:* ]]; then
        configuration_error "Git metadata path must not contain Docker mount syntax"
        exit 2
    fi
    GIT_METADATA_MOUNT=(--volume "$git_common_directory:$git_common_directory:ro")
fi
readonly -a GIT_METADATA_MOUNT

prepare_work_dir() {
    mkdir -p "$TARGET_VOLUME" "$CARGO_VOLUME" "$TMP_DIR" "$REPORT_DIR"
}

usage() {
    cat <<'EOF'
Usage: ./scripts/dev-x86_64.sh <command>

Mutable build state stays below this checkout's .work/x86_64 directory.
CRABC_X86_64_WORK_DIR may select a descendant. Target and Cargo overrides
must be explicit host paths within that boundary; named Docker volumes,
parent traversal, and symlink escapes are rejected. Legacy container /tmp
writes are bound to the same local scratch tree.

Native Linux/x86-64 staged-foundation evidence commands:
  campaign-status  emit the validated native x86 campaign report
  campaign-family <family-id>  emit one validated required-family campaign report
  campaign-static  run the owned-static product gate when its prerequisites close
  campaign-dynamic  run the owned-dynamic product gate when its prerequisites close
  campaign-qualification  run the ordered qualification gate when it is ready
  qualification-manifest  execute declared qualification cases in the pinned native container
  campaign-promotion-check  run the final promotion gate when it is ready
  campaign-all  run the complete native x86 campaign gate sequence
  routine-c-abi-matrix <family-id>  run checked routine C ABI evidence for one family
  headers-layouts-aggregate  run finite non-promoting header accounting evidence
  image  build the pinned Linux/amd64 core-evidence image
  musl-oracle  verify the pinned musl-1.2.6 x86 C/POSIX oracle toolchain
  linux-5-10-uapi  verify the fixed Linux 5.10 x86 exported-UAPI input
  header-abi-reference  verify the pinned x86 SysV LP64/x87 header baseline
  public-header-surface  inventory all pinned x86 public headers for C consumability
  candidate-header-closure  require isolated C11/C++17 public-header include closure
  installed-header-tree-closure  verify the materialized target-owned x86 public-header closure
  selected-header-install-projection  verify the private pinned-path x86 installed-header projection
  header-callable-visibility-matrix  check all-header callable feature-visibility evidence
  header-callable-disposition  check all-header callable ownership routing evidence
  header-abi-matrix  check all-header callable and named noncallable ABI evidence
  header-record-layout-matrix  check all-header record byte-layout evidence
  header-declaration-macro-visibility-matrix  check all-header declaration/macro feature-visibility evidence
  feature-profile-control-plane-header-abi  verify pinned-musl feature-selector declaration boundaries
  header-callable-linkage-audit  audit declared x86 header callables against the static archive
  header-callable-provider-linkage-audit  audit selected default/feature callable archive providers
  uapi-wrapper-matrix  verify the selected Linux 5.10 UAPI wrapper C/C++ ABI profile matrix
  epoll-header-abi  verify the selected x86 packed sys/epoll.h C/C++ ABI profile matrix
  event-descriptors-header-abi  verify selected x86 eventfd/inotify C/C++ ABI profiles
  fanotify-header-abi  verify selected x86 fanotify record-traversal C/C++ ABI profiles
  dirent-header-abi  verify selected x86 dirent C/C++ ABI and feature profiles
  ftw-header-abi  verify selected x86 ftw C/C++ ABI and feature profiles
  stat-ftw-header-source-form  verify x86 sys/stat.h through ftw.h pinned-musl source forms
  param-header-source-form  verify x86 sys/param.h and sys/resource.h pinned-musl source forms
  pathname-lifecycle-header-abi  verify selected x86 pathname-lifecycle C/C++ ABI profiles
  ioctl-header-abi  verify selected direct sys/ioctl.h C/C++ ABI profile matrix
  ioctl-header-source-form  verify x86 ioctl header forms and frozen AArch64 arm
  link-header-source-form  verify x86 <link.h> pinned-musl include topology
  reboot-header-source-form  verify x86 <sys/reboot.h> pinned-musl macro form
  mount-header-source-form  verify x86 <sys/mount.h> pinned-musl source form
  klog-header-source-form  verify x86 <sys/klog.h> pinned-musl macro surface
  cachectl-header-source-form  verify x86 <sys/cachectl.h> pinned-musl macro forms
  syslog-header-abi  verify syslog profiles, C linkage, and SYSLOG_NAMES consumers
  sysmacros-header-source-form  verify x86 <sys/sysmacros.h> macro forms and frozen AArch64 arm
  fcntl-event-header-topology  verify x86 fcntl/event direct-header topology
  math-tgmath-source-form  verify x86 math/tgmath source forms and frozen AArch64 arm
  mman-mcl-onfault-header-source-form  verify x86 MCL_ONFAULT header form and frozen AArch64 arm
  sys-io-header-abi  verify x86 sys/io.h inline port-I/O C/C++ ABI and object code
  timeval-transitive-header-abi  verify selected timeval-dependent header layouts across C/C++ profiles
  sys-time-direct-header-abi  verify selected direct sys/time.h C/C++ ABI profiles and C linkage
  access-header-abi  verify selected direct unistd/fcntl access C/C++ ABI profiles and C linkage
  xattr-header-abi  verify selected direct sys/xattr.h C/C++ ABI profiles and C linkage
  header-abi-project  compile the staged crabc x86 fenv/float header slice
  math-complex-header-abi  verify x86 math/complex/tgmath C/C++ header semantics
  math-complex-complete-header-abi  verify complete x86 math.complex C++ ABI/linkage
  math-elementary-long-double-header-abi  verify complete x86 math.elementary-long-double C++ ABI/linkage
  math-special-header-abi  verify complete x86 math.special C++ ABI/linkage
  math-exp2-header-abi  verify x86 exp2/exp2f C++ ABI/linkage
  math-expm1-header-abi  verify x86 expm1/expm1f C++ ABI/linkage
  math-log10-header-abi  verify x86 log10/log10f C++ ABI/linkage
  sys-reg-header-abi  compile the staged crabc x86 ptrace-register header slice
  machine-context-header-abi  verify staged x86 machine/context C/C++ header ABI profiles
  types-header-abi  compile the staged crabc x86 C/C++ type-layout header slice
  stddef-header-abi  verify staged x86 stddef.h C/C++ request-boundary layouts
  stat-header-abi  compile the staged x86 C/C++ sys/stat header layouts
  utime-header-abi  compile the staged x86 C/C++ utime header ABI/linkage slice
  pthread-c11-header-abi  verify staged x86 pthread/C11-thread C/C++ header ABI profiles
  pthread-header-source-form  verify x86 <pthread.h> pinned-musl direct source forms
  atomic-addressable-abi  verify addressable C11 atomic flag/fence symbols
  pthread-cancellation-header-abi  verify staged x86 deferred pthread-cancellation C/C++ header ABI profiles
  pthread-spin-destroy-header-abi  verify x86 pthread_spin_destroy C/C++ declaration and linkage
  pthread-spin-operations-header-abi  verify x86 pthread spin-operation C/C++ declarations and linkage
  stdlib-header-abi  compare x86 <stdlib.h> strict/POSIX/XOPEN/GNU/BSD/LFS profiles with musl
  getloadavg-header-abi  verify x86 GNU/BSD <stdlib.h> getloadavg C/C++ declaration and linkage
  stdio-standard-header-abi  compare selected x86 <stdio.h> standard-stream C/C++ profiles with musl
  stdio-header-source-form  verify x86 <stdio.h>/<stdio_ext.h> pinned-musl declaration form
  fopen64-header-abi  verify x86 _LARGEFILE64_SOURCE fopen64 C/C++ macro-alias profiles
  stdio-permanent-line-io-header-abi  verify x86 <stdio.h> permanent line-I/O C/C++ declarations and linkage
  stdio-permanent-byte-io-header-abi  verify x86 <stdio.h> permanent byte-I/O C/C++ declarations and linkage
  stdio-permanent-status-header-abi  verify x86 <stdio.h> permanent stream-status C/C++ declarations and linkage
  stdio-permanent-freading-stdin-header-abi  verify x86 <stdio_ext.h> permanent stdin __freading C/C++ declaration and linkage
  stdio-permanent-fsetlocking-stdin-header-abi  verify x86 <stdio_ext.h> permanent stdin __fsetlocking C/C++ declaration and linkage
  stdio-permanent-fseterr-stdin-header-abi  verify x86 <stdio_ext.h> permanent stdin __fseterr C/C++ declaration and linkage
  stdio-permanent-freadable-stdin-header-abi  verify x86 <stdio_ext.h> permanent stdin __freadable C/C++ declaration and linkage
  stdio-permanent-fwritable-stderr-header-abi  verify x86 <stdio_ext.h> permanent stderr __fwritable C/C++ declaration and linkage
  stdio-permanent-fbufsize-stderr-header-abi  verify x86 <stdio_ext.h> permanent stderr __fbufsize C/C++ declaration and linkage
  stdio-permanent-flbf-stderr-header-abi  verify x86 <stdio_ext.h> permanent stderr __flbf C/C++ declaration and linkage
  stdio-permanent-fileno-header-abi  verify x86 <stdio.h> permanent fileno C/C++ declarations and linkage
  stdio-permanent-fileno-unlocked-header-abi  verify x86 GNU/BSD permanent fileno_unlocked C/C++ declarations and linkage
  stdio-permanent-feof-unlocked-header-abi  verify x86 GNU/BSD permanent feof_unlocked C/C++ declarations and linkage
  stdio-permanent-ferror-unlocked-header-abi  verify x86 GNU/BSD permanent ferror_unlocked C/C++ declarations and linkage
  ctype-header-abi  compile staged x86 C/C++ ctype declarations and feature-gated macros
  locale-profile-header-abi  verify x86 fixed setlocale/localeconv C/C++ declarations and linkage
  locale-multibyte-header-abi  verify x86 named-locale/multibyte C/C++ declarations and linkage
  iconv-header-abi  verify x86 selected UTF/ASCII iconv C/C++ declarations and linkage
  wide-character-header-abi  verify x86 selected wide-character C/C++ declarations and linkage
  wcswcs-header-abi  verify x86 wchar.h wcswcs C/C++ declaration and linkage
  locale-object-wide-header-abi  verify x86 built-in locale-object/localized-wide C/C++ ABI
  locale-narrow-header-abi  verify x86 fixed-locale narrow text C/C++ ABI
  integer-arithmetic-header-abi  compile the staged x86 C/C++ stdlib integer-arithmetic declarations
  integer-parse-header-abi  compile the staged x86 C/C++ integer-parsing declarations
  float-parse-header-abi  verify complete x86 numeric.parse-float-locale declarations and linkage
  crypt-header-abi  verify x86 crypt.h C/C++ declaration, layout, and linkage
  getsubopt-header-abi  verify x86 getsubopt C/C++ feature visibility and linkage
  l64a-header-abi  verify x86 X/Open/GNU/BSD a64l/l64a C/C++ feature visibility and linkage
  intmax-arithmetic-header-abi  compile the staged x86 C/C++ inttypes intmax-arithmetic declarations
  credential-observation-header-abi  compile the staged x86 C/C++ unistd credential-observation declarations
  login-name-header-abi  compile the staged x86 C/C++ unistd login-name declarations
  child-reaping-header-abi  compile the staged x86 C/C++ sys/wait child-reaping declarations
  wait-extensions-header-abi  verify x86 GNU/BSD wait3/wait4 header feature profiles
  immediate-termination-header-abi  compile the staged x86 C/C++ stdlib immediate-termination declaration
  posix-exit-header-abi  compile the staged x86 C/C++ unistd POSIX _exit declaration
  sched-cpucount-header-abi  verify selected x86 GNU sched CPU-count C/C++ ABI profiles
  sched-cpu-macros-header-abi  verify x86 GNU sched CPU-set construction C/C++ header macros
  sched-cpu-set-source-form  verify x86 sched cpu_set_t pinned-musl source form and C/C++ profiles
  sched-getcpu-header-abi  verify selected x86 GNU sched_getcpu C/C++ ABI profiles
  sched-priority-bounds-header-abi  verify selected x86 sched priority-bounds C/C++ ABI profiles
  sched-yield-header-abi  verify selected x86 sched_yield C/C++ ABI profiles
  sched-get-priority-max-header-abi  verify selected x86 sched_get_priority_max C/C++ ABI profiles
  sched-get-priority-min-header-abi  verify selected x86 sched_get_priority_min C/C++ ABI profiles
  bsearch-header-abi  verify staged x86 C/C++ stdlib bsearch declaration and linkage
  linear-search-header-abi  verify staged x86 C/C++ search.h lfind/lsearch declarations and linkage
  intrusive-queue-header-abi  verify staged x86 C/C++ search.h insque/remque declarations and linkage
  qsort-header-abi  verify staged x86 C/C++ stdlib qsort declaration and linkage
  callback-algorithms-header-abi  compile the staged x86 C/C++ stdlib callback-algorithm declarations
  ffs-header-abi  compile the staged x86 C/C++ strings.h find-first-set declarations
  memory-special-header-abi  compile x86 explicit_bzero/swab C/C++ declarations
  memccpy-header-abi  compile the staged x86 C/C++ string.h memccpy declarations
  aio-error-header-abi  verify x86 <aio.h> aio_error C/C++ declaration and layout
  byte-strings-header-abi  compile the staged x86 C/C++ string.h byte-string declarations
  memory-search-header-abi  compile the staged x86 C/C++ memory-search declarations
  memccpy-header-abi  compile the staged x86 C/C++ string.h memccpy declaration
  mempcpy-header-abi  compile the staged x86 C/C++ string.h mempcpy declaration
  strsep-header-abi  compile the staged x86 C/C++ string.h strsep declaration
  strtok-header-abi  verify staged x86 C/C++ string.h strtok declaration and linkage
  stateful-byte-strings-header-abi  verify x86 C/C++ dirname/strcasestr/strtok_r declarations
  string-copy-header-abi  compile the staged x86 C/C++ C-string-copy declarations
  string-duplication-header-abi  compile the staged x86 C/C++ C-string-duplication declarations
  error-strings-header-abi  compile the staged x86 C/C++ error-string declarations
  strsignal-header-abi  compile the staged x86 C/C++ strsignal declarations
  gettext-catalog-header-abi  verify staged x86 libintl/nl_types C/C++ declarations and linkage
  random-entropy-header-abi  compile the staged x86 C/C++ random-source declarations
  time-header-abi  compile the staged x86 C/C++ time header layouts
  clock-adjtime-header-abi  verify x86 sys/timex.h clock_adjtime C/C++ ABI profiles
  clock-settime-header-abi  verify x86 POSIX clock_settime C/C++ ABI profiles
  timer-getoverrun-header-abi  verify x86 POSIX timer_getoverrun C/C++ ABI profiles
  timer-delete-header-abi  verify x86 POSIX timer_delete C/C++ ABI profiles
  timer-gettime-header-abi  verify x86 POSIX timer_gettime C/C++ ABI profiles
  timer-settime-header-abi  verify x86 POSIX timer_settime C/C++ ABI profiles
  sleep-header-abi  compile the staged x86 C/C++ POSIX sleep declaration
  timerfd-header-abi  verify the selected x86 sys/timerfd.h C/C++ ABI profiles
  signalfd-header-abi  verify the selected x86 sys/signalfd.h C/C++ ABI profiles
  poll-header-abi  compile the staged x86 C/C++ poll header layouts
  select-header-abi  compile the staged x86 C/C++ sys/select header layouts
  fcntl-header-abi compile the staged x86 C/C++ fcntl header layouts
  file-handles-header-abi verify x86 GNU <fcntl.h> file-handle C/C++ ABI
  posix-spawn-file-actions-header-abi verify x86 C/C++ POSIX spawn file-actions ABI
  process-exec-header-abi verify x86 C/C++ process-exec declarations and linkage
  descriptor-advice-header-abi verify x86 C/C++ descriptor-advice header profiles
  filesystem-capacity-header-abi verify x86 C/C++ filesystem-capacity header profiles
  vector-io-header-abi verify x86 C/C++ vector-I/O header profiles
  libc-uio-cxx-linkage  link a freestanding C++ sys/uio consumer to static x86 crabc-libc
  flock-header-abi compile the staged x86 C/C++ sys/file.h header layouts
  sendfile-header-abi compile the staged x86 C/C++ sys/sendfile.h header layouts
  tee-header-abi      compile the staged x86 C/C++ GNU fcntl.h tee declaration
  splice-header-abi   compile the staged x86 C/C++ GNU fcntl.h splice declaration
  sync-file-range-header-abi compile the staged x86 C/C++ GNU fcntl.h sync_file_range declaration
  copy-file-range-header-abi compile the staged x86 C/C++ GNU unistd.h copy_file_range declaration
  unistd-header-abi  compile the staged x86 C/C++ unistd header declarations
  getpagesize-header-abi  compile the staged x86 C/C++ GNU/BSD getpagesize declaration
  system-header-abi  compile the staged x86 C/C++ system header layouts
  syscall-header-abi  compare the staged x86 syscall macro surface with musl
  signal-header-abi  compile the staged x86 GNU/POSIX signal-header layouts
  psignal-header-abi  verify x86 POSIX-or-later psignal/psiginfo C/C++ declarations
  signal-legacy-aliases-header-abi  verify GNU bsd_signal C/C++ declaration/linkage
  signal-sysv-helpers-header-abi  verify historical SysV signal helper C/C++ declaration/linkage
  sched-getscheduler-header-abi  compile x86 sched_getscheduler C/C++ declarations
  sched-rr-interval-header-abi  compile x86 sched_rr_get_interval C/C++ declarations
  termios-header-abi  compile the staged x86 C/C++ GNU termios-header layouts
  terminal-streams-header-topology  verify x86 terminal and STREAMS direct-header topology
  ctermid-header-abi  compile the staged x86 C/C++ POSIX/XSI ctermid declaration
  grantpt-header-abi  compile the staged x86 C/C++ XSI grantpt declaration
  unlockpt-header-abi  compile the staged x86 C/C++ XSI unlockpt declaration
  gethostid-header-abi  compile the staged x86 C/C++ X/Open gethostid declaration
  issetugid-header-abi  compile the staged x86 C/C++ GNU/BSD issetugid declaration
  legacy-misc-header-abi  verify the frozen x86 legacy.misc C/C++ declaration matrix
  endhostent-header-abi  compile the staged x86 C/C++ stateless legacy netdb declarations
  gettid-header-abi  compile the staged x86 C/C++ GNU gettid declaration
  posix-close-header-abi  compile the staged x86 C/C++ POSIX posix_close declaration
  isatty-header-abi  compile the staged x86 C/C++ isatty declaration
  ttyname-r-header-abi  compile the staged x86 C/C++ ttyname_r declaration
  tcgetpgrp-header-abi  compile the staged x86 C/C++ tcgetpgrp declaration
  tcsetpgrp-header-abi  compile the staged x86 C/C++ tcsetpgrp declaration
  getpass-header-abi  compile the staged x86 C/C++ getpass declaration
  mkfifo-header-abi  verify selected x86 mkfifo C/C++ declarations
  mkdirat-header-abi  verify selected x86 mkdirat C/C++ declarations
  mkfifoat-header-abi  verify selected x86 mkfifoat C/C++ declarations
  readlinkat-header-abi  verify selected x86 POSIX readlinkat C/C++ declarations
  linkat-header-abi  verify selected x86 POSIX linkat C/C++ declarations
  renameat2-header-abi  verify selected x86 GNU renameat2 C/C++ declarations
  lchown-header-abi  verify selected x86 POSIX lchown C/C++ declarations
  hasmntopt-header-abi  verify selected x86 mntent hasmntopt C/C++ declarations
  mktemp-header-abi  compile the staged x86 C/C++ mktemp declaration
  temporary-names-header-abi  verify x86 C/C++ tmpnam/tempnam declarations
  mman-header-abi  compile the staged x86 C/C++ mapping-header declarations
  memory-sync-header-abi  verify selected x86 msync C/C++ declarations
  memory-locking-header-abi  verify selected x86 per-range mlock C/C++ declarations
  memfd-create-header-abi  verify selected x86 GNU memfd_create C/C++ declarations
  resource-header-abi  compile the staged x86 C/C++ resource-header layouts
  socket-header-abi  verify staged x86 base socket C/C++ declarations/layouts plus IPv4/IPv6 and source-filter macros
  tcp-header-abi  verify staged x86 netinet/tcp.h C/C++ feature-profile layouts
  nameser-header-abi  verify staged x86 resolv.h C/C++ dn_skipname/dn_expand/_ns_flagdata/ns_get16/ns_get32/ns_put16 declarations
  quota-header-abi  verify the complete x86 sys/quota.h through C/C++ profiles
  endservent-header-abi  verify staged x86 legacy service-terminator C/C++ declaration
  service-lifecycle-header-abi  verify staged x86 no-op/null service lifecycle C/C++ declarations
  inet-address-header-abi  verify selected x86 arpa/inet C/C++ numeric-address declarations
  socket-messages-header-abi  verify staged x86 socket-message/options C/C++ declarations/layouts
  sysv-semaphore-header-abi  verify staged x86 SysV semaphore C/C++ declarations/layouts
  posix-semaphore-header-abi  verify staged x86 POSIX semaphore C/C++ declarations/layouts
  sysv-message-shared-memory-header-abi  verify staged x86 SysV message/shared-memory C/C++ declarations/layouts
  mq-setattr-header-abi  compile the staged x86 C/C++ mqueue.h mq_setattr declaration
  libc-event-descriptors  run the static x86 crabc-libc epoll/eventfd/inotify slice
  libc-mq-setattr  run the static x86 crabc-libc mq_setattr slice
  libc-timerfd  run the static x86 crabc-libc timer-descriptor slice
  libc-signalfd  run the static x86 crabc-libc signal-descriptor slice
  libc-sigpause  run the static x86 crabc-libc one-signal pause slice
  libc-sigisemptyset  run the static x86 crabc-libc GNU signal-set predicate slice
  libc-sigandset-sigorset  run the static x86 crabc-libc GNU signal-set binary slice
  libc-sigpending  run the static x86 crabc-libc POSIX pending-signal slice
  libc-sigrtmax  run the static x86 crabc-libc realtime-maximum ABI bridge slice
  libc-sigrtmin  run the static x86 crabc-libc realtime-minimum ABI bridge slice
  libc-sched-getscheduler  run the static x86 musl-ENOSYS scheduler observation slice
  libc-sched-rr-interval  run the opt-in static x86 scheduler-interval observation slice
  libc-alarm  run the static x86 crabc-libc historical SIGALRM timer slice
  ualarm-header-abi  run the x86 musl/project ualarm C/C++ declaration matrix
  libc-ualarm  run the opt-in static x86 crabc-libc ualarm timer slice
  libc-interval-timers  run the opt-in static x86 crabc-libc getitimer/setitimer slice
  usleep-header-abi  run the x86 musl/project usleep C/C++ declaration matrix
  libc-usleep  run the static x86 crabc-libc usleep nanosleep-adapter slice
  basename-header-abi  run the x86 musl/project basename C/C++ declaration matrix
  siginterrupt-header-abi  run the x86 musl/project siginterrupt C/C++ declaration matrix
  mlockall-header-abi  run the x86 musl/project mlockall C/C++ declaration matrix
  munlockall-header-abi  run the x86 musl/project munlockall C/C++ declaration matrix
  ftime-header-abi  run the x86 musl/project ftime C/C++ declaration matrix
  clock-getcpuclockid-header-abi  run the x86 musl/project clock_getcpuclockid C/C++ declaration matrix
  libc-basename  run the static x86 crabc-libc basename slice
  libc-siginterrupt  run the static x86 crabc-libc siginterrupt slice
  libc-mlockall  run the static x86 crabc-libc mlockall slice
  libc-munlockall  run the static x86 crabc-libc munlockall slice
  libc-ftime  run the static x86 crabc-libc ftime slice
  libc-clock-getcpuclockid  run the static x86 crabc-libc clock_getcpuclockid slice
  libc-sigaddset-sigdelset-sigfillset  run the static x86 crabc-libc POSIX signal-set mutation slice
  libc-extended-attributes  run the static x86 crabc-libc extended-attribute slice
  libc-pathname-lifecycle  run the static x86 crabc-libc pathname-lifecycle slice
  libc-directory-streams  run the static x86 crabc-libc directory-stream slice
  libc-filesystem-traversal  run the opt-in static x86 crabc-libc ftw/nftw slice
  libc-filesystem-directory  run the selected-private x86 directory capability aggregate
  libc-filesystem-extensions  run the selected-private x86 filesystem-extensions capability aggregate
  libc-lchmod-unsupported  run the static x86 crabc-libc lchmod unsupported slice
  libc-fchdir  run the static x86 crabc-libc fchdir O_PATH fallback slice
  libc-ulimit  run the static x86 crabc-libc historical RLIMIT_FSIZE slice
  mm-abi-reference  verify pinned-musl x86 mapping syscall and flag constants
  mapping-reference  verify pinned-musl/raw x86 anonymous mapping lifecycle
  memory-vm-reference  verify pinned-musl/raw x86 raw-break and VM-policy seam
  pty-basic-reference  verify pinned-musl/raw x86 safe pseudoterminal pair/name seam
  terminal-reference  verify pinned-musl/raw x86 PTY session and terminal-control seam
  mlock-reference  verify pinned-musl x86 memory-locking ABI and behavior
  msync-reference  verify pinned-musl x86 mapping-synchronization ABI and behavior
  madvise-reference  verify pinned-musl x86 mapping-advice ABI and behavior
  mincore-reference  verify pinned-musl x86 mapping-residency ABI and behavior
  fs-advice-reference  verify pinned-musl x86 fadvise64/readahead ABI and behavior
  memfd-reference  verify direct typed x86 memfd/sealing ABI and lifecycle
  ftruncate-reference  verify pinned-musl x86 descriptor-length ABI and lifecycle
  statfs-reference  verify pinned-musl/raw x86 filesystem-capacity metadata ABI and behavior
  timestamp-reference  verify pinned-musl/raw x86 timestamp-mutation ABI and behavior
  path-lifecycle-reference  verify pinned-musl/raw x86 pathname metadata and lifecycle ABI and behavior
  namespace-reference  verify pinned-musl/raw x86 links, symbolic links, and rename ABI and behavior
  path-core-reference  verify the complete native x86 filesystem.path-core capability
  xattr-reference  verify pinned-musl/raw x86 extended-attribute ABI and behavior
  directory-reference  verify pinned-musl/raw x86 directory-record ABI and behavior
  temporary-object-reference  verify pinned-musl/raw x86 temporary-object ABI and ownership behavior
  statx-reference  verify pinned-musl/raw x86 extended-metadata ABI and behavior
  cwd-canonicalize-reference  verify pinned-musl/raw x86 CWD mutation and physical canonicalization
  root-change-reference  verify child-contained pinned-musl/raw x86 process-root change
  mount-reference  verify unprivileged pinned-musl/raw x86 direct mount/unmount failure behavior
  thread-kill-reference  verify pinned-musl/raw x86 same-process thread-directed signal delivery
  ipc-reference  verify pinned-musl/raw x86 POSIX named-message-queue ABI and behavior
  shm-reference  verify pinned-musl/raw x86 POSIX shared-memory name and descriptor behavior
  inotify-reference  verify pinned-musl/raw x86 owned inotify descriptor and event behavior
  socket-transport-reference  verify pinned-musl/raw x86 socket/address transport ABI and behavior
  interface-device-reference  verify pinned-musl/raw x86 interface ioctl/rtnetlink ABI and behavior
  resolver-transport-reference  verify bounded x86 core DNS UDP/TCP exchange behavior
  resolver-facade-reference  verify x86 alloc resolver and hosts-snapshot behavior
  netdb-reference  verify x86 owned conventional netdb snapshot behavior
  users-databases-reference  verify x86 owned conventional passwd/group snapshot behavior
  posix-fallocate-reference  verify pinned-musl x86 POSIX range-allocation ABI and behavior
  fallocate-reference  verify pinned-musl/raw x86 general range-allocation ABI and behavior
  file-position-reference  verify pinned-musl x86 lseek/fsync/fdatasync ABI and behavior
  sync-reference  verify pinned-musl/raw x86 global sync ABI and request contract
  syncfs-reference  verify pinned-musl/raw x86 syncfs ABI and filesystem requests
  sync-file-range-reference  verify pinned-musl/raw x86 sync_file_range ABI and writeback requests
  rand-reference  verify pinned-musl x86 getrandom ABI and behavior reference
  time-abi-reference  verify pinned-musl x86 timespec and clock ABI constants
  time-observation-reference  verify pinned-musl x86 realtime observation behavior
  calendar-time-reference  verify pinned-musl/raw x86 wall-clock, UTC-calendar, and explicit timezone-rule behavior
  advanced-time-reference  verify pinned-musl/raw x86 advanced-clock and owned POSIX-timer ABI/lifecycle
  relative-sleep-reference  verify pinned-musl x86 nanosleep behavior
  clock-nanosleep-reference  verify pinned-musl x86 clock_nanosleep behavior
  getitimer-reference  verify pinned-musl x86 read-only interval-timer ABI and behavior
  setitimer-reference  verify pinned-musl x86 interval-timer control and Rust aliases
  timerfd-reference  verify pinned-musl x86 timerfd ABI and lifecycle
  pselect-reference  verify pinned-musl/raw x86 direct select/pselect ABI and behavior
  poll-reference  verify pinned-musl x86 poll ABI and behavior reference
  ppoll-reference  verify pinned-musl x86 ppoll/pause signal-mask behavior
  epoll-reference  verify pinned-musl/raw x86 direct typed epoll ABI and behavior
  process-identity-reference  verify pinned-musl x86 process-identity behavior
  child-ownership-reference  verify pinned-musl/raw x86 child lifecycle ownership behavior
  getgroups-reference  verify pinned-musl x86 supplementary-group ABI and behavior
  process-session-reference  verify pinned-musl x86 process group/session behavior
  pidfd-open-reference  verify pinned-musl x86 pidfd_open behavior
  fcntl-getlk-reference  verify pinned-musl x86 fcntl lock-query behavior
  fcntl-status-reference  verify pinned-musl/raw x86 fcntl status-flag behavior
  flock-reference  verify pinned-musl/raw x86 advisory whole-file flock behavior
  sendfile-reference  verify pinned-musl/raw x86 descriptor-to-descriptor sendfile behavior
  copy-file-range-reference  verify pinned-musl/raw x86 descriptor-range copy behavior
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
  getcwd-reference  verify pinned-musl/raw x86 physical and logical current-directory behavior
  readlinkat-reference  verify pinned-musl x86 private caller-buffer readlinkat behavior reference
  access-reference  verify pinned-musl/raw x86 access and accessat behavior reference
  system-reference  verify pinned-musl x86 uname/sysinfo ABI and behavior reference
  thread-reference  verify pinned-musl x86 thread observation/yield behavior
  thread-credentials-reference  verify pinned-musl x86 calling-thread credential ABI and behavior
  fs-credentials-reference  verify pinned-musl x86 filesystem-credential ABI and behavior
  core [--cached]  run native crabc-core tests (cold qualification by default)
  facade run the bounded native x86_64 crabc-rs direct-facade tests
  facade-record-owning  run the closed native x86_64 record-owning facade aggregate
  libc-syscall  run the isolated x86 C-ABI syscall register probe
  libc-errno-tls  run the source-only x86 C errno/initial-TLS probe
  libc-stat-compat  run the static x86 crabc-libc stat/errno compatibility slice
  libc-credentials  run the static x86 crabc-libc credential/errno compatibility slice
  libc-bootstrap-primitives  run the static x86 crabc-libc memory/fenv/setjmp slice
  libc-signal-control  run the static x86 crabc-libc simple signal action/mask slice
  libc-signal-legacy-aliases  run the opt-in static x86 musl signal.c alias slice
  libc-signal-sysv-helpers  run the opt-in static x86 SysV signal-helper slice
  libc-signal-execution  run the static x86 crabc-libc process-signal execution slice
  libc-signal-altstack  run the static x86 crabc-libc alternate signal-stack slice
  libc-psignal  run the opt-in static x86 psignal/psiginfo reporting slice
  libc-process-signal  run the frozen x86 process.signal aggregate
  libc-static-tls-v1  run the static x86 crabc-libc initial TLS template slice
  libc-crt-static-tls  run the real x86 rcrt1-to-libc static TLS composition slice
  libc-crt1-static-tls  run the real x86 crt1.o ET_EXEC-to-libc static TLS composition slice
  owned-resolver-network  compare owned products with musl in isolated loopback DNS fixtures
  owned-dynamic-io-cancellation  qualify shared-runtime cancellation through kernel and direct entry

  owned-system-cancellation  qualify isolated system/pclose cancellation and child wait ownership
  owned-dynamic-spawn  qualify installed dynamic spawn semantics against musl
  owned-assert  test installed C assertion diagnostics and termination
  owned-linux-control  test owned Linux C mechanisms and kernel error translation
  owned-io-cancellation  qualify installed syscall cancellation and FILE cleanup
  owned-pthread-getattr  test installed live pthread stack and guard metadata
  owned-pthread-join-cancel  test installed join cancellation and target reclamation
  owned-pthread-cond-cancel  test condition cancellation and mutex reacquisition
  owned-pthread-cond-timed  test timed/shared condition transactions and mutex handoffs
  owned-pthread-lifecycle  run pinned-musl and installed pthread lifetime consumers
  owned-static-sysroot  build twice and run the private installed x86 static pthread/TLS consumer
  lua-static-source-build  build installed x86 static Lua source/bytecode ET_EXEC/static-PIE qualification
  lua-dynamic-source-build  qualify pinned Lua through installed/extracted x86 dynamic sysroots
  libc-owned-wordexp  run the installed x86 wordexp/wordfree ET_EXEC/static-PIE gate
  owned-dynamic-sysroot  qualify both clean dynamic builds and extracted runtime
  owned-dynamic-pthread-exit  test installed dynamic main and last pthread exit
  owned-dynamic-fork  test installed loader, TLS and pthread fork transactions
  materialized-dynamic-sysroot  build and test the installed initial-graph shared runtime
  crt-object-bundle  stage and audit the private five-object x86 Rust CRT bundle
  crt-dynamic-startup  run the private x86 Scrt1.o dynamic-PIE startup artifact
  crt-dynamic-link-contract  audit the closed x86 Rust CRT dynamic-PIE link boundary
  consumer-static-pie-lto  run the private no-std crabc-rs O3/full-LTO owned-runtime consumer
  consumer-native-facade-lto  run the private filesystem/pipe/eventfd crabc-rs full-LTO consumer
  libc-pthread-create-join-tls  run the static x86 crabc-libc private create/exit/join TLS slice
  libc-pthread-identity  run the static x86 crabc-libc pthread/C11 identity alias slice
  libc-c11-lifecycle  run the static x86 crabc-libc bounded C11 lifecycle slice
  libc-c11-plain-sync  run the static x86 crabc-libc C11 plain synchronization slice
  libc-pthread-c11-once  run the static x86 crabc-libc pthread/C11 once slice
  libc-pthread-c11-tsd  run the static x86 crabc-libc pthread-key/C11 TSS lifecycle slice
  libc-pthread-cancel-deferred  run the static x86 crabc-libc deferred pthread-cancellation slice
  libc-pthread-atfork  run the static x86 crabc-libc bounded pthread_atfork/fork/exit-hook slice
  libc-stack-chk-fail  run the private static x86 stack-check failure archive seam
  libc-pthread-affinity  run the static x86 crabc-libc bounded pthread-affinity slice
  libc-pthread-detach  run the static x86 crabc-libc bounded pthread/C11 detach slice
  libc-thrd-sleep  run the static x86 crabc-libc bounded C11 thrd_sleep slice
  libc-thrd-yield  run the static x86 crabc-libc bounded C11 thrd_yield slice
  libc-pthread-cpuclock  run the static x86 crabc-libc bounded pthread CPU-clock slice
  libc-pthread-name  run the static x86 crabc-libc bounded pthread task-name slice
  libc-pthread-attributes  run the static x86 crabc-libc pthread-attribute metadata slice
  libc-pthread-attr-lifecycle  run the static x86 crabc-libc mutex/condition attribute lifecycle slice
  libc-pthread-barrierattr-pshared  run the static x86 crabc-libc barrier-attribute pshared record slice
  libc-pthread-barrier  run the static x86 crabc-libc private/shared pthread-barrier slice
  libc-pthread-spin-destroy  run the static x86 crabc-libc private pthread spin-destruction leaf
  libc-pthread-spin-operations  run the opt-in static x86 crabc-libc pthread spin-operation slice
  libc-pthread-mutex-normal  run the static x86 crabc-libc normal pthread-mutex slice
  libc-pthread-rwlock  run the static x86 crabc-libc pthread read/write-lock slice
  libc-pthread-cond-private  run the static x86 crabc-libc private pthread-condition slice
  libc-pthread-tls-aggregate  run the static x86 crabc-libc pthread/TLS composition slice
  libc-termios-control  run the static x86 crabc-libc termios-control slice
  libc-ctermid  run the static x86 crabc-libc ctermid spelling slice
  libc-grantpt  run the static x86 crabc-libc grantpt compatibility slice
  libc-unlockpt  run the static x86 crabc-libc PTY lock-release slice
  libc-gethostid  run the static x86 crabc-libc gethostid compatibility slice
  libc-issetugid  run the static x86 crabc-libc issetugid compatibility slice
  libc-legacy-misc  run the static x86 crabc-libc frozen legacy.misc aggregate
  libc-endhostent  run the static x86 crabc-libc legacy netdb terminator slice
  libc-sethostent  run the opt-in static x86 crabc-libc legacy netdb setter slice
  libc-gettid  run the static x86 crabc-libc gettid compatibility slice
  libc-posix-close  run the static x86 crabc-libc posix_close compatibility slice
  libc-isatty  run the static x86 crabc-libc descriptor-observation slice
  libc-ttyname-r  run the static x86 crabc-libc terminal-name slice
  libc-tcgetpgrp  run the static x86 crabc-libc foreground-group observation slice
  libc-tcsetpgrp  run the static x86 crabc-libc foreground-group assignment slice
  libc-getpass  run the static x86 crabc-libc getpass terminal slice
  libc-mkfifo  run the static x86 crabc-libc mkfifo leaf
  libc-mkdirat  run the static x86 crabc-libc mkdirat leaf
  libc-mkfifoat  run the static x86 crabc-libc mkfifoat leaf
  libc-readlinkat  run the static x86 crabc-libc readlinkat leaf
  libc-linkat  run the static x86 crabc-libc linkat leaf
  libc-renameat2  run the static x86 crabc-libc GNU renameat2 leaf
  libc-lchown  run the static x86 crabc-libc lchown leaf
  libc-hasmntopt  run the static x86 crabc-libc hasmntopt leaf
  libc-mktemp  run the static x86 crabc-libc historical mktemp slice
  libc-temporary-names  run the opt-in static x86 tmpnam/tempnam slice
  libc-file-handles  run the opt-in static x86 file-handle syscall slice
  libc-posix-spawn-file-actions  run the opt-in mixed-runtime x86 spawn file-actions lifecycle
  libc-process-exec  run the opt-in x86 process-image replacement slice
  libc-process-context  run the static x86 crabc-libc selected process-context slice
  libc-environment  run the static x86 crabc-libc environment-mutation slice
  libc-secure-environment  run the static x86 crabc-libc GNU secure-environment slice
  libc-login-name  run the static x86 crabc-libc environment-backed login-name slice
  libc-child-reaping  run the static x86 crabc-libc child-reaping slice
  libc-wait-extensions  run the static x86 crabc-libc GNU/BSD wait3/wait4 slice
  libc-immediate-termination  run the static x86 crabc-libc C11 immediate-termination slice
  libc-posix-exit  run the static x86 crabc-libc POSIX _exit forwarding slice
  libc-posix-spawnattr-init  run the static x86 crabc-libc spawn-attribute initialization slice
  libc-posix-spawnattr-getpgroup  run the static x86 crabc-libc spawn-attribute process-group readback slice
  libc-posix-spawnattr-signal-fields  run the static x86 crabc-libc spawn-attribute signal-field slice
  libc-posix-spawnattr-getschedparam  run the static x86 crabc-libc spawn-attribute scheduler-parameter compatibility slice
  libc-posix-spawnattr-getschedpolicy  run the static x86 crabc-libc spawn-attribute scheduler-policy compatibility slice
  libc-bsearch  run the static x86 crabc-libc standalone bsearch slice
  libc-linear-search  run the static x86 crabc-libc standalone lfind/lsearch slice
  libc-intrusive-queue  run the static x86 crabc-libc standalone insque/remque slice
  libc-wcswcs  run the static x86 crabc-libc standalone wcswcs slice
  libc-qsort  run the static x86 crabc-libc standalone qsort slice
  libc-callback-algorithms  run the static x86 crabc-libc callback-algorithms slice
  libc-search-tree-intrusive  run the static x86 crabc-libc search.h callback-tree slice
  libc-search-hash-table  run the static x86 crabc-libc search.h hash-table slice
  libc-gettext-catalog  run the static x86 crabc-libc no-catalog gettext/catalog slice
  libc-access  run the static x86 crabc-libc access/faccessat slice
  libc-clock-gettime  run the static x86 crabc-libc clock_gettime slice
  libc-clock-adjtime  run the static x86 crabc-libc clock_adjtime error-ABI slice
  libc-clock-settime  run the static x86 crabc-libc clock_settime error-ABI slice
  libc-timer-getoverrun  run the static x86 crabc-libc timer_getoverrun error-ABI slice
  libc-timer-delete  run the static x86 crabc-libc timer_delete raw-error ABI slice
  libc-timer-gettime  run the static x86 crabc-libc timer_gettime error-ABI slice
  libc-timer-settime  run the static x86 crabc-libc timer_settime error-ABI slice
  libc-time-observation  run the static x86 crabc-libc clock-observation slice
  libc-difftime  run the static x86 crabc-libc binary64 difftime slice
  libc-timegm  run the static x86 crabc-libc fixed-UTC timegm slice
  libc-gmtime-r  run the static x86 crabc-libc caller-buffered UTC gmtime_r slice
  libc-system-configuration  run the static x86 crabc-libc system-configuration slice
  libc-getpagesize  run the static x86 crabc-libc getpagesize slice
  libc-mapping-core  run the static x86 crabc-libc caller-owned mapping-core slice
  libc-memory-sync  run the static x86 crabc-libc no-cancellation msync slice
  libc-memory-locking  run the static x86 crabc-libc per-range memory-locking slice
  libc-memfd-create  run the static x86 crabc-libc memfd_create slice
  libc-allocator-runtime  run the opt-in mixed-runtime crabc-libc allocator wrapper slice
  libc-allocator-basic-runtime-v1  run the private real-runtime x86 allocator-basic composition
  libc-allocator-string-duplication  run the opt-in mixed-runtime crabc-libc strdup/strndup slice
  libc-scandir  run the opt-in mixed-runtime crabc-libc scandir slice
  libc-allocator-observability  run the complete x86 malloc_usable_size capability slice
  libc-alloca  verify the static x86 musl-compatible alloca builtin boundary
  libc-static-c-abi-differential  run the private static-C ABI musl differential bootstrap
  libc-static-c-abi-same-object-differential  run the private same-object static-C ABI differential
  qualification-posix-abi-admission  run the closed non-promoting POSIX/ABI artifact admission inventory
  libc-header-layouts-baseline  run the static x86 crabc-libc C/C++ header/layout baseline
  libc-nanosleep  run the static x86 crabc-libc nanosleep slice
  libc-sleep  run the static x86 crabc-libc sleep wrapper slice
  libc-clock-nanosleep  run the static x86 crabc-libc clock_nanosleep slice
  libc-descriptor-entry  run the static x86 crabc-libc descriptor-entry slice
  libc-descriptor-lifecycle  run the static x86 crabc-libc descriptor lifecycle composition
  libc-descriptor-pipeline  run the static x86 crabc-libc pipe/readiness/vector composition
  libc-timestamp-updates  run the static x86 rcrt1/libc timestamp-update block
  libc-fcntl-status-control  run the static x86 crabc-libc fcntl status-control slice
  libc-fcntl-record-locks  run the static x86 crabc-libc fcntl record-lock slice
  libc-flock  run the static x86 crabc-libc advisory flock slice
  libc-sendfile  run the static x86 crabc-libc regular-file sendfile slice
  libc-tee       run the static x86 crabc-libc GNU pipe-buffer tee slice
  libc-splice    run the static x86 crabc-libc GNU file-to-pipe splice slice
  libc-sync-file-range  run the static x86 crabc-libc GNU descriptor-range writeback slice
  libc-copy-file-range  run the static x86 crabc-libc GNU descriptor-range copy slice
  libc-posix-fallocate  run the static x86 crabc-libc mode-zero POSIX range-allocation slice
  libc-descriptor-advice  run the static x86 crabc-libc descriptor-advice slice
  libc-filesystem-capacity  run the static x86 crabc-libc filesystem-capacity slice
  libc-vector-io  run the static x86 crabc-libc vector-I/O slice
  libc-ioctl  run the static x86 crabc-libc generic ioctl slice
  libc-sysv-semaphore  run the static x86 crabc-libc SysV semaphore slice
  libc-posix-semaphore  run the static x86 crabc-libc unnamed POSIX semaphore slice
  libc-sysv-message-shared-memory  run the static x86 crabc-libc SysV message/shared-memory slice
  libc-descriptor-io  run the static x86 crabc-libc selected descriptor-I/O slice
  libc-process-resources  run the static x86 crabc-libc selected resource slice
  libc-sched-cpucount  run the static x86 crabc-libc GNU CPU-count helper slice
  libc-sched-getcpu  run the static x86 crabc-libc GNU current-CPU observation slice
  libc-sched-priority-bounds  run the static x86 crabc-libc scheduler priority-bounds slice
  libc-sched-yield  run the static x86 crabc-libc POSIX scheduler-yield slice
  libc-sched-get-priority-max  run the static x86 crabc-libc scheduler priority-maximum slice
  libc-sched-get-priority-min  run the static x86 crabc-libc scheduler priority-minimum slice
  libc-readiness-waits  run the static x86 crabc-libc readiness/signal-waits slice
  libc-system-observation  run the static x86 crabc-libc uname/sysinfo slice
  libc-system-information  run the static x86 crabc-libc processor/page slice
  libc-getloadavg  run the static x86 crabc-libc historical load-average slice
  libc-uts-identity  run the static x86 crabc-libc hostname/domain identity slice
  libc-ctype  run the static x86 crabc-libc C-locale ctype slice
  libc-locale-profile  run the static x86 fixed setlocale/localeconv profile slice
  libc-locale-multibyte  run the static x86 crabc-libc named locale/multibyte slice
  libc-regex  run the bounded static x86 crabc-libc POSIX regex slice
  libc-locale-wide-iconv  run the static x86 crabc-libc locale/wide/iconv composition slice
  libc-wide-character  run the static x86 crabc-libc allocation-free wide-character core
  libc-locale-object-wide  run the static x86 built-in locale-object/localized-wide slice
  libc-locale-narrow  run the static x86 fixed-locale narrow ctype/case/collation slice
  libc-locale-ctype-locators  run the static x86 musl-compatible ctype table locators
  libc-locale-error-strings  run the static x86 fixed-profile locale error-string slice
  libc-integer-arithmetic  run the static x86 crabc-libc integer-arithmetic slice
  libc-integer-parse  run the static x86 crabc-libc integer-parsing slice
  libc-float-parse  run the complete static x86 numeric.parse-float-locale slice
  libc-getsubopt  run the static x86 crabc-libc state-free getsubopt slice
  libc-crypt  run the private static x86 bounded SHA-crypt compatibility slice
  libc-crypt-allocator-composition  run the private x86 crypt/allocator provider composition
  libc-l64a  run the static x86 crabc-libc shared radix-64 result-buffer slice
  libc-a64l  run the opt-in static x86 crabc-libc radix-64 decoder slice
  libc-stdio-standard  run the static x86 crabc-libc permanent standard-stream slice
  libc-stdio-format-scan  run the static x86 crabc-libc byte-string format/scan slice
  libc-stdio-permanent-format-scan  run the opt-in permanent-stream formatted-I/O slice
  libc-stdio-integer-scan  run the static x86 crabc-libc bounded integer-source scan slice
  stdio-octal-hex-scan-header-abi  compile C11/C++17 scanf declaration/linkage evidence
  libc-stdio-octal-hex-scan  run the static x86 crabc-libc bounded octal/uppercase-hex scan slice
  stdio-fixed-percent-scan-header-abi  compile C11/C++17 literal-percent scanf declaration/linkage evidence
  libc-stdio-fixed-percent-scan  run the static x86 crabc-libc sealed literal-percent scan slice
  stdio-fixed-format-whitespace-scan-header-abi  compile C11/C++17 format-whitespace scanf declaration/linkage evidence
  libc-stdio-fixed-format-whitespace-scan  run the static x86 crabc-libc sealed format-whitespace scan slice
  stdio-fixed-literal-scan-header-abi  compile C11/C++17 raw-literal scanf declaration/linkage evidence
  libc-stdio-fixed-literal-scan  run the static x86 crabc-libc sealed raw-literal scan slice
  stdio-fixed-empty-format-scan-header-abi  compile C11/C++17 empty-format scanf declaration/linkage evidence
  libc-stdio-fixed-empty-format-scan  run the static x86 crabc-libc sealed empty-format scan slice
  stdio-fixed-suppressed-character-scan-header-abi  compile C11/C++17 suppressed-character scanf declaration/linkage evidence
  libc-stdio-fixed-suppressed-character-scan  run the static x86 crabc-libc sealed suppressed-character scan slice
  stdio-fixed-suppressed-string-scan-header-abi  compile C11/C++17 suppressed-string scanf declaration/linkage evidence
  libc-stdio-fixed-suppressed-string-scan  run the static x86 crabc-libc sealed suppressed-string scan slice
  stdio-fixed-suppressed-scanset-scan-header-abi  compile C11/C++17 suppressed-scanset scanf declaration/linkage evidence
  libc-stdio-fixed-suppressed-scanset-scan  run the static x86 crabc-libc sealed suppressed-scanset scan slice
  stdio-fixed-suppressed-count-scan-header-abi  compile C11/C++17 suppressed-count scanf declaration/linkage evidence
  libc-stdio-fixed-suppressed-count-scan  run the static x86 crabc-libc sealed suppressed-count scan slice
  libc-stdio-float-hex-output  run the static x86 crabc-libc binary64 hexadecimal-output slice
  libc-stdio-errno-output  run the static x86 crabc-libc errno-message format slice
  libc-stdio-path-stream  run the static x86 crabc-libc fixed pathname-stream slice
  libc-fopen64-alias  run the static x86 crabc-libc source-only fopen64 alias slice
  libc-stdio-tmpfile  run the static x86 crabc-libc bounded tmpfile stream slice
  libc-text-math-locale-stdio-composition  run the static x86 selected text/math/locale/stdio composition
  libc-intmax-arithmetic  run the static x86 crabc-libc intmax-arithmetic slice
  libc-credential-observation  run the static x86 crabc-libc credential-observation slice
  libc-ffs  run the static x86 crabc-libc find-first-set slice
  libc-memory-special  run the opt-in static x86 crabc-libc explicit_bzero/swab slice
  libc-memccpy  run the archive-free static x86 crabc-libc memccpy slice
  libc-aio-error  run the archive-free static x86 crabc-libc aio_error slice
  libc-byte-strings  run the static x86 crabc-libc byte-string slice
  libc-legacy-memory  run the static x86 crabc-libc bcopy/bzero adapter slice
  libc-memccpy  run the static x86 crabc-libc memccpy slice
  libc-mempcpy  run the static x86 crabc-libc mempcpy slice
  libc-strsep  run the static x86 crabc-libc strsep slice
  libc-strtok  run the static x86 crabc-libc strtok slice
  libc-stateful-byte-strings  run the static x86 caller-owned byte-string provider slice
  libc-network-byte-order  run the static x86 crabc-libc network byte-order slice
  libc-in6addr-any  run the archive-free static x86 crabc-libc IPv6 unspecified-address object slice
  libc-in6addr-loopback  run the archive-free static x86 crabc-libc IPv6 loopback-address object slice
  libc-dn-skipname  run the archive-free static x86 crabc-libc DNS wire-name span slice
  libc-dn-expand  run the archive-free static x86 crabc-libc DNS wire-name expansion slice
  libc-ns-flagdata  run the archive-free static x86 crabc-libc nameserver flag-accessor data slice
  libc-ns-get16  run the archive-free static x86 crabc-libc DNS 16-bit wire-read slice
  libc-ns-get32  run the archive-free static x86 crabc-libc DNS 32-bit wire-read slice
  libc-ns-put16  run the archive-free static x86 crabc-libc DNS 16-bit wire-write slice
  libc-process-globals-getopt  run the static x86 crabc-libc program-name/getopt slice
  libc-auxv-observation  run the static x86 crabc-libc initial aux-vector lookup slice
  libc-inet-address  run the static x86 crabc-libc numeric Internet-address codec slice
  libc-inet-ntoa  run the archive-free static x86 crabc-libc inet_ntoa scratch-buffer slice
  libc-inet-classful  run the archive-free static x86 crabc-libc classful IPv4 slice
  libc-hstrerror  run the static x86 crabc-libc h_errno message-string slice
  libc-h-errno  run the opt-in static x86 crabc-libc h_errno status-slot slice
  libc-endservent  run the archive-free static x86 crabc-libc legacy service-terminator slice
  libc-service-lifecycle  run the archive-free static x86 crabc-libc no-op/null service lifecycle slice
  libc-numeric-netdb  run the static x86 crabc-libc deterministic numeric netdb slice
  libc-resolver-runtime  run the hermetic static x86 C resolver-runtime slice
  libc-interface-discovery  run the static x86 C interface index/address discovery slice
  libc-random-entropy  run the static x86 crabc-libc random-entropy slice
  libc-memory-search  run the static x86 crabc-libc memory-search slice
  libc-string-copy  run the static x86 crabc-libc C-string-copy slice
  libc-error-strings  run the static x86 crabc-libc error-string slice
  string-duplication-header-abi  run the C/C++ x86 string-duplication declaration gate
  libc-strsignal  run the static x86 crabc-libc strsignal slice
  libc-socket-transport  run the static x86 crabc-libc base socket transport slice
  libc-socket-messages  run the static x86 crabc-libc socket-message/options slice
  libc-thread-pointer  run the source-only x86 opaque %fs:0 thread-pointer probe
  libc-foundation  run the source-only x86 C runtime primitive-composition probe
  libc-fenv  run the source-only x86 C x87/MXCSR floating-point-environment probe
  libc-math-complex  run the static x86 long-double/complex ABI foundation
  libc-math-complex-complete  run the complete static x86 math.complex capability
  libc-elementary-sqrt-fenv  run the static x86 sqrt/sqrtf/sqrtl fenv-sensitive slice
  libc-fenv-rounding  run the static x86 rint/nearbyint fenv-sensitive slice
  libc-owned-scalar-math  run installed x86 fma/fmaf, hypot/hypotf, and log1p/log1pf scalar completion
  libc-owned-binary80-math  run installed x86 fmal, hypotl, and log1pl binary80 completion
  libc-math-long-double-completion  run the private x86 binary80 fdiml/exp10l/pow10l closure
  libc-math-elementary-fenv-sensitive  run the complete private x86 math.elementary-fenv-sensitive aggregate
  libc-math-minmax  run the static x86 fmax/fmin minmax slice
  libc-math-bit-sign  run the static x86 fabs/copysign bit-sign slice
  libc-math-trunc  run the static x86 trunc/truncf scalar slice
  libc-math-fmod  run the static x86 fmod/fmodf scalar remainder slice
  libc-math-cbrt  run the static x86 cbrt/cbrtf scalar cube-root slice
  libc-math-exp2  run the static x86 exp2/exp2f scalar base-two exponential slice
  libc-math-expm1  run the static x86 expm1/expm1f scalar exponential-minus-one slice
  libc-math-log10  run the static x86 log10/log10f scalar base-ten logarithm slice
  libc-math-ceil  run the static x86 ceil/ceilf fixed-direction slice
  libc-math-floor  run the static x86 floor/floorf fixed-direction slice
  libc-math-round  run the static x86 round/roundf half-away slice
  libc-math-log2  run the static x86 log2/log2f scalar slice
  libc-math-elementary-long-double  run the complete static x86 math.elementary-long-double capability
  libc-math-x87-extended  run the static x86 x87 long-double math/remainder block
  libc-math-special  run the complete static x86 math.special capability
  libc-fdim  run the static x86 binary32/binary64 positive-difference slice
  libc-memory  run the source-only x86 C memcpy/memmove/memset probe
  libc-setjmp  run the source-only x86 C setjmp/signal-mask ABI probe
  libc-atomic  run the source-only x86 atomic-helper probe
  libc-clone-raw  run the source-only x86 musl-shaped raw clone probe
  libc-signal-foundation  run the source-only x86 signal-action packing probe
  ldso-relocation  run the source-only checked x86 RELA/RELR foundation tests
  ldso-image  run the source-only checked x86 ELF image parser tests
  ldso-initial-graph  run the bounded x86 ET_DYN initial-interpreter graph artifact
  ldso-target-root  run the feature-gated x86 crabc-ldso ET_DYN target-root admission
  ldso-general-initial-graph  run the bounded general non-TLS x86 initial dependency graph artifact
  ldso-general-initial-target-root  run the feature-gated general x86 crabc-ldso target-root admission
  ldso-general-initial-tls  run the private general x86 initial-TLS materialization artifact
  ldso-general-initial-tls-target-root  run the feature-gated general x86 initial-TLS target-root admission
  ldso-initial-tls  run the bounded x86 Variant-II initial-TLS interpreter graph artifact
  loader-libc-tls-runtime-v1  run the private x86 loader/libc initial-TLS RuntimeV1 handoff foundation
  loader-libc-tls-runtime-v1-registry  run the private x86 RuntimeV1 initial-module registry foundation
  loader-libc-general-tls-runtime-v1  run the private general x86 loader/libc initial-TLS RuntimeV1 handoff
  loader-libc-general-tls-runtime-v1-target-root  run the feature-gated general x86 RuntimeV1 target-root admission
  dynamic-main-thread-runtime-v1  run the private real-Scrt1 x86 RuntimeV1 dynamic-libc bridge
  dynamic-main-thread-runtime-v1-target-root  run the feature-gated real-Scrt1 x86 RuntimeV1 target-root admission
  general-dynamic-lifecycle  check general-loader owned CRT/libc initialization and process exit
  general-relocations  check general COPY, symbol scope, and initial-exec TLS
  ldso-initial-exec-tls  run the fixed x86 DF_STATIC_TLS/TPOFF64 sibling artifact
  ldso-owned-crt-handoff  run the bounded x86 ldso-to-Rust-Scrt1 handoff artifact
  ldso-fixed-graph-introspection  run copied introspection over the fixed x86 loader graph
  ldso-fixed-graph-dlfcn  run handle/symbol operations over the fixed x86 loader graph
  ldso-public-dlfcn  run the public C bridge over the fixed x86 loader graph
  ldso-dladdr-symbol-bounds  run finite-symbol dladdr evidence over the fixed x86 loader graph
  ldso-bounded-dlopen  run the one-slot x86 runtime DSO mapping/search artifact
  ldso-dynamic-admission  run the bounded x86 dynamic-loader admission inventory

This closed runner rejects non-native Linux/x86-64 hosts and does not provide
a general x86 libc artifact, ldso, CRT, sysroot, allocator, generic Cargo, or
shell command. `libc-stat-compat` is one private static `libc.a` stat/errno
slice with fixture-local initial-TLS setup; it is not a dynamic libc or
application-startup claim. `libc-credentials` exercises the same static archive
through a separate freestanding credential fixture; it is not a dynamic libc or
application-startup claim. `libc-bootstrap-primitives` exercises the same
static archive through a freestanding project-header memory/fenv/continuation
fixture after an equivalent pinned-musl run; it is a narrow artifact boundary,
not a dynamic libc or application-startup claim. `libc-signal-control` exercises
the same static archive through a freestanding simple action/set/mask/pending
fixture after an equivalent pinned-musl run. It does not select generic signal
delivery, waits, queues, pthread signal behavior, dynamic libc, or application
startup. `libc-signal-execution` composes that existing simple signal boundary
with a freestanding process-signal execution fixture after an equivalent
pinned-musl run. It selects only `kill`, `killpg`, `raise`, `sigqueue`, and
the `sigtimedwait`/`sigwaitinfo`/`sigwait` block, including a contained raw
clone/pipe EINTR retry proof. It does not select generic process lifecycle,
`tgkill`, alternate stacks outside their separate artifact, signalfd, legacy
signal APIs, pthread signal policy, dynamic libc, or application startup.
`libc-signal-altstack` proves one
24-byte `stack_t` preflight/query/disable boundary and one real `SA_ONSTACK`
handler entry/return through the existing hidden restorer. It retains the
selected fixed x86 `MINSIGSTKSZ=2048` preflight rather than claiming musl's
startup-auxv dynamic minimum, and does not select signal allocation, generic
delivery, pthread signal policy, dynamic libc, or application startup.
`libc-timerfd` is a separate three-entry timer-descriptor boundary. It proves
direct Linux creation/query/control, `TFD_NONBLOCK`/`TFD_CLOEXEC`, one-shot and
periodic/disarm behavior, and the eight-byte expiration read through a bounded
descriptor fixture. It is not a POSIX process timer, signal delivery policy,
callback/registry runtime, generic event loop, dynamic libc, or application
startup.
`libc-signalfd` is a separate one-entry signal-descriptor boundary. It proves
direct Linux `signalfd4` creation/update, the one-word kernel signal-set size,
nonblocking/close-on-exec flags, and bounded queued-signal reads. It does not
select signal-mask/disposition policy, process signaling, timer/readiness
policy, a generic event loop, dynamic libc, or application startup.
`libc-sigpause` is a separate one-entry legacy/XSI signal-wait boundary. It
derives one temporary mask from the calling mask, removes only the requested
application signal, and proves Linux restores the original mask after the
interrupted wait. It does not select a public mask/action API, process control,
signal queues/descriptors, timers, pthread behavior, dynamic libc, or
application startup.
`libc-mq-setattr` exercises one separate freestanding project-header C fixture
after the equivalent pinned-musl run. It selects only direct POSIX
message-queue status-flag replacement through `mq_getsetattr`: the LP64
`mq_attr` record, nonblocking flag transition, optional old-attribute output,
stale `errno` on success, and direct `EINVAL`/`EBADF` errors. It does not
select queue open/close/unlink, message transfer, notification, timed
operations, general IPC, dynamic libc, or application startup.
`libc-sigisemptyset` is a separate one-entry GNU signal-set predicate boundary.
It reads exactly musl's first public x86 signal-set word, ignores the remaining
128-byte-record tail, preserves stale errno, and has no syscall path. It does
not select signal actions/handlers, mask or process signaling, waits,
descriptors, timers, pthread behavior, dynamic libc, or application startup.
`libc-sigandset-sigorset` is a separate two-entry GNU signal-set binary boundary.
It reads both first public x86 signal-set words and writes only the destination
first word with AND or OR, including destination/operand aliasing; it preserves
tail storage and stale errno with no syscall path. It does not select the
predicate, signal actions/handlers, mask or process signaling, waits,
descriptors, timers, pthread behavior, dynamic libc, or application startup.
`libc-sigpending` is a separate one-entry POSIX pending-signal observation
boundary. It calls Linux `rt_sigpending=127` with only the public set's first
eight-byte kernel word, preserves the fifteen-word public tail, and maps raw
errors through initial-TLS errno. Fixture-only raw block/delivery setup creates
one pending `SIGUSR1`; it does not select a C mask/action/delivery/wait API,
descriptors, timers, pthread behavior, dynamic libc, or application startup.
`libc-sigrtmax` is a separate one-entry realtime-maximum ABI bridge. It is
the exact musl x86 `_NSIG - 1` return: `_NSIG=65` makes direct
`__libc_current_sigrtmax()` and the public `SIGRTMAX` macro return 64 without
storage, errno writes, calls, or syscalls. It leaves the separately selected
realtime-minimum bridge out of its candidate and does not select delivery,
actions, masks, waits, descriptors, timers, pthread behavior, dynamic libc,
or application startup.
`libc-sigrtmin` is a separate one-entry realtime-minimum ABI bridge. It is the
exact musl x86 fixed-35 return: direct `__libc_current_sigrtmin()` returns 35
without storage, errno writes, calls, or syscalls. Its fixture also checks the
pre-existing public `SIGRTMIN` value; it leaves the separately selected
realtime-maximum bridge out of its candidate and does not select delivery,
actions, masks, waits, descriptors, timers, pthread behavior, dynamic libc,
or application startup.
`libc-sched-getscheduler` is a separate one-entry POSIX scheduler-observation
compatibility boundary. Pinned musl deliberately returns `-1` with `ENOSYS`
for every `sched_getscheduler(pid_t)` input instead of exposing Linux's
thread-scoped raw syscall 145 as a process API. The common reference/candidate
fixture proves raw-current success and raw-invalid `EINVAL`, then proves the
musl `ENOSYS` result for current, invalid, and missing pid-shaped inputs. It
does not select scheduler policy mutation or parameters, priority bounds,
affinity, lifecycle, pthread scheduling attributes, dynamic libc, or
application startup.
`libc-alarm` is a separate one-entry historical SIGALRM interval-timer adapter.
It follows musl's direct x86 `setitimer(ITIMER_REAL)` closure: replace the
one-shot real-time timer, discard the C return after its ordinary errno side
effect, and return the prior whole seconds plus one for a fractional remainder.
Its fixture seeds and inspects
the kernel record through a private raw syscall, proving fractional rounding,
one-shot state, disarm behavior, and stale errno. It exports neither public
`setitimer` nor `ualarm`, and does not select handlers/actions, masks, waits,
delivery policy, timer-family completion, dynamic libc, or application startup.
`libc-sigaddset-sigdelset-sigfillset` is a separate three-entry POSIX
signal-set mutation boundary. It follows musl's one-word x86 helpers: fill
writes `0xfffffffc7fffffff`, while add/delete reject 0, 32--34, and 65 with
EINVAL before touching storage. It preserves the fifteen-word public tail and
stale errno on success, but does not select signal actions/handlers, masks,
delivery, waits, descriptors, timers, pthread behavior, dynamic libc, or
application startup.
`libc-static-tls-v1` passes a real
final static executable's untouched entry stack to a hidden libc owner, which
validates and retains its one PT_TLS template, installs the main Variant-II
thread pointer, and materializes initialized/TBSS/high-alignment copies for
the selected worker leaf. It is not general TLS, a CRT, loader, or support
claim. `libc-pthread-create-join-tls` exercises one private null-attribute
worker through that same archive: it either returns normally or takes the
selected worker-only pthread_exit path after publishing one result, while each
child gets an independent v1 final-image TLS copy and the kernel
clear-child-tid futex gates mapping reclamation. A fixed private 64-worker
registry validates an explicit-exit caller's `%fs:0`, kernel `gettid`, and
still-live clear-child-tid word, and serializes its publication with join
withdrawal before reclamation. The
candidate-only capacity route exhausts all 64 slots and proves reuse after
joining. It is not a general pthread runtime: attributes, pthread-exit
cleanup/TSD/main-thread/signal-handler behavior, cancellation, synchronization,
dynamic TLS/DTV, loader/CRT integration, and public x86 support remain outside
this artifact. Its handle identity and self/equal behavior are selected only
by the separate identity artifact below.
`libc-pthread-identity` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects
stable nonzero main identity, macro and function equality, weak same-address
`pthread_self`/`thrd_current` and `pthread_equal`/`thrd_equal` pairs, and
creator-handle identity for normal and selected explicit-exit workers. It does
not establish a general pthread runtime, synchronization, dynamic TLS, CRT,
loader, sysroot, or public x86 support.
`libc-c11-lifecycle` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects
typed `thrd_create`/`thrd_join`/`thrd_exit` callback/result transport over the
same TP-handle and Static Initial TLS v1 worker seam, including normal and
explicit signed-int return paths, a null join result, two live workers, and a
candidate-only 64-worker admission/reuse check. It does not select the
separately recorded C11 sleep or direct `thrd_yield` artifacts, synchronization, TSS, cancellation, dynamic TLS, CRT,
loader, sysroot, C11-family completion, or public x86 support.
`libc-pthread-detach` is a separate static project-header fixture that first
runs comparable pthread/C11 detach routes through pinned musl, then links only
the selected archive. It selects prompt `pthread_detach`/`thrd_detach`
ownership transitions over the existing selected worker seam, with later
selected create/join reaping only after `CLONE_CHILD_CLEARTID`. Its comparable
routes run before and after the fixture's callback-completion signal, not after
kernel exit; candidate-only checks cover self-detach, null/repeated-handle
rejection, ownership races, and 64-slot reuse. It does not select detached-at-create
attributes, a general pthread/C11 runtime, cancellation, TSS, synchronization,
dynamic TLS, CRT, loader, sysroot, C11-family completion, or public x86
support.
`libc-thrd-sleep` is a separate static project-header fixture that first runs
through pinned musl, then links only the selected archive. It selects only the
direct non-cancellation C11 `thrd_sleep` adapter over
`clock_nanosleep(CLOCK_REALTIME, 0, ...)`: completion returns zero, `EINTR`
returns `-1`, and invalid-nanosecond or null-duration failures return `-2`
without changing errno. Its reference/candidate route proves zero, invalid,
null, and SIGALRM-interrupted requests with a positive remaining interval. It
does not select the separately recorded `thrd_yield` leaf, cancellation cleanup, C11
lifecycle/synchronization/TSS, dynamic TLS, CRT, loader, sysroot,
C11-family completion, or public x86 support.
`libc-thrd-yield` is a separate static project-header fixture that first runs
through pinned musl, then links only the selected archive. It selects only the
void C11 `thrd_yield` raw Linux `sched_yield=24` call: normal and
fixture-local seccomp-forced `EPERM` invocations discard their raw result and
preserve errno exactly as musl does. It makes no scheduler handoff, fairness,
or peer-progress guarantee, and does not select the separate POSIX sched_yield
status-returning C API artifact,
scheduler policy/parameters, affinity or pthread scheduling attributes, C11
lifecycle/synchronization/TSS/cancellation, dynamic TLS, CRT, loader, sysroot,
C11-family completion, or public x86 support.
`libc-pthread-cpuclock` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects
only `pthread_getcpuclockid` for the bootstrapped process-main
`pthread_self()` handle: direct `gettid=186` is encoded as Linux's thread CPU
clock without dereferencing a TCB, and the fixture proves its exact result,
clock_gettime acceptance, and errno preservation. Candidate-only null/non-self
handles fail closed with `ESRCH` without touching output or errno. It does not
select worker/foreign handles, `clock_getcpuclockid` or general C clocks,
scheduler/affinity attributes, lifecycle/cancellation/synchronization/TSS, a
TCB/thread list, dynamic TLS, CRT, loader, sysroot, or public x86 support.
`libc-pthread-name` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects
only GNU `pthread_setname_np`/`pthread_getname_np` for the bootstrapped
process-main `pthread_self()` handle: direct `prctl=157` sets or reads Linux's
16-byte task-comm slot, long names and short reads return `ERANGE`, and neither
entry writes errno. Candidate-only non-self handles fail closed with `ESRCH`
before their name input or output is observed. It does not select worker or
foreign names, musl's procfs path, cancellation, a general prctl C API,
scheduler/affinity attributes, lifecycle/synchronization/TSS, a pthread TCB or
thread list, dynamic TLS, CRT, loader, sysroot, general pthread/TLS behavior,
or public x86 support.
`libc-pthread-barrierattr-pshared` remains a separate static project-header
fixture that first runs through pinned musl, then links only its record leaf
from the selected archive. It selects the four-byte public
`pthread_barrierattr_t` record's `pthread_barrierattr_setpshared`/
`pthread_barrierattr_getpshared` behavior: accepted private/shared inputs
replace its whole word with `0`/`INT_MIN`, invalid inputs preserve it, and any
nonzero raw word queries as shared. The fixture deliberately constructs
caller-owned record words and does not call an attribute lifecycle function or
the separately selected barrier block. Its record-only proof does not
establish barrier initialization, waiting, destruction, or process-shared
barrier operation; thread, TLS, synchronization, cancellation, CRT, loader,
sysroot, pthread-family completion, or public x86 support.
`libc-pthread-barrier` is the separate complete static project-header barrier
fixture. It first runs through pinned musl, then links a true
`-nostdlib -static` candidate for attribute lifecycle/pshared records, count
validation, two reusable private selected-worker rounds, and one shared-futex
cross-fork round followed by quiescent destroy. The fixture's mapping, fork,
wait, clock, and exit plumbing is test-only. It does not claim arbitrary
destroy races, a general pthread synchronization/lifecycle runtime,
cancellation, pthread-family completion, or public x86 support.
`libc-pthread-spin-init` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects only
`pthread_spin_init`'s four-byte public `pthread_spinlock_t` record reset: every
call replaces arbitrary caller-owned bits with zero and returns zero while
ignoring `pshared`. It does not select spin acquisition, release, destruction,
or process sharing; synchronization, thread/TLS lifecycle, cancellation, CRT,
loader, sysroot, pthread-family completion, or public x86 support remain
outside this artifact.
`libc-pthread-mutex-normal` is a separate static project-header fixture that
first runs through pinned musl, then links only the selected archive. It
selects only zero/NULL-attribute process-private `PTHREAD_MUTEX_NORMAL`
init/lock/trylock/unlock/destroy behavior over the existing selected worker
seam. The fixture proves held-lock `EBUSY`, private-futex contention and wake,
mutual exclusion, and errno preservation; attributes, recursive,
error-checking, robust, PI, process-shared, timed, C11 mutex or condition
behavior beyond the selected plain adapter, general condition-variable
behavior, cancellation, dynamic TLS, CRT, loader, sysroot,
pthread-family completion, and public x86 support remain outside this
artifact. `libc-pthread-cond-private` is its separately evidenced sibling:
it selects only zero/NULL-attribute process-private condition init/destroy,
wait, signal, and broadcast paired with that normal mutex. Its static fixture
proves all-zero initialization, waiter publication, signal, broadcast,
repeated predicate handoff, private-futex requeue, errno preservation, and
quiescent destruction. It does not select condition attributes, timed/shared
or C11 condition behavior beyond the selected plain adapter, cancellation, a
general pthread runtime, dynamic TLS,
CRT, loader, sysroot, pthread-family completion, or public x86 support.
`libc-c11-plain-sync` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects
only distinct `mtx_t`/`cnd_t` records, `mtx_plain`, and the corresponding
untimed mutex and condition operations through the private normal-mutex and
waiter/requeue engines; held trylock maps to `thrd_busy`. Recursive/timed
kinds are candidate-only `thrd_error` rejections. Timed/static C11 behavior,
cancellation, TSS, once, pthread/TLS parity, promotion, and public x86 support
remain excluded.
`libc-pthread-c11-once` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects
only normal-return `pthread_once` and C11 `call_once` over their shared
four-byte zero-initialized state word: one initializer, an ordinary payload's
completion publication, private-futex contention/wake, and errno preservation.
Cancellation reset, initializer thread exit, recursive same-control entry,
fork/atfork, TSS, dynamic TLS, broad pthread/C11 synchronization, pthread/TLS
parity, promotion, and public x86 support remain excluded.
`libc-pthread-c11-tsd` is a separate static project-header fixture that first
runs through pinned musl, then links only the selected archive. It selects only
a private 128-key pthread/C11 TSD lifecycle across the selected main and worker
tables: get/set isolation, deletion clearing, and four clear-before-destructor
passes for normal return, `pthread_exit`, C11 return, and `thrd_exit`. It does
not select cancellation, foreign threads, main-process-exit destruction,
concurrent deletion/destructor interaction, fork/atfork, dynamic or loader
TLS, a general pthread/C11 runtime, pthread/TLS parity, promotion, or public
x86 support.
`libc-termios-control` exercises the same archive through a
freestanding project-header C fixture after an equivalent pinned-musl run. It
selects only fixed baud/raw helpers, named attribute/queue/flow/break requests,
and fixed window-size records; it does not select generic ioctl,
`tcdrain`/cancellation, terminal/session/PTY policy, dynamic libc, or
application startup. `libc-process-context` exercises the same archive through
a freestanding project-header C fixture after an equivalent pinned-musl run.
It selects only scalar identity, `umask`, and named process-group/session
wrappers, with raw-forked fixture children containing the state transitions.
It does not select C fork/exec, generic process control, or pthread
coordination; child reaping is a separately bounded archive artifact. It also
does not select dynamic libc or application startup. `libc-child-reaping`
exercises the same archive through a freestanding project-header C fixture
after an equivalent pinned-musl run. It selects only `wait`, `waitpid`, and
`waitid`: raw clone/pipe fixture control fixes `WNOHANG` no-event, `WNOWAIT`
observation, exact reap, and post-reap `ECHILD` states without selecting C
fork/exec or a general process supervisor. It deliberately omits musl pthread
cancellation and atfork machinery, dynamic libc, and application startup.
`libc-immediate-termination` exercises the same archive through a
freestanding project-header C fixture after an equivalent pinned-musl run. It
selects only C11 `_Exit`: fixture-local raw clone/wait observes the exact child
status, while no ordinary exit, quick-exit hooks, stdio/fini processing, fork
coordination, or pthread lifecycle is selected. It has no errno result,
dynamic libc, or application-startup claim.
`libc-posix-exit` is a separate freestanding project-header C fixture after an
equivalent pinned-musl run. It selects only POSIX `_exit`: musl's complete
source is one no-return forward to the separately selected `_Exit` sibling;
fixture-local raw clone/wait observes child status 41 and emitted `_exit` has
no raw syscall. Ordinary exit, hooks, stdio/fini processing, fork
coordination, pthread lifecycle, dynamic libc, and application startup remain
outside this forwarding artifact.
`libc-descriptor-io`
exercises the same archive through a freestanding project-header C fixture
after an equivalent pinned-musl run. It selects only direct descriptor
transfer/position/truncate/sync requests, duplication, and pipe creation;
fixture-local raw memfd/fcntl setup does not select C open/path or generic
fcntl-command APIs.
Pthread cancellation, AIO coordination, durability policy, dynamic libc, and
application startup remain outside that artifact. `libc-descriptor-lifecycle`
composes existing selected open/openat/creat, fcntl-status, descriptor-I/O,
and stat leaves through one PID-isolated relative-directory lifecycle. Its raw
Linux calls only create and clean that temporary directory; they never replace
candidate C calls. It does not establish descriptor/filesystem capability,
general C runtime, cancellation, CRT, loader, sysroot, family completion, or
public x86 support. `libc-descriptor-pipeline` composes the already-selected
pipe2, fcntl status/descriptor flags, poll readiness, vector transfer, dup,
and close leaves through one nonblocking pipe lifecycle. It adds no C API or
generic descriptor policy. `libc-process-resources`
exercises the same archive through a freestanding project-header C fixture
after an equivalent pinned-musl run. It selects only limits, resource usage,
priority, and `nice`; raw child/pipe control contains mutations and a live
target query. It does not select C scheduler policy, cgroups, `times`, process
lifecycle, dynamic libc, or application startup. `libc-readiness-waits`
exercises the same archive through a freestanding project-header C fixture
after an equivalent pinned-musl run. It selects only `poll`/GNU `ppoll`,
`select`/`pselect`, `pause`, and `sigsuspend`; existing selected pipe and
simple signal-control calls only arrange the tested readiness and pending-mask
states. It preserves musl's caller-timeout copies and atomic temporary-mask
restoration, but deliberately omits pthread cancellation. `pause` has an
emitted-code gate rather than a racy runtime wakeup harness. It does not select
epoll/eventfd, C open/path or generic fcntl-command APIs, generic delivery or signal waits, timers,
process lifecycle, dynamic libc, or application startup.
`libc-system-observation` exercises the same archive through a freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
`uname` and `sysinfo`, including Linux's 112-byte `sysinfo` kernel write: the
first four public `__reserved` bytes at offsets 108 through 111 are
kernel-initialized, while offsets 112 through 367 remain caller-resident. It
does not select the separately recorded hostname/domain identity boundary,
system-file parsing, process identity, dynamic libc, or application startup.
`libc-system-information` exercises a separate freestanding project-header C
fixture after its equivalent pinned-musl run. It selects only musl's fixed
128-byte `sched_getaffinity` CPU count and `sysinfo` physical/free-plus-buffer
page calculations, including the child-local affinity-error CPU-zero fallback.
It does not select load observation, affinity control, topology, general
`sysconf`, dynamic libc, or application startup.
`libc-getloadavg` exercises a separate GNU/BSD project-header C/C++ declaration
gate and freestanding project-header C fixture after its equivalent pinned-musl
run. It selects only historical `getloadavg`: count <= 0/no-output/stale-errno,
the three-entry clamp, and caller output from an adjacent raw `sysinfo` snapshot.
It does not select public sysinfo/uname, `/proc`, processor or topology policy,
general `sysconf`, dynamic libc, or application startup.
`libc-fcntl-record-locks` exercises a separate freestanding project-header C
fixture after its equivalent pinned-musl run. It selects only pointer-bearing
nonblocking `fcntl(F_GETLK)`/`fcntl(F_SETLK)` record locks: an unlocked query,
a child observation/conflict against a parent lock, release, stale `errno` on
success, and direct kernel errors. It does not select `F_SETLKW` cancellation,
OFD locks, `lockf`, `flock`, generic fcntl, dynamic libc, or application
startup.
`libc-flock` exercises a separate freestanding project-header C fixture after
its equivalent pinned-musl run. It selects only direct nonblocking `flock`:
the public operation bits, raw-duplicate open-file-description release state,
a separately opened child conflict and later exclusive reacquisition, stale
`errno`, and direct kernel errors. It does not select fcntl record-lock
interaction, `lockf`, generic descriptor/pathname policy, dynamic libc, or
application startup.
`libc-sendfile` exercises a separate freestanding project-header C fixture
after its equivalent pinned-musl run. It selects only direct regular-file
`sendfile`: explicit offset advance without input-position mutation,
null-offset short-transfer and EOF-zero behavior, stale `errno`, and direct
kernel errors. It does not select pathname, socket/pipe, splice,
copy-file-range, vector-I/O, durability, cancellation, dynamic libc, or
application startup.
`libc-copy-file-range` exercises a separate freestanding project-header C
fixture after its equivalent pinned-musl run. It selects only one direct GNU
same-filesystem regular-file explicit-offset request: wrapper/raw result and
pointed-offset agreement, copied bytes, retained shared descriptor positions,
stale `errno` on success, and direct invalid-flags `EINVAL` plus bad-input
`EBADF`. It does not select pathname or descriptor ownership, copy fallback or
cross-filesystem policy, `sendfile`/`splice`, durability, cancellation,
dynamic libc, or application startup.
`libc-splice` exercises a separate freestanding project-header C fixture after
its equivalent pinned-musl run. It selects only one direct GNU regular-file-to-
pipe explicit-input-offset request: wrapper/raw result and pointed-offset
agreement, copied pipe bytes, stable file position, stale `errno` on success,
and direct invalid-flags `EINVAL` plus bad-input `EBADF`. It does not select
pathname or descriptor/pipe ownership, blocking, fallback, general
pipe/filesystem transfer policy, `tee`/`vmsplice`/`sendfile`/`copy_file_range`,
durability, cancellation, dynamic libc, or application startup.
`libc-tee` exercises a separate freestanding project-header C fixture after
its equivalent pinned-musl run. It selects only direct GNU pipe-buffer
duplication: source bytes remain readable after an equal destination copy,
zero-length success retains stale `errno`, and a bad source descriptor maps to
`EBADF`. Fixture-local raw pipe setup is evidence plumbing, not selected pipe
creation, ownership, descriptor policy, `splice`/`vmsplice` transfer,
cancellation, dynamic libc, or application startup.
`libc-sync-file-range` exercises a separate freestanding project-header C
fixture after its equivalent pinned-musl run. It selects only one direct GNU
regular-file range request: raw result/`errno` agreement, stable shared
descriptor position, stale `errno` on success, and direct invalid-flags
`EINVAL` plus bad-descriptor `EBADF`. It does not select pathname or descriptor
ownership, cache/writeback policy or durability, `sync`/`syncfs`, `fallocate`,
cancellation, dynamic libc, or application startup.
`libc-posix-fallocate` exercises a separate freestanding project-header C
fixture after its equivalent pinned-musl run. It selects only mode-zero
`posix_fallocate`: regular-file extension with preserved file position, a
retained prefix and zero-filled extension, direct positive POSIX errors, and
unchanged `errno`. It does not select general fallocate flags, pathname or
filesystem policy, durability, cancellation, dynamic libc, or application
startup.
`descriptor-advice-header-abi` proves only the project and pinned-musl C/C++
declaration profiles for unconditional `posix_fadvise`, the six
`POSIX_FADV_*` values, the `_LARGEFILE64_SOURCE` macro alias, and GNU-only
`readahead`; it does not select a runtime C API. `libc-descriptor-advice`
exercises a separate freestanding project-header C fixture after its equivalent
pinned-musl run. It selects only `posix_fadvise` and GNU `readahead` over an
unlinked regular file: all six advice words, stable descriptor position,
direct POSIX versus `-1`/`errno` error conventions, and no cache-effect claim.
It does not select cache policy, pathname behavior, allocation, durability,
cancellation, dynamic libc, or application startup.
`filesystem-capacity-header-abi` proves only the project and pinned-musl
C/C++ declaration, LP64 layout, feature-selection, and C++ C-linkage profiles
for `statfs`, `fstatfs`, `statvfs`, and `fstatvfs`, including their
`_LARGEFILE64_SOURCE` macro aliases. It does not select a runtime C API.
`libc-filesystem-capacity` exercises a separate freestanding project-header C
fixture after its equivalent pinned-musl and raw-syscall reference runs. It
selects only direct `statfs`/`fstatfs` records and musl's derived
`statvfs`/`fstatvfs` conversion for one unlinked regular file, including
stale-`errno` success and missing-path/closed-fd errors. It does not select
filesystem policy, pathname behavior, allocation, durability, cancellation,
dynamic libc, or application startup.
`vector-io-header-abi` proves only the project and pinned-musl C/C++
`sys/uio.h` declarations, x86 iovec layout, feature visibility, LF64 aliases,
and C++ C-linkage profiles. `libc-vector-io` exercises a separate freestanding
project-header C fixture after its equivalent pinned-musl run. It selects only
`readv`/`writev`/`preadv`/`pwritev`: segment order, positioned-offset stability,
invalid count/signed-offset errors, a sparse offset above 4 GiB, and musl's
selected pwritev append boundary. It does not select cancellation, v2 or
process-vm runtime, scalar descriptor I/O, stdio, dynamic libc, or application
startup.
`libc-uts-identity` exercises the same archive through a freestanding
project-header C fixture after an equivalent pinned-musl run. Each fixture arm
creates a fresh UTS namespace before it mutates hostname/domain-name state; the
canonical launcher grants only this command `--cap-add=SYS_ADMIN` for that
namespace creation. It selects only `gethostname`, `sethostname`,
`getdomainname`, and `setdomainname` atop the separately selected `uname`
record seam: musl's bounded hostname copy, the complete-fitting domain copy,
and direct setter errno behavior. It does not select namespace management,
gethostid/sethostid, system-file parsing, sysconf, dynamic libc, or application
startup. `libc-socket-transport` exercises the same archive through a
freestanding project-header C fixture after an equivalent pinned-musl run. It
selects only base `socket`/`socketpair`, bind/listen/accept/`accept4`/connect,
send/receive, name-query, and shutdown calls on local socket endpoints. Linux
5.10 direct paths atomically observe SOCK_CLOEXEC|SOCK_NONBLOCK on socket,
socketpair, and accept4, have no pre-5.10 fallback, and this closed leaf
intentionally provides no pthread-cancellation machinery. The generic container
grants it no extra capabilities. Socket options, vectored or ancillary messages,
resolver/netdb state, interface ioctls, general socket policy, dynamic libc,
and application startup remain outside that artifact. `facade` covers only the
separately admitted direct `crabc-rs`
subset, including borrowed-atomic futex wait/wake and the complete typed
`seek`/`tell`/`ftruncate`/`fsync`/`fdatasync` file-position family, typed
`fs::{StatFs, StatVfs, StatVfsMountFlags, statfs, fstatfs, statvfs, fstatvfs}`
filesystem-capacity observation,
`fs::{FlockOperation, flock}` whole-file advisory locking,
`fs::sendfile` descriptor-to-descriptor transfer with an optional input
offset, `fs::copy_file_range` descriptor-range copying, and
`fs::posix_fallocate` mode-zero descriptor-range allocation,
`fs::fallocate` closed-mode descriptor-range allocation,
`fs::sync` system-wide filesystem synchronization,
`fs::syncfs` descriptor-associated filesystem synchronization, and typed
`io::{sync_file_range, SyncFileRangeFlags}` range-writeback requests,
direct `mm::{mmap, mmap_anonymous, mprotect, munmap}` mapping lifecycle,
query/replay-only `process::kernel_brk`, direct process-wide
`mm::{MlockAllFlags, mlockall, munlockall}`, and unsafe legacy
`mm::remap_file_pages` VM-policy seams,
direct checked `mount::{mount, unmount}` requests whose x86 evidence is
limited to validation and failures against a unique missing target,
anonymous memory-file creation plus bounded seal observation/mutation,
direct typed `access`/`accessat` real/effective-credential observations,
direct typed `fcntl(F_GETFL/F_SETFL)` status-flag observation/mutation,
calling-process `getrlimit`/`setrlimit`, typed supplementary-group query/fill,
typed read-only `getrusage` observations, typed read-only `times` accounting,
typed read-only interval-timer and round-robin interval, plus direct typed
CPU-affinity observation/mutation, and typed
process-global `umask` exchange, plus direct same-process exact-thread
`signal::kill_thread` delivery,
calling-thread `setresuid`/`setresgid` transitions with typed no-change
sentinels, and typed scheduling-priority mutation,
plus a staged pathname lifecycle and namespace boundary for metadata,
open/create, directories and FIFO nodes, pathname truncate, removal,
permissions/ownership, hard and symbolic links, caller-buffer `readlinkat`,
and ordinary/no-replace/exchange rename, plus direct socket creation/pairs,
IPv4/IPv6 address values, loopback datagram and stream transport, typed socket
options, vectored/batched messages, and the fixed urgent-data-mark ioctl,
plus bounded typed clock-nanosleep with its relative-remainder and
absolute-no-remainder modes, direct typed timer descriptors, direct
select/pselect and packed epoll readiness with masked waits, and caller-buffer
and alloc-gated physical and validated-logical current-directory observation.
The dedicated `getcwd-reference` gate also covers alloc-gated physical retry
and logical explicit-PWD decisions. `path-lifecycle-reference` and
`namespace-reference` prove only their named direct Rust facade boundaries;
`path-core-reference` composes them with stat/timestamp/raw-readlink evidence
and the selected owned `readlink` retry boundary. Canonicalization, general
`AT_EMPTY_PATH`, and CWD mutation remain excluded from that aggregate;
extended attributes, allocation-free directory records, temporary-object
ownership, and direct extended metadata are the separate `xattr-reference`,
`directory-reference`, `temporary-object-reference`, and `statx-reference`
boundaries. The statx boundary alone admits its operation-specific
`AT_EMPTY_PATH` form and preserves direct `ENOSYS` rather than musl's
`fstatat` fallback. The interval-timer-
control slice is admitted only through the typed Rust facade; none of these
commands selects the C record-owning family.
`socket-transport-reference` establishes only the named direct typed-Rust
socket/address boundary. It proves native x86 LP64 `iovec`/`msghdr`/`mmsghdr`,
IPv4/IPv6 socket-address, and socket-storage records; raw/pinned-musl paired
Unix, UDP loopback, TCP loopback, socket-option, `accept4` flag, vectored, and
batched-message behavior. It excludes C socket/errno APIs, resolver and netdb
state, interface/device ioctls, ancillary-control buffers, Unix-domain address
values, and public x86 runtime support.
`interface-device-reference` establishes the separately bounded x86
`net::netdevice` interface-name/index and owned snapshot boundary: fixed
40-byte `ifreq` ioctl records, checked `recvmsg(MSG_TRUNC)` link and IPv4/IPv6
address rtnetlink dump records, loopback index/name self-consistency, ordered
owned link/address snapshots, malformed-record regressions, and no-std static
interface probes. A datagram above the fixed 8192-byte receive bound is
rejected as `OVERFLOW`, never parsed as a partial snapshot. It does not select
generic ioctl APIs, the C `ifreq`/`ifaddrs`/`if_nameindex` ABI, resolver/netdb
state, interface mutation, C errno/TLS, or public x86 runtime support.
`resolver-transport-reference` establishes only the private
`crabc-core::resolver` exchange seam: caller-owned nameservers, local UDP
wrong-ID/question-mismatch/record-framing/oversize filtering through a checked
`recvmsg(MSG_TRUNC)` buffer seam, bounded configured-order failover, and
truncation retry through partial length-prefixed TCP I/O. It does not expose
or evidence the separately staged alloc-backed `crabc-rs` resolver/netdb
facade, parse system files, use C resolver state, or contact an external
nameserver.
`resolver-facade-reference` establishes the separately staged alloc-backed
`crabc-rs::resolver` and `netdb::HostDatabase` boundary: strict owned hosts
snapshots, caller-owned and direct-system resolver configuration, numeric and
local-only DNS policy, and a host-only no-std probe. It does not select C
resolver/netdb state or ABI, NSS/plugins, external DNS, or public x86 runtime
support.
`netdb-reference` establishes the separately staged alloc-backed
`crabc-rs::netdb` conventional snapshot boundary: strict caller-owned and
direct system snapshots for `/etc/hosts`, `/etc/services`, and
`/etc/protocols`, typed owned lookup records, malformed whole-snapshot
rejection, and a no-std all-three-parser probe. It does not select
`/etc/networks`, C netdb/resolver state or ABI, NSS/plugins, external DNS, or
public x86 runtime support.
`users-databases-reference` establishes the separately staged alloc-backed
`crabc-rs::users` conventional local-account snapshot boundary: strict owned
`/etc/passwd` and `/etc/group` records, deterministic source-order lookup,
bounded direct descriptor snapshots, and a no-std static probe. It does not
select C passwd/group APIs, NSS/provider lookup or mutation, shadow, utmp,
mntent, or public x86 runtime support.
`musl-oracle` proves only C/POSIX oracle provenance, and
`header-abi-reference` proves only its pinned reference baseline.
`header-abi-project` compiles only the staged public fenv/float/fundamental
type declarations and does not link an x86 libc artifact.
`math-complex-header-abi` executes pinned-musl and project-header-first C
consumers in SSE and x87 modes, then checks C++ references retain unmangled C
linkage. It proves only the named math/complex/tgmath header semantics; both
C consumers intentionally link pinned musl's math runtime, not crabc-libc.
`math-complex-complete-header-abi` type-checks all 66 `math.complex` function
addresses against project headers and pinned musl in SSE and x87 modes,
including 16-byte binary80 and 32-byte complex-binary80 storage. It is a
declaration/linkage gate; the separate complete static differential owns
runtime behavior.
`math-elementary-long-double-header-abi` type-checks all 35 exact
`math.elementary-long-double` function addresses against project headers and
pinned musl in SSE and x87 modes. It ratchets the SysV 16-byte binary80
storage and unmangled C++ linkage; the separate static differential owns
runtime behavior.
`math-special-header-abi` compile-checks every `math.special` function-pointer
type and unmangled C++ reference in SSE and x87 modes. It records declarations
and ABI spelling only; the separate static differential owns runtime behavior.
`sys-reg-header-abi` compiles only the staged ptrace register-index header.
`machine-context-header-abi` compares only selected x86 aux-vector, ptrace,
user-register, procfs, and ucontext declaration/layout profiles against pinned
musl. It rejects AArch64 HWCAP/register leaks and does not select runtime,
archive linkage, header-family completion, or public x86 support.
`types-header-abi` compiles only staged C/C++ type declarations and opaque
pthread object layouts. `stat-header-abi`, `time-header-abi`, `poll-header-abi`,
`select-header-abi`, `fcntl-header-abi`, `flock-header-abi`, `sendfile-header-abi`, `tee-header-abi`, `splice-header-abi`, `sync-file-range-header-abi`, `copy-file-range-header-abi`, `ioctl-header-abi`, `unistd-header-abi`, and
`system-header-abi` compile only their named C/C++ layout/declaration slices.
`stddef-header-abi` separately compares project-first and pinned-musl strict,
POSIX, XOPEN, GNU, and BSD C/C++ `<stddef.h>` profiles for its `_STDDEF_H`
guard, `NULL` spelling, alltypes request boundary, fundamental LP64 types,
`max_align_t`, and `offsetof`. It is compile-only header evidence; it does not
select archive linkage, allocation behavior, installed-header completion,
family completion, or public x86 support.
`syscall-header-abi` compares only staged syscall number macros.
`signal-header-abi`, `termios-header-abi`, `mman-header-abi`,
`memory-sync-header-abi`, `memory-locking-header-abi`,
`memfd-create-header-abi`, and `resource-header-abi` compile only their named
staged signal-frame, GNU termios, mapping, no-cancellation msync, per-range
memory-locking, GNU memfd_create, and strict/GNU/LFS resource declarations.
`termios-header-abi` remains a header-only C/C++ layout/declaration gate, not
a general C terminal/runtime claim. `resource-header-abi` is likewise
header-only and does not select process-resource behavior or a C runtime.
`socket-header-abi` compile-checks only staged C/C++ base transport
declarations, `socklen_t` and generic/IPv4/IPv6 socket-address layouts, and
creation, shutdown, and basic send/receive constants, then executes installed
IPv4/IPv6 address-equality/classification macros and checks GNU/BSD multicast
source-filter layouts/size macros through project and pinned-musl headers. It
does not select socket membership, packet I/O, socket options, vectored or
ancillary-message APIs, address-conversion or socket behavior, a C runtime,
or a general socket capability.
`tcp-header-abi` separately compares project-first and pinned-musl strict,
POSIX, XOPEN, GNU, and BSD C/C++ `<netinet/tcp.h>` feature profiles for
unconditional TCP option/state and netlink vocabulary, GNU/BSD option parsing
and `struct tcphdr`, and GNU-only TCP information, MD5, repair, and zero-copy
record layouts. It is compile-only header evidence; it does not select TCP
socket-option or transport behavior, archive linkage, installed-header
completion, family completion, or public x86 support.
`socket-messages-header-abi` separately compares project-first and pinned-musl
C/C++ profiles for the bounded `<sys/socket.h>` message/options declarations,
their LP64 `msghdr`/`cmsghdr`/GNU `mmsghdr` layouts and visibility, CMSG macro
boundaries, and unmangled C++ linkage. It is declaration/layout evidence only,
not a general installed-header, socket, cancellation, or runtime claim.
`mm-abi-reference` establishes only the pinned-musl constants used by the
separately admitted Rust mapping facade.
`memory-vm-reference` establishes only the separate private x86 VM-policy
boundary: raw `brk=12` current-break query and same-address replay (not libc
`brk`/`sbrk` bookkeeping), process-global `mlockall=151`/`munlockall=152`
with child-contained cleanup, and legacy `remap_file_pages=216` rejection for
an anonymous page. The pinned-musl oracle deliberately records its `brk`
wrapper's `ENOMEM` result for the same-address replay as a C-wrapper
difference, not a replacement for raw `kernel_brk` semantics. It does not
claim successful file-backed legacy remapping, successful lock policy,
allocator/heap ownership, a C ABI or errno TLS, newer VM policy, or public x86
support.
`pty-basic-reference` establishes only the separate private x86 safe
pseudoterminal pair/name boundary: opening `/dev/ptmx`, validating and
unlocking its devpts peer, owning the peer returned by `TIOCGPTPEER`, and
deriving the caller-buffer or alloc-owned `/dev/pts/N` name from `TIOCGPTN`.
It does not select controlling-terminal/session ownership, termios state,
queue control, terminal exclusivity, generic ioctl, a C PTY ABI, or public x86
support.
`terminal-reference` establishes the next private x86 terminal vertical over
that safe pair/name base: explicit unsafe `PtyPair` session/controlling-terminal
handoff and named Rust termios/TTY operations. It proves the private
36-byte/align-4 x86 `TCGETS` record, distinct from musl's
60-byte/`NCCS=32` public record, standard baud/special-code attributes,
queue/flow/break, exclusive mode, foreground/session group, window size, and
validated tty paths. The raw/pinned-musl C oracle confines `setsid` plus
`TIOCSCTTY` to a child. This Rust vertical selects no general C terminal
ABI/errno TLS, generic ioctl, public peer-open helper, process supervisor, or
public x86 support. The separate `libc-termios-control` static artifact
forwards a public C termios pointer only for its closed named C boundary; it
does not promote this Rust vertical or a general C terminal capability.
`mlock-reference` establishes only the pinned-musl x86 per-range memory-locking
boundary used by that facade.
`msync-reference`, `madvise-reference`, and `mincore-reference` establish only
their named mapping-synchronization, Linux/POSIX advisory, and page-residency
boundaries used by the typed Rust facade.
`fs-advice-reference` establishes only the typed Rust file-access advice and
readahead boundary; it does not select a C filesystem API.
`access-reference` establishes the direct typed Rust `fs::{access, accessat}`
boundary: legacy `faccessat` for real-credential checks and flags-bearing
`faccessat2` for the closed effective-credential/final-symlink policy. It does
not select C APIs, errno TLS, pathname mutation, or broader path-core behavior.
`fcntl-status-reference` establishes only direct typed Rust
`fs::{OFlags, fcntl_getfl, fcntl_setfl}` status-flag observation and mutation:
the shared open-file-description state, immutable access/creation/descriptor
bits, exact restoration, and direct `EBADF`. It does not select x86 pathname
opening, a generic C `fcntl` API, or errno TLS.
`flock-reference` establishes only direct typed Rust
`fs::{FlockOperation, flock}` whole-file advisory locking: x86 `flock=73`,
the closed `LOCK_SH`/`LOCK_EX`/`LOCK_NB`/`LOCK_UN` values, shared
duplicate-descriptor lock state, nonblocking contention from a separately
opened descriptor, and direct invalid-operation/closed-descriptor errors. It
does not select `flock`/`fcntl` record-lock interaction or `fcntl`
record-lock mutation, a C API, pathname opening, errno TLS,
or network/distributed-filesystem semantics.
`sendfile-reference` establishes only direct typed Rust `fs::sendfile`
descriptor-to-descriptor transfer: x86 `sendfile=40`, direct descriptor
arguments exercised through borrowed handles, an optional mutable input offset that preserves the input
descriptor position, null-offset shared-position advancement, short EOF
transfers, and direct invalid-offset/closed-descriptor errors. It does not
select a C API, errno TLS, pathname opening, socket/network or splice
semantics, durability, or kernel descriptor ownership transfer. Passing a
reference or `BorrowedFd` retains Rust descriptor ownership; an owning `AsFd`
passed by value follows ordinary Rust move/drop semantics.
`copy-file-range-reference` establishes only direct typed Rust
`fs::copy_file_range` descriptor-range copying: x86 `copy_file_range=326`,
two optional mutable input/output offsets with staged success-only commit,
shared-position advancement when either offset is null, short and EOF-zero
transfers, and fixed zero flags. Its C fixture records raw/pinned-musl negative
offset `EOVERFLOW`, nonzero-flag `EINVAL`, and closed-descriptor `EBADF`; the
typed Rust boundary rejects unrepresentable unsigned ranges with `Errno::INVAL`
before either `AsFd` conversion. It does not select C APIs or errno TLS,
pathname operations, copy flags, sendfile/splice fallbacks, filesystem copy
policy, or durability.
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
`statfs-reference` establishes the direct typed-Rust x86
`fs::{statfs, fstatfs, statvfs, fstatvfs}` capacity-metadata family: x86
`statfs=137`/`fstatfs=138`, the complete 120-byte align-8 Linux `struct
statfs` output layout, path and borrowed-descriptor observations, and the
documented `StatFs` to `StatVfs` mapping. The raw and pinned-musl fixture
checks path/descriptor agreement, fragment-size fallback, available-node and
first-filesystem-id-word mapping, preserved mount flags, and direct
`ENOENT`/`EBADF`.
It does not select C `statfs`/`statvfs` APIs, errno TLS, pathname opening, or
the broader record-owning filesystem/path family.
`timestamp-reference` establishes the bounded typed-Rust x86 timestamp-
mutation family through `utimensat=280` and `syscall4`'s
`rdi`/`rsi`/`rdx`/`r10` placement. It covers descriptor timestamps through
`fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT, futimens}`, directory-
relative and current-directory timestamp mutation, final-symlink timestamp
mutation, and the legacy whole-second form. The two signed 16-byte align-8
Linux `timespec` values, explicit and current/omit behavior, path selection,
and direct kernel validation are pinned against musl/raw evidence. It does
not select general `filesystem.path-core`, a public C timestamp ABI, or errno
TLS.
`posix-fallocate-reference` establishes only the typed Rust
`fs::posix_fallocate` mode-zero range-allocation boundary: x86
`fallocate=285`, signed 64-bit `off_t`, fixed mode zero, allocation over an
unlinked regular-file fixture with retained prefix and zero-filled new range,
and stable file position. Pinned musl's C
spelling returns `EINVAL`/`EBADF` directly without changing `errno`, while the
raw syscall returns `-1` with `errno`; the typed Rust boundary instead returns
`Errno` and rejects unrepresentable unsigned ranges before it borrows the
descriptor. It does not select a C API, pathname allocation, general Linux
fallocate modes, filesystem fallback or policy, durability, or errno TLS.
`fallocate-reference` establishes the separate typed Rust `fs::fallocate`
closed-mode boundary: x86 `fallocate=285`, signed 64-bit `off_t`,
`ALLOCATE=0`, `KEEP_SIZE=0x01`, `PUNCH_HOLE=0x02`, and `ZERO_RANGE=0x10`,
stable file position, extension and keep-size behavior, and direct invalid
combinations. A fixture filesystem that supports zero-range or punch-hole
proves their retained-edge and zeroed-range effects; otherwise matched C/raw
`EOPNOTSUPP` preserves size and position. The safe Rust facade preflights
unknown flags, invalid combinations, and unsigned ranges before borrowing the
descriptor. The ordinary C `fallocate` wrapper uses `-1` with `errno`, as does
the raw syscall; C ABI and errno TLS remain excluded. It does not select future
flags, pathname allocation, filesystem fallback or policy, durability, or
public x86 support.
`file-position-reference` establishes the remaining admitted typed x86
`lseek`/`fsync`/`fdatasync` boundary: signed 64-bit `off_t`, syscall numbers
8/74/75, `SEEK_SET`/`SEEK_CUR`/`SEEK_END` positions, accepted descriptor-sync
requests, and direct `EINVAL`/`ESPIPE`/`EBADF` errors. Its fresh memfd
avoids host-filesystem durability claims. It does not select a C filesystem
API, pathname behavior, or broader filesystem semantics.
`sync-reference` establishes only the typed Rust `fs::sync` request: x86
`sync=162`, system-wide Linux kernel/filesystem writeback completion, and its
specified unit success contract. It neither promises storage-cache or
power-loss durability nor selects `syncfs`, a C filesystem API, pathname
opening, or broader filesystem behavior.
`syncfs-reference` establishes only the typed Rust `fs::syncfs` request:
x86 `syncfs=306`, a borrowed descriptor, raw/pinned-musl regular-file
success with stable file position, accepted pipefs descriptors, and direct
invalid-descriptor `EBADF`. A successful request is a kernel/filesystem
writeback completion point, not a media-cache durability promise. It does not
select the separate process/system-wide `sync(2)` operation, a C filesystem
API, pathname opening, or broader filesystem behavior.
`sync-file-range-reference` establishes only the admitted typed Rust
`io::{sync_file_range, SyncFileRangeFlags}` range-writeback request: x86
`sync_file_range=277`, four scalar syscall arguments, signed 64-bit `loff_t`,
the closed `WAIT_BEFORE`/`WRITE`/`WAIT_AFTER` flags, Linux's zero-length
through-EOF request, preserved file position, safe local invalid-input
rejection, and direct kernel errors. It does not claim metadata or
storage-cache durability, select a C filesystem API, pathname opening, or
broader filesystem behavior.
`rand-reference`, `time-abi-reference`, `time-observation-reference`,
`relative-sleep-reference`, `clock-nanosleep-reference`,
`getitimer-reference`, `setitimer-reference`, `timerfd-reference`, `pselect-reference`,
`poll-reference`, `ppoll-reference`, and `epoll-reference`,
`process-identity-reference`, `child-ownership-reference`, `getgroups-reference`, `process-session-reference`,
`setpriority-reference`, `rlimit-targeted-reference`, `setrlimit-reference`, `umask-reference`,
`pidfd-open-reference`, `fcntl-getlk-reference`, `fcntl-status-reference`,
`flock-reference`,
`sendfile-reference`,
`copy-file-range-reference`,
`sync-reference`, `syncfs-reference`, `sync-file-range-reference`,
`scheduler-priority-bounds-reference`, `rlimit-reference`, `rusage-reference`,
`times-reference`,
`fstat-reference`, `statat-reference`, `getcwd-reference`,
`readlinkat-reference`, `access-reference`, `system-reference`, and
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
`timerfd-reference` proves the direct typed x86
`time::{timerfd_create, timerfd_settime, timerfd_gettime}` boundary: the
32-byte, align-8 `itimerspec` record with offsets 0/16, syscall numbers
283/286/287, all five named Linux timer clocks with alarm-clock capability
results, known and future-bit kernel validation, and raw/pinned-musl
relative/absolute behavior, `CANCEL_ON_SET` acceptance, periodic-setting,
disarm, and expiration-read behavior.
C facades, errno TLS, and broader timer policy remain excluded.
`getitimer-reference` proves the direct typed read-only interval-timer query:
the x86 `itimerval` record, closed selectors, canonical transient output, and
invalid-selector `EINVAL`. It does not select C time APIs, timer/signal delivery
policy, or a broader process API.
`setitimer-reference` proves the x86 `time.process-interval-control` boundary:
syscall 38, all three `ITIMER_*` selectors, validated microsecond settings,
complete old-setting exchange, and malformed-`timeval` `EINVAL` behavior in
short-lived child processes. Its Rust-only `alarm` and `ualarm` aliases operate
on `ITIMER_REAL`; `alarm` returns a prior fractional remainder rounded up to
seconds, while `ualarm` returns bounded whole microseconds. The pinned-musl C
`ualarm` comparison is valid only for subsecond inputs because musl does not
normalize inputs of one second or more; the Rust facade intentionally accepts
`u32` microseconds through `Duration`. These aliases add no C ABI. C time APIs,
timer/signal delivery policy, and broader timer control remain excluded.
`statat-reference` proves only the x86 `newfstatat` record with CWD and
`AT_SYMLINK_NOFOLLOW`; it is the private `st_dev`/`st_ino` identity foundation
for the separately admitted logical-current-directory name. It does not select
`AT_EMPTY_PATH` or the aggregate `filesystem.path-core` capability.
`getcwd-reference` proves the direct x86 typed
`process::{getcwd,getcwd_alloc,get_current_dir_name,get_current_dir_name_alloc}`
boundary. Raw/pinned-musl `getcwd=79` proves physical prefix and `ERANGE`
behavior, including the intentional musl zero-size `EINVAL` versus raw-kernel
`ERANGE` difference. Pinned musl's environment-backed
`get_current_dir_name` and raw/musl `newfstatat=262` establish the matching
device/inode trust decision; the Rust facade instead receives an explicit
caller-owned `&CStr` snapshot and requires it to be nonempty and absolute.
Only a matching snapshot preserves its exact logical spelling; mismatch,
relative, empty, or absent snapshots fall back to physical `getcwd`. The
alloc-gated native Rust tests cover physical retry plus logical and fallback
results. The facade neither reads `PWD` nor selects C `get_current_dir_name`.
The separate `cwd-canonicalize-reference` gate selects direct `chdir`/`fchdir`
only; C APIs, errno TLS, and the broader record-owning facade family remain
excluded.
`mount-reference` proves only the direct typed x86 `mount=165` and
`umount2=166` request ABI through checked non-null byte paths, optional
borrowed mount data, and matched raw/musl direct failures for a unique missing
target (`EPERM` before lookup without mount authority, or `ENOENT` after it),
plus the existing `MS_*`/`MNT_*` bit vocabulary. It runs without
`CAP_SYS_ADMIN` and deliberately does not attempt or claim a successful mount,
unmount, bind, remount, propagation, or other mount-namespace transition. It
does not select C mount or errno APIs, `pivot_root`, namespace-management
policy, the newer filesystem-descriptor mount API family (`fsopen`,
`fsconfig`, `fsmount`, `open_tree`, `move_mount`, or `mount_setattr`), or
public x86 support.
`ipc-reference` proves the separate typed POSIX named-message-queue boundary:
the POSIX leading-slash versus raw-kernel name translation, x86 LP64
`mq_attr`/absolute-deadline records, owned close-on-exec descriptors,
attributes, priority ordering and range, full/empty nonblocking errors,
absolute real-time deadlines, and unlink-after-open lifetime. It requires live
native mqueuefs evidence and fails rather than falling back or skipping when
that facility is unavailable. It does not select `mq_notify`, POSIX shared
memory, SysV IPC, semaphores, C IPC/errno APIs, or public x86 support.
`shm-reference` proves the separate typed POSIX shared-memory boundary: a
validated POSIX name maps directly to `/dev/shm`, the returned descriptor is
owned and always close-on-exec, requested status flags otherwise stay direct,
and unlink-after-open lifetime remains a kernel property. The Rust facade
intentionally matches the existing AArch64/Rustix direct boundary by forcing
only `O_CLOEXEC`; pinned musl's C `shm_open` wrapper additionally forces
`O_NOFOLLOW|O_NONBLOCK`, which this private native API does not emulate. It
does not select a C API/errno TLS/cancellation behavior, SysV shared memory,
semaphores, mapping or sizing policy, mount fallback, global registries, or
public x86 support.
`inotify-reference` proves the separate typed inotify boundary: close-on-exec
and nonblocking descriptor creation, byte-preserving event records in
caller-owned storage, descriptor-scoped watch ownership, explicit watch
removal, malformed-record detection, and direct errors. It does not select C
inotify/errno APIs, legacy `inotify_init`, fanotify, recursive/background
watching, global registries, namespaces/capability mutation, or public x86
support.
`readlinkat-reference` proves only the private x86 caller-buffer-only
`readlinkat` target query: the caller owns writable storage, the result is a
non-NUL-terminated initialized prefix, and a short output buffer succeeds with
its truncated prefix. Its direct raw kernel boundary rejects a zero-length
buffer with `EINVAL`, unlike musl's empty successful C-wrapper result. It does
not by itself select allocation-backed path APIs or the aggregate
`filesystem.path-core` capability; the dedicated path-core command supplies
the selected owned-readlink evidence.
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
`libc-syscall` compiles only the isolated raw syscall module probe.
`libc-errno-tls` compiles only the standalone errno source probe and its C
fixture; the same owner supplies the selected static archive boundaries.
`libc-stat-compat` builds the selected x86 `crabc-libc` static archive and
links one freestanding C `stat` fixture after the pinned-musl oracle run. Its
test-only initial-TLS setup proves only `stat`/`lstat`/`fstat`/`fstatat`, their
historical aliases, the x86 `struct stat` record, and calling-thread `errno`.
It does not provide `libc.so`, dynamic TLS, a general pthread runtime, normal CRT startup,
sysroot integration, allocator, or general C ABI support.
`libc-credentials` links the same static archive into a separate freestanding
C fixture. It proves only the selected credential setter profiles and
initial-TLS errno translation; it does not provide `libc.so`, dynamic TLS, a
general pthread runtime, normal CRT startup, sysroot integration, allocator, or general C ABI
support.
`libc-bootstrap-primitives` links the same static archive into one
freestanding project-header C fixture after an equivalent pinned-musl run. It
selects only fixed musl-derived memory comparison/copy/fill, x87/MXCSR fenv,
and normal/signal-mask continuation leaves, plus the fixture-local initial-TLS
errno setup it observes. It proves narrow primitive behavior and no ambient
runtime dependency; it does not provide `libc.so`, dynamic TLS, a general pthread runtime,
normal CRT startup, sysroot integration, allocator, or general C ABI support.
`libc-signal-control` links that static archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
simple application signal sets, `sigaction`/`signal`, calling-thread mask and
pending state, musl's partial public output writes, and the exact hidden
syscall-15 restorer relocation. Its fixture-local raw tgkill delivery does not select a C delivery wrapper, generic process signal
behavior, waits, queues, alternate stacks, pthread signal policy, or a general
signal runtime.
`libc-termios-control` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
fixed baud/raw helpers, named attribute/queue/flow/break requests, and fixed
window-size records. The selected C `tcgetattr`/`tcsetattr` boundary passes the
public record directly so Linux consumes only its 36-byte prefix; it excludes
generic ioctl, `tcdrain`/cancellation, C terminal/session/PTY policy, dynamic
libc, CRT/TLS lifecycle, loader, sysroot, and public x86 support.
`libc-process-context` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
scalar identity, reversible `umask`, and named process-group/session wrappers;
raw fixture children contain `setpgrp`/`setpgid`/`setsid` state transitions.
It does not provide C fork/exec, generic process control, or pthread
coordination; child reaping is a separately bounded archive artifact. It also
does not provide dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public
x86 support.
`libc-environment` is the private selected `static-c-environment` slice for
exactly `process.environment-mutation`: `clearenv`, `setenv`, and `unsetenv`.
`getenv`, `putenv`, and the one-object `__environ`/`environ`/underscore aliases
are supporting ABI only and do not select `process.globals`. After the pinned-
musl comparison, the real crabc `crt1`/`crti`/`crtn` candidate publishes entry-
stack `envp` before an ordinary `.init_array` constructor; the constructor's
`setenv` mutation is visible in `main`. It proves ordinary lookup, copied versus
caller-owned replacement, duplicate removal, direct-vector mutation, growth,
and reclamation. Fixture-only `--wrap=malloc`/`--wrap=realloc` cases prove
pre-publication `ENOMEM` rollback for copied-string replacement, direct-vector
append, and owned-vector append; post-publication ownership-registry allocation
failure remains outside the claim. Returned-pointer use, direct writers,
caller-owned `putenv` storage, signals, and fork/exec transitions remain
caller-coordinated. It does not provide secure execution, a general environment
lifecycle, dynamic libc, CRT completion, loader, sysroot, family completion,
promotion, or public x86 support.
`libc-secure-environment` separately selects GNU `secure_getenv` only.
Static startup composes the already-qualified raw auxv observation with a
private musl-shaped secure cache: the final `AT_SECURE`/UID/EUID/GID/EGID
values decide whether it returns null without inspecting its name. In an
ordinary start it returns the selected borrowed `getenv` value. The synthetic
vectors prove final-tag and UID/EUID-mismatch secure cases. It does not alter
raw `getauxval`, sanitize descriptors, mutate credentials or environment,
manage execution, signals, loaders, or a general x86 runtime.
`libc-login-name` composes that bounded environment owner without widening it.
It selects exactly `getlogin` and `getlogin_r`: first-match borrowed `LOGNAME`,
direct ENXIO/ERANGE results, and exact caller-buffer copying with stale errno.
It owns no storage or lock and does not add passwd/utmp/terminal lookup,
allocation, secure-execution policy, session identity, process supervision,
dynamic runtime, promotion, or public x86 support.
`libc-child-reaping` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
`wait`, `waitpid`, and `waitid`; raw clone/pipe fixture control fixes the
`WNOHANG` no-event, `WNOWAIT` observation, exact reap, and post-reap `ECHILD`
states without selecting C fork/exec or a general process supervisor. It
deliberately omits musl pthread-cancellation and atfork machinery, dynamic
libc, CRT/TLS lifecycle, loader, sysroot, and public x86 support.
`libc-wait-extensions` is separate private GNU/BSD evidence after an
equivalent pinned-musl run. It selects only historical `wait3` and `wait4`,
their direct Linux wait4 syscall path, optional status/resource outputs, and
the `WNOHANG`, exact reap, and post-reap `ECHILD` states. Its raw
fork/pipe/setpgid fixture control exists only to make those waits observable;
it does not select `process.control`, C fork/exec, general process
supervision, child-reaping capability ownership, pthread cancellation or
atfork machinery, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public
x86 support.
`libc-immediate-termination` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
C11 `_Exit`: fixture-local raw clone/wait observes its exact child status,
without ordinary exit, quick-exit hooks, stdio/fini processing, fork
coordination, pthread lifecycle, dynamic libc, CRT/TLS lifecycle, loader,
sysroot, or public x86 support.
`libc-posix-exit` separately links that archive into a freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
POSIX `_exit`: the complete musl source forwards once to the separately
selected C11 `_Exit` sibling, while fixture-local raw clone/wait observes child
status 41. It does not select ordinary exit/hook/stdio/fini state, fork
coordination, pthread lifecycle, dynamic libc, CRT/TLS lifecycle, loader,
sysroot, or public x86 support.
`libc-clock-gettime` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the ordinary `clock_gettime` zero-or-`-1`/initial-TLS-errno boundary for
realtime, monotonic, and process-CPU observations, including invalid-clock
errors. Valid calls require a writable output record: musl may route a clock
through vDSO code before a null pointer reaches the kernel. The direct x86
syscall-228 leaf intentionally does not import musl's vDSO resolver or its
dynamic process state. It does not
select clock resolution or mutation, `time`, calendar/timer state, pthread
cancellation, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
`libc-timegm` links that archive into a separate freestanding project-header
C fixture after an equivalent pinned-musl run. It selects only GNU/BSD
`timegm`'s caller-owned UTC `struct tm` normalization: epoch, negative-month,
leap-carry, valid-pre-epoch-minus-one, and unchanged-overflow-record behavior.
It neither reads environment/TZ state nor selects local conversion,
calendar formatting/parsing, clock observation/mutation, timer state, dynamic
libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-gmtime-r` links the same archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the caller-buffered POSIX UTC `gmtime_r` conversion: epoch, pre-epoch,
leap-day, and unchanged-overflow-record behavior. It neither reads
environment/TZ state nor selects non-reentrant storage, local conversion,
calendar formatting/parsing, clock observation/mutation, timer state, dynamic
libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-difftime` links the same archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the scalar signed-time_t subtraction followed by a binary64 return: ordinary
and endpoint-adjacent values preserve subtraction-before-conversion rounding.
It has no clock observation, timezone/calendar state, formatting, timer, or
floating-environment policy, dynamic libc, CRT/TLS lifecycle, loader, sysroot,
or public x86 support.
`libc-system-configuration` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the bounded page/tick `sysconf`, `confstr`, table-based `pathconf`/`fpathconf`,
`getpagesize`, and `getdtablesize` boundary. It follows musl's path- and
fd-independent table; the corresponding AArch64 focused dynamic fixture now
proves the same selected behavior. It does not select a full `sysconf` table,
startup/auxv ownership, filesystem capacity APIs, dynamic libc, CRT/TLS
lifecycle, loader, sysroot, or public x86 support.
`libc-mapping-core` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the caller-owned `mmap`/`munmap`/`mprotect`/`madvise`/`posix_madvise`/`mincore`
block: musl's mapping offset and `PTRDIFF_MAX` prechecks, page-rounded
`mprotect`, anonymous `EPERM` to `ENOMEM` fallback, POSIX `DONTNEED` no-op and
direct-positive-error convention, and Linux residency vectors. Its local
no-op VM-wait site is explicitly not musl's process-wide `__vm_wait` contract.
Its separate direct `msync` sibling still does not select musl cancellation,
`mremap`, `mlock*`, shared memory,
allocator, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
`libc-memory-sync` separately links that archive into one freestanding
project-header C fixture after an equivalent pinned-musl run, and runs the
eight-profile C/C++ declaration gate first. It selects only caller-owned
`msync`: x86 `msync=26`, all three public MS flag bits, Linux's flag-first and
alignment-before-zero-length validation order, and stale-errno success over a
private anonymous mapping. Pinned musl implements `msync` through its
cancellation-point syscall path; this direct artifact intentionally has no
such state machine, so it does not establish cancellation or full musl C ABI
parity. It also does not prove file-backed shared-map writeback, invalidation,
persistence, or durability. It excludes `mremap`, mlock, mapping policy,
allocator, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
`libc-memory-locking` separately links that archive into one freestanding
project-header C fixture after an equivalent pinned-musl run, and runs the
six-profile C/C++ declaration gate first. It selects only caller-owned
`mlock`, `munlock`, and GNU `mlock2(MLOCK_ONFAULT)`: direct x86
`mlock=149`/`munlock=150` wrappers, musl's zero-flags `mlock2` delegation to
`mlock`, and direct `mlock2=325` for nonzero flags. Its fixture accepts the
environment-dependent `EPERM`/`EAGAIN`/`ENOMEM` lock-limit outcome; otherwise
it proves stale-errno success, first-fault locking, invalid-flag `EINVAL`, and
overflow-range `EINVAL`. The direct musl-shaped wrappers deliberately omit a
cancellation path. It does not select `mlockall`/`munlockall`, `msync`,
`mremap`, mapping policy, allocator, dynamic libc, CRT/TLS lifecycle, loader,
sysroot, or public x86 support.
`libc-memfd-create` separately links that archive into one freestanding
project-header C fixture after an equivalent pinned-musl run, and runs the
eight-profile GNU-only C/C++ declaration gate first. It selects only direct
`memfd_create=319`: ordinary and 249-byte labels, flag forwarding, 250-byte
and all-ones-flag-word `EINVAL`, bad-pointer `EFAULT`, stale errno on success, and
fixture-local raw close cleanup. It does not select C fcntl, sealing,
memfd_secret, huge-page resource policy, descriptor lifecycle, dynamic libc,
CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-header-layouts-baseline` links one project-header C fixture and one
separately compiled freestanding C++17 companion into the same static
candidate after an equivalent pinned-musl run. It proves the named existing
record layouts and unmangled C++ references resolve only through already
selected archive APIs; it neither adds an export/header nor selects
installed-header closure, a C++ runtime, dynamic libc, CRT/TLS lifecycle,
loader, sysroot, or public x86 support.
`libc-nanosleep` links that archive into a separate freestanding project-header
C fixture after an equivalent pinned-musl run. It selects only the normal
`nanosleep` result/errno and relative remaining-pointer boundary: zero
completion preserves stale errno; malformed and null requests return
`-1`/`EINVAL` or `EFAULT`; and a fixture-local raw timer produces one
`-1`/`EINTR` result with a positive remainder. The direct x86 syscall-35 leaf
uses the selected initial-TLS errno slot and deliberately omits musl's
pthread-cancellation path. The separate `libc-sleep` artifact may delegate to
this boundary, but this fixture rejects it from its final candidate; `usleep`,
C clocks/timers, signal policy, dynamic libc, CRT/TLS lifecycle, loader,
sysroot, and public x86 support remain excluded here.
`libc-sleep` links that archive into a separate freestanding project-header C
fixture after an equivalent pinned-musl run. It selects only musl's one-call
`sleep(unsigned)` wrapper: zero seconds preserve stale errno, while a
fixture-local SIGALRM interruption publishes EINTR through the selected
nanosleep boundary and returns its nonzero truncated whole-second remainder.
It does not retry, install handlers, change masks, create timers, promise wake
timing, select pthread cancellation or `usleep`, C clock/timer state, signal
policy, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
`libc-clock-nanosleep` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the non-cancellation `clock_nanosleep` normal-call/result/pointer boundary:
direct positive errors without errno mutation, relative and absolute pointer
rules, musl's local `CLOCK_THREAD_CPUTIME_ID` `EINVAL` result, and the direct
x86 syscall-230 register path. It intentionally leaves musl's realtime
`nanosleep` route unused and pthread cancellation unselected, alongside
sleep/usleep, C clocks and timers, signal policy, dynamic libc, CRT/TLS
lifecycle, loader, sysroot, and public x86 support.
`libc-descriptor-entry` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
`open`, `openat`, and `creat`: their optional-mode ABI, musl's O_LARGEFILE
and private O_CLOEXEC F_SETFD path, direct errno results, relative descriptor
resolution, create mode, and truncation behavior. Fixture-local raw syscalls
own a PID-specific temporary directory and observe descriptor/stat state. It
does not exercise or expand the separately selected bounded C fcntl
status-control entry, path policy, a filesystem capability,
cancellation/AIO integration, dynamic libc, CRT/TLS lifecycle, loader,
sysroot, or public x86 support.
`libc-access` links that archive into a separate freestanding project-header
C fixture after an equivalent pinned-musl run. It selects only `access`,
`faccessat`, `euidaccess`, and musl's weak same-address `eaccess` alias:
direct `access=21` real-ID checks, zero-flag `faccessat=269`, and nonzero-flag
`faccessat2=439` with its fourth word in r10. A runner-provisioned root-owned
record and fixture-local raw child contain the real/effective-ID distinction;
this does not select path policy, a filesystem capability, `fchmodat`,
C credential/process APIs, cancellation, dynamic runtime, or public x86
support.
`libc-fcntl-status-control` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the public `fcntl` status/descriptor-flag commands `F_GETFD`, `F_SETFD`,
`F_GETFL`, and `F_SETFL`: legal absent-vararg and scalar-vararg dispatch,
musl's O_LARGEFILE rule, descriptor-local CLOEXEC, shared status state, and
direct errno results. The shared dispatcher routes the separately selected
pointer-bearing `F_GETLK`/`F_SETLK` forms to their sibling; every other command
returns the explicit selected-profile `EINVAL` result without reading a vararg
or issuing a syscall. It does not provide generic fcntl, locking beyond that
separate nonblocking record-lock boundary, descriptor lifecycle, filesystem
policy, cancellation, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or
public x86 support.
`libc-ioctl` links that archive into a separate freestanding project-header C
fixture after an equivalent pinned-musl run. It selects only generic
`ioctl=16` forwarding for one pointer input, one pointer output, and the two
known legal no-vararg forms `FIOCLEX`/`FIONCLEX`; the assembly entry supplies
their otherwise unspecified third SysV word as zero. Every other admitted call
in this bounded artifact requires an explicit third C word; other two-word
forms remain outside its contract. It does not select a
device vocabulary, terminal/session behavior, socket options, cancellation,
dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-descriptor-io` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
descriptor transfer, positioned I/O, signed seek/truncate, synchronization
requests, duplication, and pipe construction; raw fixture memfd/fcntl helpers
only establish files and observe flags. It does not provide C open/path,
generic fcntl-command, or vector-I/O APIs, cancellation/AIO integration, filesystem durability,
dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-descriptor-lifecycle` links the same archive into one separate
freestanding project-header C composition after an equivalent pinned-musl run.
It selects existing `open`/`openat`/`creat`, status-control `fcntl`,
descriptor-I/O, `fstat`/`fstatat`, duplication, and close leaves only. Raw
Linux calls only create and remove its PID-specific temporary directory; they
do not stand in for candidate C calls. It is not a descriptor/filesystem
capability, general C runtime, cancellation, CRT/TLS lifecycle, loader,
sysroot, family completion, or public x86 support.
`libc-descriptor-pipeline` links that archive into one separate freestanding
project-header C composition after an equivalent pinned-musl run. It proves
the existing `pipe2`/fcntl/poll/readv/writev/dup/close leaves cooperate through
one nonblocking CLOEXEC pipe and initial-TLS errno owner. It neither adds APIs
nor establishes generic descriptor policy, cancellation, CRT/TLS lifecycle,
loader, sysroot, family completion, or public x86 support.
`libc-process-resources` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the named limit, usage, priority, and `nice` wrappers; raw children contain
limit/priority changes and raw pipes only hold a live target for `prlimit`.
It does not provide C scheduler policy, cgroups, `times`, process lifecycle,
pthread coordination, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or
public x86 support.
`libc-readiness-waits` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
`poll`/GNU `ppoll`, `select`/`pselect`, `pause`, and `sigsuspend`; existing
selected pipe and simple signal-control calls only arrange readiness and
pending-mask observations. It preserves caller timeout records, proves atomic
temporary-mask restoration, and deliberately omits pthread cancellation.
`pause` retains a direct emitted-code gate rather than a racy runtime wakeup
harness. It does not provide epoll/eventfd, C open/path or generic fcntl-command APIs, generic signal
delivery/waits, timers, process lifecycle, dynamic libc, CRT/TLS lifecycle,
loader, sysroot, or public x86 support.
`libc-system-observation` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
`uname` and `sysinfo`, including null-pointer `EFAULT` results, the complete
390-byte public `utsname` record, and the 368-byte public `sysinfo` record.
Linux writes the 112-byte `sysinfo` kernel prefix, including the first four
public `__reserved` bytes at offsets 108 through 111; offsets 112 through 367
remain caller-resident. It does not provide gethostname, system-file parsing,
process identity, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public
x86 support.
`libc-system-information` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the fixed 128-byte `sched_getaffinity` processor count and the `sysinfo`
physical/free-plus-buffer page calculations, preserving stale `errno` and the
CPU-zero fallback in a child-local affinity-error regression. It does not
provide load observation, affinity control, CPU topology, general `sysconf`,
dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-getloadavg` links that archive into a separate GNU/BSD project-header
C/C++ declaration gate and freestanding project-header C fixture after an
equivalent pinned-musl run. It selects only historical `getloadavg`: count <=
0/no-output/stale-errno, the three-entry clamp, and caller-owned binary64
output from an adjacent raw `sysinfo` snapshot. It does not provide public
sysinfo/uname, `/proc`, processor or topology policy, general `sysconf`,
dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-fcntl-record-locks` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
pointer-bearing nonblocking `F_GETLK`/`F_SETLK` record locks: the public
`struct flock` query/mutation ABI, child-observed parent conflict, release,
stale `errno`, and direct kernel errors. It does not provide `F_SETLKW`
cancellation, OFD locks, `lockf`, `flock`, generic fcntl, dynamic libc,
CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-flock` links that archive into a separate freestanding project-header C
fixture after an equivalent pinned-musl run. It selects only direct
nonblocking `flock`: public operation bits, raw-duplicate
open-file-description release state, separately opened child conflict and
later exclusive reacquisition, stale `errno`, and direct kernel errors. It
does not provide fcntl record-lock interaction, `lockf`, generic
descriptor/pathname policy, dynamic libc, CRT/TLS lifecycle, loader, sysroot,
or public x86 support.
`libc-sendfile` links that archive into a separate freestanding project-header
C fixture after an equivalent pinned-musl run. It selects only direct
regular-file `sendfile`: explicit offset advance without input-position
mutation, null-offset short transfer and EOF zero, stale `errno`, and direct
kernel errors. It does not provide pathname, socket/pipe, splice,
copy-file-range, vector-I/O, durability, cancellation, dynamic libc, CRT/TLS
lifecycle, loader, sysroot, or public x86 support.
`libc-copy-file-range` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
one direct GNU same-filesystem regular-file explicit-offset request:
wrapper/raw result and pointed-offset agreement, copied bytes, retained shared
descriptor positions, stale `errno` on success, and direct invalid-flags
`EINVAL` plus bad-input `EBADF`. It does not provide pathname or descriptor
ownership, copy fallback or cross-filesystem policy, `sendfile`/`splice`,
durability, cancellation, dynamic libc, CRT/TLS lifecycle, loader, sysroot,
or public x86 support.
`libc-splice` links that archive into a separate freestanding project-header C
fixture after an equivalent pinned-musl run. It selects only one direct GNU
regular-file-to-pipe explicit-input-offset request: wrapper/raw result and
pointed-offset agreement, copied pipe bytes, stable file position, stale
`errno` on success, and direct invalid-flags `EINVAL` plus bad-input `EBADF`.
It does not provide pathname or descriptor/pipe ownership, blocking, fallback,
general pipe/filesystem transfer policy, `tee`/`vmsplice`/`sendfile`/
`copy_file_range`, durability, cancellation, dynamic libc, CRT/TLS lifecycle,
loader, sysroot, or public x86 support.
`libc-tee` links that archive into a separate freestanding project-header C
fixture after an equivalent pinned-musl run. It selects only direct GNU
pipe-buffer `tee`: source bytes remain readable after an equal destination
copy, zero-length success retains stale `errno`, and a bad source descriptor
maps to `EBADF`. Raw fixture pipe setup does not provide pipe creation or
ownership, generic descriptor policy, `splice`/`vmsplice` transfer,
cancellation, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
`libc-sync-file-range` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
one direct GNU regular-file range request: raw result/`errno` agreement,
stable shared descriptor position, stale `errno` on success, and direct
invalid-flags `EINVAL` plus bad-descriptor `EBADF`. It does not provide pathname
or descriptor ownership, cache/writeback policy or durability, `sync`/`syncfs`,
`fallocate`, cancellation, dynamic libc, CRT/TLS lifecycle, loader, sysroot,
or public x86 support.
`libc-posix-fallocate` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
mode-zero `posix_fallocate`: an unlinked regular-file extension with retained
prefix, zero-filled range, stable position, positive direct error returns, and
unchanged `errno`. It does not provide general fallocate flags, pathname or
filesystem policy, durability, cancellation, dynamic libc, CRT/TLS lifecycle,
loader, sysroot, or public x86 support.
`descriptor-advice-header-abi` proves only the project and pinned-musl C/C++
declaration profiles for unconditional `posix_fadvise`, the six
`POSIX_FADV_*` values, the `_LARGEFILE64_SOURCE` macro alias, and GNU-only
`readahead`; it does not select a runtime C API. `libc-descriptor-advice`
links that archive into a separate freestanding project-header C fixture after
an equivalent pinned-musl run. It selects only `posix_fadvise` and GNU
`readahead` over an unlinked regular file: all six advice words, stable
descriptor position, direct POSIX versus `-1`/`errno` error conventions, and
no cache-effect claim. It does not provide cache policy, pathname behavior,
allocation, durability, cancellation, dynamic libc, CRT/TLS lifecycle, loader,
sysroot, or public x86 support.
`filesystem-capacity-header-abi` proves only the project and pinned-musl
C/C++ declaration, LP64 layout, feature-selection, and C++ C-linkage profiles
for `statfs`, `fstatfs`, `statvfs`, and `fstatvfs`, including their
`_LARGEFILE64_SOURCE` macro aliases. It does not select a runtime C API.
`libc-filesystem-capacity` links that archive into a separate freestanding
project-header C fixture after equivalent pinned-musl and raw-syscall reference
runs. It selects only direct `statfs`/`fstatfs` records and musl's derived
`statvfs`/`fstatvfs` conversion for one unlinked regular file, including
stale-`errno` success and missing-path/closed-fd errors. It does not provide
filesystem policy, pathname behavior, allocation, durability, cancellation,
dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`vector-io-header-abi` proves only the project and pinned-musl C/C++
`sys/uio.h` declarations, x86 iovec layout, feature visibility, LF64 aliases,
and C++ C-linkage profiles. `libc-vector-io` links that archive into a separate
freestanding project-header C fixture after an equivalent pinned-musl run. It
selects only `readv`/`writev`/`preadv`/`pwritev`: segment order, positioned
offset stability, invalid count/signed-offset errors, a sparse offset above
4 GiB, and musl's selected pwritev append boundary. It does not provide
cancellation, v2 or process-vm runtime, scalar descriptor I/O, stdio, dynamic
libc, CRT/TLS lifecycle, loader, sysroot, or public x86 support.
`libc-thread-pointer` compiles only the private musl-shaped `%fs:0` identity
leaf and a pinned-musl C fixture. It establishes neither a C runtime artifact,
public C ABI, pthread/TLS lifecycle, loader TLS, nor an FS-base setup path.
`libc-foundation` composes only a private fixed-six-word raw x86 syscall-to-errno bridge
with the separately proved memory and fenv leaves in one source-only object.
It is not a selected C runtime artifact or general x86 C support.
`libc-fenv` compiles only the fixed-musl x86 x87/MXCSR fenv leaf and its C
fixture. This standalone runner remains source-only evidence; its separately
selected archive use is limited to `libc-bootstrap-primitives`, not general
x86 C support.
`libc-math-complex` links one freestanding project-header C fixture against
the selected static archive after an equivalent pinned-musl run. It selects
only x87 long-double classification/sign and the nine C99 real/imaginary
accessor plus conjugation foundation symbols. The adjacent
`libc-math-complex-complete` capability gate composes those entries with the
remaining 57 complex functions; this foundation still does not independently
select scalar math, libm, libc.so, CRT/TLS lifecycle, loader, sysroot, or
public x86 support.
`libc-math-complex-complete` proves the exact 66-symbol `math.complex`
capability through project headers, a closed static archive, and 5,712 exact
pinned-musl differential records. Private scalar and compiler-complex helpers
remain local, and every long-complex public boundary retains the SysV
binary80 ABI. It does not select an elementary capability or public support.
`libc-elementary-sqrt-fenv` links a separate freestanding project-header C
fixture against that archive after an equivalent pinned-musl run. It selects
exactly `sqrt`, `sqrtf`, and x87 binary80 `sqrtl`, including their distinct
MXCSR/x87 rounding and exception behavior. Every other scalar/complex math
operation, general libm, errno policy, libc.so, CRT/TLS lifecycle, loader,
sysroot, family completion, promotion, and public x86 support remain outside
the artifact.
`libc-fenv-rounding` is the distinct selected C ABI slice for `rint`, `rintf`,
x87 binary80 `rintl`, and their three `nearbyint*` siblings. It proves all four
MXCSR/x87 rounding modes, signed zero, `FE_INEXACT` raising versus suppression,
and preservation of preexisting exceptions against pinned musl. It does not
select `exp10*`/`pow10*`, `fdim*`, integer-result rounding, general math,
family completion, promotion, or public x86 support.
`libc-math-minmax` is the separate selected binary32/binary64 extrema slice
for `fmax`, `fmaxf`, `fmin`, and `fminf`. It compares parenthesized C calls
and default-SSE/`-mfpmath=387` C++ declarations with pinned musl, then proves
ordinary/infinite values, Annex-F signed zeros, left-to-right quiet/signaling
NaN selection without `FE_INVALID`, all four MXCSR modes, and preservation of
preexisting `FE_DIVBYZERO` in one freestanding static candidate. It excludes
`fmaxl`/`fminl`, `fdim*`, bit-sign, fenv-rounding, binary80/x87, special and
complex math, family completion, promotion, and public x86 support.
`libc-math-bit-sign` is the separate selected binary32/binary64 sign-mask
slice for `fabs`, `fabsf`, `copysign`, and `copysignf`. It compares
parenthesized C calls and default-SSE/`-mfpmath=387` C++ declarations with
pinned musl, then proves ordinary/infinite values, signed zero, raw
quiet/signaling-NaN payload and sign preservation without `FE_INVALID`, all
four MXCSR modes, and preservation of preexisting `FE_DIVBYZERO` in one
freestanding static candidate. It excludes `fabsl`/`copysignl`, `fdim*`,
fmax/fmin, fenv-rounding, binary80/x87, special and complex math, family
completion, promotion, and public x86 support.
`libc-math-trunc` is the separate selected binary32/binary64 toward-zero
truncation slice for `trunc` and `truncf`. It compares parenthesized C calls
and default-SSE/`-mfpmath=387` C++ declarations with pinned musl, then proves
ordinary/integral values, signed zero, infinities, raw quiet/signaling-NaN
payloads, ordinary/raw-subnormal fractional inputs, the required
`FE_INEXACT`/no-`FE_INVALID` path, all four MXCSR modes, and preservation of
preexisting `FE_DIVBYZERO` in one freestanding static candidate. It excludes
`truncl`, `round*`, `rint*`/`nearbyint*`, bit-sign, `fdim*`, fmax/fmin,
special and complex math, binary80/x87, family completion, promotion, and
public x86 support.
`libc-math-cbrt` is the separate selected binary32/binary64 cube-root slice
for `cbrt` and `cbrtf`. It compares parenthesized C calls and default-SSE/
`-mfpmath=387` C++ declarations with pinned musl, then runs one freestanding
static candidate. The checked GCC 15.2.0 translation of musl 1.2.6
`cbrt.c`/`cbrtf.c` preserves the binary64 estimate/Newton operation order and
the cbrtf MXCSR-directed final conversion. Its raw 32-byte records cover
signed zero, normal/subnormal bounds, ordinary powers, maximum finite values,
infinities, quiet/signaling NaNs, exception flags, and requested versus
observed direction in all four MXCSR modes. It excludes `cbrtl`, fma,
fmod/remainder/modf, rounding/truncation, bit-sign/minmax/fdim,
special/complex/binary80 math, family completion, promotion, and public x86
support.
`libc-math-exp2` is the separate selected binary32/binary64 base-two
exponential slice for `exp2` and `exp2f`. It compares parenthesized C calls
and default-SSE/`-mfpmath=387` C++ declarations with pinned musl, then runs
one freestanding static candidate. The checked GCC 15.2.0 translation of musl
1.2.6 `exp2.c`/`exp2f.c` carries private binary64/binary32 tables and local
overflow/underflow helpers rather than sharing `math.special` state. Its 232
raw 32-byte records cover signed zero, tiny and subnormal boundaries,
overflow/underflow thresholds, ordinary reduction points, infinities,
quiet/signaling NaNs, IEEE flags, and requested versus observed direction in
all four MXCSR modes. It excludes `exp2l`, adjacent exp/log/pow functions,
fenv API/policy, special/complex/binary80 math, family completion, promotion,
and public x86 support.
`libc-math-expm1` is the separate selected binary32/binary64
exponential-minus-one slice for `expm1` and `expm1f`. It compares
parenthesized C calls and default-SSE/`-mfpmath=387` C++ declarations with
pinned musl, then runs one freestanding static candidate. The checked GCC
15.2.0 translation of musl 1.2.6 `expm1.c`/`expm1f.c` is a no-call closure:
it retains binary64/binary32 reduction, polynomial, raw-subnormal
`FORCE_EVAL`, and overflow behavior without ambient libm, tables, or selected
`math.special` state. Its 248 raw 32-byte records cover signed zero, tiny and
subnormal boundaries, reduction/overflow thresholds, ordinary values,
infinities, quiet/signaling NaNs, IEEE flags, and requested versus observed
direction in all four MXCSR modes. It excludes `expm1l`, adjacent exp/log/pow
functions, fenv API/policy, special/complex/binary80 math, family completion,
promotion, and public x86 support.
`libc-math-log10` is the separate selected binary32/binary64 base-ten
logarithm slice for `log10` and `log10f`. It compares parenthesized C calls
and default-SSE/`-mfpmath=387` C++ declarations with pinned musl, then runs
one freestanding static candidate. The checked GCC 15.2.0 translation of musl
1.2.6 `log10.c`/`log10f.c` is a direct no-call closure: it retains raw
classification, subnormal scaling, reduction, polynomial, and zero/negative
domain arithmetic without ambient libm, tables, or selected `math.special`
state. Its 224 raw 32-byte records cover signed zero divide-by-zero,
negative-domain invalid, tiny/subnormal and normal boundaries, reduction
points, finite extrema, infinities, quiet/signaling NaNs, IEEE flags, and
requested versus observed direction in all four MXCSR modes. It excludes
`log10l`, adjacent log/exp/pow functions, fenv API/policy,
special/complex/binary80 math, family completion, promotion, and public x86
support.
`libc-math-ceil` is the separate selected binary32/binary64 fixed-direction
ceiling slice for `ceil` and `ceilf`. It compares parenthesized C calls and
default-SSE/`-mfpmath=387` C++ declarations with pinned musl, then runs one
freestanding static candidate. The checked GCC 15.2.0 translation of musl
1.2.6 `ceil.c`/`ceilf.c` retains raw IEEE exponent/fraction handling, the
binary64 `toint` sequence, and binary32 `FORCE_EVAL` operation order. Its raw
records cover signed zero, finite normal/subnormal and integral-neighbor
boundaries, large finite values, infinities, quiet/signaling NaNs, exception
flags, and requested versus observed direction in all four MXCSR modes. It
excludes `ceill`, floor, fma, fmod, cbrt, fenv API/policy, special/complex and
binary80 math, family completion, promotion, and public x86 support.
`libc-math-floor` is the separate selected binary32/binary64 fixed-direction
floor slice for `floor` and `floorf`. It compares parenthesized C calls and
default-SSE/`-mfpmath=387` C++ declarations with pinned musl, then runs one
freestanding static candidate. The checked GCC 15.2.0 translation of musl
1.2.6 `floor.c`/`floorf.c` retains raw IEEE exponent/fraction handling, the
binary64 `toint` sequence, and binary32 `FORCE_EVAL` operation order. Its raw
records cover signed zero, finite normal/subnormal and integral-neighbor
boundaries, large finite values, infinities, quiet/signaling NaNs, exception
flags, and requested versus observed direction in all four MXCSR modes. It
excludes `floorl`, ceiling, fma, fmod, cbrt, fenv API/policy, special/complex
and binary80 math, family completion, promotion, and public x86 support.
`libc-math-round` is the separate selected binary32/binary64 half-away slice
for `round` and `roundf`. It compares parenthesized C calls and default-SSE/
`-mfpmath=387` C++ declarations with pinned musl, then runs one freestanding
static candidate. The checked GCC 15.2.0 translation of musl 1.2.6
`round.c`/`roundf.c` retains sign normalization, the `toint` add/subtract
sequence, and the half-away correction. Its raw records cover signed zero,
finite normal/subnormal and integral-neighbor boundaries, halfway values,
large finite values, infinities, quiet/signaling NaNs, exception flags, and
requested versus observed direction in all four MXCSR modes. It excludes
`roundl`, fenv API/policy, directed ceiling/floor, fma, fmod, cbrt,
special/complex and binary80 math, family completion, promotion, and public
x86 support.
`libc-math-log2` is the separate selected binary32/binary64 scalar slice for
`log2` and `log2f`. It compares parenthesized C calls and default-SSE/
`-mfpmath=387` C++ declarations with pinned musl, then runs one freestanding
static candidate. The checked GCC 15.2.0 translation of musl 1.2.6
`log2.c`/`log2f.c` with its exact local data/error closure retains the table
reduction, close-to-one reconstruction, subnormal handling, and exceptional
expressions. Its raw records cover signed zero, finite normal/subnormal and
power-of-two-neighbor boundaries, large finite values, infinities,
quiet/signaling NaNs, exception flags, and requested versus observed direction
in all four MXCSR modes. It excludes `log2l`, other log/exp families,
fenv API/policy, special/complex and binary80 math, family completion,
promotion, and public x86 support.
`libc-math-elementary-long-double` proves the exact 35-symbol
`math.elementary-long-double` capability through project headers, a closed
static archive, and 2,764 exact pinned-musl binary80/fenv records across all
four rounding modes. The new source-faithful providers and argument-reduction
closure remain local, while every public long-double boundary retains the SysV
binary80 ABI. It does not select fenv-sensitive scalar math, general libm, or
public x86 support.
`libc-memory` compiles only the fixed-musl x86 memory leaf and its C fixture.
This standalone runner remains source-only evidence; its separately selected
archive use is limited to `libc-bootstrap-primitives`, not a general C string
or runtime claim.
`libc-setjmp` compiles only the isolated control-transfer assembly leaf. This
standalone runner remains source-only evidence; its separately selected archive
use is limited to `libc-bootstrap-primitives`, not general x86 C support.
`libc-atomic` compiles only the unintegrated x86 atomic-helper leaf.
`libc-clone-raw` compiles only the private musl-shaped x86 process-clone
machine-boundary leaf. It does not provide public `clone`, pthread, or TLS
support.
`libc-signal-foundation` compiles only the private musl-shaped x86 public-to-
kernel signal-action record packer and syscall-15 restorer. Its source-only
runner does not itself install or deliver a handler; the selected
`libc-signal-control` artifact owns the narrow public action/set/mask surface.
`ldso-relocation` compiles only the unintegrated checked relocation source.
`ldso-image` compiles only the unintegrated checked ELF image parser.
`ldso-initial-graph` builds one private self-relocating ET_DYN interpreter and
one fixed main PIE -> mid.so -> leaf.so graph. It selects only RELATIVE,
GLOB_DAT, and JUMP_SLOT relocation, absolute fixture RUNPATH lookup,
dependency DSO init arrays, and interpreter-and-graph PT_GNU_RELRO sealing;
the runner rejects malformed-file-range/TLS/relocation/tag/flag/main-init
mutations. It is not a general x86 ldso, CRT, loader TLS, dlfcn, sysroot, or
public-support claim.
`ldso-initial-tls` is a separate private Variant-II GNU-Dynamic TLS graph:
one TLS-free main and two TLS DSOs prove initial PT_TLS copying, TBSS,
alignment, DTPMOD/DTPOFF plus `__tls_get_addr`, and fail-closed malformed
TLS/TPOFF/static-TLS inputs. It remains neither general loader or pthread
TLS, dynamic CRT/sysroot, nor public x86 support.
`ldso-initial-exec-tls` is its cfg-isolated fixed-topology sibling: the same
main -> mid -> leaf graph admits `DF_STATIC_TLS` and one leaf-local
`R_X86_64_TPOFF64` definition while retaining GNU-Dynamic DTPMOD/DTPOFF
accesses. It rejects a missing/extra static-TLS flag, a nonzero TPOFF addend,
and all other initial-exec/TLSDESC forms. It remains private loader evidence,
not general static-TLS/pthread support, an installed dynamic runtime,
CRT/sysroot, or public x86 support.
`ldso-owned-crt-handoff` is a separate private post-relocation sibling of the
no-TLS initial graph. One Rust-produced Scrt1.o main weakly imports one
RELRO-sealed v1 record after direct entry; it defers only the two fixed DSO
init arrays to that record, never `%rdx`, and proves clean-environment,
absent-record, malformed-record, and out-of-order-finalizer boundaries. It
does not select a general loader, DSO finalization, candidate libc, dynamic
CRT/sysroot, or public x86 support.
`ldso-fixed-graph-dlfcn` is another private no-TLS sibling. Its exact weak-main
64-byte callback record gives only the already-loaded main/mid/leaf graph
stable reference tokens, scoped symbol lookup, and copied address/snapshot/
information results. It rejects strong-main and weak-DSO record imports,
unknown names, stale or forged handles, and global promotion; close never finalizes or unmaps startup
objects. It is not public dlfcn, runtime mapping/search, process RuntimeV1,
candidate libc, a general loader, dynamic CRT/sysroot, or public x86 support.
`ldso-public-dlfcn` links the staged static x86 libc archive into a real PIE and
exports the musl-shaped public dlopen/dlsym/dlclose/dlerror plus
dladdr/dlinfo/dl_iterate_phdr surface over that exact loader record. Its
32-live-thread TID-keyed diagnostic table does not require loader TLS. The gate
proves public C/C++ ABI layouts, per-thread one-shot errors, the pinned-musl
live-handle-within-the-32-slot-bound `dlinfo(-7)` output-preserving exact
`Unsupported request -7` diagnostic that survives one valid `RTLD_DI_LINKMAP`
call, the pinned-musl `dlclose(NULL) == 1` exact `Invalid library handle 0`
diagnostic, and a live retained-handle empty-name `dlsym` null result with exact
`Symbol not found: ` only after the bounded loader confirms `loader symbol name
is invalid`; non-empty missing names, null symbol pointers, and invalid handles
retain existing loader paths. A seeded writable `Dl_info` also proves the
pinned-musl `dladdr(NULL)` zero result leaves the record and `dlerror` clear;
the candidate also preserves a non-null no-image record only when its fixed
graph confirms `loader address not found`, while malformed/unavailable records
continue to clear output and fail closed. The gate also proves that only this
non-runtime public bridge returns musl's permanent main
handle with clear `dlerror` for `dlopen(NULL, RTLD_NOLOAD)` before mode
processing; the bounded runtime-mapping sibling retains its bare NULL/NOLOAD
initial-object rejection. Musl `ldso/dynlink.c:dl_iterate_phdr` invokes a
callback before taking its next-image reader lock; after the existing
unknown-object failure, the first callback consumes that nonempty same-thread
diagnostic, returns `74`, and leaves the next `dlerror` null. This is not
callback-driven mapping, graph mutation, or general loader reentrancy. The
gate also proves stale handles, malformed and absent records, and copied
introspection, while continuing to exclude search, mutation, global promotion,
RTLD_NEXT, finalization, and unload.
It remains a staged fixed-graph artifact, not capability or platform promotion.
`ldso-dladdr-symbol-bounds` is a separate no-TLS fixed-graph differential for
one pinned-musl `dladdr` boundary: a four-byte public leaf dynamic object names
its exact and interior addresses, while its one-past private mapped padding
retains only the containing image name/base and has null symbol fields. It
ratchets the existing seven-symbol static archive without adding a declaration
or loader operation, proves malformed and absent records fail closed, and does
not select dynamic lookup, mapping, unload, dlfcn capability, or public x86
support.
`ldso-bounded-dlopen` admits one append-only runtime mapping through the main
image's already-validated absolute RUNPATH. It proves serialized concurrent
open, one validated executable legacy `DT_INIT` entry followed by its bounded
constructor array, each exactly once, plus one validated but inert legacy
`DT_FINI` target, retained dependencies, copied four-image introspection, and
bounded `RTLD_NOLOAD` acquisitions of only that published runtime basename.
Those legacy tags are limited to the appended DSO: initial main/mid/leaf
`DT_INIT`/`DT_FINI` remain reject-only, and a malformed runtime target fails
before publication. Pinned musl leaves the admitted legacy fini target inert
on ordinary final close; `DT_FINI_ARRAY` remains reject-only.
The same fourth-slot DSO may carry one bounded `DT_PREINIT_ARRAY`/
`DT_PREINIT_ARRAYSZ` pair as inert metadata: pinned musl and the candidate
leave its entries undispatched, while an out-of-load pair fails before
publication. Initial main/mid/leaf preinit tags remain reject-only.
Before publication, `NULL`, and named initial-graph identities fail closed
without mapping; PT_TLS/malformed rejection and a hard one-object capacity
remain enforced. `RTLD_NODELETE` is a lifecycle-neutral accepted flag
only for the same appended object: process-lifetime mapping already retains it,
while closed explicit tokens still go stale. It does not provide general search, recursive
dependency mapping, TLS growth, global promotion, RTLD_NEXT, `DT_FINI_ARRAY`,
finalization/unload, general already-loaded-object queries, capability
selection, or public x86 support.
`ldso-dynamic-admission` executes the initial no-TLS, GNU-Dynamic TLS, owned-
CRT, copied-introspection, retained-object-dlfcn, public-C-bridge and finite-
symbol-dladdr fixed-graph,
and bounded runtime-mapping/DT_INIT/inert-DT_FINI/DT_PREINIT_ARRAY/RTLD_NOLOAD/RTLD_NODELETE
fixtures as one consumed admission gate. Their fresh candidate ELF inspection
and negative launches retain only the explicit accepted shapes and rejected
metadata, relocation, record, handle, and scope forms. It is not a general x86 ldso,
public dlfcn, runtime mapping/search, dynamic CRT/sysroot, or public-support
claim.
None of the other C-runtime commands is a crabc-libc or crabc-ldso build,
general facade admission, or C ABI support claim.
  ether-line-header-abi  compile the staged x86 C/C++ legacy Ethernet-line declaration
  libc-ether-line  run the static x86 crabc-libc legacy Ethernet-line slice
  ether-header-abi  compile the staged x86 C/C++ complete musl ether.c declarations
  libc-ether  run the static x86 crabc-libc complete musl ether.c provider slice
  protocol-database-header-abi  compile the staged x86 C/C++ musl proto.c declarations
  libc-protocol-database  run the static x86 crabc-libc musl proto.c provider slice
  libc-posix-spawn-file-actions-init  run the static x86 crabc-libc POSIX spawn file-actions init slice
  libc-posix-spawn-file-actions  run the opt-in mixed-runtime x86 POSIX spawn file-actions lifecycle
  libc-posix-spawnattr-destroy  run the static x86 crabc-libc POSIX spawn-attribute destroy slice
  libc-posix-spawnattr-getflags  run the static x86 crabc-libc POSIX spawn-attribute getflags slice
  libc-posix-spawnattr-setpgroup  run the static x86 crabc-libc POSIX spawn-attribute setpgroup slice
  libc-posix-spawnattr-setschedparam  run the static x86 crabc-libc POSIX spawn-attribute setschedparam slice
  libc-posix-spawnattr-setschedpolicy  run the static x86 crabc-libc POSIX spawn-attribute setschedpolicy slice
  libc-res-init  run the static x86 crabc-libc legacy resolver-initializer slice
  posix-spawn-file-actions-init-header-abi  compile the staged x86 C/C++ POSIX spawn file-actions init declaration
  posix-spawn-file-actions-header-abi  compile the staged x86 C/C++ POSIX spawn file-actions declarations
  posix-spawnattr-destroy-header-abi  compile the staged x86 C/C++ POSIX spawn-attribute destroy declaration
  posix-spawnattr-getflags-header-abi  compile the staged x86 C/C++ POSIX spawn-attribute getflags declaration
  posix-spawnattr-setpgroup-header-abi  compile the staged x86 C/C++ POSIX spawn-attribute setpgroup declaration
  posix-spawnattr-setschedparam-header-abi  compile the staged x86 C/C++ POSIX spawn-attribute setschedparam declaration
  posix-spawnattr-setschedpolicy-header-abi  compile the staged x86 C/C++ POSIX spawn-attribute setschedpolicy declaration
  res-init-header-abi  compile the staged x86 C/C++ legacy resolver-initializer declaration
  h-errno-header-abi  verify x86 <netdb.h> h_errno C/C++ feature visibility and linkage
  resolver-runtime-header-abi  verify x86 C/C++ resolver-state and legacy resolver ABI
  c32rtomb-header-abi  verify x86 C11 UTF-32 encoder C/C++ declarations and linkage
  uchar-stateful-header-abi  verify x86 C11 stateful uchar C/C++ declarations and linkage
  chown-header-abi  verify selected x86 POSIX chown C/C++ declarations
  libc-c32rtomb  run the static x86 crabc-libc C11 UTF-32 encoder adapter
  libc-uchar-stateful  run the static x86 crabc-libc stateful uchar conversion block
  libc-chown  run the static x86 crabc-libc chown leaf
  libc-sync  run the static x86 crabc-libc void sync leaf
  libc-sync-file-range  run the static x86 crabc-libc GNU sync_file_range leaf
  libc-unlinkat  run the static x86 crabc-libc unlinkat leaf
  sync-file-range-header-abi  verify selected x86 GNU sync_file_range C/C++ declarations
  sync-header-abi  verify selected x86 X/Open/GNU/BSD sync C/C++ declarations
  unlinkat-header-abi  verify selected x86 POSIX unlinkat C/C++ declarations
  libc-math-asinh  run the static x86 asinh/asinhf scalar slice
  libc-math-cos  run the static x86 cos/cosf scalar slice
  libc-math-cosh  run the static x86 cosh/coshf scalar slice
  libc-math-exp  run the static x86 exp/expf scalar slice
  libc-math-exp10f  run the static x86 GNU exp10f/pow10f scalar slice
  libc-math-sinh  run the static x86 sinh/sinhf scalar slice
  libc-pthread-spin-init  run the static x86 crabc-libc bounded pthread spin-init record slice
  pthread-spin-init-header-abi  verify x86 pthread_spin_init C/C++ ABI/linkage
  libc-math-log  run the static x86 log/logf scalar natural-logarithm slice
  libc-math-sin  run the static x86 sin/sinf scalar trigonometric slice
  libc-math-tan  run the static x86 tan/tanf scalar trigonometric slice
  math-log-header-abi  verify x86 log/logf C++ ABI/linkage
  math-sin-header-abi  verify x86 sin/sinf C++ ABI/linkage
  math-tan-header-abi  verify x86 tan/tanf C++ ABI/linkage
  libc-inet-netof  run the archive-free static x86 crabc-libc classful IPv4 network-part slice
  libc-inet-network  run the static x86 crabc-libc inet_network parser-composition slice
  libc-ns-put32  run the archive-free static x86 crabc-libc DNS 32-bit wire-write slice
  libc-ns-skiprr  run the static x86 crabc-libc DNS resource-record span slice
  libc-nameser-wire-aggregate  run the static x86 crabc-libc nameser wire/data composition slice
  libc-nameser-message-parser  run the static x86 crabc-libc nameserver message-parser slice
  libc-io-permissions  run the opt-in static x86 iopl/ioperm negative-path slice
  libc-personality  run the static x86 process-personality slice
  libc-sched-getaffinity  run the static x86 GNU scheduler-affinity observation slice
  libc-sched-setaffinity  run the static x86 GNU scheduler-affinity mutation slice
  libc-sched-getparam  run the static x86 musl-ENOSYS scheduler-record observation slice
  libc-sched-setparam  run the static x86 musl-ENOSYS scheduler-parameter compatibility slice
  libc-sched-setscheduler  run the static x86 musl-ENOSYS scheduler-policy compatibility slice
  libc-setfsgid  run the static x86 filesystem-credential setfsgid slice
  libc-setfsuid  run the static x86 filesystem-credential setfsuid slice
  personality-header-abi  compile x86 sys/personality.h C/C++ declarations
  posix-spawnattr-getpgroup-header-abi  verify x86 C/C++ spawn-attribute process-group ABI
  posix-spawnattr-signal-fields-header-abi  verify x86 C/C++ spawn-attribute signal-field ABI
  posix-spawnattr-getschedparam-header-abi  verify x86 C/C++ spawn-attribute scheduler-parameter ABI
  posix-spawnattr-getschedpolicy-header-abi  verify x86 C/C++ spawn-attribute scheduler-policy ABI
  posix-spawnattr-init-header-abi  verify x86 C/C++ spawn-attribute initialization ABI
  sched-getaffinity-header-abi  compile x86 GNU sched_getaffinity C/C++ declarations
  sched-setaffinity-header-abi  compile x86 GNU sched_setaffinity C/C++ declarations
  sched-getparam-header-abi  compile x86 sched_getparam C/C++ declarations
  sched-setparam-header-abi  compile x86 sched_setparam C/C++ declarations
  sched-setscheduler-header-abi  compile x86 sched_setscheduler C/C++ declarations
  setfsgid-header-abi  compile x86 sys/fsuid.h setfsgid C/C++ declarations
  setfsuid-header-abi  compile x86 sys/fsuid.h setfsuid C/C++ declarations
  libc-pthread-condattr-clock  run the static x86 crabc-libc condition-attribute clock record slice
  libc-pthread-condattr-pshared  run the static x86 crabc-libc condition-attribute pshared record slice
  libc-pthread-getconcurrency  run the static x86 crabc-libc fixed pthread concurrency-query slice
  libc-pthread-mutex-prioceiling-query  run the static x86 crabc-libc direct mutex priority-ceiling query slice
  libc-pthread-mutexattr-protocol-query  run the static x86 crabc-libc mutex-attribute protocol-bit query slice
  libc-pthread-mutexattr-pshared-query  run the static x86 crabc-libc mutex-attribute pshared-bit query slice
  libc-pthread-mutexattr-robust-query  run the static x86 crabc-libc mutex-attribute robust-bit query slice
  libc-pthread-mutexattr-type-query  run the static x86 crabc-libc mutex-attribute type-bit query slice
  libc-pthread-mutexattr-type-setter  run the static x86 crabc-libc mutex-attribute type-bit setter slice
  libc-pthread-setconcurrency  run the static x86 crabc-libc stateless pthread concurrency-status slice
  libc-lrand48  run the static x86 crabc-libc legacy rand48 provider slice
  libc-rand-r  run the static x86 crabc-libc caller-state rand_r slice
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
    prepare_work_dir
    # Older fixtures spell /tmp explicitly. This compatibility bind contains
    # their writes too; new runners use the repository-local TMPDIR directly.
    docker run --rm --init \
        "${GIT_METADATA_MOUNT[@]}" \
        --platform "$PLATFORM" \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CRABC_WORK_DIR=/workspace/.work/x86_64 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TMP_DIR:/tmp" --volume "$WORK_DIR:/workspace/.work/x86_64" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/x86_64/cargo" \
        "$IMAGE" "$@"
}

# Interface discovery snapshots only the disposable container's loopback
# namespace. Keeping network-none at this command boundary makes its lack of
# external resolver and database behavior structural.
run_in_network_none_container() {
    prepare_work_dir
    docker run --rm --init \
        "${GIT_METADATA_MOUNT[@]}" \
        --platform "$PLATFORM" \
        --network none \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CRABC_WORK_DIR=/workspace/.work/x86_64 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TMP_DIR:/tmp" --volume "$WORK_DIR:/workspace/.work/x86_64" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/x86_64/cargo" \
        "$IMAGE" "$@"
}

# Only the process-root-change evidence needs this privilege. Keeping it off
# the shared runner makes each additional authority explicit at its one call
# site rather than widening every native x86 command.
run_in_chroot_cap_container() {
    prepare_work_dir
    docker run --rm --init \
        "${GIT_METADATA_MOUNT[@]}" \
        --platform "$PLATFORM" \
        --cap-add=SYS_CHROOT \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CRABC_WORK_DIR=/workspace/.work/x86_64 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TMP_DIR:/tmp" --volume "$WORK_DIR:/workspace/.work/x86_64" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/x86_64/cargo" \
        "$IMAGE" "$@"
}

# Resolver execution sees only loopback and its private conventional files.
# Product construction happens separately, before network isolation.
run_in_resolver_network_container() {
    prepare_work_dir
    docker run --rm --init \
        "${GIT_METADATA_MOUNT[@]}" \
        --platform "$PLATFORM" \
        --cap-add=SYS_CHROOT \
        --network none \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CRABC_WORK_DIR=/workspace/.work/x86_64 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TMP_DIR:/tmp" --volume "$WORK_DIR:/workspace/.work/x86_64" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/x86_64/cargo" \
        "$IMAGE" "$@"
}

# The installed loader's executable-ORIGIN and AT_SECURE evidence mounts a
# read-only proc filesystem inside disposable child roots, with trap-owned
# unmount cleanup. Only this gate admits mount authority and disables the
# container AppArmor profile; its mount namespace contains those changes.
run_in_dynamic_loader_mount_container() {
    prepare_work_dir
    docker run --rm --init \
        "${GIT_METADATA_MOUNT[@]}" \
        --platform "$PLATFORM" \
        --cap-add=SYS_CHROOT \
        --cap-add=SYS_ADMIN \
        --security-opt=apparmor=unconfined \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CRABC_WORK_DIR=/workspace/.work/x86_64 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TMP_DIR:/tmp" --volume "$WORK_DIR:/workspace/.work/x86_64" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/x86_64/cargo" \
        "$IMAGE" "$@"
}

# Only the UTS-identity artifact needs SYS_ADMIN, solely to create a fresh UTS
# namespace before its fixture changes hostname/domain-name state. Keeping this
# grant off the shared runner and all other artifact commands does not select a
# general namespace-management capability.
run_in_uts_cap_container() {
    prepare_work_dir
    docker run --rm --init \
        "${GIT_METADATA_MOUNT[@]}" \
        --platform "$PLATFORM" \
        --cap-add=SYS_ADMIN \
        --workdir /workspace \
        --env CARGO_HOME=/workspace/.work/x86_64/cargo \
        --env CRABC_WORK_DIR=/workspace/.work/x86_64 \
        --env TMPDIR=/workspace/.work/x86_64/tmp \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env GIT_OPTIONAL_LOCKS=0 \
        --env GIT_CONFIG_COUNT=1 \
        --env GIT_CONFIG_KEY_0=safe.directory \
        --env GIT_CONFIG_VALUE_0=/workspace \
        --volume "$ROOT_DIR:/workspace" \
        --volume "$TMP_DIR:/tmp" --volume "$WORK_DIR:/workspace/.work/x86_64" \
        --volume "$TARGET_VOLUME:/workspace/target" \
        --volume "$CARGO_VOLUME:/workspace/.work/x86_64/cargo" \
        "$IMAGE" "$@"
}

run_core_tests() {
    run_in_container bash -ceu '
        target_dir="$(mktemp -d "$TMPDIR/crabc-x86-64-core.XXXXXX")"
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

run_linux_5_10_uapi() {
    run_in_container bash /workspace/compat/x86_64/run_linux_5_10_uapi.sh
}

run_header_abi_reference() {
    run_in_container bash /workspace/compat/x86_64/run_header_abi_reference.sh
}

run_public_header_surface() {
    run_in_container bash /workspace/compat/x86_64/run_public_header_surface.sh
}

run_candidate_header_closure() {
    run_in_container bash /workspace/compat/x86_64/run_candidate_header_closure.sh
}

run_headers_layouts_aggregate() {
    run_in_container bash /workspace/compat/x86_64/run_headers_layouts_aggregate.sh
}

run_installed_header_tree_closure() {
    run_in_container bash /workspace/compat/x86_64/run_installed_header_tree_closure.sh
}

run_selected_header_install_projection() {
    run_in_container bash /workspace/compat/x86_64/run_selected_header_install_projection.sh
}

run_header_callable_visibility_matrix() {
    run_in_container bash /workspace/compat/x86_64/run_header_callable_visibility_matrix.sh
}

run_header_callable_disposition() {
    run_in_container bash /workspace/compat/x86_64/run_header_callable_disposition.sh
}

run_header_abi_matrix() {
    run_in_container bash /workspace/compat/x86_64/run_header_abi_matrix.sh
}

run_header_record_layout_matrix() {
    run_in_container bash /workspace/compat/x86_64/run_header_record_layout_matrix.sh
}

run_header_declaration_macro_visibility_matrix() {
    run_in_container bash /workspace/compat/x86_64/run_header_declaration_macro_visibility_matrix.sh
}

run_feature_profile_control_plane_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_feature_profile_control_plane_header_abi.sh
}

run_header_callable_linkage_audit() {
    run_in_container bash /workspace/compat/x86_64/run_header_callable_linkage_audit.sh
}

run_header_callable_provider_linkage_audit() {
    run_in_container bash /workspace/compat/x86_64/run_header_callable_provider_linkage_audit.sh
}

run_uapi_wrapper_matrix() {
    run_in_container bash /workspace/compat/x86_64/run_uapi_wrapper_matrix.sh
}

run_epoll_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_epoll_header_abi.sh
}

run_event_descriptors_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_event_descriptors_header_abi.sh
}

run_fanotify_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_fanotify_header_abi.sh
}

run_dirent_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_dirent_header_abi.sh
}

run_ftw_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ftw_header_abi.sh
}

run_stat_ftw_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_stat_ftw_header_source_form.sh
}

run_param_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_param_header_source_form.sh
}

run_pathname_lifecycle_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pathname_lifecycle_header_abi.sh
}

run_ioctl_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ioctl_header_abi.sh
}

run_ioctl_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_ioctl_header_source_form.sh
}

run_link_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_link_header_source_form.sh
}

run_reboot_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_reboot_header_source_form.sh
}

run_math_tgmath_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_math_tgmath_source_form.sh
}

run_mman_mcl_onfault_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_mman_mcl_onfault_header_source_form.sh
}

run_mount_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_mount_header_source_form.sh
}

run_klog_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_klog_header_source_form.sh
}

run_cachectl_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_cachectl_header_source_form.sh
}

run_sysmacros_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_sysmacros_header_source_form.sh
}

run_fcntl_event_header_topology() {
    run_in_container bash /workspace/compat/x86_64/run_fcntl_event_header_topology.sh
}

run_sys_io_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sys_io_header_abi.sh
}

run_timeval_transitive_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_timeval_transitive_header_abi.sh
}

run_sys_time_direct_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sys_time_direct_header_abi.sh
}

run_access_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_access_header_abi.sh
}

run_xattr_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_xattr_header_abi.sh
}

run_header_abi_project() {
    run_in_container bash /workspace/compat/x86_64/run_project_header_abi.sh
}

run_math_complex_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_complex_header_abi.sh
}

run_math_complex_complete_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_complex_complete_header_abi.sh
}

run_math_elementary_long_double_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_elementary_long_double_header_abi.sh
}

run_math_special_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_special_header_abi.sh
}

run_math_exp2_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_exp2_header_abi.sh
}

run_math_expm1_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_expm1_header_abi.sh
}

run_math_log10_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_log10_header_abi.sh
}

run_sys_reg_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sys_reg_header_abi.sh
}

run_machine_context_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_machine_context_header_abi.sh
}

run_types_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_types_header_abi.sh
}

run_stddef_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_stddef_header_abi.sh
}

run_stat_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_stat_header_abi.sh
}

run_utime_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_utime_header_abi.sh
}

run_pthread_c11_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_c11_header_abi.sh
}

run_pthread_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_header_source_form.sh
}

run_atomic_addressable_abi() {
    run_in_container bash /workspace/compat/x86_64/run_atomic_addressable_abi.sh
}

run_pthread_cancellation_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_cancellation_header_abi.sh
}

run_pthread_spin_destroy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_spin_destroy_header_abi.sh
}

run_pthread_spin_operations_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_spin_operations_header_abi.sh
}

run_stdlib_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_stdlib_header_abi.sh
}

run_syslog_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_syslog_header_abi.sh
}

run_stdio_standard_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_stdio_standard_header_abi.sh
}

run_stdio_header_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_stdio_header_source_form.sh
}

run_fopen64_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_fopen64_header_abi.sh
}

run_ctype_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ctype_header_abi.sh
}

run_locale_profile_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_locale_profile_header_abi.sh
}

run_locale_multibyte_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_locale_multibyte_header_abi.sh
}

run_iconv_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_iconv_header_abi.sh
}

run_wide_character_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_wide_character_header_abi.sh
}

run_locale_object_wide_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_locale_object_wide_header_abi.sh
}

run_locale_narrow_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_locale_narrow_header_abi.sh
}

run_integer_arithmetic_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_integer_arithmetic_header_abi.sh
}

run_integer_parse_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_integer_parse_header_abi.sh
}

run_float_parse_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_float_parse_header_abi.sh
}

run_intmax_arithmetic_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_intmax_arithmetic_header_abi.sh
}

run_libc_intmax_arithmetic() {
    run_in_container bash /workspace/compat/x86_64/run_libc_intmax_arithmetic.sh
}

run_credential_observation_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_credential_observation_header_abi.sh
}

run_login_name_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_login_name_header_abi.sh
}

run_child_reaping_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_child_reaping_header_abi.sh
}

run_wait_extensions_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_wait_extensions_header_abi.sh
}

run_immediate_termination_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_immediate_termination_header_abi.sh
}

run_posix_exit_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_exit_header_abi.sh
}

run_posix_spawnattr_init_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_init_header_abi.sh
}

run_posix_spawnattr_getpgroup_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_getpgroup_header_abi.sh
}

run_posix_spawnattr_signal_fields_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_signal_fields_header_abi.sh
}

run_posix_spawnattr_getschedpolicy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_getschedpolicy_header_abi.sh
}

run_posix_spawnattr_getschedparam_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_getschedparam_header_abi.sh
}

run_bsearch_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_bsearch_header_abi.sh
}

run_linear_search_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_linear_search_header_abi.sh
}

run_intrusive_queue_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_intrusive_queue_header_abi.sh
}

run_wcswcs_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_wcswcs_header_abi.sh
}

run_qsort_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_qsort_header_abi.sh
}

run_sched_yield_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_yield_header_abi.sh
}

run_sched_cpucount_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_cpucount_header_abi.sh
}

run_sched_cpu_macros_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_cpu_macros_header_abi.sh
}

run_sched_cpu_set_source_form() {
    run_in_container bash /workspace/compat/x86_64/run_sched_cpu_set_source_form.sh
}

run_sched_getcpu_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_getcpu_header_abi.sh
}

run_sched_priority_bounds_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_priority_bounds_header_abi.sh
}

run_callback_algorithms_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_callback_algorithms_header_abi.sh
}

run_libc_credential_observation() {
    run_in_container bash /workspace/compat/x86_64/run_libc_credential_observation.sh
}

run_libc_child_reaping() {
    run_in_container bash /workspace/compat/x86_64/run_libc_child_reaping.sh
}

run_libc_wait_extensions() {
    run_in_container bash /workspace/compat/x86_64/run_libc_wait_extensions.sh
}

run_libc_immediate_termination() {
    run_in_container bash /workspace/compat/x86_64/run_libc_immediate_termination.sh
}

run_libc_posix_exit() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_exit.sh
}

run_libc_posix_spawn_file_actions() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawn_file_actions.sh
}

run_libc_posix_spawnattr_init() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_init.sh
}

run_libc_posix_spawnattr_getpgroup() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_getpgroup.sh
}

run_libc_posix_spawnattr_signal_fields() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_signal_fields.sh
}

run_libc_posix_spawnattr_getschedpolicy() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_getschedpolicy.sh
}

run_libc_posix_spawnattr_getschedparam() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_getschedparam.sh
}

run_libc_bsearch() {
    run_in_container bash /workspace/compat/x86_64/run_libc_bsearch.sh
}

run_libc_linear_search() {
    run_in_container bash /workspace/compat/x86_64/run_libc_linear_search.sh
}

run_libc_intrusive_queue() {
    run_in_container bash /workspace/compat/x86_64/run_libc_intrusive_queue.sh
}

run_libc_wcswcs() {
    run_in_container bash /workspace/compat/x86_64/run_libc_wcswcs.sh
}

run_libc_qsort() {
    run_in_container bash /workspace/compat/x86_64/run_libc_qsort.sh
}

run_libc_callback_algorithms() {
    run_in_container bash /workspace/compat/x86_64/run_libc_callback_algorithms.sh
}

run_libc_search_tree_intrusive() {
    run_in_container bash /workspace/compat/x86_64/run_libc_search_tree_intrusive.sh
}

run_libc_search_hash_table() {
    run_in_container bash /workspace/compat/x86_64/run_libc_search_hash_table.sh
}

run_libc_gettext_catalog() {
    run_in_container bash /workspace/compat/x86_64/run_libc_gettext_catalog.sh
}

run_libc_access() {
    run_in_container bash /workspace/compat/x86_64/run_libc_access.sh
}

run_libc_clock_gettime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_clock_gettime.sh
}

run_libc_clock_adjtime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_clock_adjtime.sh
}

run_libc_clock_settime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_clock_settime.sh
}

run_libc_timer_getoverrun() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timer_getoverrun.sh
}

run_libc_timer_delete() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timer_delete.sh
}

run_libc_timer_gettime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timer_gettime.sh
}

run_libc_timer_settime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timer_settime.sh
}

run_libc_time_observation() {
    run_in_container bash /workspace/compat/x86_64/run_libc_time_observation.sh
}

run_libc_difftime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_difftime.sh
}

run_libc_timegm() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timegm.sh
}

run_libc_gmtime_r() {
    run_in_container bash /workspace/compat/x86_64/run_libc_gmtime_r.sh
}

run_libc_system_configuration() {
    run_in_container bash /workspace/compat/x86_64/run_libc_system_configuration.sh
}

run_libc_getpagesize() {
    run_in_container bash /workspace/compat/x86_64/run_libc_getpagesize.sh
}

run_libc_mapping_core() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mapping_core.sh
}

run_libc_memory_sync() {
    run_in_container bash /workspace/compat/x86_64/run_libc_memory_sync.sh
}

run_libc_memory_locking() {
    run_in_container bash /workspace/compat/x86_64/run_libc_memory_locking.sh
}

run_libc_memfd_create() {
    run_in_container bash /workspace/compat/x86_64/run_libc_memfd_create.sh
}

run_libc_legacy_memory() {
    run_in_container bash /workspace/compat/x86_64/run_libc_legacy_memory.sh
}

run_libc_memory_special_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_memory_special.sh
}

run_libc_memccpy() {
    run_in_container bash /workspace/compat/x86_64/run_libc_memccpy.sh
}

run_libc_mempcpy() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mempcpy.sh
}

run_libc_strsep() {
    run_in_container bash /workspace/compat/x86_64/run_libc_strsep.sh
}

run_libc_strtok() {
    run_in_container bash /workspace/compat/x86_64/run_libc_strtok.sh
}

run_libc_stateful_byte_strings() {
    run_in_container bash /workspace/compat/x86_64/run_libc_stateful_byte_strings.sh
}

run_libc_rand_r() {
    run_in_container bash /workspace/compat/x86_64/run_libc_rand_r.sh
}

run_libc_lrand48() {
    run_in_container bash /workspace/compat/x86_64/run_libc_lrand48.sh
}

run_libc_allocator_runtime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_allocator_runtime.sh
}

run_libc_allocator_basic_runtime_v1() {
    run_in_container bash /workspace/compat/x86_64/run_libc_allocator_basic_runtime_v1.sh
}

run_libc_allocator_string_duplication() {
    run_in_container bash /workspace/compat/x86_64/run_libc_allocator_string_duplication.sh
}

run_libc_scandir() {
    run_in_container bash /workspace/compat/x86_64/run_libc_scandir.sh
}

run_libc_allocator_observability() {
    run_in_container bash /workspace/compat/x86_64/run_libc_allocator_observability.sh
}

run_libc_alloca() {
    run_in_container bash /workspace/compat/x86_64/run_libc_alloca.sh
}

run_libc_static_c_abi_differential() {
    run_in_container bash /workspace/compat/x86_64/run_libc_static_c_abi_differential.sh
}

run_libc_same_object_static_c_abi_differential() {
    run_in_container bash /workspace/compat/x86_64/run_libc_same_object_static_c_abi_differential.sh
}

run_qualification_posix_abi_admission() {
    run_in_container python3 /workspace/compat/x86_64/run_qualification_posix_abi.py
}

run_libc_header_layouts_baseline() {
    run_in_container bash /workspace/compat/x86_64/run_libc_header_layouts_baseline.sh
}

run_libc_nanosleep() {
    run_in_container bash /workspace/compat/x86_64/run_libc_nanosleep.sh
}

run_libc_sleep() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sleep.sh
}

run_libc_clock_nanosleep() {
    run_in_container bash /workspace/compat/x86_64/run_libc_clock_nanosleep.sh
}

run_libc_descriptor_entry() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_entry.sh
}

run_libc_fcntl_status_control() {
    run_in_container bash /workspace/compat/x86_64/run_libc_fcntl_status_control.sh
}

run_libc_ioctl() {
    run_in_container bash /workspace/compat/x86_64/run_libc_ioctl.sh
}

run_libc_sysv_semaphore() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sysv_semaphore.sh
}

run_libc_posix_semaphore() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_semaphore.sh
}

run_libc_sysv_message_shared_memory() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sysv_message_shared_memory.sh
}

run_libc_event_descriptors() {
    run_in_container bash /workspace/compat/x86_64/run_libc_event_descriptors.sh
}

run_libc_timerfd_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timerfd.sh
}

run_libc_mq_setattr_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mq_setattr.sh
}

run_libc_signalfd_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signalfd.sh
}

run_libc_sigpause_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigpause.sh
}

run_libc_sigisemptyset_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigisemptyset.sh
}

run_libc_sigandset_sigorset_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigandset_sigorset.sh
}

run_libc_sigpending_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigpending.sh
}

run_libc_sigrtmax_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigrtmax.sh
}

run_libc_sigrtmin_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigrtmin.sh
}

run_libc_sched_getscheduler_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_getscheduler.sh
}

run_libc_sched_rr_interval_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_rr_interval.sh
}

run_libc_sched_getparam_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_getparam.sh
}

run_libc_sched_setparam_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_setparam.sh
}

run_libc_sched_setscheduler_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_setscheduler.sh
}

run_libc_sched_getaffinity_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_getaffinity.sh
}

run_libc_sched_setaffinity_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_setaffinity.sh
}

run_libc_setfsuid_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_setfsuid.sh
}

run_libc_setfsgid_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_setfsgid.sh
}

run_libc_personality_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_personality.sh
}

run_libc_io_permissions_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_io_permissions.sh
}

run_libc_alarm_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_alarm.sh
}

run_ualarm_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ualarm_header_abi.sh
}

run_libc_ualarm_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_ualarm.sh
}

run_libc_interval_timers_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_interval_timers.sh
}

run_libc_pthread_spin_operations_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_spin_operations.sh
}

run_usleep_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_usleep_header_abi.sh
}

run_libc_usleep_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_usleep.sh
}

run_libc_sigset_mutation_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sigaddset_sigdelset_sigfillset.sh
}

run_libc_extended_attributes() {
    run_in_container bash /workspace/compat/x86_64/run_libc_extended_attributes.sh
}

run_libc_pathname_lifecycle() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pathname_lifecycle.sh
}

run_libc_directory_streams() {
    run_in_container bash /workspace/compat/x86_64/run_libc_directory_streams.sh
}

run_libc_filesystem_traversal() {
    run_in_container bash /workspace/compat/x86_64/run_libc_filesystem_traversal.sh
}

run_libc_filesystem_directory() {
    run_in_container bash /workspace/compat/x86_64/run_libc_filesystem_directory.sh
}

run_libc_filesystem_extensions() {
    run_in_container bash /workspace/compat/x86_64/run_libc_filesystem_extensions.sh
}

run_libc_lchmod_unsupported() {
    run_in_container bash /workspace/compat/x86_64/run_libc_lchmod_unsupported.sh
}

run_libc_fchdir() {
    run_in_container bash /workspace/compat/x86_64/run_libc_fchdir.sh
}

run_libc_ulimit() {
    run_in_container bash /workspace/compat/x86_64/run_libc_ulimit.sh
}

run_ffs_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ffs_header_abi.sh
}

run_memccpy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memccpy_header_abi.sh
}

run_memory_special_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memory_special_header_abi.sh
}

run_aio_error_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_aio_error_header_abi.sh
}

run_byte_strings_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_byte_strings_header_abi.sh
}

run_memory_search_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memory_search_header_abi.sh
}

run_memccpy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memccpy_header_abi.sh
}

run_mempcpy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mempcpy_header_abi.sh
}

run_strsep_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_strsep_header_abi.sh
}

run_strtok_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_strtok_header_abi.sh
}

run_stateful_byte_strings_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_stateful_byte_strings_header_abi.sh
}

run_string_copy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_string_copy_header_abi.sh
}

run_error_strings_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_error_strings_header_abi.sh
}

run_strsignal_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_strsignal_header_abi.sh
}

run_gettext_catalog_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_gettext_catalog_header_abi.sh
}

run_string_duplication_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_string_duplication_header_abi.sh
}

run_random_entropy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_random_entropy_header_abi.sh
}

run_time_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_time_header_abi.sh
}

run_clock_adjtime_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_clock_adjtime_header_abi.sh
}

run_clock_settime_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_clock_settime_header_abi.sh
}

run_timer_getoverrun_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_timer_getoverrun_header_abi.sh
}

run_timer_delete_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_timer_delete_header_abi.sh
}

run_timer_gettime_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_timer_gettime_header_abi.sh
}

run_timer_settime_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_timer_settime_header_abi.sh
}

run_sleep_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sleep_header_abi.sh
}

run_timerfd_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_timerfd_header_abi.sh
}

run_mq_setattr_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mq_setattr_header_abi.sh
}

run_signalfd_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_signalfd_header_abi.sh
}

run_poll_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_poll_header_abi.sh
}

run_select_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_select_header_abi.sh
}

run_fcntl_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_fcntl_header_abi.sh
}

run_file_handles_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_file_handles_header_abi.sh
}

run_posix_spawn_file_actions_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_spawn_file_actions_header_abi.sh
}

run_process_exec_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_process_exec_header_abi.sh
}

run_flock_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_flock_header_abi.sh
}

run_sendfile_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sendfile_header_abi.sh
}

run_tee_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_tee_header_abi.sh
}

run_splice_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_splice_header_abi.sh
}

run_sync_file_range_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sync_file_range_header_abi.sh
}

run_copy_file_range_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_copy_file_range_header_abi.sh
}

run_unistd_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_unistd_header_abi.sh
}

run_getpagesize_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_getpagesize_header_abi.sh
}

run_system_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_system_header_abi.sh
}

run_getloadavg_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_getloadavg_header_abi.sh
}

run_syscall_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_x86_syscall_header.sh
}

run_signal_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_signal_header_abi.sh
}

run_psignal_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_psignal_header_abi.sh
}

run_signal_legacy_aliases_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_signal_legacy_aliases_header_abi.sh
}

run_signal_sysv_helpers_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_signal_sysv_helpers_header_abi.sh
}

run_sched_getscheduler_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_getscheduler_header_abi.sh
}

run_sched_rr_interval_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_rr_interval_header_abi.sh
}

run_sched_getparam_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_getparam_header_abi.sh
}

run_sched_setparam_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_setparam_header_abi.sh
}

run_sched_setscheduler_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_setscheduler_header_abi.sh
}

run_sched_getaffinity_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_getaffinity_header_abi.sh
}

run_sched_setaffinity_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sched_setaffinity_header_abi.sh
}

run_setfsuid_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_setfsuid_header_abi.sh
}

run_setfsgid_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_setfsgid_header_abi.sh
}

run_personality_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_personality_header_abi.sh
}

run_termios_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_termios_header_abi.sh
}

run_terminal_streams_header_topology() {
    run_in_container bash /workspace/compat/x86_64/run_terminal_streams_header_topology.sh
}

run_ctermid_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ctermid_header_abi.sh
}

run_grantpt_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_grantpt_header_abi.sh
}

run_unlockpt_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_unlockpt_header_abi.sh
}

run_gethostid_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_gethostid_header_abi.sh
}

run_issetugid_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_issetugid_header_abi.sh
}

run_legacy_misc_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_legacy_misc_header_abi.sh
}

run_endhostent_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_endhostent_header_abi.sh
}

run_gettid_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_gettid_header_abi.sh
}

run_posix_close_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_close_header_abi.sh
}

run_isatty_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_isatty_header_abi.sh
}

run_ttyname_r_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ttyname_r_header_abi.sh
}

run_tcgetpgrp_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_tcgetpgrp_header_abi.sh
}

run_tcsetpgrp_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_tcsetpgrp_header_abi.sh
}

run_getpass_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_getpass_header_abi.sh
}

run_mktemp_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mktemp_header_abi.sh
}

run_temporary_names_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_temporary_names_header_abi.sh
}

run_mkfifo_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mkfifo_header_abi.sh
}

run_mkdirat_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mkdirat_header_abi.sh
}

run_mkfifoat_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mkfifoat_header_abi.sh
}

run_readlinkat_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_readlinkat_header_abi.sh
}
run_linkat_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_linkat_header_abi.sh
}
run_renameat2_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_renameat2_header_abi.sh
}
run_lchown_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_lchown_header_abi.sh
}
run_hasmntopt_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_hasmntopt_header_abi.sh
}

run_fchdir_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_fchdir_header_abi.sh
}

run_ulimit_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ulimit_header_abi.sh
}

run_mman_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mman_header_abi.sh
}

run_memory_locking_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memory_locking_header_abi.sh
}

run_memory_sync_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memory_sync_header_abi.sh
}

run_memfd_create_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memfd_create_header_abi.sh
}

run_resource_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_resource_header_abi.sh
}

run_socket_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_socket_header_abi.sh
}

run_tcp_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_tcp_header_abi.sh
}

run_nameser_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_nameser_header_abi.sh
}

run_quota_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_quota_header_abi.sh
}

run_endservent_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_endservent_header_abi.sh
}

run_service_lifecycle_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_service_lifecycle_header_abi.sh
}

run_protocol_database_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_protocol_database_header_abi.sh
}

run_inet_address_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_inet_address_header_abi.sh
}

run_socket_messages_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_socket_messages_header_abi.sh
}

run_sysv_semaphore_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sysv_semaphore_header_abi.sh
}

run_posix_semaphore_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_posix_semaphore_header_abi.sh
}

run_sysv_message_shared_memory_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_sysv_message_shared_memory_header_abi.sh
}

run_mm_abi_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_mm_reference.sh
}

run_mapping_reference() {
    # This private mapping-lifecycle slice owns ordinary anonymous/file
    # mappings, protection transitions, and exact unmapping. It does not
    # reclassify the separately admitted remap, locking, synchronization,
    # advice, residency, or broader VM-policy boundaries.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_memory_mapping \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example mapping_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_mapping_reference.sh
}

run_memory_vm_reference() {
    # This separate VM-policy slice keeps the program-break query/replay and
    # process-wide locking transitions in disposable test children. It does
    # not claim allocator ownership, successful legacy file remapping, or a
    # wider VM-policy surface.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_memory_vm \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example memory_vm_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_memory_vm_reference.sh
}

run_pty_basic_reference() {
    # This private PTY slice owns only a non-session-changing master/slave
    # pair and its `/dev/pts/N` name. It deliberately leaves controlling
    # terminals, sessions, termios, and generic ioctl outside x86 scope.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_pty_basic \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc --test x86_64_pty_basic \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example pty_basic_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_pty_basic_reference.sh
}

run_terminal_reference() {
    # The terminal vertical retains PtyPair's forced O_NOCTTY construction and
    # selects only its explicit unsafe session handoff plus typed terminal
    # operations. This Rust vertical does not expose C termios records or a
    # generic ioctl API; the separate static C termios artifact does not alter it.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_terminal \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc --test x86_64_terminal \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example x86_64_terminal_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_terminal_reference.sh
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

run_statfs_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_statfs_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_fs_capacity -- --test-threads=1
}

run_timestamp_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_timestamp_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_futimens \
        --test x86_64_timestamp_paths -- --test-threads=1
}

run_path_lifecycle_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_path_lifecycle_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_path_lifecycle -- --test-threads=1
}

run_namespace_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_namespace_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_namespace -- --test-threads=1
}

run_path_core_reference() {
    # The individual probes retain narrow musl/raw ABI contracts. This command
    # composes them only after the owned readlink boundary closes the selected
    # Rust path-core capability; it does not select canonicalization, statx,
    # directory streams, temporary-object lifecycles, the separate xattr
    # boundary, or CWD mutation.
    run_fstat_reference
    run_statat_reference
    run_path_lifecycle_reference
    run_namespace_reference
    run_timestamp_reference
    run_readlinkat_reference
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features std \
        --test x86_64_fs --test x86_64_statat --test x86_64_readlink \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --example path_core_owned_direct_probe
}

run_xattr_reference() {
    # This is the complete direct xattr family: path, no-follow-path, and
    # descriptor forms. It intentionally excludes statx, newer *xattrat forms,
    # directory/temporary abstractions, the C ABI, and public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_xattr -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example xattr_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_xattr_reference.sh
}

run_directory_reference() {
    # This is the complete private directory-record trio: caller-buffered raw
    # getdents64, owned streams, and opaque seek/rewind cookies. It does not
    # select C DIR APIs, C headers/ABI, temporary objects, CWD mutation, or
    # public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --test x86_64_raw_directory --test x86_64_directory \
        --test x86_64_directory_position -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --example directory_direct_probe --example directory_position_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_directory_reference.sh
}

run_temporary_object_reference() {
    # This is the complete private temporary-object family: named files with
    # retained-parent cleanup, anonymous O_TMPFILE descriptors without a
    # fallback, and caller-buffered/owned temporary-directory names. It does
    # not select C mk* APIs, CWD mutation, file handles, C ABI, or public x86
    # support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_temporary_objects \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc --test x86_64_temporary_objects \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --example fs_named_tempfile_direct_probe --example fs_tempfile_direct_probe \
        --example fs_tempdir_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_temporary_object_reference.sh
}

run_statx_reference() {
    # This is the private direct extended-metadata slice: a typed Linux
    # statx record, a statx-specific lookup-flag vocabulary, and no fallback
    # or availability cache. It does not widen general x86 AT_EMPTY_PATH,
    # select C statx APIs, or provide public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_statx -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example statx_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_statx_reference.sh
}

run_cwd_canonicalize_reference() {
    # This private filesystem-context slice resolves physical byte paths and
    # changes/restores process-global CWD through direct Linux seams. It does
    # not select chroot, openat2, C APIs, errno TLS, or public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --test x86_64_canonicalize --test x86_64_cwd_mutation \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --test x86_64_canonicalize --test x86_64_cwd_mutation \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --example fs_canonicalize_direct_probe --example process_cwd_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_cwd_canonicalize_reference.sh
}

run_root_change_reference() {
    # This separate privileged transition changes root only in disposable test
    # children. It is not a sandbox, containment framework, C ABI, or public
    # x86 support claim.
    run_in_chroot_cap_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_chroot -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example process_chroot_direct_probe
    run_in_chroot_cap_container bash /workspace/compat/x86_64/run_x86_root_change_reference.sh
}

run_mount_reference() {
    # This private mount request slice exercises only direct checked failures.
    # It deliberately receives no CAP_SYS_ADMIN and makes no successful
    # namespace, bind, remount, propagation, or filesystem-descriptor mount
    # API claim.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_mount \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example mount_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_mount_reference.sh
}

run_thread_kill_reference() {
    # This private direct signal-delivery slice fixes the thread group to the
    # calling process and targets one named thread. It does not select generic
    # process/group signaling, signal-mask management, C APIs, or public x86
    # support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_thread_kill \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example thread_kill_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_thread_kill_reference.sh
}

run_ipc_reference() {
    # This private IPC slice owns POSIX named queue descriptors, attributes,
    # priorities, absolute deadlines, and unlink-after-open lifetime. It does
    # not select mq_notify, POSIX shared memory, SysV IPC, semaphores, C APIs,
    # errno TLS, or public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_ipc -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example ipc_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_mqueue_reference.sh
}

run_shm_reference() {
    # This private IPC slice owns validated POSIX shared-memory names and
    # close-on-exec descriptors only. It preserves the existing AArch64/Rustix
    # direct flag policy rather than selecting musl's C wrapper, SysV IPC,
    # mapping policy, C APIs/errno TLS, or public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_shm -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example shm_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_shm_reference.sh
}

run_inotify_reference() {
    # This private system slice owns inotify descriptors, descriptor-scoped
    # watches, and caller-buffered byte records. It does not select C inotify,
    # legacy init, fanotify, recursive/background policy, global registries,
    # namespaces/capability mutation, errno TLS, or public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --lib --no-default-features system::inotify:: \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_inotify -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --example inotify_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_inotify_reference.sh
}

run_socket_transport_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_socket_transport_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_socket_transport -- --test-threads=1
}

run_interface_device_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_interface_device_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --test x86_64_interface_device -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --lib --no-default-features --features alloc net::netdevice:: \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --example network_interface_index_direct_probe \
        --example network_interface_index_name_direct_probe \
        --example interface_names_direct_probe
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --example interface_names_alloc_direct_probe \
        --example interface_addresses_direct_probe
}

run_resolver_transport_reference() {
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-core --no-default-features --test x86_64_resolver_transport \
        -- --test-threads=1
}

run_resolver_facade_reference() {
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc --test x86_64_resolver \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --example resolver_hosts_direct_probe
}

run_netdb_reference() {
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc --test x86_64_netdb \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --example resolver_direct_probe
}

run_users_databases_reference() {
    # This private alloc-backed slice owns strict conventional passwd/group
    # snapshots only. It does not select C/NSS/provider state, shadow, utmp,
    # mntent, account mutation, or public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --test x86_64_users_databases -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --example users_databases_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_users_databases_reference.sh
}

run_posix_fallocate_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_posix_fallocate_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_posix_fallocate -- --test-threads=1
}

run_fallocate_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fallocate_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_fallocate -- --test-threads=1
}

run_file_position_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_file_position_reference.sh
}

run_sync_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_sync_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_sync -- --test-threads=1
}

run_syncfs_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_syncfs_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_syncfs -- --test-threads=1
}

run_sync_file_range_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_sync_file_range_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_sync_file_range -- --test-threads=1
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

run_calendar_time_reference() {
    # This private civil-time slice owns a direct gettimeofday wall-clock
    # record, strict UTC Gregorian conversion, and one-way local projection
    # through caller-supplied immutable POSIX-TZ/TZif rules. It does not
    # select a C time/tm ABI, process-global TZ state, zoneinfo I/O, inverse
    # ambiguous-local conversion, clock mutation, or public x86 support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-core --lib --no-default-features \
        x86_64_gettimeofday_writes_one_normalized_private_record \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --test time --test calendar_utc --test x86_64_calendar_time \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --test timezone_rules --test calendar_local \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --example time_direct_probe --example calendar_utc_direct_probe
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --example calendar_local_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_calendar_time_reference.sh
}

run_advanced_time_reference() {
    # This private slice adds validated extended and dynamic clock IDs, direct
    # clock mutation, and owned POSIX timers. It retains direct kernel errors,
    # excludes C timer/sigevent ABI and SIGEV_THREAD callbacks, and does not
    # promote x86-64 platform support.
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-core --lib --no-default-features \
        x86_64_posix_timer_writes_exact_id_and_old_setting_records \
        -- --test-threads=1
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_advanced_time \
        -- --test-threads=1
    run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features \
        --example time_dynamic_direct_probe \
        --example process_clock_id_direct_probe \
        --example time_settime_direct_probe \
        --example time_timers_direct_probe
    run_in_container bash /workspace/compat/x86_64/run_x86_advanced_time_reference.sh
}

run_facade_record_owning() {
    # Keep the aggregate proof closed over the exact record-owning capability
    # slices named by compat/x86_64/parity.toml.  The two checks prove that the
    # complete Rust facade remains usable both without allocation and with its
    # explicitly alloc-gated records; the component runners retain their
    # individual behavioral, ABI, and musl-oracle evidence.
    run_in_container cargo check --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features
    run_in_container cargo check --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc

    run_root_change_reference
    run_child_ownership_reference
    run_thread_kill_reference
    run_mapping_reference
    run_memory_vm_reference
    run_pty_basic_reference
    run_terminal_reference
    run_interface_device_reference
    run_resolver_transport_reference
    run_resolver_facade_reference
    run_netdb_reference
    run_users_databases_reference
    run_mount_reference
    run_path_core_reference
    run_xattr_reference
    run_directory_reference
    run_temporary_object_reference
    run_statx_reference
    run_cwd_canonicalize_reference
    run_ipc_reference
    run_shm_reference
    run_inotify_reference
    run_calendar_time_reference
    run_advanced_time_reference
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
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_setitimer \
        -- --test-threads=1
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

run_child_ownership_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_child_ownership_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
        --test x86_64_child_ownership -- --test-threads=1
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

run_fcntl_status_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_fcntl_status_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_fcntl_flags -- --test-threads=1
}

run_flock_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_flock_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_flock -- --test-threads=1
}

run_sendfile_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_sendfile_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_sendfile -- --test-threads=1
}

run_copy_file_range_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_copy_file_range_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_copy_file_range -- --test-threads=1
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
        -p crabc-rs --no-default-features --features alloc --test x86_64_getcwd \
        --test x86_64_current_dir_name -- --test-threads=1
}

run_readlinkat_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_readlinkat_reference.sh
}

run_access_reference() {
    run_in_container bash /workspace/compat/x86_64/run_x86_access_reference.sh
    run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --test x86_64_access -- --test-threads=1
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
        probe="$TMPDIR/crabc-x86-libc-syscall-probe"
        rustc --edition=2021 --target x86_64-unknown-linux-musl \
            /workspace/compat/x86_64/libc_syscall_probe.rs -o "$probe"
        "$probe"
    '
}

run_libc_errno_tls_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_errno_tls.sh
}

run_libc_stat_compat_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_stat_compat.sh
}

run_libc_credentials_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_credentials.sh
}

run_libc_bootstrap_primitives_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_bootstrap_primitives.sh
}

run_libc_signal_control_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_control.sh
}

run_libc_signal_legacy_aliases_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_legacy_aliases.sh
}

run_libc_signal_sysv_helpers_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_sysv_helpers.sh
}

run_libc_signal_execution_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_execution.sh
}

run_libc_signal_altstack_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_altstack.sh
}

run_libc_psignal_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_psignal.sh
}

run_libc_process_signal_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_process_signal.sh
}

run_libc_process_exec_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_process_exec.sh
}

run_libc_pthread_create_join_tls_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_create_join_tls.sh
}

run_libc_pthread_identity_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_identity.sh
}

run_libc_c11_lifecycle_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_c11_lifecycle.sh
}

run_libc_c11_plain_sync_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_c11_plain_sync.sh
}

run_libc_pthread_c11_once_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_c11_once.sh
}

run_libc_pthread_c11_tsd_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_c11_tsd.sh
}

run_libc_pthread_cancel_deferred_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_cancel_deferred.sh
}

run_libc_pthread_atfork_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_atfork.sh
}

run_libc_stack_chk_fail_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_stack_chk_fail.sh
}

run_libc_pthread_affinity_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_affinity.sh
}

run_libc_pthread_cpuclock_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_cpuclock.sh
}

run_libc_pthread_name_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_name.sh
}

run_libc_pthread_barrierattr_pshared_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_barrierattr_pshared.sh
}

run_libc_pthread_attr_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_attr.sh
}

run_libc_pthread_attr_lifecycle_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_attr_lifecycle.sh
}

run_libc_pthread_barrier_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_barrier.sh
}

run_libc_pthread_condattr_pshared_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_condattr_pshared.sh
}

run_libc_pthread_condattr_clock_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_condattr_clock.sh
}

run_libc_pthread_mutexattr_robust_query_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutexattr_robust_query.sh
}

run_libc_pthread_mutexattr_protocol_query_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutexattr_protocol_query.sh
}

run_libc_pthread_mutexattr_pshared_query_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutexattr_pshared_query.sh
}

run_libc_pthread_mutexattr_type_query_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutexattr_type_query.sh
}

run_libc_pthread_mutexattr_type_setter_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutexattr_type_setter.sh
}

run_libc_pthread_mutex_prioceiling_query_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutex_prioceiling_query.sh
}

run_libc_pthread_getconcurrency_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_getconcurrency.sh
}

run_libc_pthread_setconcurrency_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_setconcurrency.sh
}

run_pthread_spin_init_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_spin_init_header_abi.sh
}

run_libc_pthread_spin_init_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_spin_init.sh
}

run_libc_pthread_detach_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_detach.sh
}

run_libc_thrd_sleep_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_thrd_sleep.sh
}

run_libc_thrd_yield_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_thrd_yield.sh
}

run_libc_pthread_mutex_normal_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_mutex_normal.sh
}

run_libc_pthread_rwlock_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_rwlock.sh
}

run_libc_pthread_cond_private_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_cond_private.sh
}

run_libc_pthread_tls_aggregate_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_tls_aggregate.sh
}

run_libc_static_tls_v1_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_static_tls_v1.sh
}

run_libc_crt_static_tls_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_crt_static_tls.sh
}

run_libc_crt1_static_tls_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_crt1_static_tls.sh
}

run_owned_static_sysroot_probe() {
    run_in_container bash /workspace/compat/x86_64/run_owned_static_sysroot.sh
}

run_lua_static_source_build_probe() {
    # Expand the bounded knobs into this exact child argv rather than relying
    # on Docker's optional host-environment forwarding semantics.
    run_in_container python3 -B /workspace/compat/lua/run_x86_static_dispatch.py \
        --jobs "${CRABC_X86_64_LUA_JOBS:-4}" \
        --timeout "${CRABC_X86_64_LUA_TIMEOUT:-120}"
}

run_owned_resolver_network_probe() {
    prepare_work_dir
    local state container_state
    state="$(mktemp -d "$TMP_DIR/owned-resolver-network.XXXXXX")"
    container_state="/workspace/.work/x86_64/tmp/${state##*/}"
    run_in_container python3 -B /workspace/compat/resolver-network/prepare_x86_64.py \
        --output "$container_state/products"
    run_in_resolver_network_container python3 -B /workspace/compat/resolver-network/run_x86_64.py \
        --static-sysroot "$container_state/products/static-sysroot" \
        --dynamic-sysroot "$container_state/products/dynamic-sysroot" \
        --extracted-static-sysroot "$container_state/products/static-extraction/crabc-x86_64-owned-static-sysroot" \
        --extracted-dynamic-sysroot "$container_state/products/dynamic-extraction" \
        --work-root "$container_state/execution"
}

run_lua_dynamic_source_build_probe() {
    run_in_container python3 -B /workspace/compat/lua/run_x86_dynamic.py \
        --jobs "${CRABC_X86_64_LUA_JOBS:-4}" \
        --timeout "${CRABC_X86_64_LUA_TIMEOUT:-180}"
}

run_libc_owned_wordexp_probe() {
    # The runner executes both static images under a private `/bin/sh` chroot
    # so ordinary expansion and missing/invalid shell behavior cannot borrow
    # the container's ambient shell namespace.
    run_in_chroot_cap_container bash /workspace/compat/x86_64/run_libc_owned_wordexp.sh
}

run_owned_dynamic_sysroot_probe() {
    run_in_dynamic_loader_mount_container bash /workspace/compat/x86_64/run_owned_dynamic_sysroot.sh
}

run_crt_object_bundle_probe() {
    run_in_container bash /workspace/compat/x86_64/run_crt_object_bundle.sh
}

run_crt_dynamic_startup_probe() {
    run_musl_oracle
    run_in_container env CRABC_X86_64_DYNAMIC_STARTUP_EVIDENCE=native \
        python3 /workspace/crt/tests/test_x86_64_dynamic_startup.py
}

run_crt_dynamic_link_contract_probe() {
    run_musl_oracle
    run_in_container env CRABC_X86_64_DYNAMIC_LINK_CONTRACT_EVIDENCE=native \
        python3 /workspace/crt/tests/test_x86_64_dynamic_link_contract.py
}

run_consumer_static_pie_lto_probe() {
    run_in_container python3 /workspace/compat/x86_64/consumer_static_pie_lto.py
}

run_consumer_native_facade_lto_probe() {
    run_in_container python3 /workspace/compat/x86_64/consumer_native_facade_lto.py
}

run_libc_termios_control_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_termios_control.sh
}

run_libc_ctermid_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_ctermid.sh
}

run_libc_grantpt_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_grantpt.sh
}

run_libc_unlockpt_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_unlockpt.sh
}

run_libc_gethostid_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_gethostid.sh
}

run_libc_issetugid_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_issetugid.sh
}

run_libc_legacy_misc_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_legacy_misc.sh
}

run_libc_endhostent_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_endhostent.sh
}

run_libc_sethostent_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sethostent.sh
}

run_libc_gettid_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_gettid.sh
}

run_libc_posix_close_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_close.sh
}

run_libc_isatty_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_isatty.sh
}

run_libc_ttyname_r_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_ttyname_r.sh
}

run_libc_tcgetpgrp_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_tcgetpgrp.sh
}

run_libc_tcsetpgrp_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_tcsetpgrp.sh
}

run_libc_getpass_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_getpass.sh
}

run_libc_mktemp_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mktemp.sh
}

run_libc_temporary_names_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_temporary_names.sh
}

run_libc_file_handles_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_file_handles.sh
}

run_libc_mkfifo_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mkfifo.sh
}

run_libc_mkdirat_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mkdirat.sh
}

run_libc_mkfifoat_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mkfifoat.sh
}

run_libc_linkat_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_linkat.sh
}

run_libc_renameat2_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_renameat2.sh
}

run_libc_lchown_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_lchown.sh
}

run_libc_hasmntopt_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_hasmntopt.sh
}

run_libc_process_context_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_process_context.sh
}

run_libc_environment_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_environment.sh
}

run_libc_secure_environment_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_secure_environment.sh
}

run_libc_login_name_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_login_name.sh
}

run_libc_descriptor_io_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_io.sh
}

run_libc_readlinkat_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_readlinkat.sh
}
run_libc_descriptor_lifecycle_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_lifecycle.sh
}

run_libc_descriptor_pipeline_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_pipeline.sh
}

run_libc_timestamp_updates_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timestamp_updates.sh
}

run_libc_process_resources_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_process_resources.sh
}

run_libc_sched_yield_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_yield.sh
}

run_libc_sched_get_priority_max_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_get_priority_max.sh
}

run_libc_sched_get_priority_min_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_get_priority_min.sh
}

run_libc_sched_cpucount_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_cpucount.sh
}

run_libc_sched_getcpu_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_getcpu.sh
}

run_libc_sched_priority_bounds_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sched_priority_bounds.sh
}

run_libc_readiness_waits_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_readiness_waits.sh
}

run_libc_system_observation_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_system_observation.sh
}

run_libc_system_information_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_system_information.sh
}

run_libc_getloadavg_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_getloadavg.sh
}

run_libc_fcntl_record_locks_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_fcntl_record_locks.sh
}

run_libc_flock_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_flock.sh
}

run_libc_sendfile_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sendfile.sh
}

run_libc_tee_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_tee.sh
}

run_libc_splice_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_splice.sh
}

run_libc_sync_file_range_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_sync_file_range.sh
}

run_libc_copy_file_range_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_copy_file_range.sh
}

run_libc_posix_fallocate_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_posix_fallocate.sh
}

run_descriptor_advice_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_descriptor_advice_header_abi.sh
}

run_libc_descriptor_advice_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_advice.sh
}

run_filesystem_capacity_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_filesystem_capacity_header_abi.sh
}

run_libc_filesystem_capacity_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_filesystem_capacity.sh
}

run_vector_io_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_vector_io_header_abi.sh
}

run_libc_vector_io_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_vector_io.sh
}

run_libc_uio_cxx_linkage_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_uio_cxx_linkage.sh
}

run_libc_uts_identity_probe() {
    run_in_uts_cap_container bash /workspace/compat/x86_64/run_libc_uts_identity.sh
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

run_libc_math_complex_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_complex.sh
}

run_libc_math_complex_complete_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_complex_complete.sh
}

run_libc_elementary_sqrt_fenv_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_elementary_sqrt_fenv.sh
}

run_libc_fenv_rounding_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_fenv_rounding.sh
}

run_libc_math_minmax_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_minmax.sh
}

run_libc_math_bit_sign_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_bit_sign.sh
}

run_libc_math_trunc_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_trunc.sh
}

run_libc_math_fmod_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_fmod.sh
}

run_libc_math_cbrt_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_cbrt.sh
}

run_libc_math_exp2_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_exp2.sh
}

run_libc_math_expm1_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_expm1.sh
}

run_libc_math_log10_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_log10.sh
}

run_libc_math_ceil_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_ceil.sh
}

run_libc_math_floor_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_floor.sh
}

run_libc_math_round_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_round.sh
}

run_libc_math_log2_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_log2.sh
}

run_libc_math_elementary_long_double_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_elementary_long_double.sh
}

run_libc_math_x87_extended_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_x87_extended.sh
}

run_libc_math_special_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_special.sh
}

run_libc_fdim_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_fdim.sh
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
        test_binary="$TMPDIR/crabc-x86-64-ldso-relocation"
        rustup run nightly-2026-07-24 rustc --edition=2021 --test \
            /workspace/ldso/src/x86_64_relocation.rs -o "$test_binary"
        "$test_binary" --test-threads=1
    '
}

run_ldso_image_tests() {
    run_in_container bash /workspace/ldso/run-x86_64-image.sh test
}

run_ldso_initial_graph_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_initial_graph.sh
}

run_ldso_general_initial_graph_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_general_initial_graph.sh
}

run_ldso_general_initial_graph_target_root_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_general_initial_graph_target_root.sh
}

run_ldso_general_initial_tls_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_general_initial_tls.sh
}

run_ldso_general_initial_tls_target_root_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_general_initial_tls_target_root.sh
}

run_ldso_target_root_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_target_root.sh
}

run_ldso_initial_tls_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_initial_tls.sh
}

run_libc_math_long_double_completion_tests() {
    run_in_container bash /workspace/compat/x86_64/run_libc_math_long_double_completion.sh
}

run_libc_math_elementary_fenv_sensitive_tests() {
    run_in_container bash -ceu '
        bash /workspace/compat/x86_64/run_libc_fenv_rounding.sh
        bash /workspace/compat/x86_64/run_libc_fdim.sh
        bash /workspace/compat/x86_64/run_libc_math_exp10.sh
        bash /workspace/compat/x86_64/run_libc_math_exp10f.sh
        bash /workspace/compat/x86_64/run_libc_math_long_double_completion.sh
    '
}

run_loader_libc_tls_runtime_v1_tests() {
    run_in_container bash /workspace/compat/x86_64/run_loader_libc_tls_runtime_v1.sh
}

run_loader_libc_tls_runtime_v1_registry_tests() {
    run_in_container bash /workspace/compat/x86_64/run_loader_libc_tls_runtime_v1_registry.sh
}

run_loader_libc_general_tls_runtime_v1_tests() {
    run_in_container bash /workspace/compat/x86_64/run_loader_libc_general_tls_runtime_v1.sh
}

run_loader_libc_general_tls_runtime_v1_target_root_tests() {
    run_in_container bash /workspace/compat/x86_64/run_loader_libc_general_tls_runtime_v1_target_root.sh
}

run_dynamic_main_thread_runtime_v1_tests() {
    run_in_container bash /workspace/compat/x86_64/run_dynamic_main_thread_runtime_v1.sh
}

run_dynamic_main_thread_runtime_v1_target_root_tests() {
    run_in_container bash /workspace/compat/x86_64/run_dynamic_main_thread_runtime_v1_target_root.sh
}

run_general_dynamic_lifecycle_tests() {
    run_in_container bash /workspace/compat/x86_64/run_general_dynamic_lifecycle.sh
}

run_ldso_initial_exec_tls_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_initial_exec_tls.sh
}

run_ldso_owned_crt_handoff_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_owned_crt_handoff.sh
}

run_ldso_fixed_graph_introspection_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_fixed_graph_introspection.sh
}

run_ldso_fixed_graph_dlfcn_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_fixed_graph_dlfcn.sh
}

run_ldso_public_dlfcn_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_public_dlfcn.sh
}

run_ldso_dladdr_symbol_bounds_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_dladdr_symbol_bounds.sh
}

run_ldso_bounded_dlopen_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_bounded_dlopen.sh
}

run_ldso_dynamic_admission_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_dynamic_admission.sh
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

case "$command" in
    campaign-status)
        [ "$#" -eq 0 ] || fail "campaign-status takes no arguments"
        python3 "$ROOT_DIR/compat/x86_64/campaign_report.py"
        ;;
    campaign-family)
        [ "$#" -eq 1 ] || fail "campaign-family requires exactly one family id"
        python3 "$ROOT_DIR/compat/x86_64/campaign_report.py" --family "$1"
        ;;
    campaign-static)
        [ "$#" -eq 0 ] || fail "campaign-static takes no arguments"
        python3 "$ROOT_DIR/compat/x86_64/campaign_runner.py" static
        ;;
    campaign-dynamic)
        [ "$#" -eq 0 ] || fail "campaign-dynamic takes no arguments"
        python3 "$ROOT_DIR/compat/x86_64/campaign_runner.py" dynamic
        ;;
    campaign-qualification)
        [ "$#" -eq 0 ] || fail "campaign-qualification takes no arguments"
        python3 "$ROOT_DIR/compat/x86_64/campaign_runner.py" qualification
        ;;
    campaign-promotion-check)
        [ "$#" -eq 0 ] || fail "campaign-promotion-check takes no arguments"
        python3 "$ROOT_DIR/compat/x86_64/campaign_runner.py" promotion-check
        ;;
    campaign-all)
        [ "$#" -eq 0 ] || fail "campaign-all takes no arguments"
        python3 "$ROOT_DIR/compat/x86_64/campaign_runner.py" all
        ;;
    routine-c-abi-matrix)
        [ "$#" -eq 1 ] || fail "routine-c-abi-matrix requires exactly one family id"
        ensure_image
        run_in_container python3 /workspace/compat/x86_64/generate_c_abi_evidence_matrix.py --run-family "$1"
        ;;
    getloadavg-header-abi) ;;
    libc-getloadavg) ;;
    sleep-header-abi) ;;
    libc-sleep) ;;
    mq-setattr-header-abi|libc-mq-setattr) ;;
    timerfd-header-abi|signalfd-header-abi) ;;
    signal-legacy-aliases-header-abi|libc-signal-legacy-aliases|signal-sysv-helpers-header-abi|libc-signal-sysv-helpers) ;;
    psignal-header-abi|libc-psignal|libc-process-signal) ;;
    h-errno-header-abi|libc-h-errno|resolver-runtime-header-abi|libc-resolver-runtime) ;;
    legacy-misc-header-abi|libc-legacy-misc) ;;
    ualarm-header-abi|usleep-header-abi|libc-timerfd|libc-signalfd|libc-sigpause|libc-sigisemptyset|libc-sigandset-sigorset|libc-sigpending|libc-sigrtmax|libc-sigrtmin|libc-sched-getscheduler|libc-sched-rr-interval|libc-alarm|libc-ualarm|libc-interval-timers|libc-usleep|libc-sigaddset-sigdelset-sigfillset|libc-sched-getparam|libc-sched-setparam|libc-sched-setscheduler|libc-sched-getaffinity|libc-sched-setaffinity|libc-setfsuid|libc-setfsgid|libc-personality|libc-io-permissions) ;;
    libc-sched-cpucount|libc-sched-getcpu|libc-sched-priority-bounds|libc-sched-yield|libc-sched-get-priority-max|libc-sched-get-priority-min) ;;
    sched-cpucount-header-abi|sched-cpu-macros-header-abi|sched-getscheduler-header-abi|sched-rr-interval-header-abi|sched-priority-bounds-header-abi|sched-get-priority-max-header-abi|sched-get-priority-min-header-abi|sched-getparam-header-abi|sched-setparam-header-abi|sched-setscheduler-header-abi|sched-getaffinity-header-abi|sched-setaffinity-header-abi|setfsuid-header-abi|setfsgid-header-abi|personality-header-abi) ;;
    sched-cpu-set-source-form) ;;
    ctermid-header-abi|grantpt-header-abi|unlockpt-header-abi|gethostid-header-abi|issetugid-header-abi|endhostent-header-abi|protocol-database-header-abi|ether-line-header-abi|ether-header-abi|res-init-header-abi|posix-spawnattr-destroy-header-abi|posix-spawnattr-getflags-header-abi|posix-spawnattr-setpgroup-header-abi|posix-spawnattr-setschedparam-header-abi|posix-spawnattr-setschedpolicy-header-abi|posix-spawn-file-actions-init-header-abi|getpagesize-header-abi|gettid-header-abi|posix-close-header-abi|isatty-header-abi|ttyname-r-header-abi|tcgetpgrp-header-abi|tcsetpgrp-header-abi|getpass-header-abi|fchdir-header-abi|ulimit-header-abi|libc-ctermid|libc-grantpt|libc-unlockpt|libc-gethostid|libc-issetugid|libc-endhostent|libc-sethostent|libc-protocol-database|libc-ether-line|libc-ether|libc-res-init|libc-posix-spawnattr-destroy|libc-posix-spawnattr-getflags|libc-posix-spawnattr-setpgroup|libc-posix-spawnattr-setschedparam|libc-posix-spawnattr-setschedpolicy|libc-posix-spawn-file-actions-init|libc-getpagesize|libc-gettid|libc-posix-close|libc-isatty|libc-ttyname-r|libc-tcgetpgrp|libc-tcsetpgrp|libc-getpass|libc-fchdir|libc-ulimit|mkfifo-header-abi|mkdirat-header-abi|mkfifoat-header-abi|libc-mkfifo|libc-mkdirat|libc-mkfifoat|mktemp-header-abi|libc-mktemp) ;;
    temporary-names-header-abi|libc-temporary-names) ;;
    file-handles-header-abi|libc-file-handles) ;;
    posix-spawn-file-actions-header-abi|libc-posix-spawn-file-actions|process-exec-header-abi|libc-process-exec) ;;
    readlinkat-header-abi|libc-readlinkat|linkat-header-abi|libc-linkat|renameat2-header-abi|libc-renameat2|lchown-header-abi|libc-lchown|hasmntopt-header-abi|libc-hasmntopt|unlinkat-header-abi|libc-unlinkat|chown-header-abi|libc-chown|sync-header-abi|libc-sync) ;;
    tee-header-abi|splice-header-abi) ;;
    sync-file-range-header-abi|copy-file-range-header-abi) ;;
    stdio-permanent-line-io-header-abi|stdio-octal-hex-scan-header-abi|stdio-fixed-percent-scan-header-abi|stdio-fixed-format-whitespace-scan-header-abi|stdio-fixed-literal-scan-header-abi|stdio-fixed-empty-format-scan-header-abi|stdio-fixed-suppressed-character-scan-header-abi|stdio-fixed-suppressed-string-scan-header-abi|stdio-fixed-suppressed-scanset-scan-header-abi|stdio-fixed-suppressed-count-scan-header-abi) ;;
    math-complex-complete-header-abi|libc-math-complex-complete) ;;
    stdio-permanent-byte-io-header-abi) ;;
    stdio-permanent-status-header-abi) ;;
    stdio-permanent-freading-stdin-header-abi) ;;
    stdio-permanent-fsetlocking-stdin-header-abi) ;;
    stdio-permanent-fseterr-stdin-header-abi) ;;
    stdio-permanent-freadable-stdin-header-abi) ;;
    stdio-permanent-fwritable-stderr-header-abi) ;;
    stdio-permanent-fbufsize-stderr-header-abi) ;;
    stdio-permanent-flbf-stderr-header-abi) ;;
    stdio-permanent-fileno-header-abi) ;;
    stdio-permanent-fileno-unlocked-header-abi) ;;
    stdio-permanent-feof-unlocked-header-abi) ;;
    stdio-permanent-ferror-unlocked-header-abi) ;;
    clock-adjtime-header-abi) ;;
    clock-settime-header-abi) ;;
    timer-getoverrun-header-abi) ;;
    timer-delete-header-abi) ;;
    timer-gettime-header-abi) ;;
    timer-settime-header-abi) ;;
    fopen64-header-abi) ;;
    pthread-spin-destroy-header-abi|pthread-spin-operations-header-abi) ;;
    pthread-header-source-form) ;;
    sys-io-header-abi) ;;
    tcp-header-abi) ;;
    stddef-header-abi) ;;
    atomic-addressable-abi) ;;
    image|musl-oracle|header-abi-reference|public-header-surface|header-abi-project|math-complex-header-abi|sys-reg-header-abi|types-header-abi|stat-header-abi|utime-header-abi|pthread-c11-header-abi|pthread-cancellation-header-abi|stdlib-header-abi|stdio-standard-header-abi|time-header-abi|poll-header-abi|select-header-abi|fcntl-header-abi|descriptor-advice-header-abi|filesystem-capacity-header-abi|flock-header-abi|sendfile-header-abi|ioctl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|termios-header-abi|mman-header-abi|resource-header-abi|socket-header-abi|socket-messages-header-abi|random-entropy-header-abi|mm-abi-reference|mapping-reference|memory-vm-reference|pty-basic-reference|terminal-reference|mlock-reference|msync-reference|mincore-reference|fs-advice-reference|memfd-reference|ftruncate-reference|statfs-reference|timestamp-reference|path-lifecycle-reference|namespace-reference|path-core-reference|xattr-reference|directory-reference|temporary-object-reference|statx-reference|cwd-canonicalize-reference|root-change-reference|mount-reference|thread-kill-reference|ipc-reference|shm-reference|inotify-reference|socket-transport-reference|interface-device-reference|resolver-transport-reference|resolver-facade-reference|netdb-reference|users-databases-reference|posix-fallocate-reference|fallocate-reference|file-position-reference|sync-reference|syncfs-reference|sync-file-range-reference|rand-reference|time-abi-reference|time-observation-reference|calendar-time-reference|advanced-time-reference|relative-sleep-reference|clock-nanosleep-reference|getitimer-reference|setitimer-reference|timerfd-reference|pselect-reference|poll-reference|ppoll-reference|epoll-reference|process-identity-reference|child-ownership-reference|getgroups-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|fcntl-status-reference|flock-reference|sendfile-reference|copy-file-range-reference|scheduler-priority-bounds-reference|rr-interval-reference|sched-affinity-reference|sched-affinity-set-reference|priority-reference|setpriority-reference|rlimit-reference|rlimit-targeted-reference|setrlimit-reference|umask-reference|rusage-reference|times-reference|fstat-reference|statat-reference|getcwd-reference|readlinkat-reference|access-reference|system-reference|thread-reference|thread-credentials-reference|fs-credentials-reference|core|facade|facade-record-owning|libc-syscall|libc-errno-tls|libc-stat-compat|libc-credentials|libc-bootstrap-primitives|libc-signal-control|libc-signal-execution|libc-static-tls-v1|libc-crt-static-tls|libc-pthread-create-join-tls|libc-c11-lifecycle|libc-c11-plain-sync|libc-pthread-c11-once|libc-pthread-c11-tsd|libc-pthread-tls-aggregate|libc-pthread-cancel-deferred|libc-pthread-atfork|libc-thrd-sleep|libc-pthread-mutex-normal|libc-pthread-rwlock|libc-pthread-cond-private|libc-termios-control|libc-process-context|libc-environment|libc-descriptor-io|libc-descriptor-lifecycle|libc-timestamp-updates|libc-process-resources|libc-socket-transport|libc-socket-messages|libc-thread-pointer|libc-foundation|libc-fenv|libc-math-complex|libc-elementary-sqrt-fenv|libc-math-x87-extended|libc-math-long-double-completion|libc-math-elementary-fenv-sensitive|libc-memory|libc-setjmp|libc-atomic|libc-clone-raw|libc-signal-altstack|libc-signal-foundation|ldso-relocation|ldso-image|ldso-initial-graph|ldso-general-initial-graph|ldso-general-initial-target-root|ldso-general-initial-tls|ldso-general-initial-tls-target-root|ldso-initial-tls|ldso-initial-exec-tls|ldso-owned-crt-handoff|ldso-fixed-graph-introspection|ldso-dynamic-admission|libc-stack-chk-fail|pthread-spin-init-header-abi) ;;
    math-elementary-long-double-header-abi|libc-math-elementary-long-double) ;;
    ldso-fixed-graph-dlfcn) ;;
    ldso-public-dlfcn|ldso-dladdr-symbol-bounds) ;;
    ldso-bounded-dlopen) ;;
    loader-libc-tls-runtime-v1) ;;
    loader-libc-tls-runtime-v1-registry) ;;
    loader-libc-general-tls-runtime-v1) ;;
    loader-libc-general-tls-runtime-v1-target-root) ;;
    dynamic-main-thread-runtime-v1) ;;
    dynamic-main-thread-runtime-v1-target-root) ;;
    general-dynamic-lifecycle) ;;
    general-relocations) ;;
    math-special-header-abi|libc-math-special) ;;
    math-exp2-header-abi|math-expm1-header-abi|math-log10-header-abi|libc-math-exp2|libc-math-expm1|libc-math-log10|math-exp10-header-abi|math-log-header-abi|math-sin-header-abi|math-tan-header-abi|math-tanh-header-abi|math-atanh-header-abi|math-acosh-header-abi|math-sincos-header-abi|math-pow-header-abi|libc-math-exp10|libc-math-log|libc-math-sin|libc-math-tan|libc-math-tanh|libc-math-atanh|libc-math-acosh|libc-math-sincos|libc-math-pow) ;;
    inet-address-header-abi|nameser-header-abi|quota-header-abi|endservent-header-abi|service-lifecycle-header-abi) ;;
    libc-network-byte-order|libc-dn-skipname|libc-dn-expand|libc-ns-flagdata|libc-ns-get16|libc-ns-get32|libc-ns-put16|libc-ns-put32|libc-ns-skiprr|libc-nameser-wire-aggregate|libc-nameser-message-parser) ;;
    ldso-target-root) ;;
    libc-fenv-rounding) ;;
    libc-owned-scalar-math) ;;
    libc-owned-binary80-math) ;;
    libc-math-minmax) ;;
    libc-math-bit-sign) ;;
    libc-math-trunc) ;;
    libc-math-fmod) ;;
    libc-math-cbrt) ;;
    libc-math-ceil) ;;
    libc-math-floor) ;;
    libc-math-round) ;;
    libc-math-log2) ;;
    libc-fdim) ;;
    machine-context-header-abi) ;;
    memory-sync-header-abi) ;;
    memory-locking-header-abi) ;;
    memfd-create-header-abi) ;;
    vector-io-header-abi) ;;
    libc-crt1-static-tls) ;;
    owned-system-cancellation) ;;
    owned-dynamic-spawn) ;;
    owned-assert|owned-linux-control) ;;
    owned-io-cancellation) ;;
    owned-resolver-network) ;;
    owned-dynamic-io-cancellation) ;;
    owned-pthread-getattr|owned-pthread-join-cancel|owned-pthread-cond-cancel|owned-pthread-cond-timed) ;;
    owned-pthread-lifecycle) ;;
    qualification-manifest) ;;
    owned-static-sysroot) ;;
    lua-static-source-build) ;;
    lua-dynamic-source-build) ;;
    libc-owned-wordexp) ;;
    owned-dynamic-sysroot) ;;
    owned-dynamic-pthread-exit) ;;
    owned-dynamic-fork) ;;
    materialized-dynamic-sysroot) ;;
    crt-object-bundle) ;;
    crt-dynamic-startup|crt-dynamic-link-contract|consumer-static-pie-lto|consumer-native-facade-lto) ;;
    linux-5-10-uapi) ;;
    candidate-header-closure) ;;
    headers-layouts-aggregate) ;;
    installed-header-tree-closure) ;;
    selected-header-install-projection) ;;
    header-callable-visibility-matrix) ;;
    header-callable-disposition) ;;
    header-abi-matrix) ;;
    header-record-layout-matrix) ;;
    header-declaration-macro-visibility-matrix) ;;
    header-callable-linkage-audit) ;;
    header-callable-provider-linkage-audit) ;;
    uapi-wrapper-matrix) ;;
    epoll-header-abi) ;;
    event-descriptors-header-abi) ;;
    fanotify-header-abi) ;;
    dirent-header-abi) ;;
    ftw-header-abi) ;;
    stat-ftw-header-source-form) ;;
    param-header-source-form) ;;
    pathname-lifecycle-header-abi) ;;
    timeval-transitive-header-abi) ;;
    sys-time-direct-header-abi) ;;
    access-header-abi) ;;
    xattr-header-abi) ;;
    madvise-reference) ;;
    basename-header-abi|siginterrupt-header-abi|mlockall-header-abi|munlockall-header-abi|ftime-header-abi|clock-getcpuclockid-header-abi|libc-basename|libc-siginterrupt|libc-mlockall|libc-munlockall|libc-ftime|libc-clock-getcpuclockid) ;;
    umask-header-abi|intrusive-queue-header-abi|getdtablesize-header-abi|membarrier-header-abi|syncfs-header-abi|confstr-header-abi|fpathconf-header-abi|pathconf-header-abi|sysconf-header-abi|libc-umask|libc-intrusive-queue|libc-getdtablesize|libc-membarrier|libc-syncfs|libc-confstr|libc-fpathconf|libc-pathconf|libc-sysconf) ;;
    ctype-header-abi|locale-profile-header-abi|locale-multibyte-header-abi|iconv-header-abi|wide-character-header-abi|wcswcs-header-abi|locale-object-wide-header-abi|locale-narrow-header-abi|c32rtomb-header-abi|uchar-stateful-header-abi) ;;
    integer-arithmetic-header-abi|integer-parse-header-abi|float-parse-header-abi|crypt-header-abi|getsubopt-header-abi|l64a-header-abi|intmax-arithmetic-header-abi|credential-observation-header-abi|login-name-header-abi|child-reaping-header-abi|wait-extensions-header-abi|immediate-termination-header-abi|sched-getcpu-header-abi|sched-yield-header-abi|bsearch-header-abi|linear-search-header-abi|intrusive-queue-header-abi|qsort-header-abi|callback-algorithms-header-abi) ;;
    posix-exit-header-abi|posix-spawnattr-init-header-abi|posix-spawnattr-getpgroup-header-abi|posix-spawnattr-signal-fields-header-abi|posix-spawnattr-getschedparam-header-abi|posix-spawnattr-getschedpolicy-header-abi) ;;
    ffs-header-abi) ;;
    memory-special-header-abi) ;;
    memccpy-header-abi) ;;
    aio-error-header-abi) ;;
    byte-strings-header-abi) ;;
    memory-search-header-abi) ;;
    memccpy-header-abi) ;;
    mempcpy-header-abi) ;;
    strsep-header-abi) ;;
    strtok-header-abi|stateful-byte-strings-header-abi) ;;
    string-copy-header-abi) ;;
    error-strings-header-abi|strsignal-header-abi|gettext-catalog-header-abi) ;;
    string-duplication-header-abi) ;;
    random-entropy-header-abi) ;;
    sysv-semaphore-header-abi|posix-semaphore-header-abi) ;;
    sysv-message-shared-memory-header-abi) ;;
    libc-event-descriptors) ;;
    libc-extended-attributes) ;;
    libc-pathname-lifecycle) ;;
    libc-directory-streams) ;;
    libc-filesystem-traversal) ;;
    libc-filesystem-directory) ;;
    libc-filesystem-extensions) ;;
    libc-lchmod-unsupported) ;;
    libc-fopen64-alias) ;;
    libc-stdio-standard|libc-stdio-format-scan|libc-stdio-integer-scan|libc-stdio-octal-hex-scan|libc-stdio-fixed-percent-scan|libc-stdio-fixed-format-whitespace-scan|libc-stdio-fixed-literal-scan|libc-stdio-fixed-empty-format-scan|libc-stdio-fixed-suppressed-character-scan|libc-stdio-fixed-suppressed-string-scan|libc-stdio-fixed-suppressed-scanset-scan|libc-stdio-fixed-suppressed-count-scan|libc-stdio-float-hex-output|libc-stdio-errno-output|libc-stdio-permanent-format-scan|libc-stdio-permanent-line-io|libc-stdio-permanent-byte-io|libc-stdio-permanent-status|libc-stdio-permanent-freading-stdin|libc-stdio-permanent-fsetlocking-stdin|libc-stdio-permanent-fseterr-stdin|libc-stdio-permanent-freadable-stdin|libc-stdio-permanent-fwritable-stderr|libc-stdio-permanent-fbufsize-stderr|libc-stdio-permanent-flbf-stderr|libc-stdio-permanent-fileno|libc-stdio-permanent-fileno-unlocked|libc-stdio-permanent-feof-unlocked|libc-stdio-permanent-ferror-unlocked|libc-stdio-path-stream|libc-stdio-tmpfile|libc-text-math-locale-stdio-composition) ;;
    libc-pthread-identity) ;;
    libc-pthread-affinity) ;;
    libc-pthread-cpuclock) ;;
    libc-pthread-name) ;;
    libc-pthread-attributes|libc-pthread-attr-lifecycle|libc-pthread-barrierattr-pshared|libc-pthread-barrier|libc-pthread-spin-init|libc-pthread-spin-operations) ;;
    libc-pthread-spin-destroy) ;;
    libc-pthread-detach) ;;
    libc-thrd-yield) ;;
    libc-memory-sync) ;;
    libc-memory-locking) ;;
    libc-memfd-create) ;;
    libc-legacy-memory) ;;
    libc-memory-special) ;;
    libc-memccpy) ;;
    libc-mempcpy) ;;
    libc-strsep) ;;
    libc-strtok|libc-stateful-byte-strings) ;;
    libc-allocator-runtime) ;;
    libc-allocator-basic-runtime-v1) ;;
    libc-allocator-string-duplication) ;;
    libc-scandir) ;;
    libc-allocator-observability) ;;
    libc-alloca) ;;
    libc-static-c-abi-differential) ;;
    libc-static-c-abi-same-object-differential|qualification-posix-abi-admission) ;;
    libc-interface-discovery) ;;
    libc-posix-exit|libc-posix-spawnattr-init|libc-posix-spawnattr-getpgroup|libc-posix-spawnattr-signal-fields|libc-posix-spawnattr-getschedparam|libc-posix-spawnattr-getschedpolicy) ;;
    libc-clock-adjtime) ;;
    libc-clock-settime) ;;
    libc-timer-getoverrun) ;;
    libc-timer-delete) ;;
    libc-timer-gettime) ;;
    libc-timer-settime) ;;
    libc-tee|libc-splice) ;;
    libc-sync-file-range|libc-copy-file-range) ;;
    libc-readiness-waits|libc-system-observation|libc-system-information|libc-fcntl-record-locks|libc-flock|libc-sendfile|libc-posix-fallocate|libc-descriptor-advice|libc-filesystem-capacity|libc-uts-identity|libc-ctype|libc-locale-profile|libc-locale-multibyte|libc-locale-wide-iconv|libc-wide-character|libc-wcswcs|libc-locale-object-wide|libc-locale-narrow|libc-locale-ctype-locators|libc-locale-error-strings|libc-regex|libc-integer-arithmetic|libc-integer-parse|libc-float-parse|libc-getsubopt|libc-crypt|libc-crypt-allocator-composition|libc-l64a|libc-a64l|libc-intmax-arithmetic|libc-credential-observation|libc-secure-environment|libc-login-name|libc-child-reaping|libc-wait-extensions|libc-immediate-termination|libc-bsearch|libc-linear-search|libc-intrusive-queue|libc-qsort|libc-callback-algorithms|libc-search-tree-intrusive|libc-search-hash-table|libc-gettext-catalog|libc-access|libc-clock-gettime|libc-time-observation|libc-difftime|libc-timegm|libc-gmtime-r|libc-system-configuration|libc-mapping-core|libc-header-layouts-baseline|libc-nanosleep|libc-clock-nanosleep|libc-descriptor-entry|libc-fcntl-status-control|libc-ioctl|libc-ffs|libc-byte-strings|libc-in6addr-any|libc-in6addr-loopback|libc-process-globals-getopt|libc-auxv-observation|libc-inet-address|libc-inet-ntoa|libc-inet-classful|libc-hstrerror|libc-endservent|libc-service-lifecycle|libc-numeric-netdb|libc-random-entropy|libc-memory-search|libc-string-copy|libc-error-strings|libc-strsignal|libc-descriptor-pipeline|libc-c32rtomb|libc-uchar-stateful|libc-memccpy|libc-aio-error|libc-inet-netof|libc-inet-network) ;;
    libc-vector-io|libc-uio-cxx-linkage) ;;
    libc-sysv-semaphore|libc-posix-semaphore) ;;
    libc-sysv-message-shared-memory) ;;
    libc-math-exp) ;;
    libc-math-cos) ;;
    libc-math-cosh) ;;
    libc-math-asinh) ;;
    libc-math-exp10f) ;;
    libc-math-sinh) ;;
    libc-pthread-condattr-pshared) ;;
    libc-pthread-attr-lifecycle) ;;
    libc-pthread-condattr-clock) ;;
    libc-pthread-mutexattr-protocol-query) ;;
    libc-pthread-mutexattr-pshared-query) ;;
    libc-pthread-mutexattr-robust-query) ;;
    libc-pthread-mutexattr-type-query) ;;
    libc-pthread-mutexattr-type-setter) ;;
    libc-pthread-mutex-prioceiling-query) ;;
    libc-pthread-getconcurrency) ;;
    libc-pthread-setconcurrency) ;;
    libc-rand-r|libc-lrand48) ;;
    feature-profile-control-plane-header-abi) ;;
    terminal-streams-header-topology) ;;
    link-header-source-form) ;;
    reboot-header-source-form) ;;
    stdio-header-source-form) ;;
    math-tgmath-source-form) ;;
    mman-mcl-onfault-header-source-form) ;;
    mount-header-source-form) ;;
    klog-header-source-form) ;;
    cachectl-header-source-form) ;;
    syslog-header-abi) ;;
    sysmacros-header-source-form) ;;
    ioctl-header-source-form) ;;
    fcntl-event-header-topology) ;;

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
    linux-5-10-uapi)
        [ "$#" -eq 0 ] || fail "linux-5-10-uapi takes no arguments"
        ensure_image
        run_linux_5_10_uapi
        ;;
    header-abi-reference)
        [ "$#" -eq 0 ] || fail "header-abi-reference takes no arguments"
        ensure_image
        run_header_abi_reference
        ;;
    public-header-surface)
        [ "$#" -eq 0 ] || fail "public-header-surface takes no arguments"
        ensure_image
        run_public_header_surface
        ;;
    candidate-header-closure)
        [ "$#" -eq 0 ] || fail "candidate-header-closure takes no arguments"
        ensure_image
        run_candidate_header_closure
        ;;
    headers-layouts-aggregate)
        [ "$#" -eq 0 ] || fail "headers-layouts-aggregate takes no arguments"
        ensure_image
        run_headers_layouts_aggregate
        ;;
    installed-header-tree-closure)
        [ "$#" -eq 0 ] || fail "installed-header-tree-closure takes no arguments"
        ensure_image
        run_installed_header_tree_closure
        ;;
    selected-header-install-projection)
        [ "$#" -eq 0 ] || fail "selected-header-install-projection takes no arguments"
        ensure_image
        run_selected_header_install_projection
        ;;
    header-callable-visibility-matrix)
        [ "$#" -eq 0 ] || fail "header-callable-visibility-matrix takes no arguments"
        ensure_image
        run_header_callable_visibility_matrix
        ;;
    header-callable-disposition)
        [ "$#" -eq 0 ] || fail "header-callable-disposition takes no arguments"
        ensure_image
        run_header_callable_disposition
        ;;
    header-abi-matrix)
        [ "$#" -eq 0 ] || fail "header-abi-matrix takes no arguments"
        ensure_image
        run_header_abi_matrix
        ;;
    header-record-layout-matrix)
        [ "$#" -eq 0 ] || fail "header-record-layout-matrix takes no arguments"
        ensure_image
        run_header_record_layout_matrix
        ;;
    header-declaration-macro-visibility-matrix)
        [ "$#" -eq 0 ] || fail "header-declaration-macro-visibility-matrix takes no arguments"
        ensure_image
        run_header_declaration_macro_visibility_matrix
        ;;
    feature-profile-control-plane-header-abi)
        [ "$#" -eq 0 ] || fail "feature-profile-control-plane-header-abi takes no arguments"
        ensure_image
        run_feature_profile_control_plane_header_abi
        ;;
    header-callable-linkage-audit)
        [ "$#" -eq 0 ] || fail "header-callable-linkage-audit takes no arguments"
        ensure_image
        run_header_callable_linkage_audit
        ;;
    header-callable-provider-linkage-audit)
        [ "$#" -eq 0 ] || fail "header-callable-provider-linkage-audit takes no arguments"
        ensure_image
        run_header_callable_provider_linkage_audit
        ;;
    uapi-wrapper-matrix)
        [ "$#" -eq 0 ] || fail "uapi-wrapper-matrix takes no arguments"
        ensure_image
        run_uapi_wrapper_matrix
        ;;
    epoll-header-abi)
        [ "$#" -eq 0 ] || fail "epoll-header-abi takes no arguments"
        ensure_image
        run_epoll_header_abi
        ;;
    event-descriptors-header-abi)
        [ "$#" -eq 0 ] || fail "event-descriptors-header-abi takes no arguments"
        ensure_image
        run_event_descriptors_header_abi
        ;;
    fanotify-header-abi)
        [ "$#" -eq 0 ] || fail "fanotify-header-abi takes no arguments"
        ensure_image
        run_fanotify_header_abi
        ;;
    dirent-header-abi)
        [ "$#" -eq 0 ] || fail "dirent-header-abi takes no arguments"
        ensure_image
        run_dirent_header_abi
        ;;
    ftw-header-abi)
        [ "$#" -eq 0 ] || fail "ftw-header-abi takes no arguments"
        ensure_image
        run_ftw_header_abi
        ;;
    stat-ftw-header-source-form)
        [ "$#" -eq 0 ] || fail "stat-ftw-header-source-form takes no arguments"
        ensure_image
        run_stat_ftw_header_source_form
        ;;
    param-header-source-form)
        [ "$#" -eq 0 ] || fail "param-header-source-form takes no arguments"
        ensure_image
        run_param_header_source_form
        ;;
    pathname-lifecycle-header-abi)
        [ "$#" -eq 0 ] || fail "pathname-lifecycle-header-abi takes no arguments"
        ensure_image
        run_pathname_lifecycle_header_abi
        ;;
    ioctl-header-abi)
        [ "$#" -eq 0 ] || fail "ioctl-header-abi takes no arguments"
        ensure_image
        run_ioctl_header_abi
        ;;
    ioctl-header-source-form)
        [ "$#" -eq 0 ] || fail "ioctl-header-source-form takes no arguments"
        ensure_image
        run_ioctl_header_source_form
        ;;
    link-header-source-form)
        [ "$#" -eq 0 ] || fail "link-header-source-form takes no arguments"
        ensure_image
        run_link_header_source_form
        ;;
    reboot-header-source-form)
        [ "$#" -eq 0 ] || fail "reboot-header-source-form takes no arguments"
        ensure_image
        run_reboot_header_source_form
        ;;
    math-tgmath-source-form)
        [ "$#" -eq 0 ] || fail "math-tgmath-source-form takes no arguments"
        ensure_image
        run_math_tgmath_source_form
        ;;
    mman-mcl-onfault-header-source-form)
        [ "$#" -eq 0 ] || fail "mman-mcl-onfault-header-source-form takes no arguments"
        ensure_image
        run_mman_mcl_onfault_header_source_form
        ;;
    mount-header-source-form)
        [ "$#" -eq 0 ] || fail "mount-header-source-form takes no arguments"
        ensure_image
        run_mount_header_source_form
        ;;
    klog-header-source-form)
        [ "$#" -eq 0 ] || fail "klog-header-source-form takes no arguments"
        ensure_image
        run_klog_header_source_form
        ;;
    cachectl-header-source-form)
        [ "$#" -eq 0 ] || fail "cachectl-header-source-form takes no arguments"
        ensure_image
        run_cachectl_header_source_form
        ;;
    sysmacros-header-source-form)
        [ "$#" -eq 0 ] || fail "sysmacros-header-source-form takes no arguments"
        ensure_image
        run_sysmacros_header_source_form
        ;;
    fcntl-event-header-topology)
        [ "$#" -eq 0 ] || fail "fcntl-event-header-topology takes no arguments"
        ensure_image
        run_fcntl_event_header_topology
        ;;
    sys-io-header-abi)
        [ "$#" -eq 0 ] || fail "sys-io-header-abi takes no arguments"
        ensure_image
        run_sys_io_header_abi
        ;;
    timeval-transitive-header-abi)
        [ "$#" -eq 0 ] || fail "timeval-transitive-header-abi takes no arguments"
        ensure_image
        run_timeval_transitive_header_abi
        ;;
    sys-time-direct-header-abi)
        [ "$#" -eq 0 ] || fail "sys-time-direct-header-abi takes no arguments"
        ensure_image
        run_sys_time_direct_header_abi
        ;;
    access-header-abi)
        [ "$#" -eq 0 ] || fail "access-header-abi takes no arguments"
        ensure_image
        run_access_header_abi
        ;;
    xattr-header-abi)
        [ "$#" -eq 0 ] || fail "xattr-header-abi takes no arguments"
        ensure_image
        run_xattr_header_abi
        ;;
    header-abi-project)
        [ "$#" -eq 0 ] || fail "header-abi-project takes no arguments"
        ensure_image
        run_header_abi_project
        ;;
    math-complex-header-abi)
        [ "$#" -eq 0 ] || fail "math-complex-header-abi takes no arguments"
        ensure_image
        run_math_complex_header_abi
        ;;
    math-complex-complete-header-abi)
        [ "$#" -eq 0 ] || fail "math-complex-complete-header-abi takes no arguments"
        ensure_image
        run_math_complex_complete_header_abi
        ;;
    math-elementary-long-double-header-abi)
        [ "$#" -eq 0 ] || fail "math-elementary-long-double-header-abi takes no arguments"
        ensure_image
        run_math_elementary_long_double_header_abi
        ;;
    math-special-header-abi)
        [ "$#" -eq 0 ] || fail "math-special-header-abi takes no arguments"
        ensure_image
        run_math_special_header_abi
        ;;
    math-exp2-header-abi)
        [ "$#" -eq 0 ] || fail "math-exp2-header-abi takes no arguments"
        ensure_image
        run_math_exp2_header_abi
        ;;
    math-expm1-header-abi)
        [ "$#" -eq 0 ] || fail "math-expm1-header-abi takes no arguments"
        ensure_image
        run_math_expm1_header_abi
        ;;
    math-log10-header-abi)
        [ "$#" -eq 0 ] || fail "math-log10-header-abi takes no arguments"
        ensure_image
        run_math_log10_header_abi
        ;;
    sys-reg-header-abi)
        [ "$#" -eq 0 ] || fail "sys-reg-header-abi takes no arguments"
        ensure_image
        run_sys_reg_header_abi
        ;;
    machine-context-header-abi)
        [ "$#" -eq 0 ] || fail "machine-context-header-abi takes no arguments"
        ensure_image
        run_machine_context_header_abi
        ;;
    types-header-abi)
        [ "$#" -eq 0 ] || fail "types-header-abi takes no arguments"
        ensure_image
        run_types_header_abi
        ;;
    stddef-header-abi)
        [ "$#" -eq 0 ] || fail "stddef-header-abi takes no arguments"
        ensure_image
        run_stddef_header_abi
        ;;
    stat-header-abi)
        [ "$#" -eq 0 ] || fail "stat-header-abi takes no arguments"
        ensure_image
        run_stat_header_abi
        ;;
    utime-header-abi)
        [ "$#" -eq 0 ] || fail "utime-header-abi takes no arguments"
        ensure_image
        run_utime_header_abi
        ;;
    pthread-c11-header-abi)
        [ "$#" -eq 0 ] || fail "pthread-c11-header-abi takes no arguments"
        ensure_image
        run_pthread_c11_header_abi
        ;;
    pthread-header-source-form)
        [ "$#" -eq 0 ] || fail "pthread-header-source-form takes no arguments"
        ensure_image
        run_pthread_header_source_form
        ;;
    atomic-addressable-abi)
        [ "$#" -eq 0 ] || fail "atomic-addressable-abi takes no arguments"
        ensure_image
        run_atomic_addressable_abi
        ;;
    pthread-cancellation-header-abi)
        [ "$#" -eq 0 ] || fail "pthread-cancellation-header-abi takes no arguments"
        ensure_image
        run_pthread_cancellation_header_abi
        ;;
    pthread-spin-destroy-header-abi)
        [ "$#" -eq 0 ] || fail "pthread-spin-destroy-header-abi takes no arguments"
        ensure_image
        run_pthread_spin_destroy_header_abi
        ;;
    pthread-spin-operations-header-abi)
        [ "$#" -eq 0 ] || fail "pthread-spin-operations-header-abi takes no arguments"
        ensure_image
        run_pthread_spin_operations_header_abi
        ;;
    stdlib-header-abi)
        [ "$#" -eq 0 ] || fail "stdlib-header-abi takes no arguments"
        ensure_image
        run_stdlib_header_abi
        ;;
    syslog-header-abi)
        [ "$#" -eq 0 ] || fail "syslog-header-abi takes no arguments"
        ensure_image
        run_syslog_header_abi
        ;;
    getloadavg-header-abi)
        [ "$#" -eq 0 ] || fail "getloadavg-header-abi takes no arguments"
        ensure_image
        run_getloadavg_header_abi
        ;;
    stdio-standard-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-standard-header-abi takes no arguments"
        ensure_image
        run_stdio_standard_header_abi
        ;;
    stdio-header-source-form)
        [ "$#" -eq 0 ] || fail "stdio-header-source-form takes no arguments"
        ensure_image
        run_stdio_header_source_form
        ;;
    fopen64-header-abi)
        [ "$#" -eq 0 ] || fail "fopen64-header-abi takes no arguments"
        ensure_image
        run_fopen64_header_abi
        ;;
    stdio-permanent-line-io-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-line-io-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_line_io_header_abi.sh
        ;;
    stdio-permanent-byte-io-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-byte-io-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_byte_io_header_abi.sh
        ;;
    stdio-octal-hex-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-octal-hex-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_octal_hex_scan_header_abi.sh
        ;;
    stdio-fixed-percent-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-percent-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_percent_scan_header_abi.sh
        ;;
    stdio-fixed-format-whitespace-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-format-whitespace-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_format_whitespace_scan_header_abi.sh
        ;;
    stdio-fixed-literal-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-literal-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_literal_scan_header_abi.sh
        ;;
    stdio-fixed-empty-format-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-empty-format-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_empty_format_scan_header_abi.sh
        ;;
    stdio-fixed-suppressed-character-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-suppressed-character-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_character_scan_header_abi.sh
        ;;
    stdio-fixed-suppressed-string-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-suppressed-string-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_string_scan_header_abi.sh
        ;;
    stdio-fixed-suppressed-scanset-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-suppressed-scanset-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_scanset_scan_header_abi.sh
        ;;
    stdio-fixed-suppressed-count-scan-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-fixed-suppressed-count-scan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_count_scan_header_abi.sh
        ;;
    stdio-permanent-status-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-status-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_status_header_abi.sh
        ;;
    stdio-permanent-freading-stdin-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-freading-stdin-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_freading_stdin_header_abi.sh
        ;;
    stdio-permanent-fsetlocking-stdin-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-fsetlocking-stdin-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_fsetlocking_stdin_header_abi.sh
        ;;
    stdio-permanent-fseterr-stdin-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-fseterr-stdin-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_fseterr_stdin_header_abi.sh
        ;;
    stdio-permanent-freadable-stdin-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-freadable-stdin-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_freadable_stdin_header_abi.sh
        ;;
    stdio-permanent-fwritable-stderr-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-fwritable-stderr-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_fwritable_stderr_header_abi.sh
        ;;
    stdio-permanent-fbufsize-stderr-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-fbufsize-stderr-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_fbufsize_stderr_header_abi.sh
        ;;
    stdio-permanent-flbf-stderr-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-flbf-stderr-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_flbf_stderr_header_abi.sh
        ;;
    stdio-permanent-fileno-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-fileno-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_fileno_header_abi.sh
        ;;
    stdio-permanent-fileno-unlocked-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-fileno-unlocked-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_fileno_unlocked_header_abi.sh
        ;;
    stdio-permanent-feof-unlocked-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-feof-unlocked-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_feof_unlocked_header_abi.sh
        ;;
    stdio-permanent-ferror-unlocked-header-abi)
        [ "$#" -eq 0 ] || fail "stdio-permanent-ferror-unlocked-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_permanent_ferror_unlocked_header_abi.sh
        ;;
    ctype-header-abi)
        [ "$#" -eq 0 ] || fail "ctype-header-abi takes no arguments"
        ensure_image
        run_ctype_header_abi
        ;;
    locale-profile-header-abi)
        [ "$#" -eq 0 ] || fail "locale-profile-header-abi takes no arguments"
        ensure_image
        run_locale_profile_header_abi
        ;;
    locale-multibyte-header-abi)
        [ "$#" -eq 0 ] || fail "locale-multibyte-header-abi takes no arguments"
        ensure_image
        run_locale_multibyte_header_abi
        ;;
    iconv-header-abi)
        [ "$#" -eq 0 ] || fail "iconv-header-abi takes no arguments"
        ensure_image
        run_iconv_header_abi
        ;;
    wide-character-header-abi)
        [ "$#" -eq 0 ] || fail "wide-character-header-abi takes no arguments"
        ensure_image
        run_wide_character_header_abi
        ;;
    locale-object-wide-header-abi)
        [ "$#" -eq 0 ] || fail "locale-object-wide-header-abi takes no arguments"
        ensure_image
        run_locale_object_wide_header_abi
        ;;
    locale-narrow-header-abi)
        [ "$#" -eq 0 ] || fail "locale-narrow-header-abi takes no arguments"
        ensure_image
        run_locale_narrow_header_abi
        ;;
    integer-arithmetic-header-abi)
        [ "$#" -eq 0 ] || fail "integer-arithmetic-header-abi takes no arguments"
        ensure_image
        run_integer_arithmetic_header_abi
        ;;
    integer-parse-header-abi)
        [ "$#" -eq 0 ] || fail "integer-parse-header-abi takes no arguments"
        ensure_image
        run_integer_parse_header_abi
        ;;
    float-parse-header-abi)
        [ "$#" -eq 0 ] || fail "float-parse-header-abi takes no arguments"
        ensure_image
        run_float_parse_header_abi
        ;;
    crypt-header-abi)
        [ "$#" -eq 0 ] || fail "crypt-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_crypt_header_abi.sh
        ;;
    getsubopt-header-abi)
        [ "$#" -eq 0 ] || fail "getsubopt-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_getsubopt_header_abi.sh
        ;;
    l64a-header-abi)
        [ "$#" -eq 0 ] || fail "l64a-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_l64a_header_abi.sh
        ;;
    libc-intmax-arithmetic)
        [ "$#" -eq 0 ] || fail "libc-intmax-arithmetic takes no arguments"
        ensure_image
        run_libc_intmax_arithmetic
        ;;
    intmax-arithmetic-header-abi)
        [ "$#" -eq 0 ] || fail "intmax-arithmetic-header-abi takes no arguments"
        ensure_image
        run_intmax_arithmetic_header_abi
        ;;
    credential-observation-header-abi)
        [ "$#" -eq 0 ] || fail "credential-observation-header-abi takes no arguments"
        ensure_image
        run_credential_observation_header_abi
        ;;
    login-name-header-abi)
        [ "$#" -eq 0 ] || fail "login-name-header-abi takes no arguments"
        ensure_image
        run_login_name_header_abi
        ;;
    child-reaping-header-abi)
        [ "$#" -eq 0 ] || fail "child-reaping-header-abi takes no arguments"
        ensure_image
        run_child_reaping_header_abi
        ;;
    wait-extensions-header-abi)
        [ "$#" -eq 0 ] || fail "wait-extensions-header-abi takes no arguments"
        ensure_image
        run_wait_extensions_header_abi
        ;;
    immediate-termination-header-abi)
        [ "$#" -eq 0 ] || fail "immediate-termination-header-abi takes no arguments"
        ensure_image
        run_immediate_termination_header_abi
        ;;
    posix-exit-header-abi)
        [ "$#" -eq 0 ] || fail "posix-exit-header-abi takes no arguments"
        ensure_image
        run_posix_exit_header_abi
        ;;
    posix-spawnattr-init-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-init-header-abi takes no arguments"
        ensure_image
        run_posix_spawnattr_init_header_abi
        ;;
    posix-spawnattr-getpgroup-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-getpgroup-header-abi takes no arguments"
        ensure_image
        run_posix_spawnattr_getpgroup_header_abi
        ;;
    posix-spawnattr-signal-fields-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-signal-fields-header-abi takes no arguments"
        ensure_image
        run_posix_spawnattr_signal_fields_header_abi
        ;;
    posix-spawnattr-getschedpolicy-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-getschedpolicy-header-abi takes no arguments"
        ensure_image
        run_posix_spawnattr_getschedpolicy_header_abi
        ;;
    posix-spawnattr-getschedparam-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-getschedparam-header-abi takes no arguments"
        ensure_image
        run_posix_spawnattr_getschedparam_header_abi
        ;;
    bsearch-header-abi)
        [ "$#" -eq 0 ] || fail "bsearch-header-abi takes no arguments"
        ensure_image
        run_bsearch_header_abi
        ;;
    linear-search-header-abi)
        [ "$#" -eq 0 ] || fail "linear-search-header-abi takes no arguments"
        ensure_image
        run_linear_search_header_abi
        ;;
    intrusive-queue-header-abi)
        [ "$#" -eq 0 ] || fail "intrusive-queue-header-abi takes no arguments"
        ensure_image
        run_intrusive_queue_header_abi
        ;;
    wcswcs-header-abi)
        [ "$#" -eq 0 ] || fail "wcswcs-header-abi takes no arguments"
        ensure_image
        run_wcswcs_header_abi
        ;;
    qsort-header-abi)
        [ "$#" -eq 0 ] || fail "qsort-header-abi takes no arguments"
        ensure_image
        run_qsort_header_abi
        ;;
    sched-yield-header-abi)
        [ "$#" -eq 0 ] || fail "sched-yield-header-abi takes no arguments"
        ensure_image
        run_sched_yield_header_abi
        ;;
    sched-cpucount-header-abi)
        [ "$#" -eq 0 ] || fail "sched-cpucount-header-abi takes no arguments"
        ensure_image
        run_sched_cpucount_header_abi
        ;;
    sched-cpu-macros-header-abi)
        [ "$#" -eq 0 ] || fail "sched-cpu-macros-header-abi takes no arguments"
        ensure_image
        run_sched_cpu_macros_header_abi
        ;;
    sched-cpu-set-source-form)
        [ "$#" -eq 0 ] || fail "sched-cpu-set-source-form takes no arguments"
        ensure_image
        run_sched_cpu_set_source_form
        ;;
    sched-getcpu-header-abi)
        [ "$#" -eq 0 ] || fail "sched-getcpu-header-abi takes no arguments"
        ensure_image
        run_sched_getcpu_header_abi
        ;;
    sched-priority-bounds-header-abi)
        [ "$#" -eq 0 ] || fail "sched-priority-bounds-header-abi takes no arguments"
        ensure_image
        run_sched_priority_bounds_header_abi
        ;;
    sched-get-priority-max-header-abi)
        [ "$#" -eq 0 ] || fail "sched-get-priority-max-header-abi takes no arguments"
        ensure_image
        run_sched_get_priority_max_header_abi
        ;;
    sched-get-priority-min-header-abi)
        [ "$#" -eq 0 ] || fail "sched-get-priority-min-header-abi takes no arguments"
        ensure_image
        run_sched_get_priority_min_header_abi
        ;;
    callback-algorithms-header-abi)
        [ "$#" -eq 0 ] || fail "callback-algorithms-header-abi takes no arguments"
        ensure_image
        run_callback_algorithms_header_abi
        ;;
    ffs-header-abi)
        [ "$#" -eq 0 ] || fail "ffs-header-abi takes no arguments"
        ensure_image
        run_ffs_header_abi
        ;;
    memory-special-header-abi)
        [ "$#" -eq 0 ] || fail "memory-special-header-abi takes no arguments"
        ensure_image
        run_memory_special_header_abi
        ;;
    memccpy-header-abi)
        [ "$#" -eq 0 ] || fail "memccpy-header-abi takes no arguments"
        ensure_image
        run_memccpy_header_abi
        ;;
    aio-error-header-abi)
        [ "$#" -eq 0 ] || fail "aio-error-header-abi takes no arguments"
        ensure_image
        run_aio_error_header_abi
        ;;
    byte-strings-header-abi)
        [ "$#" -eq 0 ] || fail "byte-strings-header-abi takes no arguments"
        ensure_image
        run_byte_strings_header_abi
        ;;
    memory-search-header-abi)
        [ "$#" -eq 0 ] || fail "memory-search-header-abi takes no arguments"
        ensure_image
        run_memory_search_header_abi
        ;;
    memccpy-header-abi)
        [ "$#" -eq 0 ] || fail "memccpy-header-abi takes no arguments"
        ensure_image
        run_memccpy_header_abi
        ;;
    mempcpy-header-abi)
        [ "$#" -eq 0 ] || fail "mempcpy-header-abi takes no arguments"
        ensure_image
        run_mempcpy_header_abi
        ;;
    strsep-header-abi)
        [ "$#" -eq 0 ] || fail "strsep-header-abi takes no arguments"
        ensure_image
        run_strsep_header_abi
        ;;
    strtok-header-abi)
        [ "$#" -eq 0 ] || fail "strtok-header-abi takes no arguments"
        ensure_image
        run_strtok_header_abi
        ;;
    stateful-byte-strings-header-abi)
        [ "$#" -eq 0 ] || fail "stateful-byte-strings-header-abi takes no arguments"
        ensure_image
        run_stateful_byte_strings_header_abi
        ;;
    string-copy-header-abi)
        [ "$#" -eq 0 ] || fail "string-copy-header-abi takes no arguments"
        ensure_image
        run_string_copy_header_abi
        ;;
    error-strings-header-abi)
        [ "$#" -eq 0 ] || fail "error-strings-header-abi takes no arguments"
        ensure_image
        run_error_strings_header_abi
        ;;
    strsignal-header-abi)
        [ "$#" -eq 0 ] || fail "strsignal-header-abi takes no arguments"
        ensure_image
        run_strsignal_header_abi
        ;;
    gettext-catalog-header-abi)
        [ "$#" -eq 0 ] || fail "gettext-catalog-header-abi takes no arguments"
        ensure_image
        run_gettext_catalog_header_abi
        ;;
    random-entropy-header-abi)
        [ "$#" -eq 0 ] || fail "random-entropy-header-abi takes no arguments"
        ensure_image
        run_random_entropy_header_abi
        ;;
    time-header-abi)
        [ "$#" -eq 0 ] || fail "time-header-abi takes no arguments"
        ensure_image
        run_time_header_abi
        ;;
    clock-adjtime-header-abi)
        [ "$#" -eq 0 ] || fail "clock-adjtime-header-abi takes no arguments"
        ensure_image
        run_clock_adjtime_header_abi
        ;;
    clock-settime-header-abi)
        [ "$#" -eq 0 ] || fail "clock-settime-header-abi takes no arguments"
        ensure_image
        run_clock_settime_header_abi
        ;;
    timer-getoverrun-header-abi)
        [ "$#" -eq 0 ] || fail "timer-getoverrun-header-abi takes no arguments"
        ensure_image
        run_timer_getoverrun_header_abi
        ;;
    timer-delete-header-abi)
        [ "$#" -eq 0 ] || fail "timer-delete-header-abi takes no arguments"
        ensure_image
        run_timer_delete_header_abi
        ;;
    timer-gettime-header-abi)
        [ "$#" -eq 0 ] || fail "timer-gettime-header-abi takes no arguments"
        ensure_image
        run_timer_gettime_header_abi
        ;;
    timer-settime-header-abi)
        [ "$#" -eq 0 ] || fail "timer-settime-header-abi takes no arguments"
        ensure_image
        run_timer_settime_header_abi
        ;;
    sleep-header-abi)
        [ "$#" -eq 0 ] || fail "sleep-header-abi takes no arguments"
        ensure_image
        run_sleep_header_abi
        ;;
    timerfd-header-abi)
        [ "$#" -eq 0 ] || fail "timerfd-header-abi takes no arguments"
        ensure_image
        run_timerfd_header_abi
        ;;
    mq-setattr-header-abi)
        [ "$#" -eq 0 ] || fail "mq-setattr-header-abi takes no arguments"
        ensure_image
        run_mq_setattr_header_abi
        ;;
    signalfd-header-abi)
        [ "$#" -eq 0 ] || fail "signalfd-header-abi takes no arguments"
        ensure_image
        run_signalfd_header_abi
        ;;
    poll-header-abi)
        [ "$#" -eq 0 ] || fail "poll-header-abi takes no arguments"
        ensure_image
        run_poll_header_abi
        ;;
    select-header-abi)
        [ "$#" -eq 0 ] || fail "select-header-abi takes no arguments"
        ensure_image
        run_select_header_abi
        ;;
    fcntl-header-abi)
        [ "$#" -eq 0 ] || fail "fcntl-header-abi takes no arguments"
        ensure_image
        run_fcntl_header_abi
        ;;
    file-handles-header-abi)
        [ "$#" -eq 0 ] || fail "file-handles-header-abi takes no arguments"
        ensure_image
        run_file_handles_header_abi
        ;;
    posix-spawn-file-actions-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawn-file-actions-header-abi takes no arguments"
        ensure_image
        run_posix_spawn_file_actions_header_abi
        ;;
    process-exec-header-abi)
        [ "$#" -eq 0 ] || fail "process-exec-header-abi takes no arguments"
        ensure_image
        run_process_exec_header_abi
        ;;
    flock-header-abi)
        [ "$#" -eq 0 ] || fail "flock-header-abi takes no arguments"
        ensure_image
        run_flock_header_abi
        ;;
    sendfile-header-abi)
        [ "$#" -eq 0 ] || fail "sendfile-header-abi takes no arguments"
        ensure_image
        run_sendfile_header_abi
        ;;
    tee-header-abi)
        [ "$#" -eq 0 ] || fail "tee-header-abi takes no arguments"
        ensure_image
        run_tee_header_abi
        ;;
    splice-header-abi)
        [ "$#" -eq 0 ] || fail "splice-header-abi takes no arguments"
        ensure_image
        run_splice_header_abi
        ;;
    sync-file-range-header-abi)
        [ "$#" -eq 0 ] || fail "sync-file-range-header-abi takes no arguments"
        ensure_image
        run_sync_file_range_header_abi
        ;;
    copy-file-range-header-abi)
        [ "$#" -eq 0 ] || fail "copy-file-range-header-abi takes no arguments"
        ensure_image
        run_copy_file_range_header_abi
        ;;
    unistd-header-abi)
        [ "$#" -eq 0 ] || fail "unistd-header-abi takes no arguments"
        ensure_image
        run_unistd_header_abi
        ;;
    getpagesize-header-abi)
        [ "$#" -eq 0 ] || fail "getpagesize-header-abi takes no arguments"
        ensure_image
        run_getpagesize_header_abi
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
    psignal-header-abi)
        [ "$#" -eq 0 ] || fail "psignal-header-abi takes no arguments"
        ensure_image
        run_psignal_header_abi
        ;;
    signal-legacy-aliases-header-abi)
        [ "$#" -eq 0 ] || fail "signal-legacy-aliases-header-abi takes no arguments"
        ensure_image
        run_signal_legacy_aliases_header_abi
        ;;
    signal-sysv-helpers-header-abi)
        [ "$#" -eq 0 ] || fail "signal-sysv-helpers-header-abi takes no arguments"
        ensure_image
        run_signal_sysv_helpers_header_abi
        ;;
    sched-getscheduler-header-abi)
        [ "$#" -eq 0 ] || fail "sched-getscheduler-header-abi takes no arguments"
        ensure_image
        run_sched_getscheduler_header_abi
        ;;
    sched-rr-interval-header-abi)
        [ "$#" -eq 0 ] || fail "sched-rr-interval-header-abi takes no arguments"
        ensure_image
        run_sched_rr_interval_header_abi
        ;;
    termios-header-abi)
        [ "$#" -eq 0 ] || fail "termios-header-abi takes no arguments"
        ensure_image
        run_termios_header_abi
        ;;
    terminal-streams-header-topology)
        [ "$#" -eq 0 ] || fail "terminal-streams-header-topology takes no arguments"
        ensure_image
        run_terminal_streams_header_topology
        ;;
    ctermid-header-abi)
        [ "$#" -eq 0 ] || fail "ctermid-header-abi takes no arguments"
        ensure_image
        run_ctermid_header_abi
        ;;
    grantpt-header-abi)
        [ "$#" -eq 0 ] || fail "grantpt-header-abi takes no arguments"
        ensure_image
        run_grantpt_header_abi
        ;;
    unlockpt-header-abi)
        [ "$#" -eq 0 ] || fail "unlockpt-header-abi takes no arguments"
        ensure_image
        run_unlockpt_header_abi
        ;;
    gethostid-header-abi)
        [ "$#" -eq 0 ] || fail "gethostid-header-abi takes no arguments"
        ensure_image
        run_gethostid_header_abi
        ;;
    issetugid-header-abi)
        [ "$#" -eq 0 ] || fail "issetugid-header-abi takes no arguments"
        ensure_image
        run_issetugid_header_abi
        ;;
    legacy-misc-header-abi)
        [ "$#" -eq 0 ] || fail "legacy-misc-header-abi takes no arguments"
        ensure_image
        run_legacy_misc_header_abi
        ;;
    endhostent-header-abi)
        [ "$#" -eq 0 ] || fail "endhostent-header-abi takes no arguments"
        ensure_image
        run_endhostent_header_abi
        ;;
    gettid-header-abi)
        [ "$#" -eq 0 ] || fail "gettid-header-abi takes no arguments"
        ensure_image
        run_gettid_header_abi
        ;;
    posix-close-header-abi)
        [ "$#" -eq 0 ] || fail "posix-close-header-abi takes no arguments"
        ensure_image
        run_posix_close_header_abi
        ;;
    isatty-header-abi)
        [ "$#" -eq 0 ] || fail "isatty-header-abi takes no arguments"
        ensure_image
        run_isatty_header_abi
        ;;
    ttyname-r-header-abi)
        [ "$#" -eq 0 ] || fail "ttyname-r-header-abi takes no arguments"
        ensure_image
        run_ttyname_r_header_abi
        ;;
    tcgetpgrp-header-abi)
        [ "$#" -eq 0 ] || fail "tcgetpgrp-header-abi takes no arguments"
        ensure_image
        run_tcgetpgrp_header_abi
        ;;
    tcsetpgrp-header-abi)
        [ "$#" -eq 0 ] || fail "tcsetpgrp-header-abi takes no arguments"
        ensure_image
        run_tcsetpgrp_header_abi
        ;;
    getpass-header-abi)
        [ "$#" -eq 0 ] || fail "getpass-header-abi takes no arguments"
        ensure_image
        run_getpass_header_abi
        ;;
    mkfifo-header-abi)
        [ "$#" -eq 0 ] || fail "mkfifo-header-abi takes no arguments"
        ensure_image
        run_mkfifo_header_abi
        ;;
    mkdirat-header-abi)
        [ "$#" -eq 0 ] || fail "mkdirat-header-abi takes no arguments"
        ensure_image
        run_mkdirat_header_abi
        ;;
    mkfifoat-header-abi)
        [ "$#" -eq 0 ] || fail "mkfifoat-header-abi takes no arguments"
        ensure_image
        run_mkfifoat_header_abi
        ;;
    readlinkat-header-abi)
        [ "$#" -eq 0 ] || fail "readlinkat-header-abi takes no arguments"
        ensure_image
        run_readlinkat_header_abi
        ;;
    linkat-header-abi)
        [ "$#" -eq 0 ] || fail "linkat-header-abi takes no arguments"
        ensure_image
        run_linkat_header_abi
        ;;
    renameat2-header-abi)
        [ "$#" -eq 0 ] || fail "renameat2-header-abi takes no arguments"
        ensure_image
        run_renameat2_header_abi
        ;;
    lchown-header-abi)
        [ "$#" -eq 0 ] || fail "lchown-header-abi takes no arguments"
        ensure_image
        run_lchown_header_abi
        ;;
    hasmntopt-header-abi)
        [ "$#" -eq 0 ] || fail "hasmntopt-header-abi takes no arguments"
        ensure_image
        run_hasmntopt_header_abi
        ;;
    fchdir-header-abi)
        [ "$#" -eq 0 ] || fail "fchdir-header-abi takes no arguments"
        ensure_image
        run_fchdir_header_abi
        ;;
    ulimit-header-abi)
        [ "$#" -eq 0 ] || fail "ulimit-header-abi takes no arguments"
        ensure_image
        run_ulimit_header_abi
        ;;
    mktemp-header-abi)
        [ "$#" -eq 0 ] || fail "mktemp-header-abi takes no arguments"
        ensure_image
        run_mktemp_header_abi
        ;;
    temporary-names-header-abi)
        [ "$#" -eq 0 ] || fail "temporary-names-header-abi takes no arguments"
        ensure_image
        run_temporary_names_header_abi
        ;;
    mman-header-abi)
        [ "$#" -eq 0 ] || fail "mman-header-abi takes no arguments"
        ensure_image
        run_mman_header_abi
        ;;
    memory-sync-header-abi)
        [ "$#" -eq 0 ] || fail "memory-sync-header-abi takes no arguments"
        ensure_image
        run_memory_sync_header_abi
        ;;
    memory-locking-header-abi)
        [ "$#" -eq 0 ] || fail "memory-locking-header-abi takes no arguments"
        ensure_image
        run_memory_locking_header_abi
        ;;
    memfd-create-header-abi)
        [ "$#" -eq 0 ] || fail "memfd-create-header-abi takes no arguments"
        ensure_image
        run_memfd_create_header_abi
        ;;
    resource-header-abi)
        [ "$#" -eq 0 ] || fail "resource-header-abi takes no arguments"
        ensure_image
        run_resource_header_abi
        ;;
    socket-header-abi)
        [ "$#" -eq 0 ] || fail "socket-header-abi takes no arguments"
        ensure_image
        run_socket_header_abi
        ;;
    tcp-header-abi)
        [ "$#" -eq 0 ] || fail "tcp-header-abi takes no arguments"
        ensure_image
        run_tcp_header_abi
        ;;
    nameser-header-abi)
        [ "$#" -eq 0 ] || fail "nameser-header-abi takes no arguments"
        ensure_image
        run_nameser_header_abi
        ;;
    quota-header-abi)
        [ "$#" -eq 0 ] || fail "quota-header-abi takes no arguments"
        ensure_image
        run_quota_header_abi
        ;;
    endservent-header-abi)
        [ "$#" -eq 0 ] || fail "endservent-header-abi takes no arguments"
        ensure_image
        run_endservent_header_abi
        ;;
    service-lifecycle-header-abi)
        [ "$#" -eq 0 ] || fail "service-lifecycle-header-abi takes no arguments"
        ensure_image
        run_service_lifecycle_header_abi
        ;;
    protocol-database-header-abi)
        [ "$#" -eq 0 ] || fail "protocol-database-header-abi takes no arguments"
        ensure_image
        run_protocol_database_header_abi
        ;;
    inet-address-header-abi)
        [ "$#" -eq 0 ] || fail "inet-address-header-abi takes no arguments"
        ensure_image
        run_inet_address_header_abi
        ;;
    socket-messages-header-abi)
        [ "$#" -eq 0 ] || fail "socket-messages-header-abi takes no arguments"
        ensure_image
        run_socket_messages_header_abi
        ;;
    sysv-semaphore-header-abi)
        [ "$#" -eq 0 ] || fail "sysv-semaphore-header-abi takes no arguments"
        ensure_image
        run_sysv_semaphore_header_abi
        ;;
    posix-semaphore-header-abi)
        [ "$#" -eq 0 ] || fail "posix-semaphore-header-abi takes no arguments"
        ensure_image
        run_posix_semaphore_header_abi
        ;;
    sysv-message-shared-memory-header-abi)
        [ "$#" -eq 0 ] || fail "sysv-message-shared-memory-header-abi takes no arguments"
        ensure_image
        run_sysv_message_shared_memory_header_abi
        ;;
    mm-abi-reference)
        [ "$#" -eq 0 ] || fail "mm-abi-reference takes no arguments"
        ensure_image
        run_mm_abi_reference
        ;;
    mapping-reference)
        [ "$#" -eq 0 ] || fail "mapping-reference takes no arguments"
        ensure_image
        run_mapping_reference
        ;;
    memory-vm-reference)
        [ "$#" -eq 0 ] || fail "memory-vm-reference takes no arguments"
        ensure_image
        run_memory_vm_reference
        ;;
    pty-basic-reference)
        [ "$#" -eq 0 ] || fail "pty-basic-reference takes no arguments"
        ensure_image
        run_pty_basic_reference
        ;;
    terminal-reference)
        [ "$#" -eq 0 ] || fail "terminal-reference takes no arguments"
        ensure_image
        run_terminal_reference
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
    statfs-reference)
        [ "$#" -eq 0 ] || fail "statfs-reference takes no arguments"
        ensure_image
        run_statfs_reference
        ;;
    timestamp-reference)
        [ "$#" -eq 0 ] || fail "timestamp-reference takes no arguments"
        ensure_image
        run_timestamp_reference
        ;;
    path-lifecycle-reference)
        [ "$#" -eq 0 ] || fail "path-lifecycle-reference takes no arguments"
        ensure_image
        run_path_lifecycle_reference
        ;;
    namespace-reference)
        [ "$#" -eq 0 ] || fail "namespace-reference takes no arguments"
        ensure_image
        run_namespace_reference
        ;;
    path-core-reference)
        [ "$#" -eq 0 ] || fail "path-core-reference takes no arguments"
        ensure_image
        run_path_core_reference
        ;;
    xattr-reference)
        [ "$#" -eq 0 ] || fail "xattr-reference takes no arguments"
        ensure_image
        run_xattr_reference
        ;;
    directory-reference)
        [ "$#" -eq 0 ] || fail "directory-reference takes no arguments"
        ensure_image
        run_directory_reference
        ;;
    temporary-object-reference)
        [ "$#" -eq 0 ] || fail "temporary-object-reference takes no arguments"
        ensure_image
        run_temporary_object_reference
        ;;
    statx-reference)
        [ "$#" -eq 0 ] || fail "statx-reference takes no arguments"
        ensure_image
        run_statx_reference
        ;;
    cwd-canonicalize-reference)
        [ "$#" -eq 0 ] || fail "cwd-canonicalize-reference takes no arguments"
        ensure_image
        run_cwd_canonicalize_reference
        ;;
    root-change-reference)
        [ "$#" -eq 0 ] || fail "root-change-reference takes no arguments"
        ensure_image
        run_root_change_reference
        ;;
    mount-reference)
        [ "$#" -eq 0 ] || fail "mount-reference takes no arguments"
        ensure_image
        run_mount_reference
        ;;
    thread-kill-reference)
        [ "$#" -eq 0 ] || fail "thread-kill-reference takes no arguments"
        ensure_image
        run_thread_kill_reference
        ;;
    ipc-reference)
        [ "$#" -eq 0 ] || fail "ipc-reference takes no arguments"
        ensure_image
        run_ipc_reference
        ;;
    shm-reference)
        [ "$#" -eq 0 ] || fail "shm-reference takes no arguments"
        ensure_image
        run_shm_reference
        ;;
    inotify-reference)
        [ "$#" -eq 0 ] || fail "inotify-reference takes no arguments"
        ensure_image
        run_inotify_reference
        ;;
    socket-transport-reference)
        [ "$#" -eq 0 ] || fail "socket-transport-reference takes no arguments"
        ensure_image
        run_socket_transport_reference
        ;;
    interface-device-reference)
        [ "$#" -eq 0 ] || fail "interface-device-reference takes no arguments"
        ensure_image
        run_interface_device_reference
        ;;
    resolver-transport-reference)
        [ "$#" -eq 0 ] || fail "resolver-transport-reference takes no arguments"
        ensure_image
        run_resolver_transport_reference
        ;;
    resolver-facade-reference)
        [ "$#" -eq 0 ] || fail "resolver-facade-reference takes no arguments"
        ensure_image
        run_resolver_facade_reference
        ;;
    netdb-reference)
        [ "$#" -eq 0 ] || fail "netdb-reference takes no arguments"
        ensure_image
        run_netdb_reference
        ;;
    users-databases-reference)
        [ "$#" -eq 0 ] || fail "users-databases-reference takes no arguments"
        ensure_image
        run_users_databases_reference
        ;;
    posix-fallocate-reference)
        [ "$#" -eq 0 ] || fail "posix-fallocate-reference takes no arguments"
        ensure_image
        run_posix_fallocate_reference
        ;;
    fallocate-reference)
        [ "$#" -eq 0 ] || fail "fallocate-reference takes no arguments"
        ensure_image
        run_fallocate_reference
        ;;
    file-position-reference)
        [ "$#" -eq 0 ] || fail "file-position-reference takes no arguments"
        ensure_image
        run_file_position_reference
        ;;
    sync-reference)
        [ "$#" -eq 0 ] || fail "sync-reference takes no arguments"
        ensure_image
        run_sync_reference
        ;;
    syncfs-reference)
        [ "$#" -eq 0 ] || fail "syncfs-reference takes no arguments"
        ensure_image
        run_syncfs_reference
        ;;
    sync-file-range-reference)
        [ "$#" -eq 0 ] || fail "sync-file-range-reference takes no arguments"
        ensure_image
        run_sync_file_range_reference
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
    calendar-time-reference)
        [ "$#" -eq 0 ] || fail "calendar-time-reference takes no arguments"
        ensure_image
        run_calendar_time_reference
        ;;
    advanced-time-reference)
        [ "$#" -eq 0 ] || fail "advanced-time-reference takes no arguments"
        ensure_image
        run_advanced_time_reference
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
    child-ownership-reference)
        [ "$#" -eq 0 ] || fail "child-ownership-reference takes no arguments"
        ensure_image
        run_child_ownership_reference
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
    fcntl-status-reference)
        [ "$#" -eq 0 ] || fail "fcntl-status-reference takes no arguments"
        ensure_image
        run_fcntl_status_reference
        ;;
    flock-reference)
        [ "$#" -eq 0 ] || fail "flock-reference takes no arguments"
        ensure_image
        run_flock_reference
        ;;
    sendfile-reference)
        [ "$#" -eq 0 ] || fail "sendfile-reference takes no arguments"
        ensure_image
        run_sendfile_reference
        ;;
    copy-file-range-reference)
        [ "$#" -eq 0 ] || fail "copy-file-range-reference takes no arguments"
        ensure_image
        run_copy_file_range_reference
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
    access-reference)
        [ "$#" -eq 0 ] || fail "access-reference takes no arguments"
        ensure_image
        run_access_reference
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
        [ "$#" -eq 0 ] || { [ "$#" -eq 1 ] && [ "$1" = --cached ]; } ||
            fail "usage: core [--cached]"
        ensure_image
        if [ "$#" -eq 1 ]; then
            run_in_container python3 -B /workspace/compat/x86_64/run_core_tests.py
        else
            run_core_tests
        fi
        ;;
    facade)
        [ "$#" -eq 0 ] || fail "facade takes no arguments"
        ensure_image
        run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
            -p crabc-rs --lib --no-default-features --test fenv --test futex --test x86_64_foundation --test x86_64_fnmatch \
            --test x86_64_memory_mapping --test x86_64_memory_vm --test x86_64_pty_basic --test x86_64_terminal --test x86_64_mount \
            --test x86_64_epoll --test x86_64_eventfd --test x86_64_fcntl_getlk --test x86_64_fcntl_flags --test x86_64_flock --test x86_64_sendfile --test x86_64_copy_file_range --test x86_64_fs --test x86_64_fs_capacity --test x86_64_fs_advice --test x86_64_file_position --test x86_64_sync --test x86_64_syncfs --test x86_64_sync_file_range --test x86_64_ftruncate --test x86_64_futimens --test x86_64_timestamp_paths --test x86_64_path_lifecycle --test x86_64_namespace --test x86_64_xattr --test x86_64_raw_directory --test x86_64_directory --test x86_64_directory_position --test x86_64_temporary_objects --test x86_64_statx --test x86_64_canonicalize --test x86_64_cwd_mutation --test x86_64_ipc --test x86_64_shm --test x86_64_inotify --test x86_64_socket_transport --test x86_64_posix_fallocate --test x86_64_fallocate --test x86_64_fs_credentials --test x86_64_getgroups --test x86_64_getitimer --test x86_64_setitimer --test x86_64_io --test x86_64_memfd --test x86_64_mm --test x86_64_param --test x86_64_pipe --test x86_64_poll --test x86_64_pselect --test x86_64_priority --test x86_64_setpriority --test x86_64_process_identity --test x86_64_process_session --test x86_64_pidfd_open --test x86_64_rand --test x86_64_rlimit --test x86_64_rlimit_targeted --test x86_64_setrlimit --test x86_64_umask --test x86_64_rusage --test x86_64_scheduler_priority_bounds --test x86_64_sleep --test x86_64_clock_nanosleep --test x86_64_statat --test x86_64_access --test x86_64_getcwd --test x86_64_current_dir_name --test x86_64_readlink --test x86_64_sched_rr_interval --test x86_64_sched_affinity --test x86_64_sched_setaffinity --test x86_64_system --test x86_64_thread --test x86_64_thread_kill --test x86_64_thread_credentials --test x86_64_time --test time --test calendar_utc --test x86_64_calendar_time --test x86_64_advanced_time --test x86_64_timerfd --test x86_64_times \
            -- --test-threads=1
        # The allocation-free matcher keeps its separate static no-std archive
        # proof beside the direct facade test.
        run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
            -p crabc-rs --no-default-features --release --example fnmatch_direct_probe
        run_in_container bash /workspace/compat/x86_64/verify_fnmatch_direct.sh
        run_in_chroot_cap_container cargo test --locked --target x86_64-unknown-linux-musl \
            -p crabc-rs --no-default-features --test x86_64_chroot -- --test-threads=1
        run_in_container cargo test --locked --target x86_64-unknown-linux-musl \
        -p crabc-rs --no-default-features --features alloc \
            --test timezone_rules --test calendar_local --test x86_64_glob --test x86_64_child_ownership \
            --test x86_64_pty_basic --test x86_64_terminal \
            --test x86_64_users_databases \
            -- --test-threads=1
        # The alloc-gated glob proof supplies its own fixed Rust allocator.
        # Native archive inspection therefore rejects public C traversal,
        # errno, and allocation boundaries without requiring allocation-free
        # code generation.
        run_in_container cargo build --locked --target x86_64-unknown-linux-musl \
            -p crabc-rs --no-default-features --features alloc --release --example glob_direct_probe
        run_in_container bash /workspace/compat/x86_64/verify_glob_direct.sh
        ;;
    facade-record-owning)
        [ "$#" -eq 0 ] || fail "facade-record-owning takes no arguments"
        ensure_image
        run_facade_record_owning
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
    libc-stat-compat)
        [ "$#" -eq 0 ] || fail "libc-stat-compat takes no arguments"
        ensure_image
        run_libc_stat_compat_probe
        ;;
    libc-credentials)
        [ "$#" -eq 0 ] || fail "libc-credentials takes no arguments"
        ensure_image
        run_libc_credentials_probe
        ;;
    libc-bootstrap-primitives)
        [ "$#" -eq 0 ] || fail "libc-bootstrap-primitives takes no arguments"
        ensure_image
        run_libc_bootstrap_primitives_probe
        ;;
    libc-signal-control)
        [ "$#" -eq 0 ] || fail "libc-signal-control takes no arguments"
        ensure_image
        run_libc_signal_control_probe
        ;;
    libc-signal-legacy-aliases)
        [ "$#" -eq 0 ] || fail "libc-signal-legacy-aliases takes no arguments"
        ensure_image
        run_libc_signal_legacy_aliases_probe
        ;;
    libc-signal-sysv-helpers)
        [ "$#" -eq 0 ] || fail "libc-signal-sysv-helpers takes no arguments"
        ensure_image
        run_libc_signal_sysv_helpers_probe
        ;;
    libc-signal-execution)
        [ "$#" -eq 0 ] || fail "libc-signal-execution takes no arguments"
        ensure_image
        run_libc_signal_execution_probe
        ;;
    libc-signal-altstack)
        [ "$#" -eq 0 ] || fail "libc-signal-altstack takes no arguments"
        ensure_image
        run_libc_signal_altstack_probe
        ;;
    libc-psignal)
        [ "$#" -eq 0 ] || fail "libc-psignal takes no arguments"
        ensure_image
        run_libc_psignal_probe
        ;;
    libc-process-signal)
        [ "$#" -eq 0 ] || fail "libc-process-signal takes no arguments"
        ensure_image
        run_libc_process_signal_probe
        ;;
    libc-process-exec)
        [ "$#" -eq 0 ] || fail "libc-process-exec takes no arguments"
        ensure_image
        run_libc_process_exec_probe
        ;;
    libc-pthread-create-join-tls)
        [ "$#" -eq 0 ] || fail "libc-pthread-create-join-tls takes no arguments"
        ensure_image
        run_libc_pthread_create_join_tls_probe
        ;;
    libc-pthread-identity)
        [ "$#" -eq 0 ] || fail "libc-pthread-identity takes no arguments"
        ensure_image
        run_libc_pthread_identity_probe
        ;;
    libc-c11-lifecycle)
        [ "$#" -eq 0 ] || fail "libc-c11-lifecycle takes no arguments"
        ensure_image
        run_libc_c11_lifecycle_probe
        ;;
    libc-c11-plain-sync)
        [ "$#" -eq 0 ] || fail "libc-c11-plain-sync takes no arguments"
        ensure_image
        run_libc_c11_plain_sync_probe
        ;;
    libc-pthread-c11-once)
        [ "$#" -eq 0 ] || fail "libc-pthread-c11-once takes no arguments"
        ensure_image
        run_libc_pthread_c11_once_probe
        ;;
    libc-pthread-c11-tsd)
        [ "$#" -eq 0 ] || fail "libc-pthread-c11-tsd takes no arguments"
        ensure_image
        run_libc_pthread_c11_tsd_probe
        ;;
    libc-pthread-cancel-deferred)
        [ "$#" -eq 0 ] || fail "libc-pthread-cancel-deferred takes no arguments"
        ensure_image
        run_libc_pthread_cancel_deferred_probe
        ;;
    libc-pthread-atfork)
        [ "$#" -eq 0 ] || fail "libc-pthread-atfork takes no arguments"
        ensure_image
        run_libc_pthread_atfork_probe
        ;;
    libc-stack-chk-fail)
        [ "$#" -eq 0 ] || fail "libc-stack-chk-fail takes no arguments"
        ensure_image
        run_libc_stack_chk_fail_probe
        ;;
    libc-pthread-affinity)
        [ "$#" -eq 0 ] || fail "libc-pthread-affinity takes no arguments"
        ensure_image
        run_libc_pthread_affinity_probe
        ;;
    libc-pthread-cpuclock)
        [ "$#" -eq 0 ] || fail "libc-pthread-cpuclock takes no arguments"
        ensure_image
        run_libc_pthread_cpuclock_probe
        ;;
    libc-pthread-name)
        [ "$#" -eq 0 ] || fail "libc-pthread-name takes no arguments"
        ensure_image
        run_libc_pthread_name_probe
        ;;
    libc-pthread-barrierattr-pshared)
        [ "$#" -eq 0 ] || fail "libc-pthread-barrierattr-pshared takes no arguments"
        ensure_image
        run_libc_pthread_barrierattr_pshared_probe
        ;;
    libc-pthread-attributes)
        [ "$#" -eq 0 ] || fail "libc-pthread-attributes takes no arguments"
        ensure_image
        run_libc_pthread_attr_probe
        ;;
    libc-pthread-attr-lifecycle)
        [ "$#" -eq 0 ] || fail "libc-pthread-attr-lifecycle takes no arguments"
        ensure_image
        run_libc_pthread_attr_lifecycle_probe
        ;;
    libc-pthread-barrier)
        [ "$#" -eq 0 ] || fail "libc-pthread-barrier takes no arguments"
        ensure_image
        run_libc_pthread_barrier_probe
        ;;
    libc-pthread-condattr-pshared)
        [ "$#" -eq 0 ] || fail "libc-pthread-condattr-pshared takes no arguments"
        ensure_image
        run_libc_pthread_condattr_pshared_probe
        ;;
    libc-pthread-condattr-clock)
        [ "$#" -eq 0 ] || fail "libc-pthread-condattr-clock takes no arguments"
        ensure_image
        run_libc_pthread_condattr_clock_probe
        ;;
    libc-pthread-mutexattr-robust-query)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutexattr-robust-query takes no arguments"
        ensure_image
        run_libc_pthread_mutexattr_robust_query_probe
        ;;
    libc-pthread-mutexattr-protocol-query)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutexattr-protocol-query takes no arguments"
        ensure_image
        run_libc_pthread_mutexattr_protocol_query_probe
        ;;
    libc-pthread-mutexattr-pshared-query)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutexattr-pshared-query takes no arguments"
        ensure_image
        run_libc_pthread_mutexattr_pshared_query_probe
        ;;
    libc-pthread-mutexattr-type-query)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutexattr-type-query takes no arguments"
        ensure_image
        run_libc_pthread_mutexattr_type_query_probe
        ;;
    libc-pthread-mutexattr-type-setter)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutexattr-type-setter takes no arguments"
        ensure_image
        run_libc_pthread_mutexattr_type_setter_probe
        ;;
    libc-pthread-mutex-prioceiling-query)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutex-prioceiling-query takes no arguments"
        ensure_image
        run_libc_pthread_mutex_prioceiling_query_probe
        ;;
    libc-pthread-getconcurrency)
        [ "$#" -eq 0 ] || fail "libc-pthread-getconcurrency takes no arguments"
        ensure_image
        run_libc_pthread_getconcurrency_probe
        ;;
    libc-pthread-setconcurrency)
        [ "$#" -eq 0 ] || fail "libc-pthread-setconcurrency takes no arguments"
        ensure_image
        run_libc_pthread_setconcurrency_probe
        ;;
    libc-pthread-spin-destroy)
        [ "$#" -eq 0 ] || fail "libc-pthread-spin-destroy takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_pthread_spin_destroy.sh
        ;;
    libc-pthread-spin-operations)
        [ "$#" -eq 0 ] || fail "libc-pthread-spin-operations takes no arguments"
        ensure_image
        run_libc_pthread_spin_operations_probe
        ;;
    libc-pthread-detach)
        [ "$#" -eq 0 ] || fail "libc-pthread-detach takes no arguments"
        ensure_image
        run_libc_pthread_detach_probe
        ;;
    libc-thrd-sleep)
        [ "$#" -eq 0 ] || fail "libc-thrd-sleep takes no arguments"
        ensure_image
        run_libc_thrd_sleep_probe
        ;;
    libc-thrd-yield)
        [ "$#" -eq 0 ] || fail "libc-thrd-yield takes no arguments"
        ensure_image
        run_libc_thrd_yield_probe
        ;;
    libc-pthread-mutex-normal)
        [ "$#" -eq 0 ] || fail "libc-pthread-mutex-normal takes no arguments"
        ensure_image
        run_libc_pthread_mutex_normal_probe
        ;;
    libc-pthread-rwlock)
        [ "$#" -eq 0 ] || fail "libc-pthread-rwlock takes no arguments"
        ensure_image
        run_libc_pthread_rwlock_probe
        ;;
    libc-pthread-cond-private)
        [ "$#" -eq 0 ] || fail "libc-pthread-cond-private takes no arguments"
        ensure_image
        run_libc_pthread_cond_private_probe
        ;;
    libc-pthread-tls-aggregate)
        [ "$#" -eq 0 ] || fail "libc-pthread-tls-aggregate takes no arguments"
        ensure_image
        run_libc_pthread_tls_aggregate_probe
        ;;
    libc-static-tls-v1)
        [ "$#" -eq 0 ] || fail "libc-static-tls-v1 takes no arguments"
        ensure_image
        run_libc_static_tls_v1_probe
        ;;
    libc-crt-static-tls)
        [ "$#" -eq 0 ] || fail "libc-crt-static-tls takes no arguments"
        ensure_image
        run_libc_crt_static_tls_probe
        ;;
    libc-crt1-static-tls)
        [ "$#" -eq 0 ] || fail "libc-crt1-static-tls takes no arguments"
        ensure_image
        run_libc_crt1_static_tls_probe
        ;;
    owned-resolver-network)
        [ "$#" -eq 0 ] || fail "owned-resolver-network takes no arguments"
        ensure_image
        run_owned_resolver_network_probe
        ;;
    owned-dynamic-io-cancellation)
        [ "$#" -eq 0 ] || fail "owned-dynamic-io-cancellation takes no arguments"
        ensure_image
        run_in_chroot_cap_container bash /workspace/compat/x86_64/run_owned_dynamic_io_cancellation.sh
        ;;
    owned-system-cancellation)
        [ "$#" -eq 0 ] || fail "owned-system-cancellation takes no arguments"
        ensure_image
        run_in_chroot_cap_container bash /workspace/compat/x86_64/run_owned_system_cancellation.sh
        ;;
    owned-dynamic-spawn)
        [ "$#" -eq 0 ] || fail "owned-dynamic-spawn takes no arguments"
        ensure_image
        run_in_chroot_cap_container bash /workspace/compat/x86_64/run_owned_dynamic_spawn.sh
        ;;
    owned-assert)
        [ "$#" -eq 0 ] || fail "owned-assert takes no arguments"
        ensure_image
        run_in_chroot_cap_container bash /workspace/compat/x86_64/run_owned_assert.sh
        ;;
    owned-linux-control)
        [ "$#" -eq 0 ] || fail "owned-linux-control takes no arguments"
        ensure_image
        run_in_chroot_cap_container bash /workspace/compat/x86_64/run_owned_linux_control.sh
        ;;
    owned-io-cancellation)
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_owned_io_cancellation.sh "$@"
        ;;
    owned-pthread-join-cancel)
        run_in_container bash /workspace/compat/x86_64/run_owned_pthread_join_cancel.sh "$@"
        ;;
    owned-pthread-cond-cancel)
        run_in_container bash /workspace/compat/x86_64/run_owned_pthread_cond_cancel.sh "$@"
        ;;
    owned-pthread-cond-timed)
        run_in_container bash /workspace/compat/x86_64/run_owned_pthread_cond_timed.sh "$@"
        ;;
    owned-pthread-getattr)
        [ "$#" -eq 0 ] || fail "owned-pthread-getattr takes no arguments"
        run_in_container bash /workspace/compat/x86_64/run_owned_pthread_getattr.sh
        ;;
    owned-pthread-lifecycle)
        [ "$#" -eq 0 ] || fail "owned-pthread-lifecycle takes no arguments"
        run_in_container bash /workspace/compat/x86_64/run_owned_pthread_lifecycle.sh
        ;;
    qualification-manifest)
        if [ "$#" -ne 0 ]; then
            [ "$#" -eq 2 ] && [ "$1" = --through ] ||
                fail "qualification-manifest accepts only --through GATE"
            case "$2" in
                compat.abi-differential|compat.posix-process|compat.resolver-network|compat.loader-corpus|consumer.rust-std-lto|consumer.source-build|capability.accounting|performance.release) ;;
                *) fail "qualification-manifest has an unknown prefix endpoint" ;;
            esac
        fi
        ensure_image
        run_in_container python3 /workspace/compat/x86_64/run_qualification_manifest.py "$@"
        ;;
    owned-static-sysroot)
        [ "$#" -eq 0 ] || fail "owned-static-sysroot takes no arguments"
        ensure_image
        run_owned_static_sysroot_probe
        ;;
    lua-static-source-build)
        [ "$#" -eq 0 ] || fail "lua-static-source-build takes no arguments"
        ensure_image
        run_lua_static_source_build_probe
        ;;
    lua-dynamic-source-build)
        [ "$#" -eq 0 ] || fail "lua-dynamic-source-build takes no arguments"
        ensure_image
        run_lua_dynamic_source_build_probe
        ;;
    libc-owned-wordexp)
        [ "$#" -eq 0 ] || fail "libc-owned-wordexp takes no arguments"
        ensure_image
        run_libc_owned_wordexp_probe
        ;;
    owned-dynamic-sysroot)
        [ "$#" -eq 0 ] || fail "owned-dynamic-sysroot takes no arguments"
        ensure_image
        run_owned_dynamic_sysroot_probe
        ;;
    owned-dynamic-fork)
        [ "$#" -eq 0 ] || fail "owned-dynamic-fork takes no arguments"
        run_in_container bash /workspace/compat/x86_64/run_owned_dynamic_fork.sh
        ;;
    owned-dynamic-pthread-exit)
        [ "$#" -eq 0 ] || fail "owned-dynamic-pthread-exit takes no arguments"
        run_in_container bash /workspace/compat/x86_64/run_owned_dynamic_pthread_exit.sh
        ;;
    materialized-dynamic-sysroot)
        [ "$#" -eq 0 ] || fail "materialized-dynamic-sysroot takes no arguments"
        ensure_image
        run_in_dynamic_loader_mount_container bash /workspace/compat/x86_64/run_materialized_dynamic_sysroot.sh
        ;;
    crt-object-bundle)
        [ "$#" -eq 0 ] || fail "crt-object-bundle takes no arguments"
        ensure_image
        run_crt_object_bundle_probe
        ;;
    crt-dynamic-startup)
        [ "$#" -eq 0 ] || fail "crt-dynamic-startup takes no arguments"
        ensure_image
        run_crt_dynamic_startup_probe
        ;;
    crt-dynamic-link-contract)
        [ "$#" -eq 0 ] || fail "crt-dynamic-link-contract takes no arguments"
        ensure_image
        run_crt_dynamic_link_contract_probe
        ;;
    consumer-static-pie-lto)
        [ "$#" -eq 0 ] || fail "consumer-static-pie-lto takes no arguments"
        ensure_image
        run_consumer_static_pie_lto_probe
        ;;
    consumer-native-facade-lto)
        [ "$#" -eq 0 ] || fail "consumer-native-facade-lto takes no arguments"
        ensure_image
        run_consumer_native_facade_lto_probe
        ;;
    libc-termios-control)
        [ "$#" -eq 0 ] || fail "libc-termios-control takes no arguments"
        ensure_image
        run_libc_termios_control_probe
        ;;
    libc-ctermid)
        [ "$#" -eq 0 ] || fail "libc-ctermid takes no arguments"
        ensure_image
        run_libc_ctermid_probe
        ;;
    libc-grantpt)
        [ "$#" -eq 0 ] || fail "libc-grantpt takes no arguments"
        ensure_image
        run_libc_grantpt_probe
        ;;
    libc-unlockpt)
        [ "$#" -eq 0 ] || fail "libc-unlockpt takes no arguments"
        ensure_image
        run_libc_unlockpt_probe
        ;;
    libc-gethostid)
        [ "$#" -eq 0 ] || fail "libc-gethostid takes no arguments"
        ensure_image
        run_libc_gethostid_probe
        ;;
    libc-issetugid)
        [ "$#" -eq 0 ] || fail "libc-issetugid takes no arguments"
        ensure_image
        run_libc_issetugid_probe
        ;;
    libc-legacy-misc)
        [ "$#" -eq 0 ] || fail "libc-legacy-misc takes no arguments"
        ensure_image
        run_libc_legacy_misc_probe
        ;;
    libc-endhostent)
        [ "$#" -eq 0 ] || fail "libc-endhostent takes no arguments"
        ensure_image
        run_libc_endhostent_probe
        ;;
    libc-sethostent)
        [ "$#" -eq 0 ] || fail "libc-sethostent takes no arguments"
        ensure_image
        run_libc_sethostent_probe
        ;;
    libc-gettid)
        [ "$#" -eq 0 ] || fail "libc-gettid takes no arguments"
        ensure_image
        run_libc_gettid_probe
        ;;
    libc-posix-close)
        [ "$#" -eq 0 ] || fail "libc-posix-close takes no arguments"
        ensure_image
        run_libc_posix_close_probe
        ;;
    libc-isatty)
        [ "$#" -eq 0 ] || fail "libc-isatty takes no arguments"
        ensure_image
        run_libc_isatty_probe
        ;;
    libc-ttyname-r)
        [ "$#" -eq 0 ] || fail "libc-ttyname-r takes no arguments"
        ensure_image
        run_libc_ttyname_r_probe
        ;;
    libc-tcgetpgrp)
        [ "$#" -eq 0 ] || fail "libc-tcgetpgrp takes no arguments"
        ensure_image
        run_libc_tcgetpgrp_probe
        ;;
    libc-tcsetpgrp)
        [ "$#" -eq 0 ] || fail "libc-tcsetpgrp takes no arguments"
        ensure_image
        run_libc_tcsetpgrp_probe
        ;;
    libc-getpass)
        [ "$#" -eq 0 ] || fail "libc-getpass takes no arguments"
        ensure_image
        run_libc_getpass_probe
        ;;
    libc-mkfifo)
        [ "$#" -eq 0 ] || fail "libc-mkfifo takes no arguments"
        ensure_image
        run_libc_mkfifo_probe
        ;;
    libc-mkdirat)
        [ "$#" -eq 0 ] || fail "libc-mkdirat takes no arguments"
        ensure_image
        run_libc_mkdirat_probe
        ;;
    libc-mkfifoat)
        [ "$#" -eq 0 ] || fail "libc-mkfifoat takes no arguments"
        ensure_image
        run_libc_mkfifoat_probe
        ;;
    libc-readlinkat)
        [ "$#" -eq 0 ] || fail "libc-readlinkat takes no arguments"
        ensure_image
        run_libc_readlinkat_probe
        ;;
    libc-linkat)
        [ "$#" -eq 0 ] || fail "libc-linkat takes no arguments"
        ensure_image
        run_libc_linkat_probe
        ;;
    libc-renameat2)
        [ "$#" -eq 0 ] || fail "libc-renameat2 takes no arguments"
        ensure_image
        run_libc_renameat2_probe
        ;;
    libc-lchown)
        [ "$#" -eq 0 ] || fail "libc-lchown takes no arguments"
        ensure_image
        run_libc_lchown_probe
        ;;
    libc-hasmntopt)
        [ "$#" -eq 0 ] || fail "libc-hasmntopt takes no arguments"
        ensure_image
        run_libc_hasmntopt_probe
        ;;
    libc-fchdir)
        [ "$#" -eq 0 ] || fail "libc-fchdir takes no arguments"
        ensure_image
        run_libc_fchdir
        ;;
    libc-ulimit)
        [ "$#" -eq 0 ] || fail "libc-ulimit takes no arguments"
        ensure_image
        run_libc_ulimit
        ;;
    libc-mktemp)
        [ "$#" -eq 0 ] || fail "libc-mktemp takes no arguments"
        ensure_image
        run_libc_mktemp_probe
        ;;
    libc-temporary-names)
        [ "$#" -eq 0 ] || fail "libc-temporary-names takes no arguments"
        ensure_image
        run_libc_temporary_names_probe
        ;;
    libc-file-handles)
        [ "$#" -eq 0 ] || fail "libc-file-handles takes no arguments"
        ensure_image
        run_libc_file_handles_probe
        ;;
    libc-posix-spawn-file-actions)
        [ "$#" -eq 0 ] || fail "libc-posix-spawn-file-actions takes no arguments"
        ensure_image
        run_libc_posix_spawn_file_actions
        ;;
    libc-process-context)
        [ "$#" -eq 0 ] || fail "libc-process-context takes no arguments"
        ensure_image
        run_libc_process_context_probe
        ;;
    libc-environment)
        [ "$#" -eq 0 ] || fail "libc-environment takes no arguments"
        ensure_image
        run_libc_environment_probe
        ;;
    libc-secure-environment)
        [ "$#" -eq 0 ] || fail "libc-secure-environment takes no arguments"
        ensure_image
        run_libc_secure_environment_probe
        ;;
    libc-login-name)
        [ "$#" -eq 0 ] || fail "libc-login-name takes no arguments"
        ensure_image
        run_libc_login_name_probe
        ;;
    libc-descriptor-io)
        [ "$#" -eq 0 ] || fail "libc-descriptor-io takes no arguments"
        ensure_image
        run_libc_descriptor_io_probe
        ;;
    libc-descriptor-lifecycle)
        [ "$#" -eq 0 ] || fail "libc-descriptor-lifecycle takes no arguments"
        ensure_image
        run_libc_descriptor_lifecycle_probe
        ;;
    libc-descriptor-pipeline)
        [ "$#" -eq 0 ] || fail "libc-descriptor-pipeline takes no arguments"
        ensure_image
        run_libc_descriptor_pipeline_probe
        ;;
    libc-timestamp-updates)
        [ "$#" -eq 0 ] || fail "libc-timestamp-updates takes no arguments"
        ensure_image
        run_libc_timestamp_updates_probe
        ;;
    libc-socket-transport)
        [ "$#" -eq 0 ] || fail "libc-socket-transport takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_socket_transport.sh
        ;;
    libc-socket-messages)
        [ "$#" -eq 0 ] || fail "libc-socket-messages takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_socket_messages.sh
        ;;
    libc-process-resources)
        [ "$#" -eq 0 ] || fail "libc-process-resources takes no arguments"
        ensure_image
        run_libc_process_resources_probe
        ;;
    libc-sched-yield)
        [ "$#" -eq 0 ] || fail "libc-sched-yield takes no arguments"
        ensure_image
        run_libc_sched_yield_probe
        ;;
    libc-sched-get-priority-max)
        [ "$#" -eq 0 ] || fail "libc-sched-get-priority-max takes no arguments"
        ensure_image
        run_libc_sched_get_priority_max_probe
        ;;
    libc-sched-get-priority-min)
        [ "$#" -eq 0 ] || fail "libc-sched-get-priority-min takes no arguments"
        ensure_image
        run_libc_sched_get_priority_min_probe
        ;;
    libc-sched-cpucount)
        [ "$#" -eq 0 ] || fail "libc-sched-cpucount takes no arguments"
        ensure_image
        run_libc_sched_cpucount_probe
        ;;
    libc-sched-getcpu)
        [ "$#" -eq 0 ] || fail "libc-sched-getcpu takes no arguments"
        ensure_image
        run_libc_sched_getcpu_probe
        ;;
    libc-sched-priority-bounds)
        [ "$#" -eq 0 ] || fail "libc-sched-priority-bounds takes no arguments"
        ensure_image
        run_libc_sched_priority_bounds_probe
        ;;
    libc-readiness-waits)
        [ "$#" -eq 0 ] || fail "libc-readiness-waits takes no arguments"
        ensure_image
        run_libc_readiness_waits_probe
        ;;
    libc-system-observation)
        [ "$#" -eq 0 ] || fail "libc-system-observation takes no arguments"
        ensure_image
        run_libc_system_observation_probe
        ;;
    libc-system-information)
        [ "$#" -eq 0 ] || fail "libc-system-information takes no arguments"
        ensure_image
        run_libc_system_information_probe
        ;;
    libc-getloadavg)
        [ "$#" -eq 0 ] || fail "libc-getloadavg takes no arguments"
        ensure_image
        run_libc_getloadavg_probe
        ;;
    libc-fcntl-record-locks)
        [ "$#" -eq 0 ] || fail "libc-fcntl-record-locks takes no arguments"
        ensure_image
        run_libc_fcntl_record_locks_probe
        ;;
    libc-flock)
        [ "$#" -eq 0 ] || fail "libc-flock takes no arguments"
        ensure_image
        run_libc_flock_probe
        ;;
    libc-sendfile)
        [ "$#" -eq 0 ] || fail "libc-sendfile takes no arguments"
        ensure_image
        run_libc_sendfile_probe
        ;;
    libc-tee)
        [ "$#" -eq 0 ] || fail "libc-tee takes no arguments"
        ensure_image
        run_libc_tee_probe
        ;;
    libc-splice)
        [ "$#" -eq 0 ] || fail "libc-splice takes no arguments"
        ensure_image
        run_libc_splice_probe
        ;;
    libc-sync-file-range)
        [ "$#" -eq 0 ] || fail "libc-sync-file-range takes no arguments"
        ensure_image
        run_libc_sync_file_range_probe
        ;;
    libc-copy-file-range)
        [ "$#" -eq 0 ] || fail "libc-copy-file-range takes no arguments"
        ensure_image
        run_libc_copy_file_range_probe
        ;;
    libc-posix-fallocate)
        [ "$#" -eq 0 ] || fail "libc-posix-fallocate takes no arguments"
        ensure_image
        run_libc_posix_fallocate_probe
        ;;
    descriptor-advice-header-abi)
        [ "$#" -eq 0 ] || fail "descriptor-advice-header-abi takes no arguments"
        ensure_image
        run_descriptor_advice_header_abi
        ;;
    filesystem-capacity-header-abi)
        [ "$#" -eq 0 ] || fail "filesystem-capacity-header-abi takes no arguments"
        ensure_image
        run_filesystem_capacity_header_abi
        ;;
    vector-io-header-abi)
        [ "$#" -eq 0 ] || fail "vector-io-header-abi takes no arguments"
        ensure_image
        run_vector_io_header_abi
        ;;
    libc-descriptor-advice)
        [ "$#" -eq 0 ] || fail "libc-descriptor-advice takes no arguments"
        ensure_image
        run_libc_descriptor_advice_probe
        ;;
    libc-filesystem-capacity)
        [ "$#" -eq 0 ] || fail "libc-filesystem-capacity takes no arguments"
        ensure_image
        run_libc_filesystem_capacity_probe
        ;;
    libc-vector-io)
        [ "$#" -eq 0 ] || fail "libc-vector-io takes no arguments"
        ensure_image
        run_libc_vector_io_probe
        ;;
    libc-uio-cxx-linkage)
        [ "$#" -eq 0 ] || fail "libc-uio-cxx-linkage takes no arguments"
        ensure_image
        run_libc_uio_cxx_linkage_probe
        ;;
    libc-uts-identity)
        [ "$#" -eq 0 ] || fail "libc-uts-identity takes no arguments"
        ensure_image
        run_libc_uts_identity_probe
        ;;
    libc-ctype)
        [ "$#" -eq 0 ] || fail "libc-ctype takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ctype.sh
        ;;
    libc-locale-profile)
        [ "$#" -eq 0 ] || fail "libc-locale-profile takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_profile.sh
        ;;
    libc-locale-multibyte)
        [ "$#" -eq 0 ] || fail "libc-locale-multibyte takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_multibyte.sh
        ;;
    libc-regex)
        [ "$#" -eq 0 ] || fail "libc-regex takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_regex.sh
        ;;
    libc-locale-wide-iconv)
        [ "$#" -eq 0 ] || fail "libc-locale-wide-iconv takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_wide_iconv.sh
        ;;
    libc-wide-character)
        [ "$#" -eq 0 ] || fail "libc-wide-character takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_wide_character.sh
        ;;
    libc-locale-object-wide)
        [ "$#" -eq 0 ] || fail "libc-locale-object-wide takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_object_wide.sh
        ;;
    libc-locale-narrow)
        [ "$#" -eq 0 ] || fail "libc-locale-narrow takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_narrow.sh
        ;;
    libc-locale-ctype-locators)
        [ "$#" -eq 0 ] || fail "libc-locale-ctype-locators takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_ctype_locators.sh
        ;;
    libc-locale-error-strings)
        [ "$#" -eq 0 ] || fail "libc-locale-error-strings takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_locale_error_strings.sh
        ;;
    libc-integer-arithmetic)
        [ "$#" -eq 0 ] || fail "libc-integer-arithmetic takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_integer_arithmetic.sh
        ;;
    libc-integer-parse)
        [ "$#" -eq 0 ] || fail "libc-integer-parse takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_integer_parse.sh
        ;;
    libc-float-parse)
        [ "$#" -eq 0 ] || fail "libc-float-parse takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_float_parse.sh
        ;;
    libc-getsubopt)
        [ "$#" -eq 0 ] || fail "libc-getsubopt takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_getsubopt.sh
        ;;
    libc-crypt)
        [ "$#" -eq 0 ] || fail "libc-crypt takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_crypt.sh
        ;;
    libc-crypt-allocator-composition)
        [ "$#" -eq 0 ] || fail "libc-crypt-allocator-composition takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_crypt_allocator_composition.sh
        ;;
    libc-l64a)
        [ "$#" -eq 0 ] || fail "libc-l64a takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_l64a.sh
        ;;
    libc-a64l)
        [ "$#" -eq 0 ] || fail "libc-a64l takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_a64l.sh
        ;;
    libc-stdio-standard)
        [ "$#" -eq 0 ] || fail "libc-stdio-standard takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_standard.sh
        ;;
    libc-stdio-format-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-format-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_format_scan.sh
        ;;
    libc-stdio-permanent-format-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-format-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_format_scan_wave.sh
        ;;
    libc-stdio-integer-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-integer-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_integer_scan.sh
        ;;
    libc-stdio-octal-hex-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-octal-hex-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_octal_hex_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_octal_hex_scan.sh
        ;;
    libc-stdio-fixed-percent-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-percent-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_percent_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_percent_scan.sh
        ;;
    libc-stdio-fixed-format-whitespace-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-format-whitespace-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_format_whitespace_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_format_whitespace_scan.sh
        ;;
    libc-stdio-fixed-literal-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-literal-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_literal_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_literal_scan.sh
        ;;
    libc-stdio-fixed-empty-format-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-empty-format-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_empty_format_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_empty_format_scan.sh
        ;;
    libc-stdio-fixed-suppressed-character-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-suppressed-character-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_character_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_suppressed_character_scan.sh
        ;;
    libc-stdio-fixed-suppressed-string-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-suppressed-string-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_string_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_suppressed_string_scan.sh
        ;;
    libc-stdio-fixed-suppressed-scanset-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-suppressed-scanset-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_scanset_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_suppressed_scanset_scan.sh
        ;;
    libc-stdio-fixed-suppressed-count-scan)
        [ "$#" -eq 0 ] || fail "libc-stdio-fixed-suppressed-count-scan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_stdio_fixed_suppressed_count_scan_header_abi.sh
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_fixed_suppressed_count_scan.sh
        ;;
    libc-stdio-float-hex-output)
        [ "$#" -eq 0 ] || fail "libc-stdio-float-hex-output takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_float_hex_output.sh
        ;;
    libc-stdio-errno-output)
        [ "$#" -eq 0 ] || fail "libc-stdio-errno-output takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_errno_output.sh
        ;;
    libc-stdio-permanent-line-io)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-line-io takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_line_io.sh
        ;;
    libc-stdio-permanent-byte-io)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-byte-io takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_byte_io.sh
        ;;
    libc-stdio-permanent-status)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-status takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_status.sh
        ;;
    libc-stdio-permanent-freading-stdin)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-freading-stdin takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_freading_stdin.sh
        ;;
    libc-stdio-permanent-fsetlocking-stdin)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-fsetlocking-stdin takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_fsetlocking_stdin.sh
        ;;
    libc-stdio-permanent-fseterr-stdin)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-fseterr-stdin takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_fseterr_stdin.sh
        ;;
    libc-stdio-permanent-freadable-stdin)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-freadable-stdin takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_freadable_stdin.sh
        ;;
    libc-stdio-permanent-fwritable-stderr)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-fwritable-stderr takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_fwritable_stderr.sh
        ;;
    libc-stdio-permanent-fbufsize-stderr)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-fbufsize-stderr takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_fbufsize_stderr.sh
        ;;
    libc-stdio-permanent-flbf-stderr)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-flbf-stderr takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_flbf_stderr.sh
        ;;
    libc-stdio-permanent-fileno)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-fileno takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_fileno.sh
        ;;
    libc-stdio-permanent-fileno-unlocked)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-fileno-unlocked takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_fileno_unlocked.sh
        ;;
    libc-stdio-permanent-feof-unlocked)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-feof-unlocked takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_feof_unlocked.sh
        ;;
    libc-stdio-permanent-ferror-unlocked)
        [ "$#" -eq 0 ] || fail "libc-stdio-permanent-ferror-unlocked takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_permanent_ferror_unlocked.sh
        ;;
    libc-stdio-path-stream)
        [ "$#" -eq 0 ] || fail "libc-stdio-path-stream takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_path_stream.sh
        ;;
    libc-fopen64-alias)
        [ "$#" -eq 0 ] || fail "libc-fopen64-alias takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_fopen64_alias.sh
        ;;
    libc-stdio-tmpfile)
        [ "$#" -eq 0 ] || fail "libc-stdio-tmpfile takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_stdio_tmpfile.sh
        ;;
    libc-text-math-locale-stdio-composition)
        [ "$#" -eq 0 ] || fail "libc-text-math-locale-stdio-composition takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_text_math_locale_stdio_composition.sh
        ;;
    libc-credential-observation)
        [ "$#" -eq 0 ] || fail "libc-credential-observation takes no arguments"
        ensure_image
        run_libc_credential_observation
        ;;
    libc-child-reaping)
        [ "$#" -eq 0 ] || fail "libc-child-reaping takes no arguments"
        ensure_image
        run_libc_child_reaping
        ;;
    libc-wait-extensions)
        [ "$#" -eq 0 ] || fail "libc-wait-extensions takes no arguments"
        ensure_image
        run_libc_wait_extensions
        ;;
    libc-immediate-termination)
        [ "$#" -eq 0 ] || fail "libc-immediate-termination takes no arguments"
        ensure_image
        run_libc_immediate_termination
        ;;
    libc-posix-exit)
        [ "$#" -eq 0 ] || fail "libc-posix-exit takes no arguments"
        ensure_image
        run_libc_posix_exit
        ;;
    libc-posix-spawnattr-init)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-init takes no arguments"
        ensure_image
        run_libc_posix_spawnattr_init
        ;;
    libc-posix-spawnattr-getpgroup)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-getpgroup takes no arguments"
        ensure_image
        run_libc_posix_spawnattr_getpgroup
        ;;
    libc-posix-spawnattr-signal-fields)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-signal-fields takes no arguments"
        ensure_image
        run_libc_posix_spawnattr_signal_fields
        ;;
    libc-posix-spawnattr-getschedpolicy)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-getschedpolicy takes no arguments"
        ensure_image
        run_libc_posix_spawnattr_getschedpolicy
        ;;
    libc-posix-spawnattr-getschedparam)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-getschedparam takes no arguments"
        ensure_image
        run_libc_posix_spawnattr_getschedparam
        ;;
    libc-bsearch)
        [ "$#" -eq 0 ] || fail "libc-bsearch takes no arguments"
        ensure_image
        run_libc_bsearch
        ;;
    libc-linear-search)
        [ "$#" -eq 0 ] || fail "libc-linear-search takes no arguments"
        ensure_image
        run_libc_linear_search
        ;;
    libc-intrusive-queue)
        [ "$#" -eq 0 ] || fail "libc-intrusive-queue takes no arguments"
        ensure_image
        run_libc_intrusive_queue
        ;;
    libc-wcswcs)
        [ "$#" -eq 0 ] || fail "libc-wcswcs takes no arguments"
        ensure_image
        run_libc_wcswcs
        ;;
    libc-qsort)
        [ "$#" -eq 0 ] || fail "libc-qsort takes no arguments"
        ensure_image
        run_libc_qsort
        ;;
    libc-callback-algorithms)
        [ "$#" -eq 0 ] || fail "libc-callback-algorithms takes no arguments"
        ensure_image
        run_libc_callback_algorithms
        ;;
    libc-search-tree-intrusive)
        [ "$#" -eq 0 ] || fail "libc-search-tree-intrusive takes no arguments"
        ensure_image
        run_libc_search_tree_intrusive
        ;;
    libc-search-hash-table)
        [ "$#" -eq 0 ] || fail "libc-search-hash-table takes no arguments"
        ensure_image
        run_libc_search_hash_table
        ;;
    libc-gettext-catalog)
        [ "$#" -eq 0 ] || fail "libc-gettext-catalog takes no arguments"
        ensure_image
        run_libc_gettext_catalog
        ;;
    libc-access)
        [ "$#" -eq 0 ] || fail "libc-access takes no arguments"
        ensure_image
        run_libc_access
        ;;
    libc-clock-gettime)
        [ "$#" -eq 0 ] || fail "libc-clock-gettime takes no arguments"
        ensure_image
        run_libc_clock_gettime
        ;;
    libc-clock-adjtime)
        [ "$#" -eq 0 ] || fail "libc-clock-adjtime takes no arguments"
        ensure_image
        run_libc_clock_adjtime
        ;;
    libc-clock-settime)
        [ "$#" -eq 0 ] || fail "libc-clock-settime takes no arguments"
        ensure_image
        run_libc_clock_settime
        ;;
    libc-timer-getoverrun)
        [ "$#" -eq 0 ] || fail "libc-timer-getoverrun takes no arguments"
        ensure_image
        run_libc_timer_getoverrun
        ;;
    libc-timer-delete)
        [ "$#" -eq 0 ] || fail "libc-timer-delete takes no arguments"
        ensure_image
        run_libc_timer_delete
        ;;
    libc-timer-gettime)
        [ "$#" -eq 0 ] || fail "libc-timer-gettime takes no arguments"
        ensure_image
        run_libc_timer_gettime
        ;;
    libc-timer-settime)
        [ "$#" -eq 0 ] || fail "libc-timer-settime takes no arguments"
        ensure_image
        run_libc_timer_settime
        ;;
    libc-time-observation)
        [ "$#" -eq 0 ] || fail "libc-time-observation takes no arguments"
        ensure_image
        run_libc_time_observation
        ;;
    libc-difftime)
        [ "$#" -eq 0 ] || fail "libc-difftime takes no arguments"
        ensure_image
        run_libc_difftime
        ;;
    libc-timegm)
        [ "$#" -eq 0 ] || fail "libc-timegm takes no arguments"
        ensure_image
        run_libc_timegm
        ;;
    libc-gmtime-r)
        [ "$#" -eq 0 ] || fail "libc-gmtime-r takes no arguments"
        ensure_image
        run_libc_gmtime_r
        ;;
    libc-system-configuration)
        [ "$#" -eq 0 ] || fail "libc-system-configuration takes no arguments"
        ensure_image
        run_libc_system_configuration
        ;;
    libc-getpagesize)
        [ "$#" -eq 0 ] || fail "libc-getpagesize takes no arguments"
        ensure_image
        run_libc_getpagesize
        ;;
    libc-mapping-core)
        [ "$#" -eq 0 ] || fail "libc-mapping-core takes no arguments"
        ensure_image
        run_libc_mapping_core
        ;;
    libc-memory-sync)
        [ "$#" -eq 0 ] || fail "libc-memory-sync takes no arguments"
        ensure_image
        run_libc_memory_sync
        ;;
    libc-memory-locking)
        [ "$#" -eq 0 ] || fail "libc-memory-locking takes no arguments"
        ensure_image
        run_libc_memory_locking
        ;;
    libc-memfd-create)
        [ "$#" -eq 0 ] || fail "libc-memfd-create takes no arguments"
        ensure_image
        run_libc_memfd_create
        ;;
    libc-allocator-runtime)
        [ "$#" -eq 0 ] || fail "libc-allocator-runtime takes no arguments"
        ensure_image
        run_libc_allocator_runtime
        ;;
    libc-allocator-basic-runtime-v1)
        [ "$#" -eq 0 ] || fail "libc-allocator-basic-runtime-v1 takes no arguments"
        ensure_image
        run_libc_allocator_basic_runtime_v1
        ;;
    libc-allocator-string-duplication)
        [ "$#" -eq 0 ] || fail "libc-allocator-string-duplication takes no arguments"
        ensure_image
        run_libc_allocator_string_duplication
        ;;
    libc-scandir)
        [ "$#" -eq 0 ] || fail "libc-scandir takes no arguments"
        ensure_image
        run_libc_scandir
        ;;
    libc-allocator-observability)
        [ "$#" -eq 0 ] || fail "libc-allocator-observability takes no arguments"
        ensure_image
        run_libc_allocator_observability
        ;;
    libc-alloca)
        [ "$#" -eq 0 ] || fail "libc-alloca takes no arguments"
        ensure_image
        run_libc_alloca
        ;;
    libc-static-c-abi-differential)
        [ "$#" -eq 0 ] || fail "libc-static-c-abi-differential takes no arguments"
        ensure_image
        run_libc_static_c_abi_differential
        ;;
    libc-static-c-abi-same-object-differential)
        [ "$#" -eq 0 ] || fail "libc-static-c-abi-same-object-differential takes no arguments"
        ensure_image
        run_libc_same_object_static_c_abi_differential
        ;;
    qualification-posix-abi-admission)
        [ "$#" -eq 0 ] || fail "qualification-posix-abi-admission takes no arguments"
        ensure_image
        run_qualification_posix_abi_admission
        ;;
    libc-header-layouts-baseline)
        [ "$#" -eq 0 ] || fail "libc-header-layouts-baseline takes no arguments"
        ensure_image
        run_libc_header_layouts_baseline
        ;;
    libc-nanosleep)
        [ "$#" -eq 0 ] || fail "libc-nanosleep takes no arguments"
        ensure_image
        run_libc_nanosleep
        ;;
    libc-sleep)
        [ "$#" -eq 0 ] || fail "libc-sleep takes no arguments"
        ensure_image
        run_libc_sleep
        ;;
    libc-clock-nanosleep)
        [ "$#" -eq 0 ] || fail "libc-clock-nanosleep takes no arguments"
        ensure_image
        run_libc_clock_nanosleep
        ;;
    libc-descriptor-entry)
        [ "$#" -eq 0 ] || fail "libc-descriptor-entry takes no arguments"
        ensure_image
        run_libc_descriptor_entry
        ;;
    libc-fcntl-status-control)
        [ "$#" -eq 0 ] || fail "libc-fcntl-status-control takes no arguments"
        ensure_image
        run_libc_fcntl_status_control
        ;;
    libc-ioctl)
        [ "$#" -eq 0 ] || fail "libc-ioctl takes no arguments"
        ensure_image
        run_libc_ioctl
        ;;
    libc-sysv-semaphore)
        [ "$#" -eq 0 ] || fail "libc-sysv-semaphore takes no arguments"
        ensure_image
        run_libc_sysv_semaphore
        ;;
    libc-posix-semaphore)
        [ "$#" -eq 0 ] || fail "libc-posix-semaphore takes no arguments"
        ensure_image
        run_libc_posix_semaphore
        ;;
    libc-sysv-message-shared-memory)
        [ "$#" -eq 0 ] || fail "libc-sysv-message-shared-memory takes no arguments"
        ensure_image
        run_libc_sysv_message_shared_memory
        ;;
    libc-event-descriptors)
        [ "$#" -eq 0 ] || fail "libc-event-descriptors takes no arguments"
        ensure_image
        run_libc_event_descriptors
        ;;
    libc-timerfd)
        [ "$#" -eq 0 ] || fail "libc-timerfd takes no arguments"
        ensure_image
        run_libc_timerfd_probe
        ;;
    libc-mq-setattr)
        [ "$#" -eq 0 ] || fail "libc-mq-setattr takes no arguments"
        ensure_image
        run_libc_mq_setattr_probe
        ;;
    libc-signalfd)
        [ "$#" -eq 0 ] || fail "libc-signalfd takes no arguments"
        ensure_image
        run_libc_signalfd_probe
        ;;
    libc-sigpause)
        [ "$#" -eq 0 ] || fail "libc-sigpause takes no arguments"
        ensure_image
        run_libc_sigpause_probe
        ;;
    libc-sigisemptyset)
        [ "$#" -eq 0 ] || fail "libc-sigisemptyset takes no arguments"
        ensure_image
        run_libc_sigisemptyset_probe
        ;;
    libc-sigandset-sigorset)
        [ "$#" -eq 0 ] || fail "libc-sigandset-sigorset takes no arguments"
        ensure_image
        run_libc_sigandset_sigorset_probe
        ;;
    libc-sigpending)
        [ "$#" -eq 0 ] || fail "libc-sigpending takes no arguments"
        ensure_image
        run_libc_sigpending_probe
        ;;
    libc-sigrtmax)
        [ "$#" -eq 0 ] || fail "libc-sigrtmax takes no arguments"
        ensure_image
        run_libc_sigrtmax_probe
        ;;
    libc-sigrtmin)
        [ "$#" -eq 0 ] || fail "libc-sigrtmin takes no arguments"
        ensure_image
        run_libc_sigrtmin_probe
        ;;
    libc-sched-getscheduler)
        [ "$#" -eq 0 ] || fail "libc-sched-getscheduler takes no arguments"
        ensure_image
        run_libc_sched_getscheduler_probe
        ;;
    libc-sched-rr-interval)
        [ "$#" -eq 0 ] || fail "libc-sched-rr-interval takes no arguments"
        ensure_image
        run_libc_sched_rr_interval_probe
        ;;
    libc-alarm)
        [ "$#" -eq 0 ] || fail "libc-alarm takes no arguments"
        ensure_image
        run_libc_alarm_probe
        ;;
    ualarm-header-abi)
        [ "$#" -eq 0 ] || fail "ualarm-header-abi takes no arguments"
        ensure_image
        run_ualarm_header_abi
        ;;
    libc-ualarm)
        [ "$#" -eq 0 ] || fail "libc-ualarm takes no arguments"
        ensure_image
        run_libc_ualarm_probe
        ;;
    libc-interval-timers)
        [ "$#" -eq 0 ] || fail "libc-interval-timers takes no arguments"
        ensure_image
        run_libc_interval_timers_probe
        ;;
    usleep-header-abi)
        [ "$#" -eq 0 ] || fail "usleep-header-abi takes no arguments"
        ensure_image
        run_usleep_header_abi
        ;;
    libc-usleep)
        [ "$#" -eq 0 ] || fail "libc-usleep takes no arguments"
        ensure_image
        run_libc_usleep_probe
        ;;
    basename-header-abi)
        [ "$#" -eq 0 ] || fail "basename-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_basename_header_abi.sh
        ;;
    siginterrupt-header-abi)
        [ "$#" -eq 0 ] || fail "siginterrupt-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_siginterrupt_header_abi.sh
        ;;
    mlockall-header-abi)
        [ "$#" -eq 0 ] || fail "mlockall-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_mlockall_header_abi.sh
        ;;
    munlockall-header-abi)
        [ "$#" -eq 0 ] || fail "munlockall-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_munlockall_header_abi.sh
        ;;
    ftime-header-abi)
        [ "$#" -eq 0 ] || fail "ftime-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_ftime_header_abi.sh
        ;;
    clock-getcpuclockid-header-abi)
        [ "$#" -eq 0 ] || fail "clock-getcpuclockid-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_clock_getcpuclockid_header_abi.sh
        ;;
    libc-basename)
        [ "$#" -eq 0 ] || fail "libc-basename takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_basename.sh
        ;;
    libc-siginterrupt)
        [ "$#" -eq 0 ] || fail "libc-siginterrupt takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_siginterrupt.sh
        ;;
    libc-mlockall)
        [ "$#" -eq 0 ] || fail "libc-mlockall takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_mlockall.sh
        ;;
    libc-munlockall)
        [ "$#" -eq 0 ] || fail "libc-munlockall takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_munlockall.sh
        ;;
    libc-ftime)
        [ "$#" -eq 0 ] || fail "libc-ftime takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ftime.sh
        ;;
    libc-clock-getcpuclockid)
        [ "$#" -eq 0 ] || fail "libc-clock-getcpuclockid takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_clock_getcpuclockid.sh
        ;;
    libc-sigaddset-sigdelset-sigfillset)
        [ "$#" -eq 0 ] || fail "libc-sigaddset-sigdelset-sigfillset takes no arguments"
        ensure_image
        run_libc_sigset_mutation_probe
        ;;
    libc-extended-attributes)
        [ "$#" -eq 0 ] || fail "libc-extended-attributes takes no arguments"
        ensure_image
        run_libc_extended_attributes
        ;;
    libc-pathname-lifecycle)
        [ "$#" -eq 0 ] || fail "libc-pathname-lifecycle takes no arguments"
        ensure_image
        run_libc_pathname_lifecycle
        ;;
    libc-directory-streams)
        [ "$#" -eq 0 ] || fail "libc-directory-streams takes no arguments"
        ensure_image
        run_libc_directory_streams
        ;;
    libc-filesystem-traversal)
        [ "$#" -eq 0 ] || fail "libc-filesystem-traversal takes no arguments"
        ensure_image
        run_libc_filesystem_traversal
        ;;
    libc-filesystem-directory)
        [ "$#" -eq 0 ] || fail "libc-filesystem-directory takes no arguments"
        ensure_image
        run_libc_filesystem_directory
        ;;
    libc-filesystem-extensions)
        [ "$#" -eq 0 ] || fail "libc-filesystem-extensions takes no arguments"
        ensure_image
        run_libc_filesystem_extensions
        ;;
    libc-lchmod-unsupported)
        [ "$#" -eq 0 ] || fail "libc-lchmod-unsupported takes no arguments"
        ensure_image
        run_libc_lchmod_unsupported
        ;;
    libc-ffs)
        [ "$#" -eq 0 ] || fail "libc-ffs takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ffs.sh
        ;;
    libc-memory-special)
        [ "$#" -eq 0 ] || fail "libc-memory-special takes no arguments"
        ensure_image
        run_libc_memory_special_probe
        ;;
    libc-memccpy)
        [ "$#" -eq 0 ] || fail "libc-memccpy takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_memccpy.sh
        ;;
    libc-aio-error)
        [ "$#" -eq 0 ] || fail "libc-aio-error takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_aio_error.sh
        ;;
    libc-byte-strings)
        [ "$#" -eq 0 ] || fail "libc-byte-strings takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_byte_strings.sh
        ;;
    libc-legacy-memory)
        [ "$#" -eq 0 ] || fail "libc-legacy-memory takes no arguments"
        ensure_image
        run_libc_legacy_memory
        ;;
    libc-memccpy)
        [ "$#" -eq 0 ] || fail "libc-memccpy takes no arguments"
        ensure_image
        run_libc_memccpy
        ;;
    libc-mempcpy)
        [ "$#" -eq 0 ] || fail "libc-mempcpy takes no arguments"
        ensure_image
        run_libc_mempcpy
        ;;
    libc-strsep)
        [ "$#" -eq 0 ] || fail "libc-strsep takes no arguments"
        ensure_image
        run_libc_strsep
        ;;
    libc-strtok)
        [ "$#" -eq 0 ] || fail "libc-strtok takes no arguments"
        ensure_image
        run_libc_strtok
        ;;
    libc-stateful-byte-strings)
        [ "$#" -eq 0 ] || fail "libc-stateful-byte-strings takes no arguments"
        ensure_image
        run_libc_stateful_byte_strings
        ;;
    libc-rand-r)
        [ "$#" -eq 0 ] || fail "libc-rand-r takes no arguments"
        ensure_image
        run_libc_rand_r
        ;;
    libc-lrand48)
        [ "$#" -eq 0 ] || fail "libc-lrand48 takes no arguments"
        ensure_image
        run_libc_lrand48
        ;;
    libc-network-byte-order)
        [ "$#" -eq 0 ] || fail "libc-network-byte-order takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_network_byte_order.sh
        ;;
    libc-in6addr-any)
        [ "$#" -eq 0 ] || fail "libc-in6addr-any takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_in6addr_any.sh
        ;;
    libc-in6addr-loopback)
        [ "$#" -eq 0 ] || fail "libc-in6addr-loopback takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_in6addr_loopback.sh
        ;;
    libc-dn-skipname)
        [ "$#" -eq 0 ] || fail "libc-dn-skipname takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_dn_skipname.sh
        ;;
    libc-dn-expand)
        [ "$#" -eq 0 ] || fail "libc-dn-expand takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_dn_expand.sh
        ;;
    libc-ns-flagdata)
        [ "$#" -eq 0 ] || fail "libc-ns-flagdata takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ns_flagdata.sh
        ;;
    libc-ns-get16)
        [ "$#" -eq 0 ] || fail "libc-ns-get16 takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ns_get16.sh
        ;;
    libc-ns-get32)
        [ "$#" -eq 0 ] || fail "libc-ns-get32 takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ns_get32.sh
        ;;
    libc-ns-put16)
        [ "$#" -eq 0 ] || fail "libc-ns-put16 takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ns_put16.sh
        ;;
    libc-process-globals-getopt)
        [ "$#" -eq 0 ] || fail "libc-process-globals-getopt takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_process_globals_getopt.sh
        ;;
    libc-auxv-observation)
        [ "$#" -eq 0 ] || fail "libc-auxv-observation takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_auxv_observation.sh
        ;;
    libc-inet-address)
        [ "$#" -eq 0 ] || fail "libc-inet-address takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_inet_address.sh
        ;;
    libc-inet-ntoa)
        [ "$#" -eq 0 ] || fail "libc-inet-ntoa takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_inet_ntoa.sh
        ;;
    libc-inet-classful)
        [ "$#" -eq 0 ] || fail "libc-inet-classful takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_inet_classful.sh
        ;;
    libc-hstrerror)
        [ "$#" -eq 0 ] || fail "libc-hstrerror takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_hstrerror.sh
        ;;
    libc-h-errno)
        [ "$#" -eq 0 ] || fail "libc-h-errno takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_h_errno.sh
        ;;
    libc-endservent)
        [ "$#" -eq 0 ] || fail "libc-endservent takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_endservent.sh
        ;;
    libc-service-lifecycle)
        [ "$#" -eq 0 ] || fail "libc-service-lifecycle takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_service_lifecycle.sh
        ;;
    libc-protocol-database)
        [ "$#" -eq 0 ] || fail "libc-protocol-database takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_protocol_database.sh
        ;;
    libc-numeric-netdb)
        [ "$#" -eq 0 ] || fail "libc-numeric-netdb takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_numeric_netdb.sh
        ;;
    libc-resolver-runtime)
        [ "$#" -eq 0 ] || fail "libc-resolver-runtime takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_resolver_runtime.sh
        ;;
    libc-interface-discovery)
        [ "$#" -eq 0 ] || fail "libc-interface-discovery takes no arguments"
        ensure_image
        run_in_network_none_container bash /workspace/compat/x86_64/run_libc_interface_discovery.sh
        ;;
    libc-random-entropy)
        [ "$#" -eq 0 ] || fail "libc-random-entropy takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_random_entropy.sh
        ;;
    libc-memory-search)
        [ "$#" -eq 0 ] || fail "libc-memory-search takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_memory_search.sh
        ;;
    libc-string-copy)
        [ "$#" -eq 0 ] || fail "libc-string-copy takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_string_copy.sh
        ;;
    libc-error-strings)
        [ "$#" -eq 0 ] || fail "libc-error-strings takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_error_strings.sh
        ;;
    string-duplication-header-abi)
        [ "$#" -eq 0 ] || fail "string-duplication-header-abi takes no arguments"
        ensure_image
        run_string_duplication_header_abi
        ;;
    libc-strsignal)
        [ "$#" -eq 0 ] || fail "libc-strsignal takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_strsignal.sh
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
    libc-owned-scalar-math)
        [ "$#" -eq 0 ] || fail "libc-owned-scalar-math takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_owned_static_math_scalar_consumer.sh
        ;;
    libc-owned-binary80-math)
        [ "$#" -eq 0 ] || fail "libc-owned-binary80-math takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_owned_static_math_binary80_consumer.sh
        ;;
    libc-math-complex)
        [ "$#" -eq 0 ] || fail "libc-math-complex takes no arguments"
        ensure_image
        run_libc_math_complex_probe
        ;;
    libc-math-complex-complete)
        [ "$#" -eq 0 ] || fail "libc-math-complex-complete takes no arguments"
        ensure_image
        run_libc_math_complex_complete_probe
        ;;
    libc-elementary-sqrt-fenv)
        [ "$#" -eq 0 ] || fail "libc-elementary-sqrt-fenv takes no arguments"
        ensure_image
        run_libc_elementary_sqrt_fenv_probe
        ;;
    libc-fenv-rounding)
        [ "$#" -eq 0 ] || fail "libc-fenv-rounding takes no arguments"
        ensure_image
        run_libc_fenv_rounding_probe
        ;;
    libc-math-minmax)
        [ "$#" -eq 0 ] || fail "libc-math-minmax takes no arguments"
        ensure_image
        run_libc_math_minmax_probe
        ;;
    libc-math-bit-sign)
        [ "$#" -eq 0 ] || fail "libc-math-bit-sign takes no arguments"
        ensure_image
        run_libc_math_bit_sign_probe
        ;;
    libc-math-trunc)
        [ "$#" -eq 0 ] || fail "libc-math-trunc takes no arguments"
        ensure_image
        run_libc_math_trunc_probe
        ;;
    libc-math-fmod)
        [ "$#" -eq 0 ] || fail "libc-math-fmod takes no arguments"
        ensure_image
        run_libc_math_fmod_probe
        ;;
    libc-math-cbrt)
        [ "$#" -eq 0 ] || fail "libc-math-cbrt takes no arguments"
        ensure_image
        run_libc_math_cbrt_probe
        ;;
    libc-math-exp2)
        [ "$#" -eq 0 ] || fail "libc-math-exp2 takes no arguments"
        ensure_image
        run_libc_math_exp2_probe
        ;;
    libc-math-expm1)
        [ "$#" -eq 0 ] || fail "libc-math-expm1 takes no arguments"
        ensure_image
        run_libc_math_expm1_probe
        ;;
    libc-math-log10)
        [ "$#" -eq 0 ] || fail "libc-math-log10 takes no arguments"
        ensure_image
        run_libc_math_log10_probe
        ;;
    libc-math-ceil)
        [ "$#" -eq 0 ] || fail "libc-math-ceil takes no arguments"
        ensure_image
        run_libc_math_ceil_probe
        ;;
    libc-math-floor)
        [ "$#" -eq 0 ] || fail "libc-math-floor takes no arguments"
        ensure_image
        run_libc_math_floor_probe
        ;;
    libc-math-round)
        [ "$#" -eq 0 ] || fail "libc-math-round takes no arguments"
        ensure_image
        run_libc_math_round_probe
        ;;
    libc-math-log2)
        [ "$#" -eq 0 ] || fail "libc-math-log2 takes no arguments"
        ensure_image
        run_libc_math_log2_probe
        ;;
    libc-math-elementary-long-double)
        [ "$#" -eq 0 ] || fail "libc-math-elementary-long-double takes no arguments"
        ensure_image
        run_libc_math_elementary_long_double_probe
        ;;
    libc-math-x87-extended)
        [ "$#" -eq 0 ] || fail "libc-math-x87-extended takes no arguments"
        ensure_image
        run_libc_math_x87_extended_probe
        ;;
    libc-math-special)
        [ "$#" -eq 0 ] || fail "libc-math-special takes no arguments"
        ensure_image
        run_libc_math_special_probe
        ;;
    libc-fdim)
        [ "$#" -eq 0 ] || fail "libc-fdim takes no arguments"
        ensure_image
        run_libc_fdim_probe
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
    ldso-initial-graph)
        [ "$#" -eq 0 ] || fail "ldso-initial-graph takes no arguments"
        ensure_image
        run_ldso_initial_graph_tests
        ;;
    ldso-general-initial-graph)
        [ "$#" -eq 0 ] || fail "ldso-general-initial-graph takes no arguments"
        ensure_image
        run_ldso_general_initial_graph_tests
        ;;
    ldso-general-initial-target-root)
        [ "$#" -eq 0 ] || fail "ldso-general-initial-target-root takes no arguments"
        ensure_image
        run_ldso_general_initial_graph_target_root_tests
        ;;
    ldso-general-initial-tls)
        [ "$#" -eq 0 ] || fail "ldso-general-initial-tls takes no arguments"
        ensure_image
        run_ldso_general_initial_tls_tests
        ;;
    ldso-general-initial-tls-target-root)
        [ "$#" -eq 0 ] || fail "ldso-general-initial-tls-target-root takes no arguments"
        ensure_image
        run_ldso_general_initial_tls_target_root_tests
        ;;
    ldso-target-root)
        [ "$#" -eq 0 ] || fail "ldso-target-root takes no arguments"
        ensure_image
        run_ldso_target_root_tests
        ;;
    ldso-initial-tls)
        [ "$#" -eq 0 ] || fail "ldso-initial-tls takes no arguments"
        ensure_image
        run_ldso_initial_tls_tests
        ;;
    libc-math-long-double-completion)
        [ "$#" -eq 0 ] || fail "libc-math-long-double-completion takes no arguments"
        ensure_image
        run_libc_math_long_double_completion_tests
        ;;
    libc-math-elementary-fenv-sensitive)
        [ "$#" -eq 0 ] || fail "libc-math-elementary-fenv-sensitive takes no arguments"
        ensure_image
        run_libc_math_elementary_fenv_sensitive_tests
        ;;
    loader-libc-tls-runtime-v1)
        [ "$#" -eq 0 ] || fail "loader-libc-tls-runtime-v1 takes no arguments"
        ensure_image
        run_loader_libc_tls_runtime_v1_tests
        ;;
    loader-libc-tls-runtime-v1-registry)
        [ "$#" -eq 0 ] || fail "loader-libc-tls-runtime-v1-registry takes no arguments"
        ensure_image
        run_loader_libc_tls_runtime_v1_registry_tests
        ;;
    loader-libc-general-tls-runtime-v1)
        [ "$#" -eq 0 ] || fail "loader-libc-general-tls-runtime-v1 takes no arguments"
        ensure_image
        run_loader_libc_general_tls_runtime_v1_tests
        ;;
    loader-libc-general-tls-runtime-v1-target-root)
        [ "$#" -eq 0 ] || fail "loader-libc-general-tls-runtime-v1-target-root takes no arguments"
        ensure_image
        run_loader_libc_general_tls_runtime_v1_target_root_tests
        ;;
    dynamic-main-thread-runtime-v1)
        [ "$#" -eq 0 ] || fail "dynamic-main-thread-runtime-v1 takes no arguments"
        ensure_image
        run_dynamic_main_thread_runtime_v1_tests
        ;;
    dynamic-main-thread-runtime-v1-target-root)
        [ "$#" -eq 0 ] || fail "dynamic-main-thread-runtime-v1-target-root takes no arguments"
        ensure_image
        run_dynamic_main_thread_runtime_v1_target_root_tests
        ;;
    general-dynamic-lifecycle)
        [ "$#" -eq 0 ] || fail "general-dynamic-lifecycle takes no arguments"
        ensure_image
        run_general_dynamic_lifecycle_tests
        ;;
    general-relocations)
        [ "$#" -eq 0 ] || fail "general-relocations takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_general_relocations.sh
        ;;
    ldso-initial-exec-tls)
        [ "$#" -eq 0 ] || fail "ldso-initial-exec-tls takes no arguments"
        ensure_image
        run_ldso_initial_exec_tls_tests
        ;;
    ldso-owned-crt-handoff)
        [ "$#" -eq 0 ] || fail "ldso-owned-crt-handoff takes no arguments"
        ensure_image
        run_ldso_owned_crt_handoff_tests
        ;;
    ldso-fixed-graph-introspection)
        [ "$#" -eq 0 ] || fail "ldso-fixed-graph-introspection takes no arguments"
        ensure_image
        run_ldso_fixed_graph_introspection_tests
        ;;
    ldso-fixed-graph-dlfcn)
        [ "$#" -eq 0 ] || fail "ldso-fixed-graph-dlfcn takes no arguments"
        ensure_image
        run_ldso_fixed_graph_dlfcn_tests
        ;;
    ldso-public-dlfcn)
        [ "$#" -eq 0 ] || fail "ldso-public-dlfcn takes no arguments"
        ensure_image
        run_ldso_public_dlfcn_tests
        ;;
    ldso-dladdr-symbol-bounds)
        [ "$#" -eq 0 ] || fail "ldso-dladdr-symbol-bounds takes no arguments"
        ensure_image
        run_ldso_dladdr_symbol_bounds_tests
        ;;
    ldso-bounded-dlopen)
        [ "$#" -eq 0 ] || fail "ldso-bounded-dlopen takes no arguments"
        ensure_image
        run_ldso_bounded_dlopen_tests
        ;;
    ldso-dynamic-admission)
        [ "$#" -eq 0 ] || fail "ldso-dynamic-admission takes no arguments"
        ensure_image
        run_ldso_dynamic_admission_tests
        ;;
    umask-header-abi)
        [ "$#" -eq 0 ] || fail "umask-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_umask_header_abi.sh
        ;;
    intrusive-queue-header-abi)
        [ "$#" -eq 0 ] || fail "intrusive-queue-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_intrusive_queue_header_abi.sh
        ;;
    getdtablesize-header-abi)
        [ "$#" -eq 0 ] || fail "getdtablesize-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_getdtablesize_header_abi.sh
        ;;
    membarrier-header-abi)
        [ "$#" -eq 0 ] || fail "membarrier-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_membarrier_header_abi.sh
        ;;
    syncfs-header-abi)
        [ "$#" -eq 0 ] || fail "syncfs-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_syncfs_header_abi.sh
        ;;
    confstr-header-abi)
        [ "$#" -eq 0 ] || fail "confstr-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_confstr_header_abi.sh
        ;;
    fpathconf-header-abi)
        [ "$#" -eq 0 ] || fail "fpathconf-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_fpathconf_header_abi.sh
        ;;
    pathconf-header-abi)
        [ "$#" -eq 0 ] || fail "pathconf-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_pathconf_header_abi.sh
        ;;
    sysconf-header-abi)
        [ "$#" -eq 0 ] || fail "sysconf-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_sysconf_header_abi.sh
        ;;
    libc-umask)
        [ "$#" -eq 0 ] || fail "libc-umask takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_umask.sh
        ;;
    libc-intrusive-queue)
        [ "$#" -eq 0 ] || fail "libc-intrusive-queue takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_intrusive_queue.sh
        ;;
    libc-getdtablesize)
        [ "$#" -eq 0 ] || fail "libc-getdtablesize takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_getdtablesize.sh
        ;;
    libc-membarrier)
        [ "$#" -eq 0 ] || fail "libc-membarrier takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_membarrier.sh
        ;;
    libc-syncfs)
        [ "$#" -eq 0 ] || fail "libc-syncfs takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_syncfs.sh
        ;;
    libc-confstr)
        [ "$#" -eq 0 ] || fail "libc-confstr takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_confstr.sh
        ;;
    libc-fpathconf)
        [ "$#" -eq 0 ] || fail "libc-fpathconf takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_fpathconf.sh
        ;;
    libc-pathconf)
        [ "$#" -eq 0 ] || fail "libc-pathconf takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_pathconf.sh
        ;;
    libc-sysconf)
        [ "$#" -eq 0 ] || fail "libc-sysconf takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_sysconf.sh
        ;;
    ether-line-header-abi)
        [ "$#" -eq 0 ] || fail "ether-line-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_ether_line_header_abi.sh
        ;;
    ether-header-abi)
        [ "$#" -eq 0 ] || fail "ether-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_ether_header_abi.sh
        ;;
    libc-ether-line)
        [ "$#" -eq 0 ] || fail "libc-ether-line takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ether_line.sh
        ;;
    libc-ether)
        [ "$#" -eq 0 ] || fail "libc-ether takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ether.sh
        ;;
    libc-posix-spawn-file-actions-init)
        [ "$#" -eq 0 ] || fail "libc-posix-spawn-file-actions-init takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawn_file_actions_init.sh
        ;;
    libc-posix-spawnattr-destroy)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-destroy takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_destroy.sh
        ;;
    libc-posix-spawnattr-getflags)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-getflags takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_getflags.sh
        ;;
    libc-posix-spawnattr-setpgroup)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-setpgroup takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_setpgroup.sh
        ;;
    libc-posix-spawnattr-setschedparam)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-setschedparam takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_setschedparam.sh
        ;;
    libc-posix-spawnattr-setschedpolicy)
        [ "$#" -eq 0 ] || fail "libc-posix-spawnattr-setschedpolicy takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_posix_spawnattr_setschedpolicy.sh
        ;;
    libc-res-init)
        [ "$#" -eq 0 ] || fail "libc-res-init takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_res_init.sh
        ;;
    posix-spawn-file-actions-init-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawn-file-actions-init-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_posix_spawn_file_actions_init_header_abi.sh
        ;;
    posix-spawnattr-destroy-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-destroy-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_destroy_header_abi.sh
        ;;
    posix-spawnattr-getflags-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-getflags-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_getflags_header_abi.sh
        ;;
    posix-spawnattr-setpgroup-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-setpgroup-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_setpgroup_header_abi.sh
        ;;
    posix-spawnattr-setschedparam-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-setschedparam-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_setschedparam_header_abi.sh
        ;;
    posix-spawnattr-setschedpolicy-header-abi)
        [ "$#" -eq 0 ] || fail "posix-spawnattr-setschedpolicy-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_posix_spawnattr_setschedpolicy_header_abi.sh
        ;;
    res-init-header-abi)
        [ "$#" -eq 0 ] || fail "res-init-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_res_init_header_abi.sh
        ;;
    h-errno-header-abi)
        [ "$#" -eq 0 ] || fail "h-errno-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_h_errno_header_abi.sh
        ;;
    resolver-runtime-header-abi)
        [ "$#" -eq 0 ] || fail "resolver-runtime-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_resolver_runtime_header_abi.sh
        ;;
    c32rtomb-header-abi)
        [ "$#" -eq 0 ] || fail "c32rtomb-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_c32rtomb_header_abi.sh
        ;;
    uchar-stateful-header-abi)
        [ "$#" -eq 0 ] || fail "uchar-stateful-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_uchar_stateful_header_abi.sh
        ;;
    chown-header-abi)
        [ "$#" -eq 0 ] || fail "chown-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_chown_header_abi.sh
        ;;
    libc-c32rtomb)
        [ "$#" -eq 0 ] || fail "libc-c32rtomb takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_c32rtomb.sh
        ;;
    libc-uchar-stateful)
        [ "$#" -eq 0 ] || fail "libc-uchar-stateful takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_uchar_stateful.sh
        ;;
    libc-chown)
        [ "$#" -eq 0 ] || fail "libc-chown takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_chown.sh
        ;;
    libc-sync)
        [ "$#" -eq 0 ] || fail "libc-sync takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_sync.sh
        ;;
    libc-sync-file-range)
        [ "$#" -eq 0 ] || fail "libc-sync-file-range takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_sync_file_range.sh
        ;;
    libc-unlinkat)
        [ "$#" -eq 0 ] || fail "libc-unlinkat takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_unlinkat.sh
        ;;
    sync-file-range-header-abi)
        [ "$#" -eq 0 ] || fail "sync-file-range-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_sync_file_range_header_abi.sh
        ;;
    sync-header-abi)
        [ "$#" -eq 0 ] || fail "sync-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_sync_header_abi.sh
        ;;
    unlinkat-header-abi)
        [ "$#" -eq 0 ] || fail "unlinkat-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_unlinkat_header_abi.sh
        ;;
    libc-math-exp)
        [ "$#" -eq 0 ] || fail "libc-math-exp takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_exp.sh
        ;;
    libc-math-cos)
        [ "$#" -eq 0 ] || fail "libc-math-cos takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_cos.sh
        ;;
    libc-math-cosh)
        [ "$#" -eq 0 ] || fail "libc-math-cosh takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_cosh.sh
        ;;
    libc-math-asinh)
        [ "$#" -eq 0 ] || fail "libc-math-asinh takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_asinh.sh
        ;;
    libc-math-exp10f)
        [ "$#" -eq 0 ] || fail "libc-math-exp10f takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_exp10f.sh
        ;;
    libc-math-sinh)
        [ "$#" -eq 0 ] || fail "libc-math-sinh takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_sinh.sh
        ;;
    libc-pthread-spin-init)
        [ "$#" -eq 0 ] || fail "libc-pthread-spin-init takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_pthread_spin_init.sh
        ;;
    pthread-spin-init-header-abi)
        [ "$#" -eq 0 ] || fail "pthread-spin-init-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_pthread_spin_init_header_abi.sh
        ;;
    libc-math-acosh)
        [ "$#" -eq 0 ] || fail "libc-math-acosh takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_acosh.sh
        ;;
    libc-math-atanh)
        [ "$#" -eq 0 ] || fail "libc-math-atanh takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_atanh.sh
        ;;
    libc-math-exp10)
        [ "$#" -eq 0 ] || fail "libc-math-exp10 takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_exp10.sh
        ;;
    libc-math-log)
        [ "$#" -eq 0 ] || fail "libc-math-log takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_log.sh
        ;;
    libc-math-pow)
        [ "$#" -eq 0 ] || fail "libc-math-pow takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_pow.sh
        ;;
    libc-math-sin)
        [ "$#" -eq 0 ] || fail "libc-math-sin takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_sin.sh
        ;;
    libc-math-sincos)
        [ "$#" -eq 0 ] || fail "libc-math-sincos takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_sincos.sh
        ;;
    libc-math-tan)
        [ "$#" -eq 0 ] || fail "libc-math-tan takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_tan.sh
        ;;
    libc-math-tanh)
        [ "$#" -eq 0 ] || fail "libc-math-tanh takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_math_tanh.sh
        ;;
    math-acosh-header-abi)
        [ "$#" -eq 0 ] || fail "math-acosh-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_acosh_header_abi.sh
        ;;
    math-atanh-header-abi)
        [ "$#" -eq 0 ] || fail "math-atanh-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_atanh_header_abi.sh
        ;;
    math-exp10-header-abi)
        [ "$#" -eq 0 ] || fail "math-exp10-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_exp10_header_abi.sh
        ;;
    math-log-header-abi)
        [ "$#" -eq 0 ] || fail "math-log-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_log_header_abi.sh
        ;;
    math-pow-header-abi)
        [ "$#" -eq 0 ] || fail "math-pow-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_pow_header_abi.sh
        ;;
    math-sin-header-abi)
        [ "$#" -eq 0 ] || fail "math-sin-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_sin_header_abi.sh
        ;;
    math-sincos-header-abi)
        [ "$#" -eq 0 ] || fail "math-sincos-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_sincos_header_abi.sh
        ;;
    math-tan-header-abi)
        [ "$#" -eq 0 ] || fail "math-tan-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_tan_header_abi.sh
        ;;
    math-tanh-header-abi)
        [ "$#" -eq 0 ] || fail "math-tanh-header-abi takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_math_tanh_header_abi.sh
        ;;
    libc-inet-netof)
        [ "$#" -eq 0 ] || fail "libc-inet-netof takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_inet_netof.sh
        ;;
    libc-inet-network)
        [ "$#" -eq 0 ] || fail "libc-inet-network takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_inet_network.sh
        ;;
    libc-ns-put32)
        [ "$#" -eq 0 ] || fail "libc-ns-put32 takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ns_put32.sh
        ;;
    libc-ns-skiprr)
        [ "$#" -eq 0 ] || fail "libc-ns-skiprr takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ns_skiprr.sh
        ;;
    libc-nameser-wire-aggregate)
        [ "$#" -eq 0 ] || fail "libc-nameser-wire-aggregate takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_nameser_wire_aggregate.sh
        ;;
    libc-nameser-message-parser)
        [ "$#" -eq 0 ] || fail "libc-nameser-message-parser takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_nameser_message_parser.sh
        ;;
    libc-io-permissions)
        [ "$#" -eq 0 ] || fail "libc-io-permissions takes no arguments"
        ensure_image
        run_libc_io_permissions_probe
        ;;
    libc-personality)
        [ "$#" -eq 0 ] || fail "libc-personality takes no arguments"
        ensure_image
        run_libc_personality_probe
        ;;
    libc-sched-getaffinity)
        [ "$#" -eq 0 ] || fail "libc-sched-getaffinity takes no arguments"
        ensure_image
        run_libc_sched_getaffinity_probe
        ;;
    libc-sched-setaffinity)
        [ "$#" -eq 0 ] || fail "libc-sched-setaffinity takes no arguments"
        ensure_image
        run_libc_sched_setaffinity_probe
        ;;
    libc-sched-getparam)
        [ "$#" -eq 0 ] || fail "libc-sched-getparam takes no arguments"
        ensure_image
        run_libc_sched_getparam_probe
        ;;
    libc-sched-setparam)
        [ "$#" -eq 0 ] || fail "libc-sched-setparam takes no arguments"
        ensure_image
        run_libc_sched_setparam_probe
        ;;
    libc-sched-setscheduler)
        [ "$#" -eq 0 ] || fail "libc-sched-setscheduler takes no arguments"
        ensure_image
        run_libc_sched_setscheduler_probe
        ;;
    libc-setfsgid)
        [ "$#" -eq 0 ] || fail "libc-setfsgid takes no arguments"
        ensure_image
        run_libc_setfsgid_probe
        ;;
    libc-setfsuid)
        [ "$#" -eq 0 ] || fail "libc-setfsuid takes no arguments"
        ensure_image
        run_libc_setfsuid_probe
        ;;
    personality-header-abi)
        [ "$#" -eq 0 ] || fail "personality-header-abi takes no arguments"
        ensure_image
        run_personality_header_abi
        ;;
    sched-getaffinity-header-abi)
        [ "$#" -eq 0 ] || fail "sched-getaffinity-header-abi takes no arguments"
        ensure_image
        run_sched_getaffinity_header_abi
        ;;
    sched-setaffinity-header-abi)
        [ "$#" -eq 0 ] || fail "sched-setaffinity-header-abi takes no arguments"
        ensure_image
        run_sched_setaffinity_header_abi
        ;;
    sched-getparam-header-abi)
        [ "$#" -eq 0 ] || fail "sched-getparam-header-abi takes no arguments"
        ensure_image
        run_sched_getparam_header_abi
        ;;
    sched-setparam-header-abi)
        [ "$#" -eq 0 ] || fail "sched-setparam-header-abi takes no arguments"
        ensure_image
        run_sched_setparam_header_abi
        ;;
    sched-setscheduler-header-abi)
        [ "$#" -eq 0 ] || fail "sched-setscheduler-header-abi takes no arguments"
        ensure_image
        run_sched_setscheduler_header_abi
        ;;
    setfsgid-header-abi)
        [ "$#" -eq 0 ] || fail "setfsgid-header-abi takes no arguments"
        ensure_image
        run_setfsgid_header_abi
        ;;
    setfsuid-header-abi)
        [ "$#" -eq 0 ] || fail "setfsuid-header-abi takes no arguments"
        ensure_image
        run_setfsuid_header_abi
        ;;
esac
