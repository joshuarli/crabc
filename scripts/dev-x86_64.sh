#!/usr/bin/env bash
# Native Linux/x86-64 staged foundation evidence entry point.
#
# This is a deliberately closed foundation lane. It proves explicitly named
# native core, direct-facade, raw-C-syscall, source-only relocation, and a closed
# set of static C ABI archive boundaries (stat, credentials, bootstrap primitives,
# simple signal control, bounded process-signal execution, bounded pthread create/exit/join initial TLS, named termios control, selected process context, child reaping,
# C11 immediate termination, callback algorithms, direct clock_gettime,
# system configuration,
# nanosleep, and clock_nanosleep,
# selected descriptor entry, selected filesystem access, selected fcntl status control, selected descriptor I/O, selected process resources, and selected readiness
# and signal waits, system observation, UTS identity, base socket transport,
# byte strings, random entropy, memory search, C-string copy, and fixed-C-locale
# ctype, integer arithmetic, integer parsing, intmax arithmetic, credential
# observation, find-first-set, and the x87 long-double/complex foundation);
# it does not select a general libc, ldso artifact, CRT, sysroot, or allocator
# build.
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
  linux-5-10-uapi  verify the fixed Linux 5.10 x86 exported-UAPI input
  header-abi-reference  verify the pinned x86 SysV LP64/x87 header baseline
  public-header-surface  inventory all pinned x86 public headers for C consumability
  candidate-header-closure  require isolated C11/C++17 public-header include closure
  uapi-wrapper-matrix  verify the selected Linux 5.10 UAPI wrapper C/C++ ABI profile matrix
  epoll-header-abi  verify the selected x86 packed sys/epoll.h C/C++ ABI profile matrix
  ioctl-header-abi  verify selected direct sys/ioctl.h C/C++ ABI profile matrix
  timeval-transitive-header-abi  verify selected timeval-dependent header layouts across C/C++ profiles
  sys-time-direct-header-abi  verify selected direct sys/time.h C/C++ ABI profiles and C linkage
  access-header-abi  verify selected direct unistd/fcntl access C/C++ ABI profiles and C linkage
  header-abi-project  compile the staged crabc x86 fenv/float header slice
  math-complex-header-abi  verify x86 math/complex/tgmath C/C++ header semantics
  sys-reg-header-abi  compile the staged crabc x86 ptrace-register header slice
  types-header-abi  compile the staged crabc x86 C/C++ type-layout header slice
  stat-header-abi  compile the staged x86 C/C++ sys/stat header layouts
  utime-header-abi  compile the staged x86 C/C++ utime header ABI/linkage slice
  pthread-c11-header-abi  verify staged x86 pthread/C11-thread C/C++ header ABI profiles
  ctype-header-abi  compile the staged x86 C/C++ ctype declarations
  integer-arithmetic-header-abi  compile the staged x86 C/C++ stdlib integer-arithmetic declarations
  integer-parse-header-abi  compile the staged x86 C/C++ integer-parsing declarations
  intmax-arithmetic-header-abi  compile the staged x86 C/C++ inttypes intmax-arithmetic declarations
  credential-observation-header-abi  compile the staged x86 C/C++ unistd credential-observation declarations
  child-reaping-header-abi  compile the staged x86 C/C++ sys/wait child-reaping declarations
  immediate-termination-header-abi  compile the staged x86 C/C++ stdlib immediate-termination declaration
  callback-algorithms-header-abi  compile the staged x86 C/C++ stdlib callback-algorithm declarations
  ffs-header-abi  compile the staged x86 C/C++ strings.h find-first-set declarations
  byte-strings-header-abi  compile the staged x86 C/C++ string.h byte-string declarations
  memory-search-header-abi  compile the staged x86 C/C++ memory-search declarations
  string-copy-header-abi  compile the staged x86 C/C++ C-string-copy declarations
  random-entropy-header-abi  compile the staged x86 C/C++ random-source declarations
  time-header-abi  compile the staged x86 C/C++ time header layouts
  poll-header-abi  compile the staged x86 C/C++ poll header layouts
  select-header-abi  compile the staged x86 C/C++ sys/select header layouts
  fcntl-header-abi compile the staged x86 C/C++ fcntl header layouts
  unistd-header-abi  compile the staged x86 C/C++ unistd header declarations
  system-header-abi  compile the staged x86 C/C++ system header layouts
  syscall-header-abi  compare the staged x86 syscall macro surface with musl
  signal-header-abi  compile the staged x86 GNU/POSIX signal-header layouts
  termios-header-abi  compile the staged x86 C/C++ GNU termios-header layouts
  mman-header-abi  compile the staged x86 C/C++ mapping-header declarations
  resource-header-abi  compile the staged x86 C/C++ resource-header layouts
  socket-header-abi  verify staged x86 base socket C/C++ declarations/layouts and IPv6 macros
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
  core   run the native x86_64-unknown-linux-musl crabc-core lib tests
  facade run the bounded native x86_64 crabc-rs direct-facade tests
  facade-record-owning  run the closed native x86_64 record-owning facade aggregate
  libc-syscall  run the isolated x86 C-ABI syscall register probe
  libc-errno-tls  run the source-only x86 C errno/initial-TLS probe
  libc-stat-compat  run the static x86 crabc-libc stat/errno compatibility slice
  libc-credentials  run the static x86 crabc-libc credential/errno compatibility slice
  libc-bootstrap-primitives  run the static x86 crabc-libc memory/fenv/setjmp slice
  libc-signal-control  run the static x86 crabc-libc simple signal action/mask slice
  libc-signal-execution  run the static x86 crabc-libc process-signal execution slice
  libc-static-tls-v1  run the static x86 crabc-libc initial TLS template slice
  libc-crt-static-tls  run the real x86 rcrt1-to-libc static TLS composition slice
  libc-pthread-create-join-tls  run the static x86 crabc-libc private create/exit/join TLS slice
  libc-pthread-identity  run the static x86 crabc-libc pthread/C11 identity alias slice
  libc-c11-lifecycle  run the static x86 crabc-libc bounded C11 lifecycle slice
  libc-pthread-detach  run the static x86 crabc-libc bounded pthread/C11 detach slice
  libc-thrd-sleep  run the static x86 crabc-libc bounded C11 thrd_sleep slice
  libc-termios-control  run the static x86 crabc-libc termios-control slice
  libc-process-context  run the static x86 crabc-libc selected process-context slice
  libc-child-reaping  run the static x86 crabc-libc child-reaping slice
  libc-immediate-termination  run the static x86 crabc-libc C11 immediate-termination slice
  libc-callback-algorithms  run the static x86 crabc-libc callback-algorithms slice
  libc-access  run the static x86 crabc-libc access/faccessat slice
  libc-clock-gettime  run the static x86 crabc-libc clock_gettime slice
  libc-system-configuration  run the static x86 crabc-libc system-configuration slice
  libc-mapping-core  run the static x86 crabc-libc caller-owned mapping-core slice
  libc-header-layouts-baseline  run the static x86 crabc-libc C/C++ header/layout baseline
  libc-nanosleep  run the static x86 crabc-libc nanosleep slice
  libc-clock-nanosleep  run the static x86 crabc-libc clock_nanosleep slice
  libc-descriptor-entry  run the static x86 crabc-libc descriptor-entry slice
  libc-descriptor-lifecycle  run the static x86 crabc-libc descriptor lifecycle composition
  libc-timestamp-updates  run the static x86 rcrt1/libc timestamp-update block
  libc-fcntl-status-control  run the static x86 crabc-libc fcntl status-control slice
  libc-ioctl  run the static x86 crabc-libc generic ioctl slice
  libc-descriptor-io  run the static x86 crabc-libc selected descriptor-I/O slice
  libc-process-resources  run the static x86 crabc-libc selected resource slice
  libc-readiness-waits  run the static x86 crabc-libc readiness/signal-waits slice
  libc-system-observation  run the static x86 crabc-libc uname/sysinfo slice
  libc-uts-identity  run the static x86 crabc-libc hostname/domain identity slice
  libc-ctype  run the static x86 crabc-libc C-locale ctype slice
  libc-integer-arithmetic  run the static x86 crabc-libc integer-arithmetic slice
  libc-integer-parse  run the static x86 crabc-libc integer-parsing slice
  libc-intmax-arithmetic  run the static x86 crabc-libc intmax-arithmetic slice
  libc-credential-observation  run the static x86 crabc-libc credential-observation slice
  libc-ffs  run the static x86 crabc-libc find-first-set slice
  libc-byte-strings  run the static x86 crabc-libc byte-string slice
  libc-random-entropy  run the static x86 crabc-libc random-entropy slice
  libc-memory-search  run the static x86 crabc-libc memory-search slice
  libc-string-copy  run the static x86 crabc-libc C-string-copy slice
  libc-socket-transport  run the static x86 crabc-libc base socket transport slice
  libc-thread-pointer  run the source-only x86 opaque %fs:0 thread-pointer probe
  libc-foundation  run the source-only x86 C runtime primitive-composition probe
  libc-fenv  run the source-only x86 C x87/MXCSR floating-point-environment probe
  libc-math-complex  run the static x86 long-double/complex ABI foundation
  libc-memory  run the source-only x86 C memcpy/memmove/memset probe
  libc-setjmp  run the source-only x86 C setjmp/signal-mask ABI probe
  libc-atomic  run the source-only x86 atomic-helper probe
  libc-clone-raw  run the source-only x86 musl-shaped raw clone probe
  libc-signal-foundation  run the source-only x86 signal-action packing probe
  ldso-relocation  run the source-only checked x86 RELA/RELR foundation tests
  ldso-image  run the source-only checked x86 ELF image parser tests
  ldso-initial-graph  run the bounded x86 ET_DYN initial-interpreter graph artifact

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
`tgkill`, alt stacks, signalfd, legacy signal APIs, pthread signal policy,
dynamic libc, or application startup. `libc-static-tls-v1` passes a real
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
separately recorded C11 sleep artifact, `thrd_yield`, synchronization, TSS, cancellation, dynamic TLS, CRT,
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
does not select `thrd_yield`, cancellation cleanup, C11
lifecycle/synchronization/TSS, dynamic TLS, CRT, loader, sysroot,
C11-family completion, or public x86 support.
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
public x86 support. `libc-process-resources`
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
`sys-reg-header-abi` compiles only the staged ptrace register-index header.
`types-header-abi` compiles only staged C/C++ type declarations and opaque
pthread object layouts. `stat-header-abi`, `time-header-abi`, `poll-header-abi`,
`select-header-abi`, `fcntl-header-abi`, `ioctl-header-abi`, `unistd-header-abi`, and
`system-header-abi` compile only their named C/C++ layout/declaration slices.
`syscall-header-abi` compares only staged syscall number macros.
`signal-header-abi`, `termios-header-abi`, `mman-header-abi`, and
`resource-header-abi` compile only their named staged signal-frame, GNU
termios, mapping, and strict/GNU/LFS resource declarations.
`termios-header-abi` remains a header-only C/C++ layout/declaration gate, not
a general C terminal/runtime claim. `resource-header-abi` is likewise
header-only and does not select process-resource behavior or a C runtime.
`socket-header-abi` compile-checks only staged C/C++ base transport
declarations, `socklen_t` and generic/IPv4/IPv6 socket-address layouts, and
creation, shutdown, and basic send/receive constants, then executes the
installed IPv6 address-classification macros through project and pinned-musl
headers. It does not select socket options, vectored or ancillary-message
APIs, address-conversion or socket behavior, a C runtime, or a general socket
capability.
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
`libc-child-reaping` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
`wait`, `waitpid`, and `waitid`; raw clone/pipe fixture control fixes the
`WNOHANG` no-event, `WNOWAIT` observation, exact reap, and post-reap `ECHILD`
states without selecting C fork/exec or a general process supervisor. It
deliberately omits musl pthread-cancellation and atfork machinery, dynamic
libc, CRT/TLS lifecycle, loader, sysroot, and public x86 support.
`libc-immediate-termination` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
C11 `_Exit`: fixture-local raw clone/wait observes its exact child status,
without ordinary exit, quick-exit hooks, stdio/fini processing, fork
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
It does not select `msync` cancellation, `mremap`, `mlock*`, shared memory,
allocator, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
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
pthread-cancellation path. It does not select sleep/usleep, C clocks/timers,
signal policy, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
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
this does not select path policy, a filesystem capability, `fchmodat`/`lchmod`,
C credential/process APIs, cancellation, dynamic runtime, or public x86
support.
`libc-fcntl-status-control` links that archive into a separate freestanding
project-header C fixture after an equivalent pinned-musl run. It selects only
the public `fcntl` status/descriptor-flag commands `F_GETFD`, `F_SETFD`,
`F_GETFL`, and `F_SETFL`: legal absent-vararg and scalar-vararg dispatch,
musl's O_LARGEFILE rule, descriptor-local CLOEXEC, shared status state, and
direct errno results. Every other command returns the explicit selected-profile
`EINVAL` result without reading a vararg or issuing a syscall. It does not
provide generic fcntl, locking, descriptor lifecycle, filesystem policy,
cancellation, dynamic libc, CRT/TLS lifecycle, loader, sysroot, or public x86
support.
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
only x87 long-double classification/sign and C99 real/imaginary accessor plus
conjugation ABI symbols; scalar math, cabs/carg/cproj, complex powers or
transcendentals, libm, libc.so, CRT/TLS lifecycle, loader, sysroot, and public
x86 support remain outside the artifact.
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
None of the other C-runtime commands is a crabc-libc or crabc-ldso build,
general facade admission, or C ABI support claim.
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

# Only the process-root-change evidence needs this privilege. Keeping it off
# the shared runner makes each additional authority explicit at its one call
# site rather than widening every native x86 command.
run_in_chroot_cap_container() {
    docker run --rm --init \
        --platform "$PLATFORM" \
        --cap-add=SYS_CHROOT \
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

# Only the UTS-identity artifact needs SYS_ADMIN, solely to create a fresh UTS
# namespace before its fixture changes hostname/domain-name state. Keeping this
# grant off the shared runner and all other artifact commands does not select a
# general namespace-management capability.
run_in_uts_cap_container() {
    docker run --rm --init \
        --platform "$PLATFORM" \
        --cap-add=SYS_ADMIN \
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

run_uapi_wrapper_matrix() {
    run_in_container bash /workspace/compat/x86_64/run_uapi_wrapper_matrix.sh
}

run_epoll_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_epoll_header_abi.sh
}

run_ioctl_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ioctl_header_abi.sh
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

run_header_abi_project() {
    run_in_container bash /workspace/compat/x86_64/run_project_header_abi.sh
}

run_math_complex_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_math_complex_header_abi.sh
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

run_utime_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_utime_header_abi.sh
}

run_pthread_c11_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_pthread_c11_header_abi.sh
}

run_ctype_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ctype_header_abi.sh
}

run_integer_arithmetic_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_integer_arithmetic_header_abi.sh
}

run_integer_parse_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_integer_parse_header_abi.sh
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

run_child_reaping_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_child_reaping_header_abi.sh
}

run_immediate_termination_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_immediate_termination_header_abi.sh
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

run_libc_immediate_termination() {
    run_in_container bash /workspace/compat/x86_64/run_libc_immediate_termination.sh
}

run_libc_callback_algorithms() {
    run_in_container bash /workspace/compat/x86_64/run_libc_callback_algorithms.sh
}

run_libc_access() {
    run_in_container bash /workspace/compat/x86_64/run_libc_access.sh
}

run_libc_clock_gettime() {
    run_in_container bash /workspace/compat/x86_64/run_libc_clock_gettime.sh
}

run_libc_system_configuration() {
    run_in_container bash /workspace/compat/x86_64/run_libc_system_configuration.sh
}

run_libc_mapping_core() {
    run_in_container bash /workspace/compat/x86_64/run_libc_mapping_core.sh
}

run_libc_header_layouts_baseline() {
    run_in_container bash /workspace/compat/x86_64/run_libc_header_layouts_baseline.sh
}

run_libc_nanosleep() {
    run_in_container bash /workspace/compat/x86_64/run_libc_nanosleep.sh
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

run_ffs_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_ffs_header_abi.sh
}

run_byte_strings_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_byte_strings_header_abi.sh
}

run_memory_search_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_memory_search_header_abi.sh
}

run_string_copy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_string_copy_header_abi.sh
}

run_random_entropy_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_random_entropy_header_abi.sh
}

run_time_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_time_header_abi.sh
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

run_termios_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_termios_header_abi.sh
}

run_mman_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_mman_header_abi.sh
}

run_resource_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_resource_header_abi.sh
}

run_socket_header_abi() {
    run_in_container bash /workspace/compat/x86_64/run_socket_header_abi.sh
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
    # descriptor forms. It intentionally excludes statx, file-handle xattrs,
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
        probe=/tmp/crabc-x86-libc-syscall-probe
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

run_libc_signal_execution_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_signal_execution.sh
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

run_libc_pthread_detach_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_pthread_detach.sh
}

run_libc_thrd_sleep_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_thrd_sleep.sh
}

run_libc_static_tls_v1_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_static_tls_v1.sh
}

run_libc_crt_static_tls_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_crt_static_tls.sh
}

run_libc_termios_control_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_termios_control.sh
}

run_libc_process_context_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_process_context.sh
}

run_libc_descriptor_io_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_io.sh
}

run_libc_descriptor_lifecycle_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_descriptor_lifecycle.sh
}

run_libc_timestamp_updates_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_timestamp_updates.sh
}

run_libc_process_resources_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_process_resources.sh
}

run_libc_readiness_waits_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_readiness_waits.sh
}

run_libc_system_observation_probe() {
    run_in_container bash /workspace/compat/x86_64/run_libc_system_observation.sh
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

run_ldso_initial_graph_tests() {
    run_in_container bash /workspace/compat/x86_64/run_ldso_initial_graph.sh
}

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 2
fi

command="$1"
shift

case "$command" in
    image|musl-oracle|header-abi-reference|public-header-surface|header-abi-project|math-complex-header-abi|sys-reg-header-abi|types-header-abi|stat-header-abi|utime-header-abi|pthread-c11-header-abi|time-header-abi|poll-header-abi|select-header-abi|fcntl-header-abi|ioctl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|termios-header-abi|mman-header-abi|resource-header-abi|socket-header-abi|random-entropy-header-abi|mm-abi-reference|mapping-reference|memory-vm-reference|pty-basic-reference|terminal-reference|mlock-reference|msync-reference|mincore-reference|fs-advice-reference|memfd-reference|ftruncate-reference|statfs-reference|timestamp-reference|path-lifecycle-reference|namespace-reference|path-core-reference|xattr-reference|directory-reference|temporary-object-reference|statx-reference|cwd-canonicalize-reference|root-change-reference|mount-reference|thread-kill-reference|ipc-reference|shm-reference|inotify-reference|socket-transport-reference|interface-device-reference|resolver-transport-reference|resolver-facade-reference|netdb-reference|users-databases-reference|posix-fallocate-reference|fallocate-reference|file-position-reference|sync-reference|syncfs-reference|sync-file-range-reference|rand-reference|time-abi-reference|time-observation-reference|calendar-time-reference|advanced-time-reference|relative-sleep-reference|clock-nanosleep-reference|getitimer-reference|setitimer-reference|timerfd-reference|pselect-reference|poll-reference|ppoll-reference|epoll-reference|process-identity-reference|child-ownership-reference|getgroups-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|fcntl-status-reference|flock-reference|sendfile-reference|copy-file-range-reference|scheduler-priority-bounds-reference|rr-interval-reference|sched-affinity-reference|sched-affinity-set-reference|priority-reference|setpriority-reference|rlimit-reference|rlimit-targeted-reference|setrlimit-reference|umask-reference|rusage-reference|times-reference|fstat-reference|statat-reference|getcwd-reference|readlinkat-reference|access-reference|system-reference|thread-reference|thread-credentials-reference|fs-credentials-reference|core|facade|facade-record-owning|libc-syscall|libc-errno-tls|libc-stat-compat|libc-credentials|libc-bootstrap-primitives|libc-signal-control|libc-signal-execution|libc-static-tls-v1|libc-crt-static-tls|libc-pthread-create-join-tls|libc-c11-lifecycle|libc-thrd-sleep|libc-termios-control|libc-process-context|libc-descriptor-io|libc-descriptor-lifecycle|libc-timestamp-updates|libc-process-resources|libc-socket-transport|libc-thread-pointer|libc-foundation|libc-fenv|libc-math-complex|libc-memory|libc-setjmp|libc-atomic|libc-clone-raw|libc-signal-foundation|ldso-relocation|ldso-image|ldso-initial-graph) ;;
    linux-5-10-uapi) ;;
    candidate-header-closure) ;;
    uapi-wrapper-matrix) ;;
    epoll-header-abi) ;;
    timeval-transitive-header-abi) ;;
    sys-time-direct-header-abi) ;;
    access-header-abi) ;;
    madvise-reference) ;;
    ctype-header-abi) ;;
    integer-arithmetic-header-abi|integer-parse-header-abi|intmax-arithmetic-header-abi|credential-observation-header-abi|child-reaping-header-abi|immediate-termination-header-abi|callback-algorithms-header-abi) ;;
    ffs-header-abi) ;;
    byte-strings-header-abi) ;;
    memory-search-header-abi) ;;
    string-copy-header-abi) ;;
    random-entropy-header-abi) ;;
    libc-pthread-identity) ;;
    libc-pthread-detach) ;;
    libc-readiness-waits|libc-system-observation|libc-uts-identity|libc-ctype|libc-integer-arithmetic|libc-integer-parse|libc-intmax-arithmetic|libc-credential-observation|libc-child-reaping|libc-immediate-termination|libc-callback-algorithms|libc-access|libc-clock-gettime|libc-system-configuration|libc-mapping-core|libc-header-layouts-baseline|libc-nanosleep|libc-clock-nanosleep|libc-descriptor-entry|libc-fcntl-status-control|libc-ioctl|libc-ffs|libc-byte-strings|libc-random-entropy|libc-memory-search|libc-string-copy) ;;
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
    ioctl-header-abi)
        [ "$#" -eq 0 ] || fail "ioctl-header-abi takes no arguments"
        ensure_image
        run_ioctl_header_abi
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
    ctype-header-abi)
        [ "$#" -eq 0 ] || fail "ctype-header-abi takes no arguments"
        ensure_image
        run_ctype_header_abi
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
    child-reaping-header-abi)
        [ "$#" -eq 0 ] || fail "child-reaping-header-abi takes no arguments"
        ensure_image
        run_child_reaping_header_abi
        ;;
    immediate-termination-header-abi)
        [ "$#" -eq 0 ] || fail "immediate-termination-header-abi takes no arguments"
        ensure_image
        run_immediate_termination_header_abi
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
    string-copy-header-abi)
        [ "$#" -eq 0 ] || fail "string-copy-header-abi takes no arguments"
        ensure_image
        run_string_copy_header_abi
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
    termios-header-abi)
        [ "$#" -eq 0 ] || fail "termios-header-abi takes no arguments"
        ensure_image
        run_termios_header_abi
        ;;
    mman-header-abi)
        [ "$#" -eq 0 ] || fail "mman-header-abi takes no arguments"
        ensure_image
        run_mman_header_abi
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
        [ "$#" -eq 0 ] || fail "core takes no arguments"
        ensure_image
        run_core_tests
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
    libc-signal-execution)
        [ "$#" -eq 0 ] || fail "libc-signal-execution takes no arguments"
        ensure_image
        run_libc_signal_execution_probe
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
    libc-termios-control)
        [ "$#" -eq 0 ] || fail "libc-termios-control takes no arguments"
        ensure_image
        run_libc_termios_control_probe
        ;;
    libc-process-context)
        [ "$#" -eq 0 ] || fail "libc-process-context takes no arguments"
        ensure_image
        run_libc_process_context_probe
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
    libc-process-resources)
        [ "$#" -eq 0 ] || fail "libc-process-resources takes no arguments"
        ensure_image
        run_libc_process_resources_probe
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
    libc-immediate-termination)
        [ "$#" -eq 0 ] || fail "libc-immediate-termination takes no arguments"
        ensure_image
        run_libc_immediate_termination
        ;;
    libc-callback-algorithms)
        [ "$#" -eq 0 ] || fail "libc-callback-algorithms takes no arguments"
        ensure_image
        run_libc_callback_algorithms
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
    libc-system-configuration)
        [ "$#" -eq 0 ] || fail "libc-system-configuration takes no arguments"
        ensure_image
        run_libc_system_configuration
        ;;
    libc-mapping-core)
        [ "$#" -eq 0 ] || fail "libc-mapping-core takes no arguments"
        ensure_image
        run_libc_mapping_core
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
    libc-ffs)
        [ "$#" -eq 0 ] || fail "libc-ffs takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_ffs.sh
        ;;
    libc-byte-strings)
        [ "$#" -eq 0 ] || fail "libc-byte-strings takes no arguments"
        ensure_image
        run_in_container bash /workspace/compat/x86_64/run_libc_byte_strings.sh
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
    libc-math-complex)
        [ "$#" -eq 0 ] || fail "libc-math-complex takes no arguments"
        ensure_image
        run_libc_math_complex_probe
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
esac
