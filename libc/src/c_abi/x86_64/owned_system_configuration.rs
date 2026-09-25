//! Owned Linux/x86-64 C system-configuration boundary.
//!
//! This aggregate-only module retains the frozen configuration block
//! (`confstr`, `pathconf`, `fpathconf`, `getpagesize`, `getdtablesize`) and
//! ports musl's complete `sysconf` table for the installed products. The
//! frozen `system_configuration.rs` remains selected outside the owned
//! runtime with its original fixed selectors; this file cannot widen that
//! earlier archive. It borrows the already-owned immutable auxv observation,
//! the processor/page-count leaf in `system_information.rs`, and initial-TLS
//! C `errno` publication, but owns neither startup nor signal-stack storage.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/conf/sysconf.c` maps to [`sysconf`] and its [`SYSCONF_VALUES`]
//!   table, entry for entry with the source's `short` encoding: direct
//!   values, `RLIM()` resource selectors, and `JT()` jump-table cases. Its
//!   processor cases share `system_information::nprocs`, its page cases
//!   `system_information::page_count`, and its signal-stack cases
//!   [`minimum_signal_stack_size`] and [`signal_stack_size`]. The source's
//!   `name >= sizeof values` test compares a converted `size_t`, so negative
//!   selectors are `EINVAL` like every absent or zero entry.
//! - `src/conf/confstr.c` maps to [`confstr`].
//! - `src/conf/fpathconf.c` maps to [`fpathconf`]'s deliberate
//!   fd-independent selector table. The selected positive selector boundary is
//!   0 through 20 plus the defined nonnegative out-of-range `EINVAL` result;
//!   musl's unchecked negative C-array index remains outside differential admission.
//! - `src/conf/pathconf.c` maps to [`pathconf`], which delegates to that
//!   `fpathconf(-1, name)` table without dereferencing its pathname. Its
//!   selected positive-selector boundary is therefore also 0 through 20 plus
//!   the defined nonnegative out-of-range `EINVAL` result; the delegated
//!   unchecked negative C-array index remains outside differential admission.
//! - `src/legacy/getpagesize.c` maps to [`getpagesize`].
//! - `src/legacy/getdtablesize.c` maps to [`getdtablesize`].
//!
//! Linux/x86-64's base page size is architecturally 4096.
//! The signal-stack selectors require only the installed runtime's existing
//! validated initial-auxv publication. Linux 5.10 x86 does not emit
//! `AT_MINSIGSTKSZ`: upstream kernel commit
//! `1c33bb0507508af24fd754dd7123bd8e997fab2f` added x86 emission in Linux
//! 5.14. On the baseline, musl's `__getauxval` source returns zero and sets
//! `ENOENT`; `sysconf.c` then applies its clamp. That observable absence route
//! is required source behavior, not a project fallback.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};

use super::{auxv_observation, c_status, errno, raw_syscall, system_information};

const EINVAL: c_int = 22;

const AT_MINSIGSTKSZ: c_ulong = 51;
const MINSIGSTKSZ: c_uint = 2_048;
const SIGSTKSZ: c_uint = 8_192;

const CS_PATH: c_int = 0;
const CS_POSIX_V6_WIDTH_RESTRICTED_ENVS: c_int = 1;
const CS_POSIX_V7_WIDTH_RESTRICTED_ENVS: c_int = 5;
const CS_POSIX_V6_ILP32_OFF32_CFLAGS: c_int = 1116;
const CS_POSIX_V7_THREADS_LDFLAGS: c_int = 1151;

const PC_LINK_MAX: c_int = 0;
const PC_MAX_CANON: c_int = 1;
const PC_MAX_INPUT: c_int = 2;
const PC_NAME_MAX: c_int = 3;
const PC_PATH_MAX: c_int = 4;
const PC_PIPE_BUF: c_int = 5;
const PC_CHOWN_RESTRICTED: c_int = 6;
const PC_NO_TRUNC: c_int = 7;
const PC_VDISABLE: c_int = 8;
const PC_SYNC_IO: c_int = 9;
const PC_ASYNC_IO: c_int = 10;
const PC_PRIO_IO: c_int = 11;
const PC_SOCK_MAXBUF: c_int = 12;
const PC_FILESIZEBITS: c_int = 13;
const PC_REC_INCR_XFER_SIZE: c_int = 14;
const PC_REC_MAX_XFER_SIZE: c_int = 15;
const PC_REC_MIN_XFER_SIZE: c_int = 16;
const PC_REC_XFER_ALIGN: c_int = 17;
const PC_ALLOC_SIZE_MIN: c_int = 18;
const PC_SYMLINK_MAX: c_int = 19;
const PC_2_SYMLINKS: c_int = 20;

const RLIMIT_NPROC: c_int = 6;
const RLIMIT_NOFILE: c_int = 7;
const RLIM_INFINITY: c_ulong = !0;
/// Linux/x86-64's fixed 4 KiB base page is shared with the separate selected
/// system-information leaf. It is an architectural x86 fact, not an auxv or
/// C startup dependency.
pub(super) const X86_64_LINUX_PAGE_SIZE: c_int = 4096;

/// Exact x86 public `struct rlimit` storage needed by `getdtablesize`.
///
/// The existing selected process-resources artifact owns the public C resource
/// boundary. This local private record retains the same LP64 kernel layout so
/// this configuration block can remain one closed archive artifact rather than
/// coupling to a broader process-resource API.
#[repr(C)]
struct Rlimit {
    current: c_ulong,
    maximum: c_ulong,
}

const _: () = {
    assert!(size_of::<Rlimit>() == 16);
    assert!(align_of::<Rlimit>() == 8);
    assert!(offset_of!(Rlimit, current) == 0);
    assert!(offset_of!(Rlimit, maximum) == 8);
};

/// Return musl's minimum alternate-signal-stack size.
///
/// `sysconf.c` first takes the kernel-provided signal-frame size from the
/// validated initial auxv, clamps it to one KiB below the public historical
/// minimum, and adds one KiB of application working space. The source stores
/// its result in C `unsigned`; keep that x86 32-bit wrap boundary explicit.
/// Linux 5.10 x86 lacks `AT_MINSIGSTKSZ`, so the sibling musl-compatible
/// [`auxv_observation::__getauxval`] returns zero and publishes `ENOENT`; the
/// clamp then yields the historical minimum. Linux 5.14 and later x86 kernels
/// can supply the larger frame value. Deliberately retain the lookup's errno
/// side effect rather than adding a second auxv owner or a fallback branch.
pub(super) fn minimum_signal_stack_size() -> usize {
    // SAFETY: the installed static/dynamic startup has already published its
    // validated immutable auxiliary vector before calling public C code.
    let mut signal_frame_size = unsafe { auxv_observation::__getauxval(AT_MINSIGSTKSZ) };
    let floor = c_ulong::from(MINSIGSTKSZ - 1_024);
    if signal_frame_size < floor {
        signal_frame_size = floor;
    }
    (signal_frame_size as c_uint).wrapping_add(1_024) as usize
}

/// Return musl's default alternate-signal-stack size.
pub(super) fn signal_stack_size() -> usize {
    (minimum_signal_stack_size() as c_uint)
        .wrapping_add(SIGSTKSZ - MINSIGSTKSZ) as usize
}

// Musl's `sysconf.c` `short` table encoding. Values of -1 and above are
// returned directly and zero marks an absent selector. `RLIM(x)` sets bit
// 15 above a resource number; `JT(x)` names a computed case in the low byte.
const fn jt(case: i16) -> i16 {
    -256 | case
}
const fn rlim(resource: c_int) -> i16 {
    -32768 | resource as i16
}
const VER: i16 = jt(1);
const JT_ARG_MAX: i16 = jt(2);
const JT_MQ_PRIO_MAX: i16 = jt(3);
const JT_PAGE_SIZE: i16 = jt(4);
const JT_SEM_VALUE_MAX: i16 = jt(5);
const JT_NPROCESSORS_CONF: i16 = jt(6);
const JT_NPROCESSORS_ONLN: i16 = jt(7);
const JT_PHYS_PAGES: i16 = jt(8);
const JT_AVPHYS_PAGES: i16 = jt(9);
const JT_ZERO: i16 = jt(10);
const JT_DELAYTIMER_MAX: i16 = jt(11);
const JT_MINSIGSTKSZ: i16 = jt(12);
const JT_SIGSTKSZ: i16 = jt(13);

// Musl 1.2.6 `<limits.h>`/`<unistd.h>` values returned by the jump table.
const POSIX_VERSION: c_long = 200_809;
const ARG_MAX: c_long = 131_072;
const MQ_PRIO_MAX: c_long = 32_768;
const SEM_VALUE_MAX: c_long = 0x7fff_ffff;
const DELAYTIMER_MAX: c_long = 0x7fff_ffff;

// Musl 1.2.6 `<unistd.h>` selector numbers named by the source table.
const SC_ARG_MAX: usize = 0;
const SC_CHILD_MAX: usize = 1;
const SC_CLK_TCK: usize = 2;
const SC_NGROUPS_MAX: usize = 3;
const SC_OPEN_MAX: usize = 4;
const SC_STREAM_MAX: usize = 5;
const SC_TZNAME_MAX: usize = 6;
const SC_JOB_CONTROL: usize = 7;
const SC_SAVED_IDS: usize = 8;
const SC_REALTIME_SIGNALS: usize = 9;
const SC_PRIORITY_SCHEDULING: usize = 10;
const SC_TIMERS: usize = 11;
const SC_ASYNCHRONOUS_IO: usize = 12;
const SC_PRIORITIZED_IO: usize = 13;
const SC_SYNCHRONIZED_IO: usize = 14;
const SC_FSYNC: usize = 15;
const SC_MAPPED_FILES: usize = 16;
const SC_MEMLOCK: usize = 17;
const SC_MEMLOCK_RANGE: usize = 18;
const SC_MEMORY_PROTECTION: usize = 19;
const SC_MESSAGE_PASSING: usize = 20;
const SC_SEMAPHORES: usize = 21;
const SC_SHARED_MEMORY_OBJECTS: usize = 22;
const SC_AIO_LISTIO_MAX: usize = 23;
const SC_AIO_MAX: usize = 24;
const SC_AIO_PRIO_DELTA_MAX: usize = 25;
const SC_DELAYTIMER_MAX: usize = 26;
const SC_MQ_OPEN_MAX: usize = 27;
const SC_MQ_PRIO_MAX: usize = 28;
const SC_VERSION: usize = 29;
const SC_PAGE_SIZE: usize = 30;
const SC_RTSIG_MAX: usize = 31;
const SC_SEM_NSEMS_MAX: usize = 32;
const SC_SEM_VALUE_MAX: usize = 33;
const SC_SIGQUEUE_MAX: usize = 34;
const SC_TIMER_MAX: usize = 35;
const SC_BC_BASE_MAX: usize = 36;
const SC_BC_DIM_MAX: usize = 37;
const SC_BC_SCALE_MAX: usize = 38;
const SC_BC_STRING_MAX: usize = 39;
const SC_COLL_WEIGHTS_MAX: usize = 40;
const SC_EXPR_NEST_MAX: usize = 42;
const SC_LINE_MAX: usize = 43;
const SC_RE_DUP_MAX: usize = 44;
const SC_2_VERSION: usize = 46;
const SC_2_C_BIND: usize = 47;
const SC_2_C_DEV: usize = 48;
const SC_2_FORT_DEV: usize = 49;
const SC_2_FORT_RUN: usize = 50;
const SC_2_SW_DEV: usize = 51;
const SC_2_LOCALEDEF: usize = 52;
const SC_IOV_MAX: usize = 60;
const SC_THREADS: usize = 67;
const SC_THREAD_SAFE_FUNCTIONS: usize = 68;
const SC_GETGR_R_SIZE_MAX: usize = 69;
const SC_GETPW_R_SIZE_MAX: usize = 70;
const SC_LOGIN_NAME_MAX: usize = 71;
const SC_TTY_NAME_MAX: usize = 72;
const SC_THREAD_DESTRUCTOR_ITERATIONS: usize = 73;
const SC_THREAD_KEYS_MAX: usize = 74;
const SC_THREAD_STACK_MIN: usize = 75;
const SC_THREAD_THREADS_MAX: usize = 76;
const SC_THREAD_ATTR_STACKADDR: usize = 77;
const SC_THREAD_ATTR_STACKSIZE: usize = 78;
const SC_THREAD_PRIORITY_SCHEDULING: usize = 79;
const SC_THREAD_PRIO_INHERIT: usize = 80;
const SC_THREAD_PRIO_PROTECT: usize = 81;
const SC_THREAD_PROCESS_SHARED: usize = 82;
const SC_NPROCESSORS_CONF: usize = 83;
const SC_NPROCESSORS_ONLN: usize = 84;
const SC_PHYS_PAGES: usize = 85;
const SC_AVPHYS_PAGES: usize = 86;
const SC_ATEXIT_MAX: usize = 87;
const SC_PASS_MAX: usize = 88;
const SC_XOPEN_VERSION: usize = 89;
const SC_XOPEN_XCU_VERSION: usize = 90;
const SC_XOPEN_UNIX: usize = 91;
const SC_XOPEN_CRYPT: usize = 92;
const SC_XOPEN_ENH_I18N: usize = 93;
const SC_XOPEN_SHM: usize = 94;
const SC_2_CHAR_TERM: usize = 95;
const SC_2_UPE: usize = 97;
const SC_XOPEN_XPG2: usize = 98;
const SC_XOPEN_XPG3: usize = 99;
const SC_XOPEN_XPG4: usize = 100;
const SC_NZERO: usize = 109;
const SC_XBS5_ILP32_OFF32: usize = 125;
const SC_XBS5_ILP32_OFFBIG: usize = 126;
const SC_XBS5_LP64_OFF64: usize = 127;
const SC_XBS5_LPBIG_OFFBIG: usize = 128;
const SC_XOPEN_LEGACY: usize = 129;
const SC_XOPEN_REALTIME: usize = 130;
const SC_XOPEN_REALTIME_THREADS: usize = 131;
const SC_ADVISORY_INFO: usize = 132;
const SC_BARRIERS: usize = 133;
const SC_CLOCK_SELECTION: usize = 137;
const SC_CPUTIME: usize = 138;
const SC_THREAD_CPUTIME: usize = 139;
const SC_MONOTONIC_CLOCK: usize = 149;
const SC_READER_WRITER_LOCKS: usize = 153;
const SC_SPIN_LOCKS: usize = 154;
const SC_REGEXP: usize = 155;
const SC_SHELL: usize = 157;
const SC_SPAWN: usize = 159;
const SC_SPORADIC_SERVER: usize = 160;
const SC_THREAD_SPORADIC_SERVER: usize = 161;
const SC_TIMEOUTS: usize = 164;
const SC_TYPED_MEMORY_OBJECTS: usize = 165;
const SC_2_PBS: usize = 168;
const SC_2_PBS_ACCOUNTING: usize = 169;
const SC_2_PBS_LOCATE: usize = 170;
const SC_2_PBS_MESSAGE: usize = 171;
const SC_2_PBS_TRACK: usize = 172;
const SC_SYMLOOP_MAX: usize = 173;
const SC_STREAMS: usize = 174;
const SC_2_PBS_CHECKPOINT: usize = 175;
const SC_V6_ILP32_OFF32: usize = 176;
const SC_V6_ILP32_OFFBIG: usize = 177;
const SC_V6_LP64_OFF64: usize = 178;
const SC_V6_LPBIG_OFFBIG: usize = 179;
const SC_HOST_NAME_MAX: usize = 180;
const SC_TRACE: usize = 181;
const SC_TRACE_EVENT_FILTER: usize = 182;
const SC_TRACE_INHERIT: usize = 183;
const SC_TRACE_LOG: usize = 184;
const SC_IPV6: usize = 235;
const SC_RAW_SOCKETS: usize = 236;
const SC_V7_ILP32_OFF32: usize = 237;
const SC_V7_ILP32_OFFBIG: usize = 238;
const SC_V7_LP64_OFF64: usize = 239;
const SC_V7_LPBIG_OFFBIG: usize = 240;
const SC_SS_REPL_MAX: usize = 241;
const SC_TRACE_EVENT_NAME_MAX: usize = 242;
const SC_TRACE_NAME_MAX: usize = 243;
const SC_TRACE_SYS_MAX: usize = 244;
const SC_TRACE_USER_EVENT_MAX: usize = 245;
const SC_XOPEN_STREAMS: usize = 246;
const SC_THREAD_ROBUST_PRIO_INHERIT: usize = 247;
const SC_THREAD_ROBUST_PRIO_PROTECT: usize = 248;
const SC_MINSIGSTKSZ: usize = 249;
const SC_SIGSTKSZ: usize = 250;

/// Musl's `sysconf` table, in source order. Numeric literals are the pinned
/// musl header constants the source names (shown after each entry); the
/// three `sizeof(long)` rows take their LP64 values.
static SYSCONF_VALUES: [i16; SC_SIGSTKSZ + 1] = {
    let mut values = [0i16; SC_SIGSTKSZ + 1];
    values[SC_ARG_MAX] = JT_ARG_MAX;
    values[SC_CHILD_MAX] = rlim(RLIMIT_NPROC);
    values[SC_CLK_TCK] = 100;
    values[SC_NGROUPS_MAX] = 32;
    values[SC_OPEN_MAX] = rlim(RLIMIT_NOFILE);
    values[SC_STREAM_MAX] = -1;
    values[SC_TZNAME_MAX] = 6; // TZNAME_MAX
    values[SC_JOB_CONTROL] = 1;
    values[SC_SAVED_IDS] = 1;
    values[SC_REALTIME_SIGNALS] = VER;
    values[SC_PRIORITY_SCHEDULING] = -1;
    values[SC_TIMERS] = VER;
    values[SC_ASYNCHRONOUS_IO] = VER;
    values[SC_PRIORITIZED_IO] = -1;
    values[SC_SYNCHRONIZED_IO] = -1;
    values[SC_FSYNC] = VER;
    values[SC_MAPPED_FILES] = VER;
    values[SC_MEMLOCK] = VER;
    values[SC_MEMLOCK_RANGE] = VER;
    values[SC_MEMORY_PROTECTION] = VER;
    values[SC_MESSAGE_PASSING] = VER;
    values[SC_SEMAPHORES] = VER;
    values[SC_SHARED_MEMORY_OBJECTS] = VER;
    values[SC_AIO_LISTIO_MAX] = -1;
    values[SC_AIO_MAX] = -1;
    values[SC_AIO_PRIO_DELTA_MAX] = JT_ZERO;
    values[SC_DELAYTIMER_MAX] = JT_DELAYTIMER_MAX;
    values[SC_MQ_OPEN_MAX] = -1;
    values[SC_MQ_PRIO_MAX] = JT_MQ_PRIO_MAX;
    values[SC_VERSION] = VER;
    values[SC_PAGE_SIZE] = JT_PAGE_SIZE;
    values[SC_RTSIG_MAX] = 30; // _NSIG - 1 - 31 - 3
    values[SC_SEM_NSEMS_MAX] = 256; // SEM_NSEMS_MAX
    values[SC_SEM_VALUE_MAX] = JT_SEM_VALUE_MAX;
    values[SC_SIGQUEUE_MAX] = -1;
    values[SC_TIMER_MAX] = -1;
    values[SC_BC_BASE_MAX] = 99; // _POSIX2_BC_BASE_MAX
    values[SC_BC_DIM_MAX] = 2048; // _POSIX2_BC_DIM_MAX
    values[SC_BC_SCALE_MAX] = 99; // _POSIX2_BC_SCALE_MAX
    values[SC_BC_STRING_MAX] = 1000; // _POSIX2_BC_STRING_MAX
    values[SC_COLL_WEIGHTS_MAX] = 2; // COLL_WEIGHTS_MAX
    values[SC_EXPR_NEST_MAX] = -1;
    values[SC_LINE_MAX] = -1;
    values[SC_RE_DUP_MAX] = 255; // RE_DUP_MAX
    values[SC_2_VERSION] = VER;
    values[SC_2_C_BIND] = VER;
    values[SC_2_C_DEV] = -1;
    values[SC_2_FORT_DEV] = -1;
    values[SC_2_FORT_RUN] = -1;
    values[SC_2_SW_DEV] = -1;
    values[SC_2_LOCALEDEF] = -1;
    values[SC_IOV_MAX] = 1024; // IOV_MAX
    values[SC_THREADS] = VER;
    values[SC_THREAD_SAFE_FUNCTIONS] = VER;
    values[SC_GETGR_R_SIZE_MAX] = -1;
    values[SC_GETPW_R_SIZE_MAX] = -1;
    values[SC_LOGIN_NAME_MAX] = 256;
    values[SC_TTY_NAME_MAX] = 32; // TTY_NAME_MAX
    values[SC_THREAD_DESTRUCTOR_ITERATIONS] = 4; // PTHREAD_DESTRUCTOR_ITERATIONS
    values[SC_THREAD_KEYS_MAX] = 128; // PTHREAD_KEYS_MAX
    values[SC_THREAD_STACK_MIN] = 2048; // PTHREAD_STACK_MIN
    values[SC_THREAD_THREADS_MAX] = -1;
    values[SC_THREAD_ATTR_STACKADDR] = VER;
    values[SC_THREAD_ATTR_STACKSIZE] = VER;
    values[SC_THREAD_PRIORITY_SCHEDULING] = VER;
    values[SC_THREAD_PRIO_INHERIT] = -1;
    values[SC_THREAD_PRIO_PROTECT] = -1;
    values[SC_THREAD_PROCESS_SHARED] = VER;
    values[SC_NPROCESSORS_CONF] = JT_NPROCESSORS_CONF;
    values[SC_NPROCESSORS_ONLN] = JT_NPROCESSORS_ONLN;
    values[SC_PHYS_PAGES] = JT_PHYS_PAGES;
    values[SC_AVPHYS_PAGES] = JT_AVPHYS_PAGES;
    values[SC_ATEXIT_MAX] = -1;
    values[SC_PASS_MAX] = -1;
    values[SC_XOPEN_VERSION] = 700; // _XOPEN_VERSION
    values[SC_XOPEN_XCU_VERSION] = 700; // _XOPEN_VERSION
    values[SC_XOPEN_UNIX] = 1;
    values[SC_XOPEN_CRYPT] = -1;
    values[SC_XOPEN_ENH_I18N] = 1;
    values[SC_XOPEN_SHM] = 1;
    values[SC_2_CHAR_TERM] = -1;
    values[SC_2_UPE] = -1;
    values[SC_XOPEN_XPG2] = -1;
    values[SC_XOPEN_XPG3] = -1;
    values[SC_XOPEN_XPG4] = -1;
    values[SC_NZERO] = 20; // NZERO
    values[SC_XBS5_ILP32_OFF32] = -1;
    values[SC_XBS5_ILP32_OFFBIG] = -1; // sizeof(long)==4 ? 1 : -1
    values[SC_XBS5_LP64_OFF64] = 1; // sizeof(long)==8 ? 1 : -1
    values[SC_XBS5_LPBIG_OFFBIG] = -1;
    values[SC_XOPEN_LEGACY] = -1;
    values[SC_XOPEN_REALTIME] = -1;
    values[SC_XOPEN_REALTIME_THREADS] = -1;
    values[SC_ADVISORY_INFO] = VER;
    values[SC_BARRIERS] = VER;
    values[SC_CLOCK_SELECTION] = VER;
    values[SC_CPUTIME] = VER;
    values[SC_THREAD_CPUTIME] = VER;
    values[SC_MONOTONIC_CLOCK] = VER;
    values[SC_READER_WRITER_LOCKS] = VER;
    values[SC_SPIN_LOCKS] = VER;
    values[SC_REGEXP] = 1;
    values[SC_SHELL] = 1;
    values[SC_SPAWN] = VER;
    values[SC_SPORADIC_SERVER] = -1;
    values[SC_THREAD_SPORADIC_SERVER] = -1;
    values[SC_TIMEOUTS] = VER;
    values[SC_TYPED_MEMORY_OBJECTS] = -1;
    values[SC_2_PBS] = -1;
    values[SC_2_PBS_ACCOUNTING] = -1;
    values[SC_2_PBS_LOCATE] = -1;
    values[SC_2_PBS_MESSAGE] = -1;
    values[SC_2_PBS_TRACK] = -1;
    values[SC_SYMLOOP_MAX] = 40; // SYMLOOP_MAX
    values[SC_STREAMS] = JT_ZERO;
    values[SC_2_PBS_CHECKPOINT] = -1;
    values[SC_V6_ILP32_OFF32] = -1;
    values[SC_V6_ILP32_OFFBIG] = -1; // sizeof(long)==4 ? 1 : -1
    values[SC_V6_LP64_OFF64] = 1; // sizeof(long)==8 ? 1 : -1
    values[SC_V6_LPBIG_OFFBIG] = -1;
    values[SC_HOST_NAME_MAX] = 255; // HOST_NAME_MAX
    values[SC_TRACE] = -1;
    values[SC_TRACE_EVENT_FILTER] = -1;
    values[SC_TRACE_INHERIT] = -1;
    values[SC_TRACE_LOG] = -1;
    values[SC_IPV6] = VER;
    values[SC_RAW_SOCKETS] = VER;
    values[SC_V7_ILP32_OFF32] = -1;
    values[SC_V7_ILP32_OFFBIG] = -1; // sizeof(long)==4 ? 1 : -1
    values[SC_V7_LP64_OFF64] = 1; // sizeof(long)==8 ? 1 : -1
    values[SC_V7_LPBIG_OFFBIG] = -1;
    values[SC_SS_REPL_MAX] = -1;
    values[SC_TRACE_EVENT_NAME_MAX] = -1;
    values[SC_TRACE_NAME_MAX] = -1;
    values[SC_TRACE_SYS_MAX] = -1;
    values[SC_TRACE_USER_EVENT_MAX] = -1;
    values[SC_XOPEN_STREAMS] = JT_ZERO;
    values[SC_THREAD_ROBUST_PRIO_INHERIT] = -1;
    values[SC_THREAD_ROBUST_PRIO_PROTECT] = -1;
    values[SC_MINSIGSTKSZ] = JT_MINSIGSTKSZ;
    values[SC_SIGSTKSZ] = JT_SIGSTKSZ;
    values
};

// Musl's `src/conf/sysconf.c` object.
static_archive_member! { sysconf_source {
    /// Return one `sysconf` value from musl's table.
    ///
    /// Absent, zero, and out-of-range selectors, including every negative one,
    /// publish `EINVAL` and return -1. Resource selectors return -1 for
    /// `RLIM_INFINITY` and otherwise the soft limit saturated at `LONG_MAX`;
    /// `prlimit64` cannot fail for these fixed resources of the calling process,
    /// and where musl would then read an uninitialized record this translation
    /// returns -1 with the raw errno. The processor, page, and signal-stack cases
    /// keep their source errno behavior in their owners.
    #[no_mangle]
    pub extern "C" fn sysconf(name: c_int) -> c_long {
        let value = match usize::try_from(name).ok().and_then(|index| SYSCONF_VALUES.get(index)) {
            Some(&value) if value != 0 => value,
            _ => {
                // SAFETY: this C ABI owns the calling thread's initial-TLS errno
                // publication for rejected scalar selectors.
                unsafe { errno::set_errno(EINVAL) };
                return -1;
            }
        };
        if value >= -1 {
            return c_long::from(value);
        }
        if value < -256 {
            return match resource_soft_limit(c_int::from(value & 16_383)) {
                Some(RLIM_INFINITY) => -1,
                Some(current) => c_long::try_from(current).unwrap_or(c_long::MAX),
                None => -1,
            };
        }
        match value {
            VER => POSIX_VERSION,
            JT_ARG_MAX => ARG_MAX,
            JT_MQ_PRIO_MAX => MQ_PRIO_MAX,
            JT_PAGE_SIZE => c_long::from(X86_64_LINUX_PAGE_SIZE),
            JT_SEM_VALUE_MAX => SEM_VALUE_MAX,
            JT_DELAYTIMER_MAX => DELAYTIMER_MAX,
            JT_NPROCESSORS_CONF | JT_NPROCESSORS_ONLN => c_long::from(system_information::nprocs()),
            JT_PHYS_PAGES => system_information::page_count(false),
            JT_AVPHYS_PAGES => system_information::page_count(true),
            JT_MINSIGSTKSZ => minimum_signal_stack_size() as c_long,
            JT_SIGSTKSZ => signal_stack_size() as c_long,
            JT_ZERO => 0,
            // Every other table entry is a direct value handled above.
            _ => c_long::from(value),
        }
    }
}}

/// Read one resource's soft limit through musl's `getrlimit` normal path.
fn resource_soft_limit(resource: c_int) -> Option<c_ulong> {
    let mut limit = Rlimit { current: 0, maximum: 0 };
    // SAFETY: Linux/x86-64 `prlimit64=302` consumes the calling process (0),
    // the resource, a null new limit, and the writable 16-byte old-limit
    // record in rdi/rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_PRLIMIT64,
            0,
            i64::from(resource),
            0,
            core::ptr::addr_of_mut!(limit) as usize as i64,
        )
    };
    (c_status(result) == 0).then_some(limit.current)
}

#[inline]
fn confstr_value(name: c_int) -> Option<&'static [u8]> {
    match name {
        CS_PATH => Some(b"/bin:/usr/bin\0"),
        CS_POSIX_V6_WIDTH_RESTRICTED_ENVS | CS_POSIX_V7_WIDTH_RESTRICTED_ENVS => {
            Some(b"\0")
        }
        CS_POSIX_V6_ILP32_OFF32_CFLAGS..=CS_POSIX_V7_THREADS_LDFLAGS => Some(b"\0"),
        _ => None,
    }
}

// Musl's `src/conf/confstr.c` object.
static_archive_member! { confstr_source {
    /// Query or copy a selected POSIX configuration string.
    ///
    /// `buf` may be null only when `len` is zero. When it is non-null, it must
    /// designate `len` writable bytes for the call. Like musl, a too-small output
    /// buffer receives the maximal NUL-terminated prefix and the function returns
    /// the full required size including that NUL byte.
    ///
    /// # Safety
    ///
    /// When `buf` is non-null and `len` is nonzero, it must designate `len`
    /// writable bytes for the complete copy and terminator write.
    #[no_mangle]
    pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
        let Some(value) = confstr_value(name) else {
            // SAFETY: this selected C ABI owns the calling thread's initial-TLS
            // errno publication for rejected scalar selectors.
            unsafe { errno::set_errno(EINVAL) };
            return 0;
        };

        let value_len = value.len() - 1;
        if !buf.is_null() && len != 0 {
            let copy_len = core::cmp::min(len - 1, value_len);
            // Unlike musl's internal `snprintf` shortcut, copy the selected small
            // literal byte-by-byte. This retains musl's query/truncation result
            // while keeping the isolated `confstr` static candidate free of a
            // stdio or compiler-memory-helper closure.
            //
            // SAFETY: the caller owns `len` writable bytes when supplying a
            // non-null output pointer. `copy_len < len` and `copy_len <= value_len`,
            // so the source reads and destination/terminator writes remain inside
            // their respective objects.
            unsafe {
                let source = value.as_ptr();
                let mut index = 0usize;
                while index < copy_len {
                    buf.add(index).write(source.add(index).read() as c_char);
                    index += 1;
                }
                *buf.add(copy_len) = 0;
            }
        }
        value_len + 1
    }
}}

#[inline(always)]
fn pathconf_value(name: c_int) -> Option<c_long> {
    let value = match name {
        PC_LINK_MAX => 8,
        PC_MAX_CANON | PC_MAX_INPUT | PC_NAME_MAX => 255,
        PC_PATH_MAX | PC_PIPE_BUF => 4096,
        PC_CHOWN_RESTRICTED | PC_NO_TRUNC | PC_SYNC_IO | PC_2_SYMLINKS => 1,
        PC_VDISABLE => 0,
        PC_ASYNC_IO | PC_PRIO_IO | PC_SOCK_MAXBUF | PC_SYMLINK_MAX => -1,
        PC_FILESIZEBITS => 64,
        PC_REC_INCR_XFER_SIZE
        | PC_REC_MAX_XFER_SIZE
        | PC_REC_MIN_XFER_SIZE
        | PC_REC_XFER_ALIGN
        | PC_ALLOC_SIZE_MIN => X86_64_LINUX_PAGE_SIZE,
        _ => return None,
    };
    Some(c_long::from(value))
}

// Keep this scalar table decision inside both public entry points so the
// artifact's entry-point disassembly check proves it cannot acquire a hidden
// filesystem syscall.
#[inline(always)]
unsafe fn selected_pathconf(name: c_int) -> c_long {
    match pathconf_value(name) {
        Some(value) => value,
        None => {
            // SAFETY: this selected C ABI owns the calling thread's initial-TLS
            // errno publication for rejected scalar selectors.
            unsafe { errno::set_errno(EINVAL) };
            -1
        }
    }
}

// Musl's `src/conf/fpathconf.c` object.
static_archive_member! { fpathconf_source {
    /// Return a selected path configuration value for an open descriptor.
    ///
    /// Musl's selected Linux contract is table-based, so `fd` is deliberately not
    /// dereferenced or passed to Linux. Valid selectors therefore do not fail for an invalid
    /// descriptor; valid indeterminate `-1` values preserve `errno`.
    #[no_mangle]
    pub extern "C" fn fpathconf(_fd: c_int, name: c_int) -> c_long {
        // SAFETY: this helper only publishes EINVAL for an invalid scalar selector.
        unsafe { selected_pathconf(name) }
    }
}}

// Musl's `src/conf/pathconf.c` object.
static_archive_member! { pathconf_source {
    /// Return a selected path configuration value for a pathname.
    ///
    /// Musl's selected Linux contract is table-based, so `path` is deliberately
    /// not dereferenced or passed to Linux. Valid selectors therefore do not fail
    /// for a null or missing pathname; valid indeterminate `-1` values preserve
    /// `errno`. As in musl's delegated `fpathconf(-1, name)` source closure, this
    /// selected safe translation publishes `EINVAL` for every invalid Rust scalar,
    /// while the pinned C source's negative signed index remains outside the
    /// differential contract.
    #[no_mangle]
    pub extern "C" fn pathconf(_path: *const c_char, name: c_int) -> c_long {
        // SAFETY: this helper only publishes EINVAL for an invalid scalar selector.
        unsafe { selected_pathconf(name) }
    }
}}

// Musl's `src/legacy/getpagesize.c` object.
static_archive_member! { getpagesize_source {
    /// Return Linux/x86-64's fixed base page size.
    ///
    /// The x86-64 Linux ABI has a 4096-byte base page size; this is not an auxv
    /// reader and does not claim the future x86 C startup/runtime contract.
    #[no_mangle]
    pub extern "C" fn getpagesize() -> c_int {
        X86_64_LINUX_PAGE_SIZE
    }
}}

// Musl's `src/legacy/getdtablesize.c` object.
static_archive_member! { getdtablesize_source {
    /// Return the calling process's soft descriptor limit clamped to `INT_MAX`.
    ///
    /// Musl's source closure is `src/legacy/getdtablesize.c` through
    /// `src/misc/getrlimit.c`: its successful `prlimit64` normal path supplies the
    /// `RLIMIT_NOFILE` record. Linux 5.10 is above musl's historical
    /// `SYS_getrlimit` fallback boundary, so this selected x86 leaf deliberately
    /// does not invent that fallback. Musl's legacy caller ignores a failed
    /// `getrlimit` and reads an uninitialized local record; this safer leaf instead
    /// translates the raw `prlimit64` error through initial-TLS errno and returns
    /// `-1`, so an error cannot fabricate a descriptor-table size.
    #[no_mangle]
    pub extern "C" fn getdtablesize() -> c_int {
        let mut limit = Rlimit {
            current: 0,
            maximum: 0,
        };
        // SAFETY: Linux/x86-64 `prlimit64=302` consumes the target pid, resource,
        // null new-limit, and writable old-limit in rdi/rsi/rdx/r10. This stack
        // record has the exact 16-byte x86 public/kernel `rlimit` layout.
        let result = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_PRLIMIT64,
                0,
                i64::from(RLIMIT_NOFILE),
                0,
                core::ptr::addr_of_mut!(limit) as usize as i64,
            )
        };
        if c_status(result) != 0 {
            return -1;
        }
        if limit.current < c_ulong::try_from(c_int::MAX).unwrap_or(c_ulong::MAX) {
            limit.current as c_int
        } else {
            c_int::MAX
        }
    }
}}
