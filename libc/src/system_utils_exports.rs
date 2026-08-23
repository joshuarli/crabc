// system and legacy utility exports.
//
// These are deliberately small ABI shims around Linux's native interfaces:
// a64l/l64a use the POSIX radix-64 alphabet, the historical signal spellings
// share signal()'s implementation, and the priority functions translate the
// kernel's inverted priority range to the values required by libc callers.

const CABI_L64A_DIGITS: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// l64a is specified to return storage that is overwritten by the next call.
// A process-global buffer matches musl's ABI and is intentionally not a
// success-path substitute for an allocation that could fail.
static mut M64A_BUFFER: [u8; 7] = [0; 7];

#[no_mangle]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    // musl intentionally keeps the encoded payload at 32 bits even on LP64;
    // a64l's return value is the sign-extended int32_t payload.
    let mut value: c_uint = 0;
    let mut i = 0usize;
    while i < 6 {
        let c = *(s as *const u8).add(i);
        if c == 0 {
            break;
        }

        let digit = if c == b'.' {
            0
        } else if c == b'/' {
            1
        } else if c >= b'0' && c <= b'9' {
            2 + (c - b'0')
        } else if c >= b'A' && c <= b'Z' {
            12 + (c - b'A')
        } else if c >= b'a' && c <= b'z' {
            38 + (c - b'a')
        } else {
            // POSIX and musl stop at the first character outside the radix-64
            // alphabet; the already decoded low-order digits are retained.
            break;
        };

        value |= (digit as c_uint) << (i * 6);
        i += 1;
    }
    (value as c_int) as c_long
}

#[no_mangle]
pub unsafe extern "C" fn l64a(value: c_long) -> *mut c_char {
    // l64a likewise follows musl's uint32_t conversion, emitting at most six
    // radix-64 digits from the low 32 bits of the long argument.
    let mut remaining = value as c_uint;
    let mut i = 0usize;

    while i < 6 && remaining != 0 {
        M64A_BUFFER[i] = CABI_L64A_DIGITS[(remaining & 63) as usize];
        remaining >>= 6;
        i += 1;
    }
    M64A_BUFFER[i] = 0;

    core::ptr::addr_of_mut!(M64A_BUFFER).cast::<u8>() as *mut c_char
}

// musl exports these historical spellings as weak aliases of signal().
// Keep wrappers rather than duplicate signal state, so installing a handler
// through one spelling is immediately visible through all three spellings.
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn bsd_signal(signum: c_int, handler: usize) -> usize {
    signal(signum, handler)
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __sysv_signal(signum: c_int, handler: usize) -> usize {
    signal(signum, handler)
}

// Linux uses the generic syscall numbers on AArch64/RISC-V and a distinct
// ordering for getpriority/setpriority on x86_64.



const CABI_SYS_GETPRIORITY: i64 = 141;
const CABI_SYS_SETPRIORITY: i64 = 140;

const CABI_PRIO_PROCESS: c_int = 0;
const CABI_NZERO: c_int = 20;
const CABI_EPERM: c_int = 1;
const CABI_EACCES: c_int = 13;

#[inline]
unsafe fn cabi_priority_errno(result: i64) -> c_int {
    if result < 0 {
        ERRNO = (-result) as c_int;
        -1
    } else {
        result as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn getpriority(which: c_int, who: c_uint) -> c_int {
    let result = aarch64::syscall::syscall2(CABI_SYS_GETPRIORITY, which as i64, who as i64);
    if result < 0 {
        ERRNO = (-result) as c_int;
        return -1;
    }

    // The kernel returns 0..40 with the ordering inverted: 20 is the
    // highest priority and -20 is the lowest.  libc exposes the nice value.
    20 - result as c_int
}

#[no_mangle]
pub unsafe extern "C" fn setpriority(which: c_int, who: c_uint, value: c_int) -> c_int {
    let result = aarch64::syscall::syscall3(
        CABI_SYS_SETPRIORITY,
        which as i64,
        who as i64,
        value as i64,
    );
    cabi_priority_errno(result)
}

#[no_mangle]
pub unsafe extern "C" fn nice(inc: c_int) -> c_int {
    let mut priority = inc;
    // Querying first is needed to return the resulting nice value.  For large
    // increments musl avoids the query and integer overflow; the subsequent
    // clamp makes the syscall's target explicit.
    if inc > -2 * CABI_NZERO && inc < 2 * CABI_NZERO {
        priority += getpriority(CABI_PRIO_PROCESS, 0);
    }
    if priority > CABI_NZERO - 1 {
        priority = CABI_NZERO - 1;
    }
    if priority < -CABI_NZERO {
        priority = -CABI_NZERO;
    }

    if setpriority(CABI_PRIO_PROCESS, 0, priority) != 0 {
        if ERRNO == CABI_EACCES {
            ERRNO = CABI_EPERM;
        }
        -1
    } else {
        priority
    }
}
