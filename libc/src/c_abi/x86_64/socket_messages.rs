//! Selected static Linux/x86-64 C socket-message and socket-option boundary.
//!
//! This leaf extends the separately evidenced basic socket-transport block
//! with the closed message/option surface `setsockopt`, `getsockopt`,
//! `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, and `sockatmark`. It uses
//! the already selected x86 `iovec` and socket descriptor ABIs, but owns no
//! resolver, interface, ancillary-policy, allocation, or pthread state.
//! In particular, the public musl `msghdr` is not the Linux x86-64 syscall
//! record: its iovec-count and control-length words are 32-bit fields with
//! explicit padding. The wrappers below make temporary kernel-shaped records
//! and zero every padding word before Linux sees them.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/network/setsockopt.c` and `src/network/getsockopt.c` map to the
//!   corresponding direct option wrappers. Their legacy time32 conversion
//!   branches are inactive on native LP64 x86-64, where the public and old
//!   timeout option values coincide.
//! - `src/network/sendmsg.c` maps to [`sendmsg`] and its copied, bounded
//!   outgoing ancillary-control buffer with public-padding sanitisation.
//! - `src/network/recvmsg.c` maps to [`recvmsg`] and its copied message header
//!   with public-padding sanitisation and copy-back.
//! - `src/network/sendmmsg.c` maps to [`sendmmsg`]. On 64-bit targets musl
//!   deliberately loops through its padded `sendmsg` helper rather than using
//!   Linux `sendmmsg` directly.
//! - `src/network/recvmmsg.c` maps to [`recvmmsg`] and its per-record padding
//!   clearing before the direct Linux call.
//! - `src/network/sockatmark.c` maps to [`sockatmark`]'s `SIOCATMARK` ioctl
//!   request.
//!
//! The owned runtime preserves the source-defined message cancellation points
//! after record preparation, including each iteration of LP64 `sendmmsg`.
//! An empty `sendmmsg` batch performs no cancellation check. Standalone archive
//! selections retain their direct syscalls; option calls remain non-canceling.

use core::ffi::{c_int, c_uint, c_void};

use super::{c_ssize_status, c_status, raw_syscall};

const ENOMEM: i64 = 12;
const IOV_MAX: c_uint = 1024;
const SIOCATMARK: c_int = 0x8905;
const CMSG_ALIGN: usize = core::mem::size_of::<usize>();
const CMSG_HEADER_SIZE: usize = 16;
const MUSL_MAX_RIGHTS: usize = 255;

/// Musl's public Linux/x86-64 `struct msghdr` ABI.
///
/// Linux's syscall record interprets the two padded pairs as native 64-bit
/// values. Public callers must therefore never have their padding forwarded
/// directly to the kernel.
#[repr(C)]
pub struct MsgHdr {
    name: *mut c_void,
    name_length: c_uint,
    iov: *mut c_void,
    iov_length: c_int,
    iov_padding: c_int,
    control: *mut c_void,
    control_length: c_uint,
    control_padding: c_int,
    flags: c_int,
}

/// Musl's public Linux/x86-64 `struct mmsghdr` ABI.
#[repr(C)]
pub struct MMsgHdr {
    header: MsgHdr,
    length: c_uint,
}

const _: [(); 56] = [(); core::mem::size_of::<MsgHdr>()];
const _: [(); 8] = [(); core::mem::align_of::<MsgHdr>()];
const _: [(); 64] = [(); core::mem::size_of::<MMsgHdr>()];
const _: [(); 8] = [(); core::mem::align_of::<MMsgHdr>()];

#[inline]
const fn cmsg_align(length: usize) -> usize {
    length.wrapping_add(CMSG_ALIGN - 1) & !(CMSG_ALIGN - 1)
}

// Musl allocates `CMSG_SPACE(255 * sizeof(int)) / sizeof(cmsghdr) + 1`
// cmsghdr objects. On native x86-64 this is 66 * 16 = 1056 bytes, represented
// here as 132 naturally aligned machine words.
const MUSL_SEND_CONTROL_BYTES: usize = (cmsg_align(CMSG_HEADER_SIZE)
    + cmsg_align(MUSL_MAX_RIGHTS * core::mem::size_of::<c_int>()))
    / CMSG_HEADER_SIZE
    * CMSG_HEADER_SIZE
    + CMSG_HEADER_SIZE;
const MUSL_SEND_CONTROL_WORDS: usize =
    MUSL_SEND_CONTROL_BYTES / core::mem::size_of::<usize>();
const _: [(); 1_056] = [(); MUSL_SEND_CONTROL_BYTES];
const _: [(); 132] = [(); MUSL_SEND_CONTROL_WORDS];

/// Clear the invisible high word of each public cmsghdr length in a copied
/// outbound control buffer.
///
/// A malformed record remains kernel-visible exactly as musl leaves it; this
/// walk only prevents the public 32-bit length ABI's padding from becoming a
/// spurious native-size Linux length.
unsafe fn zero_cmsg_padding(control: *mut u8, length: usize) {
    let mut offset = 0usize;
    while offset + CMSG_HEADER_SIZE <= length {
        // SAFETY: the loop bound proves that the copied buffer includes the
        // public cmsghdr's padding word at bytes 4 through 7.
        unsafe {
            core::ptr::write_unaligned(control.add(offset + core::mem::size_of::<c_uint>())
                as *mut c_uint, 0);
        }
        // SAFETY: the same bound covers the public cmsg_len word.
        let cmsg_length = unsafe { core::ptr::read_unaligned(control.add(offset) as *const c_uint) }
            as usize;
        if cmsg_length < CMSG_HEADER_SIZE {
            break;
        }
        let next = cmsg_align(cmsg_length);
        let remaining = length - offset;
        // This is musl's CMSG_NXTHDR boundary: a trailing cmsghdr that ends
        // exactly at the caller's control extent is not another traversed
        // record, so its public padding remains untouched.
        if next == 0
            || next.checked_add(CMSG_HEADER_SIZE).is_none()
            || next + CMSG_HEADER_SIZE >= remaining
        {
            break;
        }
        offset += next;
    }
}

/// Build one kernel-safe copy of an outgoing public message header.
///
/// The raw result deliberately remains in Linux's negative-errno form so
/// both `sendmsg` and musl-shaped `sendmmsg` can publish its C errno behavior.
#[inline(always)]
unsafe fn sendmsg_result(file_descriptor: c_int, message: *const MsgHdr, flags: c_int) -> i64 {
    if message.is_null() {
        // SAFETY: Linux owns null message-pointer validation for this direct
        // raw form.
        return unsafe {
            #[cfg(feature = "x86-owned-static-runtime")]
            {
                super::pthread_cancel::syscall_cp(
                    raw_syscall::SYS_SENDMSG,
                    i64::from(file_descriptor),
                    0,
                    i64::from(flags),
                    0,
                    0,
                    0,
                )
            }
            #[cfg(not(feature = "x86-owned-static-runtime"))]
            {
                raw_syscall::syscall3(
                    raw_syscall::SYS_SENDMSG,
                    i64::from(file_descriptor),
                    0,
                    i64::from(flags),
                )
            }
        };
    }

    // SAFETY: the public C caller contract requires one readable msghdr for
    // the duration of this call. Unaligned access keeps this Rust boundary
    // faithful to musl's byte-addressable C record ABI.
    let mut header = unsafe { core::ptr::read_unaligned(message) };
    header.iov_padding = 0;
    header.control_padding = 0;
    let mut control_words = [0usize; MUSL_SEND_CONTROL_WORDS];

    if header.control_length != 0 {
        let length = header.control_length as usize;
        if length > core::mem::size_of_val(&control_words) {
            return -ENOMEM;
        }
        let control = control_words.as_mut_ptr() as *mut u8;
        // SAFETY: as in musl, a nonzero public control length requires the
        // caller to provide that many readable bytes. The fixed local buffer
        // was checked above and does not overlap the caller's control input.
        unsafe {
            core::ptr::copy_nonoverlapping(header.control as *const u8, control, length);
            zero_cmsg_padding(control, length);
        }
        header.control = control as *mut c_void;
    }

    // SAFETY: header and its optional bounded control copy remain live until
    // Linux returns. The caller owns iovec/name pointer validity and every
    // message-specific descriptor/policy contract.
    unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_SENDMSG,
                i64::from(file_descriptor),
                core::ptr::addr_of!(header) as usize as i64,
                i64::from(flags),
                0,
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall3(
                raw_syscall::SYS_SENDMSG,
                i64::from(file_descriptor),
                core::ptr::addr_of!(header) as usize as i64,
                i64::from(flags),
            )
        }
    }
}

/// Invoke Linux `recvmsg` with a copied, kernel-safe public header.
#[inline(always)]
unsafe fn recvmsg_result(file_descriptor: c_int, message: *mut MsgHdr, flags: c_int) -> i64 {
    if message.is_null() {
        // Keep the raw invalid-pointer result defined at this Rust boundary;
        // valid public calls always take the copy-and-sanitise path below.
        return unsafe {
            #[cfg(feature = "x86-owned-static-runtime")]
            {
                super::pthread_cancel::syscall_cp(
                    raw_syscall::SYS_RECVMSG,
                    i64::from(file_descriptor),
                    0,
                    i64::from(flags),
                    0,
                    0,
                    0,
                )
            }
            #[cfg(not(feature = "x86-owned-static-runtime"))]
            {
                raw_syscall::syscall3(
                    raw_syscall::SYS_RECVMSG,
                    i64::from(file_descriptor),
                    0,
                    i64::from(flags),
                )
            }
        };
    }

    // SAFETY: the public C caller supplies one readable/writable header. The
    // temporary gives Linux native-width zero-extension through both padding
    // words without exposing the caller's padding bytes.
    let mut header = unsafe { core::ptr::read_unaligned(message) };
    header.iov_padding = 0;
    header.control_padding = 0;
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_RECVMSG,
                i64::from(file_descriptor),
                core::ptr::addr_of_mut!(header) as usize as i64,
                i64::from(flags),
                0,
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall3(
                raw_syscall::SYS_RECVMSG,
                i64::from(file_descriptor),
                core::ptr::addr_of_mut!(header) as usize as i64,
                i64::from(flags),
            )
        }
    };
    // Musl copies its temporary public-shaped record back after the syscall,
    // including on the error path where Linux may already have updated output
    // fields. The cleared padding becomes the caller-visible public state.
    unsafe { core::ptr::write_unaligned(message, header) };
    result
}

/// Set one caller-owned socket option through Linux `setsockopt(2)`.
///
/// # Safety
///
/// When `option_length` is nonzero, `option` must designate at least that many
/// readable bytes in the option-specific representation. The caller owns
/// descriptor lifetime and socket policy.
#[no_mangle]
pub unsafe extern "C" fn setsockopt(
    file_descriptor: c_int,
    level: c_int,
    option_name: c_int,
    option: *const c_void,
    option_length: c_uint,
) -> c_int {
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_SETSOCKOPT,
            i64::from(file_descriptor),
            i64::from(level),
            i64::from(option_name),
            option as usize as i64,
            i64::from(option_length),
        )
    };
    c_status(result)
}

/// Read one caller-owned socket option through Linux `getsockopt(2)`.
///
/// # Safety
///
/// `option_length` must point to one writable x86 `socklen_t` word. `option`
/// must designate the writable capacity expressed by that word whenever Linux
/// needs output storage. The caller owns descriptor lifetime and option policy.
#[no_mangle]
pub unsafe extern "C" fn getsockopt(
    file_descriptor: c_int,
    level: c_int,
    option_name: c_int,
    option: *mut c_void,
    option_length: *mut c_uint,
) -> c_int {
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_GETSOCKOPT,
            i64::from(file_descriptor),
            i64::from(level),
            i64::from(option_name),
            option as usize as i64,
            option_length as usize as i64,
        )
    };
    c_status(result)
}

/// Send one padded public message through Linux `sendmsg(2)`.
///
/// # Safety
///
/// `message` must designate a readable x86 public `msghdr`; every nested
/// pointer and optional outbound control buffer must remain readable for the
/// call. The caller owns descriptor lifetime, blocking, SIGPIPE, and message
/// policy. The owned runtime supplies pthread cancellation.
#[no_mangle]
pub unsafe extern "C" fn sendmsg(
    file_descriptor: c_int,
    message: *const MsgHdr,
    flags: c_int,
) -> isize {
    c_ssize_status(unsafe { sendmsg_result(file_descriptor, message, flags) })
}

/// Receive one padded public message through Linux `recvmsg(2)`.
///
/// # Safety
///
/// `message` must designate a readable/writable x86 public `msghdr`; every
/// nested output pointer must remain valid for the syscall. The caller owns
/// descriptor lifetime, blocking, and message/ancillary policy. The owned runtime
/// supplies pthread cancellation.
#[no_mangle]
pub unsafe extern "C" fn recvmsg(
    file_descriptor: c_int,
    message: *mut MsgHdr,
    flags: c_int,
) -> isize {
    c_ssize_status(unsafe { recvmsg_result(file_descriptor, message, flags) })
}

/// Send a bounded batch through musl's padded `sendmsg` loop.
///
/// # Safety
///
/// If `count` is nonzero, `messages` must designate at least the first
/// `min(count, IOV_MAX)` writable public `mmsghdr` records and their complete
/// nested message inputs. The caller owns all descriptor, blocking, and
/// SIGPIPE policy. The owned runtime supplies cancellation for each message.
#[no_mangle]
pub unsafe extern "C" fn sendmmsg(
    file_descriptor: c_int,
    messages: *mut MMsgHdr,
    count: c_uint,
    flags: c_uint,
) -> c_int {
    let bounded_count = core::cmp::min(count, IOV_MAX);
    let mut index = 0u32;
    while index < bounded_count {
        // SAFETY: the caller's count/record-lifetime contract covers this
        // selected record; `sendmsg_result` prepares the ABI record before its
        // source-defined cancellation point.
        let message = unsafe { messages.add(index as usize) };
        let result = unsafe {
            sendmsg_result(
                file_descriptor,
                core::ptr::addr_of!((*message).header),
                flags as c_int,
            )
        };
        if result < 0 {
            let _ = c_ssize_status(result);
            return if index == 0 { -1 } else { index as c_int };
        }
        // Linux caps an individual sendmsg result to INT_MAX, matching musl's
        // safe conversion to the public unsigned message-length word.
        unsafe { (*message).length = result as c_uint };
        index += 1;
    }
    index as c_int
}

/// Receive a batch through Linux `recvmmsg(2)` after clearing every public
/// message header's invisible native-width padding.
///
/// # Safety
///
/// If `count` is nonzero, `messages` must designate that many readable and
/// writable public `mmsghdr` records plus all nested output storage. `timeout`
/// is either null or writable x86 `timespec` storage. The caller owns socket,
/// blocking, timeout, and message policy. The owned runtime supplies
/// pthread cancellation.
#[no_mangle]
pub unsafe extern "C" fn recvmmsg(
    file_descriptor: c_int,
    messages: *mut MMsgHdr,
    count: c_uint,
    flags: c_uint,
    timeout: *mut c_void,
) -> c_int {
    let mut index = 0u32;
    while index < count {
        // SAFETY: the caller owns all message records and their nested output
        // storage. Only the public ABI padding is written before Linux sees
        // each record.
        let header = unsafe { &mut (*messages.add(index as usize)).header };
        header.iov_padding = 0;
        header.control_padding = 0;
        index += 1;
    }
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_RECVMMSG,
                i64::from(file_descriptor),
                messages as usize as i64,
                i64::from(count),
                i64::from(flags),
                timeout as usize as i64,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall5(
                raw_syscall::SYS_RECVMMSG,
                i64::from(file_descriptor),
                messages as usize as i64,
                i64::from(count),
                i64::from(flags),
                timeout as usize as i64,
            )
        }
    };
    c_status(result)
}

/// Query a stream socket's urgent-data mark through musl's `SIOCATMARK` form.
#[no_mangle]
pub extern "C" fn sockatmark(file_descriptor: c_int) -> c_int {
    let mut at_mark = 0 as c_int;
    // SAFETY: `at_mark` is a live writable x86 int for Linux's ioctl output;
    // the fixed request takes exactly one pointer word in rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(file_descriptor),
            i64::from(SIOCATMARK),
            core::ptr::addr_of_mut!(at_mark) as usize as i64,
        )
    };
    if c_status(result) < 0 {
        -1
    } else {
        at_mark
    }
}
