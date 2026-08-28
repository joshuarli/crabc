//! Stateless Linux LP64 message-queue operations.

use core::{ffi::CStr, mem::MaybeUninit};

use crate::{RawFd, Result};
use crate::syscall::{decode, decode_i32, syscall1, syscall3, syscall4, syscall5, SYS_MQ_GETSETATTR, SYS_MQ_OPEN, SYS_MQ_TIMEDRECEIVE, SYS_MQ_TIMEDSEND, SYS_MQ_UNLINK};

/// Linux LP64 `struct mq_attr` wire layout.
///
/// The public Rust facade validates and converts these signed native-long
/// fields before exposing them. The reserved tail is retained because the
/// kernel copies the complete record for `mq_getsetattr`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelMqAttr {
    /// Queue status flags, currently `O_NONBLOCK`.
    pub mq_flags: i64,
    /// Maximum number of queued messages.
    pub mq_maxmsg: i64,
    /// Maximum message size in bytes.
    pub mq_msgsize: i64,
    /// Current number of queued messages.
    pub mq_curmsgs: i64,
    /// Linux ABI-reserved words.
    pub reserved: [i64; 4],
}

const _: () = assert!(core::mem::size_of::<KernelMqAttr>() == 64);
const _: () = assert!(core::mem::align_of::<KernelMqAttr>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelMqAttr, mq_flags) == 0);
const _: () = assert!(core::mem::offset_of!(KernelMqAttr, mq_maxmsg) == 8);
const _: () = assert!(core::mem::offset_of!(KernelMqAttr, mq_msgsize) == 16);
const _: () = assert!(core::mem::offset_of!(KernelMqAttr, mq_curmsgs) == 24);
const _: () = assert!(core::mem::offset_of!(KernelMqAttr, reserved) == 32);

/// Linux LP64 `struct timespec` used by absolute mq deadlines.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelMqTimespec {
    /// Seconds since the Unix epoch for `CLOCK_REALTIME` deadlines.
    pub tv_sec: i64,
    /// Nanoseconds within the second.
    pub tv_nsec: i64,
}

const _: () = assert!(core::mem::size_of::<KernelMqTimespec>() == 16);
const _: () = assert!(core::mem::align_of::<KernelMqTimespec>() == 8);
const _: () = assert!(core::mem::offset_of!(KernelMqTimespec, tv_sec) == 0);
const _: () = assert!(core::mem::offset_of!(KernelMqTimespec, tv_nsec) == 8);

/// Opens a kernel message queue using its fixed-arity syscall ABI.
///
/// `name` is the Linux kernel spelling without POSIX's required leading
/// slash; the higher-level facade validates and performs that translation.
/// `attr` is supplied only for creation and remains borrowed for the call.
#[inline]
pub fn open(name: &CStr, flags: i32, mode: u32, attr: Option<&KernelMqAttr>) -> Result<RawFd> {
    // SAFETY: `name` and the optional attribute remain live for the
    // fixed-arity syscall; all other arguments are scalar Linux values.
    decode_i32(unsafe {
        syscall4(
            SYS_MQ_OPEN,
            name.as_ptr() as usize,
            flags as usize,
            mode as usize,
            attr.map_or(0, |value| value as *const KernelMqAttr as usize),
        )
    })
}

/// Unlinks a kernel message-queue name.
#[inline]
pub fn unlink(name: &CStr) -> Result<()> {
    // SAFETY: `name` remains live for the duration of the direct syscall.
    decode(unsafe { syscall1(SYS_MQ_UNLINK, name.as_ptr() as usize) }).map(|_| ())
}

/// Reads or updates queue attributes through `mq_getsetattr`.
///
/// Linux always writes the previous attributes to the output record on a
/// successful call. `new_attr == None` performs a read-only query.
#[inline]
pub fn getsetattr(fd: RawFd, new_attr: Option<&KernelMqAttr>) -> Result<KernelMqAttr> {
    let mut old_attr = MaybeUninit::<KernelMqAttr>::uninit();
    // SAFETY: the optional input and output storage remain live for the
    // syscall; Linux initializes `old_attr` on success.
    decode(unsafe {
        syscall3(
            SYS_MQ_GETSETATTR,
            fd as usize,
            new_attr.map_or(0, |value| value as *const KernelMqAttr as usize),
            old_attr.as_mut_ptr() as usize,
        )
    })?;
    // SAFETY: Linux initialized the complete attribute record on success.
    Ok(unsafe { old_attr.assume_init() })
}

/// Sends one caller-borrowed message, optionally with an absolute
/// `CLOCK_REALTIME` deadline.
#[inline]
pub fn timed_send(
    fd: RawFd,
    message: &[u8],
    priority: u32,
    deadline: Option<&KernelMqTimespec>,
) -> Result<()> {
    // SAFETY: `message` and the optional deadline remain live for the
    // syscall; Linux reads at most `message.len()` bytes.
    decode(unsafe {
        syscall5(
            SYS_MQ_TIMEDSEND,
            fd as usize,
            message.as_ptr() as usize,
            message.len(),
            priority as usize,
            deadline.map_or(0, |value| value as *const KernelMqTimespec as usize),
        )
    })
    .map(|_| ())
}

/// Receives one message into caller-provided storage and returns its byte
/// length; Linux writes the message priority through `priority`.
#[inline]
pub fn timed_receive(
    fd: RawFd,
    buffer: &mut [u8],
    priority: &mut u32,
    deadline: Option<&KernelMqTimespec>,
) -> Result<usize> {
    // SAFETY: `buffer`, `priority`, and the optional deadline remain live
    // for the syscall. Linux writes no more than `buffer.len()` bytes on a
    // successful receive and initializes the priority word.
    decode(unsafe {
        syscall5(
            SYS_MQ_TIMEDRECEIVE,
            fd as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            priority as *mut u32 as usize,
            deadline.map_or(0, |value| value as *const KernelMqTimespec as usize),
        )
    })
}
