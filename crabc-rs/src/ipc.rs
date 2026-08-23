//! Owned POSIX message queues over Linux's fixed-arity mq syscalls.
//!
//! The C `mq_open` function is variadic, but Linux's `mq_open(2)` syscall is
//! always four-argument. This module uses that typed kernel ABI directly:
//! callers choose whether to open or create a queue, supply a typed creation
//! attribute, and receive an owned descriptor. Queue names use the POSIX form
//! `/name`; the Linux syscall receives the validated spelling without its
//! leading slash.
//!
//! Message buffers are borrowed only for the syscall. Send and receive use a
//! null timeout for ordinary/nonblocking operations or an explicit absolute
//! `CLOCK_REALTIME` [`Timespec`] for timed operations. There is no notification,
//! SysV IPC, semaphore, AIO, global queue registry, or C static state here.

use bitflags::bitflags;
use core::ffi::CStr;

use crate::path::Arg;
use crate::{AsFd, BorrowedFd, Errno, OwnedFd, Result};

pub use crate::fs::{Mode, Timespec};

/// Highest valid POSIX message priority.
pub const MAX_MESSAGE_PRIORITY: u32 = 32_767;

const MQ_O_CREAT: u32 = 0x0000_0040;
const MQ_O_NONBLOCK: u32 = 0x0000_0800;

bitflags! {
    /// Access and status flags accepted when opening a message queue.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct OpenFlags: u32 {
        /// Open for reading. This is the zero-valued access mode.
        const RDONLY = 0;
        /// Open for writing.
        const WRONLY = 0x0000_0001;
        /// Open for reading and writing.
        const RDWR = 0x0000_0002;
        /// Make send/receive return [`Errno::AGAIN`] instead of waiting.
        const NONBLOCK = MQ_O_NONBLOCK;
        /// Set close-on-exec on the owned descriptor.
        const CLOEXEC = 0x0008_0000;
        /// Preserve future kernel-defined bits for kernel validation.
        const _ = !0;
    }
}

bitflags! {
    /// Creation-only flags accepted by [`create`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct CreateFlags: u32 {
        /// Fail if the named queue already exists.
        const EXCLUSIVE = 0x0000_0080;
        /// Preserve future kernel-defined bits for kernel validation.
        const _ = !0;
    }
}

bitflags! {
    /// Queue status flags returned by [`MessageQueue::attributes`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct QueueFlags: u32 {
        /// Send and receive report [`Errno::AGAIN`] instead of waiting.
        const NONBLOCK = MQ_O_NONBLOCK;
        /// Preserve future kernel-defined status bits.
        const _ = !0;
    }
}

/// A validated message priority in the POSIX range `0..MQ_PRIO_MAX`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessagePriority(u32);

impl MessagePriority {
    /// Constructs a priority, rejecting values outside the POSIX range.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value <= MAX_MESSAGE_PRIORITY {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the Linux priority value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Queue capacity and status attributes.
///
/// `new` creates an attribute suitable for [`create`]. Attributes returned by
/// [`MessageQueue::attributes`] additionally report current queue occupancy and
/// status flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueAttributes {
    flags: QueueFlags,
    max_messages: u64,
    message_size: usize,
    current_messages: u64,
}

impl QueueAttributes {
    /// Creates queue capacity attributes with empty status flags and occupancy.
    pub fn new(max_messages: u64, message_size: usize) -> Result<Self> {
        if max_messages == 0
            || max_messages > i64::MAX as u64
            || message_size == 0
            || message_size as u64 > i64::MAX as u64
        {
            return Err(Errno::INVAL);
        }
        Ok(Self {
            flags: QueueFlags::empty(),
            max_messages,
            message_size,
            current_messages: 0,
        })
    }

    /// Returns queue status flags.
    #[must_use]
    pub const fn flags(self) -> QueueFlags {
        self.flags
    }

    /// Returns the maximum number of queued messages.
    #[must_use]
    pub const fn max_messages(self) -> u64 {
        self.max_messages
    }

    /// Returns the maximum message size in bytes.
    #[must_use]
    pub const fn message_size(self) -> usize {
        self.message_size
    }

    /// Returns the current number of queued messages.
    #[must_use]
    pub const fn current_messages(self) -> u64 {
        self.current_messages
    }

    fn to_kernel(self) -> crabc_core::ipc::KernelMqAttr {
        crabc_core::ipc::KernelMqAttr {
            mq_flags: 0,
            mq_maxmsg: self.max_messages as i64,
            mq_msgsize: self.message_size as i64,
            mq_curmsgs: 0,
            reserved: [0; 4],
        }
    }

    fn from_kernel(value: crabc_core::ipc::KernelMqAttr) -> Result<Self> {
        if value.mq_flags < 0
            || value.mq_flags > u32::MAX as i64
            || value.mq_maxmsg <= 0
            || value.mq_msgsize <= 0
            || value.mq_curmsgs < 0
        {
            return Err(Errno::INVAL);
        }
        let message_size = usize::try_from(value.mq_msgsize).map_err(|_| Errno::OVERFLOW)?;
        Ok(Self {
            flags: QueueFlags::from_bits_retain(value.mq_flags as u32),
            max_messages: value.mq_maxmsg as u64,
            message_size,
            current_messages: value.mq_curmsgs as u64,
        })
    }
}

/// An owned POSIX message-queue descriptor.
pub struct MessageQueue {
    fd: OwnedFd,
}

impl MessageQueue {
    fn from_raw_fd(fd: i32) -> Self {
        // SAFETY: Linux returned a newly owned message-queue descriptor.
        Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    /// Closes the queue descriptor immediately; dropping also closes it.
    pub fn close(self) -> Result<()> {
        self.fd.close()
    }

    /// Returns the current queue attributes without changing them.
    pub fn attributes(&self) -> Result<QueueAttributes> {
        QueueAttributes::from_kernel(crabc_core::ipc::getsetattr(self.fd.as_raw_fd(), None)?)
    }

    /// Enables or disables `O_NONBLOCK`, returning the previous attributes.
    pub fn set_nonblocking(&self, enabled: bool) -> Result<QueueAttributes> {
        let new_attr = crabc_core::ipc::KernelMqAttr {
            mq_flags: if enabled { MQ_O_NONBLOCK as i64 } else { 0 },
            ..crabc_core::ipc::KernelMqAttr::default()
        };
        QueueAttributes::from_kernel(crabc_core::ipc::getsetattr(
            self.fd.as_raw_fd(),
            Some(&new_attr),
        )?)
    }

    /// Sends one message, waiting according to the queue's blocking mode.
    pub fn send(&self, message: &[u8], priority: MessagePriority) -> Result<()> {
        self.send_with_deadline(message, priority, None)
    }

    /// Sends one message until an absolute `CLOCK_REALTIME` deadline.
    pub fn send_until(
        &self,
        message: &[u8],
        priority: MessagePriority,
        deadline: Timespec,
    ) -> Result<()> {
        let deadline = kernel_deadline(deadline)?;
        self.send_with_deadline(message, priority, Some(&deadline))
    }

    fn send_with_deadline(
        &self,
        message: &[u8],
        priority: MessagePriority,
        deadline: Option<&crabc_core::ipc::KernelMqTimespec>,
    ) -> Result<()> {
        crabc_core::ipc::timed_send(self.fd.as_raw_fd(), message, priority.value(), deadline)
    }

    /// Receives one message into `buffer`, returning its length and priority.
    pub fn receive(&self, buffer: &mut [u8]) -> Result<(usize, MessagePriority)> {
        self.receive_with_deadline(buffer, None)
    }

    /// Receives one message until an absolute `CLOCK_REALTIME` deadline.
    pub fn receive_until(
        &self,
        buffer: &mut [u8],
        deadline: Timespec,
    ) -> Result<(usize, MessagePriority)> {
        let deadline = kernel_deadline(deadline)?;
        self.receive_with_deadline(buffer, Some(&deadline))
    }

    fn receive_with_deadline(
        &self,
        buffer: &mut [u8],
        deadline: Option<&crabc_core::ipc::KernelMqTimespec>,
    ) -> Result<(usize, MessagePriority)> {
        let mut raw_priority = 0;
        let length = crabc_core::ipc::timed_receive(
            self.fd.as_raw_fd(),
            buffer,
            &mut raw_priority,
            deadline,
        )?;
        let priority = MessagePriority::new(raw_priority).ok_or(Errno::IO)?;
        Ok((length, priority))
    }
}

impl AsFd for MessageQueue {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Opens an existing POSIX message queue.
pub fn open<P: Arg>(name: P, flags: OpenFlags) -> Result<MessageQueue> {
    if flags.bits() & MQ_O_CREAT != 0 {
        return Err(Errno::INVAL);
    }
    with_queue_name(name, |kernel_name| {
        crabc_core::ipc::open(kernel_name, flags.bits() as i32, 0, None)
            .map(MessageQueue::from_raw_fd)
    })
}

/// Creates or opens a POSIX message queue with typed capacity attributes.
pub fn create<P: Arg>(
    name: P,
    flags: OpenFlags,
    create_flags: CreateFlags,
    mode: Mode,
    attributes: QueueAttributes,
) -> Result<MessageQueue> {
    let kernel_attributes = attributes.to_kernel();
    with_queue_name(name, |kernel_name| {
        crabc_core::ipc::open(
            kernel_name,
            (flags.bits() | MQ_O_CREAT | create_flags.bits()) as i32,
            mode.bits(),
            Some(&kernel_attributes),
        )
        .map(MessageQueue::from_raw_fd)
    })
}

/// Unlinks a POSIX message-queue name. Existing descriptors remain usable
/// until closed, matching Linux's unlink-after-open lifetime rules.
pub fn unlink<P: Arg>(name: P) -> Result<()> {
    with_queue_name(name, crabc_core::ipc::unlink)
}

fn kernel_deadline(deadline: Timespec) -> Result<crabc_core::ipc::KernelMqTimespec> {
    if !(0..1_000_000_000).contains(&deadline.tv_nsec) {
        return Err(Errno::INVAL);
    }
    Ok(crabc_core::ipc::KernelMqTimespec {
        tv_sec: deadline.tv_sec,
        tv_nsec: deadline.tv_nsec,
    })
}

fn with_queue_name<P: Arg, T, F>(name: P, operation: F) -> Result<T>
where
    F: FnOnce(&CStr) -> Result<T>,
{
    name.into_with_c_str(|name| {
        let bytes = name.to_bytes();
        if bytes.len() < 2 || bytes[0] != b'/' || bytes[1..].contains(&b'/') {
            return Err(Errno::INVAL);
        }
        let bytes_with_nul = name.to_bytes_with_nul();
        // SAFETY: `bytes_with_nul[1..]` retains the trailing NUL and has no
        // interior NUL because it came from a valid `CStr`.
        let kernel_name = unsafe { CStr::from_bytes_with_nul_unchecked(&bytes_with_nul[1..]) };
        operation(kernel_name)
    })
}
