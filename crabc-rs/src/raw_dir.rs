//! Allocation-free Linux `getdents64` directory iteration.
//!
//! [`RawDir`] deliberately exposes the kernel record boundary instead of
//! constructing a process-global C `DIR` stream. Callers own the buffer and
//! choose its size. If the kernel reports `EINVAL` for an undersized buffer,
//! drop the iterator, grow the buffer, and construct it again with the same
//! descriptor; Linux continues at the current directory position.

use core::ffi::CStr;
use core::mem::{align_of, MaybeUninit};
use core::slice;

use crate::fs::FileType;
use crate::{AsFd, BorrowedFd, Errno, Result};

const LINUX_DIRENT64_HEADER_SIZE: usize = 19;
const LINUX_DIRENT64_ALIGNMENT: usize = align_of::<u64>();

/// An allocation-free directory iterator backed by caller-owned storage.
pub struct RawDir<'buffer, Fd: AsFd> {
    fd: Fd,
    buffer: &'buffer mut [MaybeUninit<u8>],
    initialized: usize,
    offset: usize,
    pending_seek: Option<i64>,
    failed: bool,
}

impl<'buffer, Fd: AsFd> RawDir<'buffer, Fd> {
    /// Creates a directory iterator using `buffer` for Linux `getdents64`
    /// records.
    ///
    /// The start of the supplied storage is trimmed to the required record
    /// alignment. The remaining bytes retain their original lifetime, and an
    /// entry returned by [`Self::next`] borrows this iterator so it cannot be
    /// held across the next call.
    #[inline]
    pub fn new(fd: Fd, buffer: &'buffer mut [MaybeUninit<u8>]) -> Self {
        let offset = buffer.as_ptr().align_offset(LINUX_DIRENT64_ALIGNMENT);
        let buffer = if offset < buffer.len() {
            &mut buffer[offset..]
        } else {
            &mut []
        };
        Self {
            fd,
            buffer,
            initialized: 0,
            offset: 0,
            pending_seek: None,
            failed: false,
        }
    }

    /// Returns the next validated directory entry, an I/O error, or end of
    /// directory.
    ///
    /// This is intentionally an inherent method rather than `Iterator::next`:
    /// its result borrows the iterator and therefore cannot remain live while
    /// the underlying buffer is refilled.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<RawDirEntry<'_>>> {
        if self.failed {
            return None;
        }
        if let Some(offset) = self.pending_seek {
            match self.seek_to(offset) {
                Ok(_) => self.pending_seek = None,
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
        if self.is_buffer_empty() {
            // SAFETY: `self.buffer` is caller-owned writable storage for the
            // exact passed length and remains live for the syscall.
            let read = unsafe {
                crabc_core::fs::getdents64_raw(
                    self.fd.as_fd().as_raw_fd(),
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len(),
                )
            };
            match read {
                Ok(0) => return None,
                Ok(length) if length <= self.buffer.len() => {
                    self.initialized = length;
                    self.offset = 0;
                }
                Ok(_) => return Some(Err(Errno::IO)),
                Err(error) => return Some(Err(error)),
            }
        }

        let remaining = self.initialized - self.offset;
        if remaining < LINUX_DIRENT64_HEADER_SIZE {
            self.offset = self.initialized;
            return Some(Err(Errno::IO));
        }

        // SAFETY: `offset < initialized <= buffer.len()` at this point.
        let base = unsafe { self.buffer.as_ptr().add(self.offset).cast::<u8>() };
        // SAFETY: `remaining >= 19`, so offsets 0, 8, 16, and 18 are within
        // the initialized prefix. Unaligned loads avoid assuming a malformed
        // record has valid field alignment beyond the aligned buffer start.
        let inode = unsafe { core::ptr::read_unaligned(base.cast::<u64>()) };
        let cookie = unsafe { core::ptr::read_unaligned(base.add(8).cast::<i64>()) };
        let record_length =
            unsafe { core::ptr::read_unaligned(base.add(16).cast::<u16>()) } as usize;
        let d_type = unsafe { base.add(18).read() };
        if record_length <= LINUX_DIRENT64_HEADER_SIZE || record_length > remaining {
            self.offset = self.initialized;
            return Some(Err(Errno::IO));
        }

        // SAFETY: `record_length <= remaining` establishes this entire record
        // lies in the initialized prefix. Locate a NUL before constructing the
        // C string instead of trusting the nominal flexible-array size.
        let name_bytes = unsafe {
            slice::from_raw_parts(
                base.add(LINUX_DIRENT64_HEADER_SIZE),
                record_length - LINUX_DIRENT64_HEADER_SIZE,
            )
        };
        let Some(nul) = name_bytes.iter().position(|byte| *byte == 0) else {
            self.offset = self.initialized;
            return Some(Err(Errno::IO));
        };
        let name_with_nul = &name_bytes[..=nul];
        // SAFETY: The preceding search established a NUL terminator in the
        // selected prefix.
        let file_name = unsafe { CStr::from_bytes_with_nul_unchecked(name_with_nul) };
        self.offset += record_length;
        Some(Ok(RawDirEntry {
            file_name,
            file_type: FileType::from_dirent_d_type(d_type),
            inode_number: inode,
            next_entry_cookie: cookie,
        }))
    }

    /// Rewinds the directory stream to its beginning on the next call to
    /// [`Self::next`], matching Rustix's deferred `rewinddir` behavior.
    ///
    /// Existing records are discarded immediately. If Linux rejects the
    /// eventual `lseek(fd, 0, SEEK_SET)`, after retrying interruption, the
    /// next call returns that error and the stream becomes exhausted.
    #[inline]
    pub fn rewind(&mut self) {
        self.initialized = 0;
        self.offset = 0;
        self.pending_seek = Some(0);
        self.failed = false;
    }

    /// Seeks to a Linux directory-entry cookie and discards buffered records.
    ///
    /// `offset` is the `d_off` cookie exposed by
    /// [`RawDirEntry::next_entry_cookie`], not a byte position. The direct
    /// `lseek(fd, offset, SEEK_SET)` error is returned immediately after
    /// retrying interruption; after a failure, the stream is exhausted.
    #[inline]
    pub fn seek(&mut self, offset: i64) -> Result<()> {
        self.initialized = 0;
        self.offset = 0;
        self.pending_seek = None;
        self.failed = false;
        match self.seek_to(offset) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Borrows the descriptor used by this iterator without transferring its
    /// ownership.
    #[inline]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Performs Rustix's interrupted-directory-seek retry policy.
    #[inline]
    fn seek_to(&self, offset: i64) -> Result<()> {
        loop {
            match crabc_core::fs::lseek(
                self.fd.as_fd().as_raw_fd(),
                offset,
                crabc_core::fs::SEEK_SET,
            ) {
                Err(Errno::INTR) => continue,
                Ok(_) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    /// Returns true when the next call will refill the caller buffer.
    #[inline]
    pub fn is_buffer_empty(&self) -> bool {
        self.offset >= self.initialized
    }
}

/// One `getdents64` record borrowed from a [`RawDir`] buffer.
#[derive(Debug)]
pub struct RawDirEntry<'entry> {
    file_name: &'entry CStr,
    file_type: FileType,
    inode_number: u64,
    next_entry_cookie: i64,
}

impl RawDirEntry<'_> {
    /// Returns the entry name as bytes without its trailing NUL.
    ///
    /// Linux pathnames are byte sequences rather than required UTF-8. The
    /// returned slice borrows the current directory buffer and therefore
    /// cannot outlive the entry or the iterator refill which produced it.
    #[inline]
    pub fn name_bytes(&self) -> &[u8] {
        self.file_name.to_bytes()
    }

    /// Returns the byte-preserving entry name.
    #[inline]
    pub fn file_name(&self) -> &CStr {
        self.file_name
    }

    /// Returns the file type reported by the directory record.
    #[inline]
    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    /// Returns the entry inode number.
    #[inline]
    #[doc(alias = "inode_number")]
    pub fn ino(&self) -> u64 {
        self.inode_number
    }

    /// Returns the seek cookie for the next entry.
    #[inline]
    #[doc(alias = "off")]
    pub fn next_entry_cookie(&self) -> u64 {
        self.next_entry_cookie as u64
    }
}
