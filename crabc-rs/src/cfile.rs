//! Owned buffered memory streams through crabc's private libc runtime table.
//!
//! A [`CFile`] is deliberately narrower than C's public `FILE *` API: it can
//! only borrow a caller-provided byte buffer, and it owns one close operation.
//! libc remains the sole owner of buffered stream state and the backing `FILE`
//! allocation. The Rust facade carries neither a C `FILE` layout nor C errno
//! or sentinel semantics across its boundary.
//!
//! The direct methods are the primary no-std API. With the `std` feature,
//! [`std::io::Read`], [`std::io::Write`], and [`std::io::Seek`] adapt the same
//! operations using ordinary OS errors, following Rust's standard I/O model.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crabc_core::runtime::{
    CFileHandleV1, RuntimeV1, CFILE_MODE_APPEND, CFILE_MODE_APPEND_UPDATE, CFILE_MODE_READ,
    CFILE_MODE_READ_UPDATE, CFILE_MODE_WRITE, CFILE_MODE_WRITE_UPDATE, CFILE_SEEK_CURRENT,
    CFILE_SEEK_END, CFILE_SEEK_START, V1_ABI_VERSION, V1_LEGACY_SIZE,
};

use crate::{Errno, Result};

extern "C" {
    fn __crabc_runtime_v1() -> *const RuntimeV1;
}

fn runtime() -> Result<&'static RuntimeV1> {
    // SAFETY: A crabc process exports this explicit private getter from its
    // loaded libc. The returned table is immutable process-lifetime state.
    let runtime = unsafe { __crabc_runtime_v1() };
    let runtime = NonNull::new(runtime.cast_mut()).ok_or(Errno::INVAL)?;
    // SAFETY: The non-null pointer is owned by the loaded libc for the
    // process lifetime, as defined by the private runtime-table contract.
    let runtime = unsafe { runtime.as_ref() };
    if runtime.abi_version != V1_ABI_VERSION || runtime.abi_size < V1_LEGACY_SIZE as u32 {
        return Err(Errno::INVAL);
    }
    Ok(runtime)
}

fn status(status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        // Private callbacks transport a positive Linux error directly. Do
        // not consult C TLS errno if a malformed runtime returns another
        // value: its table is not a public C ABI.
        Err(Errno::from_raw(status).unwrap_or(Errno::INVAL))
    }
}

/// Direction and initial-position policy for [`CFile::from_memory`].
///
/// The three `*Update` modes correspond to C `r+`, `w+`, and `a+`,
/// respectively. The unidirectional modes reject the opposite native
/// operation with [`Errno::BADF`] before it reaches libc's buffered state.
/// This makes a mode mistake explicit even when a future C implementation
/// changes its internal `fmemopen` direction checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FileMode {
    /// Read an existing buffer from its beginning (`r`).
    Read,
    /// Truncate then write from the beginning (`w`).
    Write,
    /// Write at the existing NUL-terminated content end (`a`).
    Append,
    /// Read and write without truncating (`r+`).
    ReadUpdate,
    /// Truncate, then read and write (`w+`).
    WriteUpdate,
    /// Append, then read and write (`a+`).
    AppendUpdate,
}

impl FileMode {
    const fn wire(self) -> u32 {
        match self {
            Self::Read => CFILE_MODE_READ,
            Self::Write => CFILE_MODE_WRITE,
            Self::Append => CFILE_MODE_APPEND,
            Self::ReadUpdate => CFILE_MODE_READ_UPDATE,
            Self::WriteUpdate => CFILE_MODE_WRITE_UPDATE,
            Self::AppendUpdate => CFILE_MODE_APPEND_UPDATE,
        }
    }

    const fn readable(self) -> bool {
        matches!(
            self,
            Self::Read | Self::ReadUpdate | Self::WriteUpdate | Self::AppendUpdate
        )
    }

    const fn writable(self) -> bool {
        matches!(
            self,
            Self::Write | Self::Append | Self::ReadUpdate | Self::WriteUpdate | Self::AppendUpdate
        )
    }
}

/// A seek origin for [`CFile::seek`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SeekFrom {
    /// Seek to an absolute offset from the beginning of the memory buffer.
    Start(u64),
    /// Seek relative to the current byte position.
    Current(i64),
    /// Seek relative to the logical stream end.
    End(i64),
}

/// An owned close-on-drop buffered stream over one borrowed memory buffer.
///
/// This handle is intentionally neither `Send` nor `Sync`: the underlying
/// libc `FILE` carries mutable buffered state, while the type holds an
/// exclusive borrow of its backing bytes. Call [`close`](Self::close) to
/// observe a final flush error; dropping the handle always makes the same
/// close attempt but cannot report its status.
pub struct CFile<'buffer> {
    handle: Option<NonNull<c_void>>,
    mode: FileMode,
    _buffer: PhantomData<&'buffer mut [u8]>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl<'buffer> CFile<'buffer> {
    /// Opens an owned buffered stream over `buffer` using `mode`.
    ///
    /// The stream never allocates in this crate. Its libc-owned `FILE` and
    /// bookkeeping allocation are released by [`close`](Self::close) or
    /// [`Drop`]; the caller continues to own `buffer` and regains access only
    /// after the `CFile` borrow ends.
    pub fn from_memory(buffer: &'buffer mut [u8], mode: FileMode) -> Result<Self> {
        let mut handle = core::ptr::null_mut::<c_void>();
        // SAFETY: `buffer` is exclusively borrowed for `'buffer`; libc only
        // retains the pointer while the returned CFile holds that borrow. The
        // out-pointer is a writable stack value and the private call retains
        // neither it nor the FileMode value.
        status(unsafe {
            (runtime()?.cfile_open_memory)(
                buffer.as_mut_ptr(),
                buffer.len(),
                mode.wire(),
                &mut handle,
            )
        })?;
        let handle = NonNull::new(handle).ok_or(Errno::INVAL)?;
        Ok(Self {
            handle: Some(handle),
            mode,
            _buffer: PhantomData,
            _not_send_or_sync: PhantomData,
        })
    }

    fn handle(&self) -> Result<CFileHandleV1> {
        self.handle.map(NonNull::as_ptr).ok_or(Errno::INVAL)
    }

    fn close_inner(&mut self) -> Result<()> {
        let handle = self.handle.take().ok_or(Errno::INVAL)?;
        // SAFETY: `handle` was returned by this private table and has not
        // previously been closed because `take` clears it before the call.
        status(unsafe { (runtime()?.cfile_close)(handle.as_ptr()) })
    }

    /// Reads up to `destination.len()` bytes from this stream.
    ///
    /// A zero-length successful result is ordinary end-of-file. Reading a
    /// write-only or append-only stream returns [`Errno::BADF`].
    pub fn read(&mut self, destination: &mut [u8]) -> Result<usize> {
        if !self.mode.readable() {
            return Err(Errno::BADF);
        }
        let mut read = 0;
        // SAFETY: The handle is live and uniquely borrowed through `&mut
        // self`; `destination` remains writable for the synchronous call.
        status(unsafe {
            (runtime()?.cfile_read)(
                self.handle()?,
                destination.as_mut_ptr(),
                destination.len(),
                &mut read,
            )
        })?;
        Ok(read)
    }

    /// Writes up to `source.len()` bytes to this stream.
    ///
    /// A short successful result is possible when the supplied fixed memory
    /// buffer has no remaining capacity. Writing a read-only stream returns
    /// [`Errno::BADF`].
    pub fn write(&mut self, source: &[u8]) -> Result<usize> {
        if !self.mode.writable() {
            return Err(Errno::BADF);
        }
        let mut written = 0;
        // SAFETY: The handle is live and uniquely borrowed through `&mut
        // self`; `source` remains readable for the synchronous call.
        status(unsafe {
            (runtime()?.cfile_write)(self.handle()?, source.as_ptr(), source.len(), &mut written)
        })?;
        Ok(written)
    }

    /// Flushes buffered output to the borrowed memory buffer.
    pub fn flush(&mut self) -> Result<()> {
        // SAFETY: This live handle belongs to the private runtime table and
        // the call does not retain the Rust reference.
        status(unsafe { (runtime()?.cfile_flush)(self.handle()?) })
    }

    /// Seeks and returns the resulting absolute byte position.
    pub fn seek(&mut self, origin: SeekFrom) -> Result<u64> {
        let (offset, origin) = match origin {
            SeekFrom::Start(offset) => {
                let offset = i64::try_from(offset).map_err(|_| Errno::INVAL)?;
                (offset, CFILE_SEEK_START)
            }
            SeekFrom::Current(offset) => (offset, CFILE_SEEK_CURRENT),
            SeekFrom::End(offset) => (offset, CFILE_SEEK_END),
        };
        let mut position = 0;
        // SAFETY: The handle is live and the output pointer is a writable
        // stack value that the private call does not retain.
        status(unsafe { (runtime()?.cfile_seek)(self.handle()?, offset, origin, &mut position) })?;
        Ok(position)
    }

    /// Returns the current absolute byte position.
    pub fn tell(&self) -> Result<u64> {
        let mut position = 0;
        // SAFETY: The handle is live and the output pointer is a writable
        // stack value that the private call does not retain.
        status(unsafe { (runtime()?.cfile_tell)(self.handle()?, &mut position) })?;
        Ok(position)
    }

    /// Returns whether a prior read reached the end of the logical stream.
    pub fn eof(&self) -> Result<bool> {
        let mut eof = 0;
        // SAFETY: The handle is live and the output pointer is a writable
        // stack value that the private call does not retain.
        status(unsafe { (runtime()?.cfile_eof)(self.handle()?, &mut eof) })?;
        Ok(eof != 0)
    }

    /// Returns whether libc recorded a stream error.
    pub fn error(&self) -> Result<bool> {
        let mut error = 0;
        // SAFETY: The handle is live and the output pointer is a writable
        // stack value that the private call does not retain.
        status(unsafe { (runtime()?.cfile_error)(self.handle()?, &mut error) })?;
        Ok(error != 0)
    }

    /// Rewinds to byte zero and clears the EOF/error indicators.
    pub fn reset(&mut self) -> Result<()> {
        // SAFETY: The handle is live and the call retains no Rust reference.
        status(unsafe { (runtime()?.cfile_reset)(self.handle()?) })
    }

    /// Flushes, closes, and releases the libc-owned stream allocation.
    ///
    /// The handle is consumed even if the final flush reports an error,
    /// matching C close lifetime semantics. Use this method when final-flush
    /// failure matters; [`Drop`] makes the same best-effort close attempt.
    pub fn close(mut self) -> Result<()> {
        self.close_inner()
    }
}

impl Drop for CFile<'_> {
    fn drop(&mut self) {
        if self.handle.is_some() {
            // Drop cannot surface a final flush failure. `close_inner` clears
            // the handle before entering libc, so it never closes twice.
            let _ = self.close_inner();
        }
    }
}

#[cfg(feature = "std")]
fn io_error(error: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw())
}

#[cfg(feature = "std")]
impl std::io::Read for CFile<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        CFile::read(self, buffer).map_err(io_error)
    }
}

#[cfg(feature = "std")]
impl std::io::Write for CFile<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        CFile::write(self, buffer).map_err(io_error)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        CFile::flush(self).map_err(io_error)
    }
}

#[cfg(feature = "std")]
impl std::io::Seek for CFile<'_> {
    fn seek(&mut self, origin: std::io::SeekFrom) -> std::io::Result<u64> {
        let origin = match origin {
            std::io::SeekFrom::Start(offset) => SeekFrom::Start(offset),
            std::io::SeekFrom::Current(offset) => SeekFrom::Current(offset),
            std::io::SeekFrom::End(offset) => SeekFrom::End(offset),
        };
        CFile::seek(self, origin).map_err(io_error)
    }
}
