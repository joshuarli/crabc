//! Stateless Linux I/O operations.

use crate::{RawFd, Result};
use crate::syscall::{decode, decode_i32, syscall1, syscall3, syscall4, syscall5, syscall6, SYS_CLOSE, SYS_DUP, SYS_DUP3, SYS_FCNTL, SYS_IOCTL, SYS_PREAD64, SYS_PREADV, SYS_PREADV2, SYS_PWRITE64, SYS_PWRITEV, SYS_PWRITEV2, SYS_READ, SYS_READV, SYS_SENDFILE, SYS_SYNC_FILE_RANGE, SYS_WRITE, SYS_WRITEV};

/// One Linux `struct iovec` record for direct vectored I/O.
///
/// This is an ABI record rather than a safe buffer abstraction. Callers
/// must uphold the pointer and aliasing requirements documented by
/// [`readv_raw`] and [`writev_raw`]. The layout is the Linux/AArch64
/// `struct iovec` layout: a pointer followed by a native `size_t` length.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Iovec {
    /// Start of the byte range described by this record.
    pub iov_base: *mut u8,
    /// Number of bytes in the range.
    pub iov_len: usize,
}

/// Linux `F_DUPFD`: duplicate at or above the requested descriptor.
pub const F_DUPFD: i32 = 0;
/// Linux `F_GETFD`: read descriptor flags.
pub const F_GETFD: i32 = 1;
/// Linux `F_SETFD`: replace descriptor flags.
pub const F_SETFD: i32 = 2;
/// Linux `F_GETFL`: read the open-file-description status flags.
pub const F_GETFL: i32 = 3;
/// Linux `F_SETFL`: replace the open-file-description status flags.
pub const F_SETFL: i32 = 4;
/// Linux `F_GET_SEALS`: read an inode's sealing flags.
pub const F_GET_SEALS: i32 = 1_034;
/// Linux `F_ADD_SEALS`: add sealing flags to an inode.
pub const F_ADD_SEALS: i32 = 1_033;
/// Linux `F_DUPFD_CLOEXEC`: duplicate with close-on-exec set.
pub const F_DUPFD_CLOEXEC: i32 = 1_030;
/// Linux `FD_CLOEXEC` descriptor flag.
pub const FD_CLOEXEC: u32 = 1;
/// Linux `O_CLOEXEC` flag accepted by `dup3`.
pub const O_CLOEXEC: u32 = 0x80000;

/// Duplicates `fd` to the lowest available descriptor.
#[inline]
pub fn dup(fd: RawFd) -> Result<RawFd> {
    // SAFETY: The kernel validates the descriptor and this syscall has one
    // integer argument with no Rust memory preconditions.
    decode_i32(unsafe { syscall1(SYS_DUP, fd as usize) })
}

/// Duplicates `fd` onto `new_fd` with Linux `dup3` flags.
///
/// This is the direct primitive used for both Rustix's `dup2` and `dup3`
/// operations on AArch64, where Linux exposes no separate `dup2` syscall.
/// The caller owns the target descriptor and must preserve that ownership
/// regardless of the result.
#[inline]
pub fn dup3(fd: RawFd, new_fd: RawFd, flags: u32) -> Result<()> {
    // SAFETY: The kernel validates both descriptors and the flags; this
    // syscall has no Rust memory arguments.
    decode(unsafe { syscall3(SYS_DUP3, fd as usize, new_fd as usize, flags as usize) })
        .map(|_| ())
}

/// Performs Rustix/POSIX `dup2` semantics on AArch64.
///
/// Linux implements this through `dup3`. Unlike `dup3`, equal source and
/// target descriptors are a successful no-op, as required by `dup2`.
#[inline]
pub fn dup2(fd: RawFd, new_fd: RawFd) -> Result<()> {
    if fd == new_fd {
        return Ok(());
    }
    dup3(fd, new_fd, 0)
}

/// Reads `FD_*` flags through `fcntl(F_GETFD)`.
#[inline]
pub fn fcntl_getfd(fd: RawFd) -> Result<u32> {
    // SAFETY: F_GETFD ignores its third argument; zero is the canonical
    // immediate argument representation on Linux.
    unsafe { fcntl_raw(fd, F_GETFD, core::ptr::null_mut()) }.map(|flags| flags as u32)
}

/// Replaces `FD_*` flags through `fcntl(F_SETFD)`.
#[inline]
pub fn fcntl_setfd(fd: RawFd, flags: u32) -> Result<()> {
    // SAFETY: F_SETFD takes an immediate integer in the third syscall
    // argument; `fcntl_raw` encodes that integer without dereferencing it.
    unsafe { fcntl_raw(fd, F_SETFD, flags as usize as *mut u8) }.map(|_| ())
}

/// Reads the open-file-description status flags through `fcntl(F_GETFL)`.
///
/// The returned word belongs to the open file description, so duplicate file
/// descriptors observe the same state.
#[inline]
pub fn fcntl_getfl(fd: RawFd) -> Result<u32> {
    // SAFETY: F_GETFL ignores its third argument; zero is the canonical
    // immediate argument representation on Linux.
    unsafe { fcntl_raw(fd, F_GETFL, core::ptr::null_mut()) }.map(|flags| flags as u32)
}

/// Reads an inode's Linux sealing flags through `fcntl(F_GET_SEALS)`.
///
/// The command has no pointer argument. The returned non-negative C `int`
/// is preserved as a raw bitset so the safe facade can retain future
/// kernel-defined seal bits.
#[inline]
pub fn fcntl_get_seals(fd: RawFd) -> Result<u32> {
    // SAFETY: F_GET_SEALS ignores its third argument; zero is the
    // canonical immediate argument representation on Linux.
    unsafe { fcntl_raw(fd, F_GET_SEALS, core::ptr::null_mut()) }.map(|flags| flags as u32)
}

/// Adds Linux sealing flags to an inode through `fcntl(F_ADD_SEALS)`.
#[inline]
pub fn fcntl_add_seals(fd: RawFd, seals: u32) -> Result<()> {
    // SAFETY: F_ADD_SEALS takes the seal bitset as an immediate integer in
    // the third syscall argument; `fcntl_raw` encodes it without
    // dereferencing the value.
    unsafe { fcntl_raw(fd, F_ADD_SEALS, seals as usize as *mut u8) }.map(|_| ())
}

/// Replaces the open-file-description status flags through
/// `fcntl(F_SETFL)`.
///
/// Linux accepts the request at the descriptor boundary and applies only the
/// mutable status bits supported by the underlying open file description.
#[inline]
pub fn fcntl_setfl(fd: RawFd, flags: u32) -> Result<()> {
    // SAFETY: F_SETFL takes an immediate integer in the third syscall
    // argument; `fcntl_raw` encodes that integer without dereferencing it.
    unsafe { fcntl_raw(fd, F_SETFL, flags as usize as *mut u8) }.map(|_| ())
}

/// Duplicates `fd` at or above `minimum` through `fcntl(F_DUPFD)`.
#[inline]
pub fn fcntl_dupfd(fd: RawFd, minimum: RawFd) -> Result<RawFd> {
    // SAFETY: F_DUPFD takes an immediate integer in the third syscall
    // argument; `fcntl_raw` encodes that integer without dereferencing it.
    unsafe { fcntl_raw(fd, F_DUPFD, minimum as u32 as usize as *mut u8) }
}

/// Duplicates `fd` at or above `minimum` with close-on-exec set.
#[inline]
pub fn fcntl_dupfd_cloexec(fd: RawFd, minimum: RawFd) -> Result<RawFd> {
    // SAFETY: F_DUPFD_CLOEXEC takes an immediate integer in the third
    // syscall argument; `fcntl_raw` encodes that integer directly.
    unsafe { fcntl_raw(fd, F_DUPFD_CLOEXEC, minimum as u32 as usize as *mut u8) }
}

/// Synchronizes a byte range through AArch64's Linux `sync_file_range`
/// syscall without using libc or TLS `errno`.
///
/// The public operation calls this seam with the kernel's signed `loff_t`
/// values. AArch64 uses the generic argument order `(fd, offset, nbytes,
/// flags)` for this syscall.
#[inline]
pub fn sync_file_range(fd: RawFd, offset: i64, nbytes: i64, flags: u32) -> Result<()> {
    // SAFETY: The kernel validates the descriptor, flags, and signed byte
    // range. All four arguments are scalar AArch64 syscall registers.
    decode(unsafe {
        syscall4(
            SYS_SYNC_FILE_RANGE,
            fd as usize,
            offset as usize,
            nbytes as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Reads into a raw C-compatible buffer without using libc or TLS `errno`.
///
/// # Safety
///
/// `buffer` must be valid for mutable access to `length` bytes for the
/// duration of the call, unless `length` is zero. The descriptor's I/O
/// safety is the caller's responsibility.
#[inline]
pub unsafe fn read_raw(fd: RawFd, buffer: *mut u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies the raw-buffer validity contract and the
    // kernel validates the descriptor.
    decode(unsafe { syscall3(SYS_READ, fd as usize, buffer as usize, length) })
}

/// Reads into `buffer` without using libc or TLS `errno`.
#[inline]
pub fn read(fd: RawFd, buffer: &mut [u8]) -> Result<usize> {
    // SAFETY: A slice supplies a valid mutable buffer for the exact length.
    unsafe { read_raw(fd, buffer.as_mut_ptr(), buffer.len()) }
}

/// Reads into an array of Linux `struct iovec` records without using libc
/// or TLS `errno`.
///
/// # Safety
///
/// `iovecs` must be null or point to `count` initialized [`Iovec`] records
/// readable for the duration of the call; a null pointer is permitted only
/// when `count` is zero. Every non-empty `iov_base` range must be valid for
/// mutable access for its `iov_len` bytes, and those ranges must be
/// pairwise disjoint. Empty ranges may use any pointer. The descriptor's
/// I/O safety is the caller's responsibility.
#[inline]
pub unsafe fn readv_raw(fd: RawFd, iovecs: *const Iovec, count: usize) -> Result<usize> {
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the kernel validates the descriptor and count.
    decode(unsafe { syscall3(SYS_READV, fd as usize, iovecs as usize, count) })
}

/// Reads from `offset` without changing the descriptor's file position.
///
/// # Safety
///
/// `buffer` must be valid for mutable access to `length` bytes for the
/// duration of the call, unless `length` is zero. `offset` is the
/// non-negative Linux `off_t` value passed to `pread64`; values above
/// `i64::MAX` are rejected by Linux. The descriptor's I/O safety is the
/// caller's responsibility.
#[inline]
pub unsafe fn pread_raw(
    fd: RawFd,
    buffer: *mut u8,
    length: usize,
    offset: u64,
) -> Result<usize> {
    // SAFETY: The caller supplies the raw-buffer validity contract and the
    // kernel validates the descriptor and file offset.
    decode(unsafe {
        syscall4(
            SYS_PREAD64,
            fd as usize,
            buffer as usize,
            length,
            offset as usize,
        )
    })
}

/// Reads from `offset` without changing the descriptor's file position.
#[inline]
pub fn pread(fd: RawFd, buffer: &mut [u8], offset: u64) -> Result<usize> {
    // SAFETY: A slice supplies a valid mutable buffer for the exact length.
    unsafe { pread_raw(fd, buffer.as_mut_ptr(), buffer.len(), offset) }
}

/// Transfers up to `count` bytes from `in_fd` to `out_fd` without using
/// libc or TLS `errno`.
///
/// A non-null `offset` is an in/out pointer to the input file position:
/// Linux starts at its value, leaves the input descriptor's shared offset
/// unchanged, and advances the pointed-to value by the number of bytes
/// transferred. A null pointer starts at and advances the input
/// descriptor's shared offset. The output descriptor's shared offset is
/// advanced in either form.
///
/// # Safety
///
/// `offset` must be null or point to an aligned, writable `u64` for the
/// duration of the call. When non-null, its value is interpreted by Linux
/// as a signed `off_t`; values outside that range are rejected by Linux.
/// The descriptors' I/O validity is the caller's responsibility.
#[inline]
pub unsafe fn sendfile_raw(
    out_fd: RawFd,
    in_fd: RawFd,
    offset: *mut u64,
    count: usize,
) -> Result<usize> {
    // SAFETY: The caller supplies the optional in/out offset pointer
    // validity contract; Linux validates both descriptors and count.
    decode(unsafe {
        syscall4(
            SYS_SENDFILE,
            out_fd as usize,
            in_fd as usize,
            offset as usize,
            count,
        )
    })
}

/// Transfers up to `count` bytes between borrowed descriptors.
///
/// This typed core wrapper keeps the optional offset pointer contract
/// explicit while avoiding a C ABI or process-global error channel.
#[inline]
pub fn sendfile(
    out_fd: RawFd,
    in_fd: RawFd,
    offset: Option<&mut u64>,
    count: usize,
) -> Result<usize> {
    let offset = offset.map_or(core::ptr::null_mut(), |offset| offset);
    // SAFETY: `Option<&mut u64>` supplies either a null pointer or an
    // aligned writable pointer valid for the syscall duration.
    unsafe { sendfile_raw(out_fd, in_fd, offset, count) }
}

/// Reads from `offset` into an array of Linux `struct iovec` records
/// without changing the descriptor's file position or using libc/TLS
/// `errno`.
///
/// Linux's AArch64 `preadv` ABI passes the offset as two 32-bit words:
/// low word first, then high word. This seam keeps the caller's complete
/// non-negative `u64` representation until those registers are formed.
///
/// # Safety
///
/// The iovec-array and pointed-to-buffer requirements are the same as for
/// [`readv_raw`]. `offset` is interpreted as a signed Linux `off_t`; values
/// above `i64::MAX` are rejected by Linux with `EINVAL`.
#[inline]
pub unsafe fn preadv_raw(
    fd: RawFd,
    iovecs: *const Iovec,
    count: usize,
    offset: u64,
) -> Result<usize> {
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the kernel validates the descriptor, count,
    // and signed file offset.
    decode(unsafe {
        syscall5(
            SYS_PREADV,
            fd as usize,
            iovecs as usize,
            count,
            offset as usize,
            (offset >> 32) as usize,
        )
    })
}

/// Reads through Linux `preadv2` without libc or TLS `errno`.
///
/// AArch64 passes the non-negative `offset` as two explicit 32-bit words,
/// low first and high second. Linux reserves `u64::MAX` as the explicit
/// current-file-offset sentinel for this operation; every other value is
/// preserved as a positioned offset.
///
/// # Safety
///
/// The iovec-array and pointed-to-buffer requirements are the same as for
/// [`readv_raw`]. `flags` must contain only Linux `RWF_*` bits accepted by
/// the caller's facade contract.
#[inline]
pub unsafe fn preadv2_raw(
    fd: RawFd,
    iovecs: *const Iovec,
    count: usize,
    offset: u64,
    flags: u32,
) -> Result<usize> {
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the kernel validates the descriptor, offset,
    // and flags. The six scalar arguments occupy x0..x5.
    decode(unsafe {
        syscall6(
            SYS_PREADV2,
            fd as usize,
            iovecs as usize,
            count,
            offset as usize,
            (offset >> 32) as usize,
            flags as usize,
        )
    })
}

/// Writes a raw C-compatible buffer without using libc or TLS `errno`.
///
/// # Safety
///
/// `buffer` must be valid for immutable access to `length` bytes for the
/// duration of the call, unless `length` is zero. The descriptor's I/O
/// safety is the caller's responsibility.
#[inline]
pub unsafe fn write_raw(fd: RawFd, buffer: *const u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies the raw-buffer validity contract and the
    // kernel validates the descriptor.
    decode(unsafe { syscall3(SYS_WRITE, fd as usize, buffer as usize, length) })
}

/// Writes `buffer` without using libc or TLS `errno`.
#[inline]
pub fn write(fd: RawFd, buffer: &[u8]) -> Result<usize> {
    // SAFETY: A slice supplies a valid immutable buffer for the exact length.
    unsafe { write_raw(fd, buffer.as_ptr(), buffer.len()) }
}

/// Writes from an array of Linux `struct iovec` records without using libc
/// or TLS `errno`.
///
/// # Safety
///
/// `iovecs` must be null or point to `count` initialized [`Iovec`] records
/// readable for the duration of the call; a null pointer is permitted only
/// when `count` is zero. Every non-empty `iov_base` range must be valid for
/// immutable access for its `iov_len` bytes. The descriptor's I/O safety is
/// the caller's responsibility.
#[inline]
pub unsafe fn writev_raw(fd: RawFd, iovecs: *const Iovec, count: usize) -> Result<usize> {
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the kernel validates the descriptor and count.
    decode(unsafe { syscall3(SYS_WRITEV, fd as usize, iovecs as usize, count) })
}

/// Writes at `offset` without changing the descriptor's file position.
///
/// # Safety
///
/// `buffer` must be valid for immutable access to `length` bytes for the
/// duration of the call, unless `length` is zero. `offset` is the
/// non-negative Linux `off_t` value passed to `pwrite64`; values above
/// `i64::MAX` are rejected by Linux. The descriptor's I/O safety is the
/// caller's responsibility.
#[inline]
pub unsafe fn pwrite_raw(
    fd: RawFd,
    buffer: *const u8,
    length: usize,
    offset: u64,
) -> Result<usize> {
    // SAFETY: The caller supplies the raw-buffer validity contract and the
    // kernel validates the descriptor and file offset.
    decode(unsafe {
        syscall4(
            SYS_PWRITE64,
            fd as usize,
            buffer as usize,
            length,
            offset as usize,
        )
    })
}

/// Writes at `offset` without changing the descriptor's file position.
#[inline]
pub fn pwrite(fd: RawFd, buffer: &[u8], offset: u64) -> Result<usize> {
    // SAFETY: A slice supplies a valid immutable buffer for the exact length.
    unsafe { pwrite_raw(fd, buffer.as_ptr(), buffer.len(), offset) }
}

/// Writes from an array of Linux `struct iovec` records at `offset`
/// without changing the descriptor's file position or using libc/TLS
/// `errno`.
///
/// Linux's AArch64 `pwritev` ABI passes the offset as two 32-bit words:
/// low word first, then high word. `offset` values above `i64::MAX` are
/// rejected by Linux with `EINVAL`.
///
/// # Safety
///
/// The iovec-array and pointed-to-buffer requirements are the same as for
/// [`writev_raw`].
#[inline]
pub unsafe fn pwritev_raw(
    fd: RawFd,
    iovecs: *const Iovec,
    count: usize,
    offset: u64,
) -> Result<usize> {
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the kernel validates the descriptor, count,
    // and signed file offset.
    decode(unsafe {
        syscall5(
            SYS_PWRITEV,
            fd as usize,
            iovecs as usize,
            count,
            offset as usize,
            (offset >> 32) as usize,
        )
    })
}

/// Writes through Linux `pwritev2` without libc or TLS `errno`.
///
/// AArch64 passes the non-negative `offset` as two explicit 32-bit words,
/// low first and high second. Linux reserves `u64::MAX` as the explicit
/// current-file-offset sentinel for this operation; every other value is
/// preserved as a positioned offset.
///
/// # Safety
///
/// The iovec-array and pointed-to-buffer requirements are the same as for
/// [`writev_raw`]. `flags` must contain only Linux `RWF_*` bits accepted by
/// the caller's facade contract.
#[inline]
pub unsafe fn pwritev2_raw(
    fd: RawFd,
    iovecs: *const Iovec,
    count: usize,
    offset: u64,
    flags: u32,
) -> Result<usize> {
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the kernel validates the descriptor, offset,
    // and flags. The six scalar arguments occupy x0..x5.
    decode(unsafe {
        syscall6(
            SYS_PWRITEV2,
            fd as usize,
            iovecs as usize,
            count,
            offset as usize,
            (offset >> 32) as usize,
            flags as usize,
        )
    })
}

/// Performs an ioctl without using libc or TLS `errno`.
///
/// Linux ioctl returns a signed C `int`. Only the kernel's negative errno
/// range is an error; other negative values are successful ioctl results
/// and are preserved exactly in the returned `i32`.
///
/// # Safety
///
/// `argument` must satisfy the memory contract of `request` for the
/// duration of the call. Requests that carry an integer may pass that
/// integer through the pointer value without dereferencing it.
#[inline]
pub unsafe fn ioctl_raw(fd: RawFd, request: u32, argument: *mut u8) -> Result<i32> {
    // SAFETY: The caller supplies the request-specific argument contract;
    // the kernel validates the descriptor and request.
    decode_i32(unsafe { syscall3(SYS_IOCTL, fd as usize, request as usize, argument as usize) })
}

/// Performs Linux `fcntl` without using libc or TLS `errno`.
///
/// # Safety
///
/// `argument` must satisfy the command-specific Linux `fcntl` contract.
/// Commands using immediate integers must encode that intent explicitly;
/// pointer commands must keep their storage valid for the call.
#[inline]
pub unsafe fn fcntl_raw(fd: RawFd, command: i32, argument: *mut u8) -> Result<i32> {
    // SAFETY: The caller supplies the command-specific argument contract.
    decode_i32(unsafe { syscall3(SYS_FCNTL, fd as usize, command as usize, argument as usize) })
}

/// Closes a raw descriptor without using libc or TLS `errno`.
#[inline]
pub fn close(fd: RawFd) -> Result<()> {
    // SAFETY: The kernel validates the descriptor; `close` has one integer
    // argument and no Rust memory preconditions.
    decode(unsafe { syscall1(SYS_CLOSE, fd as usize) }).map(|_| ())
}
