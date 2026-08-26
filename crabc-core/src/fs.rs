//! Stateless Linux/AArch64 filesystem operations.

use core::ffi::CStr;

use crate::{RawFd, Result};
use crate::syscall::{decode, decode_i32, decode_i64, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, SYS_COPY_FILE_RANGE, SYS_FACCESSAT, SYS_FACCESSAT2, SYS_FADVISE64, SYS_FALLOCATE, SYS_FCHMOD, SYS_FCHMODAT, SYS_FCHOWN, SYS_FCHOWNAT, SYS_FDATASYNC, SYS_FGETXATTR, SYS_FLISTXATTR, SYS_FLOCK, SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_FSTAT, SYS_FSTATFS, SYS_FSYNC, SYS_FTRUNCATE, SYS_GETDENTS64, SYS_GETXATTR, SYS_LGETXATTR, SYS_LINKAT, SYS_LISTXATTR, SYS_LLISTXATTR, SYS_LREMOVEXATTR, SYS_LSEEK, SYS_LSETXATTR, SYS_MEMFD_CREATE, SYS_MKDIRAT, SYS_MKNODAT, SYS_NEWFSTATAT, SYS_OPENAT, SYS_OPENAT2, SYS_READAHEAD, SYS_READLINKAT, SYS_REMOVEXATTR, SYS_RENAMEAT2, SYS_SETXATTR, SYS_STATFS, SYS_STATX, SYS_SYMLINKAT, SYS_SYNC, SYS_SYNCFS, SYS_TRUNCATE, SYS_UNLINKAT, SYS_UTIMENSAT};

// This is the private Linux/AArch64 wire layout for `struct statx`.
// Keep it private: callers receive a typed facade value, while this type
// makes the output pointer passed to the kernel carry the exact ABI size
// and alignment contract.
#[repr(C)]
struct KernelStatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
struct KernelStatx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: [u16; 1],
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: KernelStatxTimestamp,
    stx_btime: KernelStatxTimestamp,
    stx_ctime: KernelStatxTimestamp,
    stx_mtime: KernelStatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    stx_subvol: u64,
    stx_atomic_write_unit_min: u32,
    stx_atomic_write_unit_max: u32,
    stx_atomic_write_segments_max: u32,
    stx_dio_read_offset_align: u32,
    stx_atomic_write_unit_max_opt: u32,
    __spare2: [u32; 1],
    __spare3: [u64; 8],
}

const _: [(); 256] = [(); core::mem::size_of::<KernelStatx>()];
const STATX_RESERVED: u32 = 0x8000_0000;
const STATX_KNOWN_MASK: u32 = 0x0000_3fff;

/// Linux `SEEK_SET`: position from the beginning of the file.
pub const SEEK_SET: u32 = 0;
/// Linux `SEEK_CUR`: position relative to the current file offset.
pub const SEEK_CUR: u32 = 1;
/// Linux `SEEK_END`: position relative to the end of the file.
pub const SEEK_END: u32 = 2;
/// Linux `SEEK_DATA`: position at the next data region.
pub const SEEK_DATA: u32 = 3;
/// Linux `SEEK_HOLE`: position at the next hole.
pub const SEEK_HOLE: u32 = 4;

/// Repositions a descriptor using Linux's `lseek` ABI without using libc
/// or TLS `errno`.
///
/// The signed `offset` is the kernel's `off_t` representation. The
/// returned position is signed at this low-level boundary because it is
/// the direct syscall result; successful Linux seeks are non-negative.
#[inline]
pub fn lseek(fd: RawFd, offset: i64, whence: u32) -> Result<i64> {
    // SAFETY: The kernel validates the descriptor, offset, and whence.
    decode_i64(unsafe { syscall3(SYS_LSEEK, fd as usize, offset as usize, whence as usize) })
}

/// Flushes file data and metadata for an open descriptor without using
/// libc or TLS `errno`.
#[inline]
pub fn fsync(fd: RawFd) -> Result<()> {
    // SAFETY: The kernel validates the descriptor.
    decode(unsafe { syscall1(SYS_FSYNC, fd as usize) }).map(|_| ())
}

/// Flushes file data for an open descriptor without using libc or TLS
/// `errno`.
#[inline]
pub fn fdatasync(fd: RawFd) -> Result<()> {
    // SAFETY: The kernel validates the descriptor.
    decode(unsafe { syscall1(SYS_FDATASYNC, fd as usize) }).map(|_| ())
}

/// Flushes pending filesystem metadata and cached file data for all
/// filesystems without using libc or TLS `errno`.
///
/// Linux `sync(2)` has process/system-wide scope: it is not limited to the
/// caller's descriptors or to one mounted filesystem. Linux waits for
/// writeback I/O completion before returning, while POSIX permits
/// `sync()` to schedule writes and return before the actual writes finish.
/// This completion point is kernel/filesystem writeback completion; it is
/// not a promise that every device's volatile write cache has committed to
/// nonvolatile media. Linux defines this syscall as always successful, so
/// the direct seam has the Rustix-shaped `()` return and does not expose an
/// errno result.
#[inline]
pub fn sync() {
    // SAFETY: `sync` takes no arguments. Linux defines the syscall as
    // always successful; discard its raw return exactly as Rustix does.
    let _ = unsafe { syscall0(SYS_SYNC) };
}

/// Gives Linux a POSIX filesystem access-pattern advisory through the
/// AArch64 `fadvise64` ABI without using libc or TLS `errno`.
///
/// `offset` and `length` are the signed Linux/AArch64 `loff_t` values. The
/// native facade validates its unsigned API before converting to these
/// arguments.
#[inline]
pub fn fadvise64(fd: RawFd, offset: i64, length: i64, advice: u32) -> Result<()> {
    // SAFETY: The kernel validates the descriptor, signed offsets, length,
    // and POSIX_FADV policy value.
    decode(unsafe {
        syscall4(
            SYS_FADVISE64,
            fd as usize,
            offset as usize,
            length as usize,
            advice as usize,
        )
    })
    .map(|_| ())
}

/// Initiates Linux file readahead through the AArch64 syscall ABI without
/// using libc or TLS `errno`.
///
/// `offset` is the signed Linux `loff_t` byte offset. `count` is the
/// AArch64 `size_t` byte count; the native facade validates the unsigned
/// caller range and its end before converting `offset` here.
#[inline]
pub fn readahead(fd: RawFd, offset: i64, count: usize) -> Result<()> {
    // SAFETY: The kernel validates the descriptor and file type. The
    // scalar arguments are the Linux/AArch64 readahead ABI.
    decode(unsafe { syscall3(SYS_READAHEAD, fd as usize, offset as usize, count) }).map(|_| ())
}

/// Copies up to `len` bytes between two descriptors through Linux's
/// `copy_file_range` syscall without using libc or TLS `errno`.
///
/// Each supplied offset is an in/out pointer to a signed Linux `loff_t`:
/// Linux starts from its value, leaves that descriptor's shared position
/// unchanged, and advances the pointed-to value by the number of bytes
/// copied. A null pointer selects and advances the descriptor's shared
/// position. The final syscall argument is fixed at zero because this
/// bounded seam does not expose filesystem-specific copy flags.
///
/// The caller must keep each optional offset aligned and writable for the
/// duration of the call. The descriptors' I/O validity is the caller's
/// responsibility.
#[inline]
pub fn copy_file_range(
    in_fd: RawFd,
    in_offset: Option<&mut u64>,
    out_fd: RawFd,
    out_offset: Option<&mut u64>,
    len: usize,
) -> Result<usize> {
    let in_offset = in_offset.map_or(core::ptr::null_mut(), |offset| offset);
    let out_offset = out_offset.map_or(core::ptr::null_mut(), |offset| offset);
    // SAFETY: Optional mutable references provide either null pointers or
    // aligned writable storage for the syscall duration. Linux validates
    // both descriptors, the signed offsets, and the copy range.
    decode(unsafe {
        syscall6(
            SYS_COPY_FILE_RANGE,
            in_fd as usize,
            in_offset as usize,
            out_fd as usize,
            out_offset as usize,
            len,
            0,
        )
    })
}

/// Flushes all pending filesystem data associated with the descriptor's
/// mounted filesystem without using libc or TLS `errno`.
#[inline]
pub fn syncfs(fd: RawFd) -> Result<()> {
    // SAFETY: The kernel validates the descriptor and identifies its
    // mounted filesystem for the direct sync operation.
    decode(unsafe { syscall1(SYS_SYNCFS, fd as usize) }).map(|_| ())
}

/// Sets the length of a pathname-selected file without using libc or TLS
/// `errno`.
///
/// `length` is the signed Linux `loff_t` representation. The public
/// facade validates its unsigned byte-count API before constructing the
/// pathname or issuing this direct syscall.
#[inline]
pub fn truncate(path: &CStr, length: i64) -> Result<()> {
    // SAFETY: `CStr` supplies a readable NUL-terminated pathname, and the
    // kernel validates the signed file length and pathname permissions.
    decode(unsafe { syscall2(SYS_TRUNCATE, path.as_ptr() as usize, length as usize) })
        .map(|_| ())
}

/// Sets the length of an open file without using libc or TLS `errno`.
///
/// `length` is the signed Linux `loff_t` representation. The kernel
/// rejects negative lengths with `EINVAL`; retaining that representation
/// here keeps this seam a direct syscall boundary.
#[inline]
pub fn ftruncate(fd: RawFd, length: i64) -> Result<()> {
    // SAFETY: The kernel validates the descriptor and signed file length.
    decode(unsafe { syscall2(SYS_FTRUNCATE, fd as usize, length as usize) }).map(|_| ())
}

/// Allocates or transforms a range in an open file without using libc or
/// TLS `errno`.
///
/// `offset` and `length` are the signed Linux `loff_t` representation.
/// The AArch64 Linux ABI passes both values as full-width registers after
/// the descriptor and `mode` arguments; unlike 32-bit ABIs, no high/low
/// word splitting is used here.
#[inline]
pub fn fallocate(fd: RawFd, mode: u32, offset: i64, length: i64) -> Result<()> {
    // SAFETY: The kernel validates the descriptor, mode, and signed file
    // range. All four arguments are scalar AArch64 syscall registers.
    decode(unsafe {
        syscall4(
            SYS_FALLOCATE,
            fd as usize,
            mode as usize,
            offset as usize,
            length as usize,
        )
    })
    .map(|_| ())
}

/// Tests a pathname using Linux's standard `access()` behavior.
///
/// AArch64 has no separate `access` syscall, so musl's public wrapper
/// selects `faccessat(AT_FDCWD, path, mode, 0)`. The Linux/AArch64 kernel
/// syscall itself has only the three arguments `(dirfd, path, mode)`; the
/// public wrapper's trailing zero is not a kernel flags argument. The
/// kernel resolves `path` from the process current working directory and
/// checks permissions using the real (not effective) UID and GID. This
/// seam does not expose the distinct `faccessat2` flags contract.
#[inline]
pub fn access(path: &CStr, mode: u32) -> Result<()> {
    // SAFETY: `CStr` guarantees a readable NUL-terminated pathname. The
    // kernel validates the access mode and performs the real-ID check.
    decode(unsafe {
        syscall3(
            SYS_FACCESSAT,
            crate::AT_FDCWD as usize,
            path.as_ptr() as usize,
            mode as usize,
        )
    })
    .map(|_| ())
}

/// Tests a pathname relative to `dirfd` using Linux's flags-bearing
/// `faccessat2` contract when `flags` is nonzero.
///
/// An empty flag word uses AArch64's three-argument `faccessat` syscall.
/// A nonempty flag word uses `faccessat2` directly and therefore preserves
/// `NOSYS` on kernels predating that syscall; this seam performs no
/// fallback, credential emulation, or availability caching. The safe
/// facade restricts the flag word to `AT_EACCESS` and
/// `AT_SYMLINK_NOFOLLOW`.
#[inline]
pub fn accessat(dirfd: RawFd, path: &CStr, mode: u32, flags: u32) -> Result<()> {
    // SAFETY: `CStr` guarantees a readable NUL-terminated pathname. The
    // kernel validates the descriptor, access mode, and supported flags;
    // the facade validates its closed flag set before reaching here.
    decode(if flags == 0 {
        unsafe {
            syscall3(
                SYS_FACCESSAT,
                dirfd as usize,
                path.as_ptr() as usize,
                mode as usize,
            )
        }
    } else {
        unsafe {
            syscall4(
                SYS_FACCESSAT2,
                dirfd as usize,
                path.as_ptr() as usize,
                mode as usize,
                flags as usize,
            )
        }
    })
    .map(|_| ())
}

/// Opens a raw C-compatible path relative to `dirfd` without using libc or
/// TLS `errno`.
///
/// # Safety
///
/// `path` must point to a NUL-terminated pathname readable by the kernel.
/// The descriptor's I/O safety is the caller's responsibility.
#[inline]
pub unsafe fn openat_raw(
    dirfd: RawFd,
    path: *const u8,
    flags: i32,
    mode: u32,
) -> Result<RawFd> {
    // SAFETY: The caller supplies the C-string validity contract. The
    // kernel validates the descriptor and flag/mode combinations.
    decode(unsafe {
        syscall4(
            SYS_OPENAT,
            dirfd as usize,
            path as usize,
            flags as usize,
            mode as usize,
        )
    })
    .map(|fd| fd as RawFd)
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Opens a raw C-compatible path with Linux `openat2` without using libc
/// or TLS `errno`.
///
/// # Safety
///
/// `path` must point to a NUL-terminated pathname readable by the kernel.
/// The descriptor's I/O safety is the caller's responsibility.
#[inline]
pub unsafe fn openat2_raw(
    dirfd: RawFd,
    path: *const u8,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> Result<RawFd> {
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    // SAFETY: The caller supplies the C-string validity contract. `how`
    // is the exact Linux/AArch64 open_how ABI and stays live for the call.
    decode(unsafe {
        syscall4(
            SYS_OPENAT2,
            dirfd as usize,
            path as usize,
            core::ptr::addr_of!(how) as usize,
            core::mem::size_of::<OpenHow>(),
        )
    })
    .map(|fd| fd as RawFd)
}

/// Opens a C string with Linux `openat2` without using libc or TLS
/// `errno`.
#[inline]
pub fn openat2(
    dirfd: RawFd,
    path: &CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> Result<RawFd> {
    // SAFETY: `CStr` supplies a NUL-terminated pathname that remains live
    // for the exact duration of this direct syscall.
    unsafe { openat2_raw(dirfd, path.as_ptr().cast(), flags, mode, resolve) }
}

/// Opens `path` relative to `dirfd` without using libc or TLS `errno`.
///
/// `flags` and `mode` retain their Linux C ABI bit representations at this
/// private, typed-operation boundary; the public Rust facade supplies
/// strong flag and mode types.
#[inline]
pub fn openat(dirfd: RawFd, path: &CStr, flags: i32, mode: u32) -> Result<RawFd> {
    // SAFETY: `CStr` guarantees the raw C-string contract required above.
    unsafe { openat_raw(dirfd, path.as_ptr().cast(), flags, mode) }
}

/// Creates an anonymous Linux memory file without using libc or TLS
/// `errno`.
///
/// `name` must remain a valid NUL-terminated byte string for the syscall;
/// the public facade supplies that contract through `Arg`.
#[inline]
pub fn memfd_create(name: &CStr, flags: u32) -> Result<RawFd> {
    // SAFETY: `CStr` supplies the name pointer and Linux validates the
    // name length and MFD flag word.
    decode_i32(unsafe { syscall2(SYS_MEMFD_CREATE, name.as_ptr() as usize, flags as usize) })
}

/// Queries the Linux/AArch64 `struct statx` representation for a C path.
///
/// This is a direct, stateless syscall seam. It intentionally propagates
/// `ENOSYS` instead of emulating musl's compatibility fallback or caching
/// process-wide availability state.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `buffer`
/// must designate writable, correctly aligned storage for the complete
/// 256-byte Linux/AArch64 `struct statx` layout.
#[inline]
pub unsafe fn statx_raw(
    dirfd: RawFd,
    path: *const u8,
    flags: u32,
    mask: u32,
    buffer: *mut u8,
) -> Result<()> {
    // Rustix rejects this reserved bit before entering the kernel. Future
    // bits are masked so an extended kernel cannot write beyond the
    // private wire layout known by this crate.
    if mask & STATX_RESERVED != 0 {
        return Err(crate::Errno::INVAL);
    }
    let mask = mask & STATX_KNOWN_MASK;
    let buffer = buffer.cast::<KernelStatx>();
    // SAFETY: The caller supplies the path and complete statx output
    // storage contract; the kernel validates dirfd, flags, and mask.
    decode(unsafe {
        syscall5(
            SYS_STATX,
            dirfd as usize,
            path as usize,
            flags as usize,
            mask as usize,
            buffer as usize,
        )
    })
    .map(|_| ())
}

/// Queries the Linux target's `struct stat` representation for `fd`.
///
/// # Safety
///
/// `buffer` must designate writable storage for the complete target
/// Linux `struct stat` layout selected for this target. The descriptor's I/O safety is the
/// caller's responsibility.
#[inline]
pub unsafe fn fstat_raw(fd: RawFd, buffer: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies complete writable `struct stat`
    // storage; the kernel validates the descriptor.
    decode(unsafe { syscall2(SYS_FSTAT, fd as usize, buffer as usize) }).map(|_| ())
}

/// Queries the Linux/AArch64 `struct statfs` representation for `fd`.
///
/// # Safety
///
/// `buffer` must designate writable storage for the complete target
/// Linux/AArch64 `struct statfs` layout. The descriptor's I/O safety is
/// the caller's responsibility.
#[inline]
pub unsafe fn fstatfs_raw(fd: RawFd, buffer: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies complete writable `struct statfs`
    // storage; the kernel validates the descriptor.
    decode(unsafe { syscall2(SYS_FSTATFS, fd as usize, buffer as usize) }).map(|_| ())
}

/// Queries the Linux/AArch64 `struct statfs` representation for a C path.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `buffer`
/// must designate writable storage for the complete target Linux/AArch64
/// `struct statfs` layout.
#[inline]
pub unsafe fn statfs_raw(path: *const u8, buffer: *mut u8) -> Result<()> {
    // SAFETY: The caller supplies the C-string and output-layout
    // contracts; the kernel validates the path.
    decode(unsafe { syscall2(SYS_STATFS, path as usize, buffer as usize) }).map(|_| ())
}

/// Queries filesystem statistics for a C path without using libc or TLS
/// `errno`.
#[inline]
pub fn statfs(path: &CStr, buffer: *mut u8) -> Result<()> {
    // SAFETY: `CStr` establishes the pathname contract; the caller
    // supplies the output-layout contract.
    unsafe { statfs_raw(path.as_ptr().cast(), buffer) }
}

/// Queries the Linux/AArch64 `struct stat` representation for a C path
/// relative to `dirfd`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `buffer`
/// must designate writable storage for the complete target
/// Linux/AArch64 `struct stat` layout.
#[inline]
pub unsafe fn statat_raw(
    dirfd: RawFd,
    path: *const u8,
    buffer: *mut u8,
    flags: u32,
) -> Result<()> {
    // SAFETY: The caller supplies the C-string and output-layout
    // contracts; the kernel validates the descriptor and flags.
    decode(unsafe {
        syscall4(
            SYS_NEWFSTATAT,
            dirfd as usize,
            path as usize,
            buffer as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Queries metadata for `path` relative to `dirfd` without using libc or
/// TLS `errno`.
///
/// # Safety
///
/// `buffer` must designate writable storage for the complete target
/// Linux/AArch64 `struct stat` layout.
#[inline]
pub unsafe fn statat(dirfd: RawFd, path: &CStr, buffer: *mut u8, flags: u32) -> Result<()> {
    // SAFETY: `CStr` establishes the pathname contract; the caller
    // supplies the output-layout contract.
    unsafe { statat_raw(dirfd, path.as_ptr().cast(), buffer, flags) }
}

/// Removes `path` relative to `dirfd` without using libc or TLS `errno`.
#[inline]
pub fn unlinkat(dirfd: RawFd, path: &CStr, flags: u32) -> Result<()> {
    // SAFETY: `CStr` guarantees the pathname is readable and
    // NUL-terminated; the kernel validates descriptor and flags.
    decode(unsafe {
        syscall3(
            SYS_UNLINKAT,
            dirfd as usize,
            path.as_ptr() as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Creates a directory relative to `dirfd` without using libc or TLS
/// `errno`.
#[inline]
pub fn mkdirat(dirfd: RawFd, path: &CStr, mode: u32) -> Result<()> {
    // SAFETY: `CStr` guarantees the pathname is readable and
    // NUL-terminated; the kernel validates descriptor and mode bits.
    decode(unsafe {
        syscall3(
            SYS_MKDIRAT,
            dirfd as usize,
            path.as_ptr() as usize,
            mode as usize,
        )
    })
    .map(|_| ())
}

/// Creates a filesystem node relative to `dirfd` without using libc or
/// TLS `errno`.
///
/// `mode` contains the Linux file-type and permission bits in the exact
/// `mknodat(2)` representation. The public facade supplies the file-type
/// and creation-mode pieces separately so callers cannot accidentally
/// duplicate or omit the type bits at this boundary.
#[inline]
pub fn mknodat(dirfd: RawFd, path: &CStr, mode: u32, dev: u64) -> Result<()> {
    // SAFETY: `CStr` guarantees the pathname is readable and
    // NUL-terminated; the kernel validates the node type, permissions,
    // device number, and directory descriptor.
    decode(unsafe {
        syscall4(
            SYS_MKNODAT,
            dirfd as usize,
            path.as_ptr() as usize,
            mode as usize,
            dev as usize,
        )
    })
    .map(|_| ())
}

/// Reads a symbolic-link target relative to `dirfd` without using libc or
/// TLS `errno`.
///
/// # Safety
///
/// `buffer` must be writable for `length` bytes for the duration of the
/// call. A successful result reports the initialized prefix length and is
/// never NUL-terminated by the kernel.
#[inline]
pub unsafe fn readlinkat_raw(
    dirfd: RawFd,
    path: &CStr,
    buffer: *mut u8,
    length: usize,
) -> Result<usize> {
    // SAFETY: `CStr` supplies the input pathname; the caller supplies
    // writable output storage for exactly `length` bytes.
    decode(unsafe {
        syscall4(
            SYS_READLINKAT,
            dirfd as usize,
            path.as_ptr() as usize,
            buffer as usize,
            length,
        )
    })
}

/// Creates a hard link without using libc or TLS `errno`.
#[inline]
pub fn linkat(
    old_dirfd: RawFd,
    old_path: &CStr,
    new_dirfd: RawFd,
    new_path: &CStr,
    flags: u32,
) -> Result<()> {
    // SAFETY: Both `CStr` inputs are readable NUL-terminated paths; the
    // kernel validates descriptors and link flags.
    decode(unsafe {
        syscall5(
            SYS_LINKAT,
            old_dirfd as usize,
            old_path.as_ptr() as usize,
            new_dirfd as usize,
            new_path.as_ptr() as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Renames a path without using libc or TLS `errno`.
#[inline]
pub fn renameat2(
    old_dirfd: RawFd,
    old_path: &CStr,
    new_dirfd: RawFd,
    new_path: &CStr,
    flags: u32,
) -> Result<()> {
    // SAFETY: Both `CStr` inputs are readable NUL-terminated paths; the
    // kernel validates descriptors and rename flags.
    decode(unsafe {
        syscall5(
            SYS_RENAMEAT2,
            old_dirfd as usize,
            old_path.as_ptr() as usize,
            new_dirfd as usize,
            new_path.as_ptr() as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Creates a symbolic link without using libc or TLS `errno`.
#[inline]
pub fn symlinkat(target: &CStr, new_dirfd: RawFd, new_path: &CStr) -> Result<()> {
    // SAFETY: Both `CStr` inputs are readable NUL-terminated paths; the
    // kernel validates the descriptor.
    decode(unsafe {
        syscall3(
            SYS_SYMLINKAT,
            target.as_ptr() as usize,
            new_dirfd as usize,
            new_path.as_ptr() as usize,
        )
    })
    .map(|_| ())
}

/// Changes permissions for an open descriptor without using libc or TLS
/// `errno`.
#[inline]
pub fn fchmod(fd: RawFd, mode: u32) -> Result<()> {
    // SAFETY: The kernel validates the descriptor and permission bits.
    decode(unsafe { syscall2(SYS_FCHMOD, fd as usize, mode as usize) }).map(|_| ())
}

/// Changes permissions for `path` relative to `dirfd` without using libc
/// or TLS `errno`.
#[inline]
pub fn fchmodat(dirfd: RawFd, path: &CStr, mode: u32, flags: u32) -> Result<()> {
    // SAFETY: `CStr` supplies the input pathname; the kernel validates the
    // descriptor, permission bits, and flags.
    decode(unsafe {
        syscall4(
            SYS_FCHMODAT,
            dirfd as usize,
            path.as_ptr() as usize,
            mode as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Changes ownership for an open descriptor through Linux/AArch64's
/// `fchown` syscall without using libc or TLS `errno`.
///
/// `owner` and `group` are Linux `uid_t`/`gid_t` words. The kernel value
/// `u32::MAX` is the explicit no-change sentinel for either field; the
/// typed native facade is responsible for translating `Option` values and
/// rejecting an invalid raw ID before reaching this seam.
#[inline]
pub fn fchown(fd: RawFd, owner: u32, group: u32) -> Result<()> {
    // SAFETY: The kernel validates the descriptor, IDs, and credentials.
    decode(unsafe { syscall3(SYS_FCHOWN, fd as usize, owner as usize, group as usize) })
        .map(|_| ())
}

/// Changes pathname-selected ownership through Linux/AArch64's
/// `fchownat` syscall without using libc or TLS `errno`.
///
/// The `flags` word is intentionally supplied by the typed facade's
/// ownership-specific flag type; this core seam remains a direct scalar
/// syscall boundary and does not broaden that safe contract.
#[inline]
pub fn fchownat(dirfd: RawFd, path: &CStr, owner: u32, group: u32, flags: u32) -> Result<()> {
    // SAFETY: `CStr` supplies the pathname; the kernel validates the
    // descriptor, IDs, flags, and credentials.
    decode(unsafe {
        syscall5(
            SYS_FCHOWNAT,
            dirfd as usize,
            path.as_ptr() as usize,
            owner as usize,
            group as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Invokes Linux `utimensat` without using libc or TLS `errno`.
///
/// # Safety
///
/// `path` may be null only for the kernel-defined `futimens` form. When
/// non-null it must point to a readable NUL-terminated pathname. `times`
/// must point to two target-Linux `timespec` values for the duration of
/// the call.
#[inline]
pub unsafe fn utimensat_raw(
    dirfd: RawFd,
    path: *const u8,
    times: *const u8,
    flags: u32,
) -> Result<()> {
    // SAFETY: The caller supplies the nullable pathname and two-timespec
    // layout contracts; the kernel validates descriptor and flags.
    decode(unsafe {
        syscall4(
            SYS_UTIMENSAT,
            dirfd as usize,
            path as usize,
            times as usize,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Reads raw Linux `getdents64` records without using libc or TLS errno.
///
/// # Safety
///
/// `buffer` must be writable for `length` bytes for the duration of the
/// call. On success the returned prefix contains kernel `linux_dirent64`
/// records, which still require record-by-record validation by a facade.
#[inline]
pub unsafe fn getdents64_raw(fd: RawFd, buffer: *mut u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies writable output storage for exactly
    // `length` bytes; the kernel validates the directory descriptor.
    decode(unsafe { syscall3(SYS_GETDENTS64, fd as usize, buffer as usize, length) })
}

/// Applies a Linux `flock` operation without using libc or TLS `errno`.
#[inline]
pub fn flock(fd: RawFd, operation: u32) -> Result<()> {
    // SAFETY: The kernel validates descriptor and flock operation bits.
    decode(unsafe { syscall2(SYS_FLOCK, fd as usize, operation as usize) }).map(|_| ())
}

/// Sets an extended attribute without using libc or TLS `errno`.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings.
/// `value` must be readable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn setxattr_raw(
    path: *const u8,
    name: *const u8,
    value: *const u8,
    length: usize,
    flags: u32,
) -> Result<()> {
    // SAFETY: The caller supplies the pathname/name/value memory
    // contracts; Linux validates flags and filesystem support.
    decode(unsafe {
        syscall5(
            SYS_SETXATTR,
            path as usize,
            name as usize,
            value as usize,
            length,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Sets a no-follow-path extended attribute without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// Same memory requirements as [`setxattr_raw`].
#[inline]
pub unsafe fn lsetxattr_raw(
    path: *const u8,
    name: *const u8,
    value: *const u8,
    length: usize,
    flags: u32,
) -> Result<()> {
    // SAFETY: The caller supplies the pathname/name/value memory
    // contracts; Linux validates flags and filesystem support.
    decode(unsafe {
        syscall5(
            SYS_LSETXATTR,
            path as usize,
            name as usize,
            value as usize,
            length,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Sets a descriptor extended attribute without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated string. `value` must be
/// readable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn fsetxattr_raw(
    fd: RawFd,
    name: *const u8,
    value: *const u8,
    length: usize,
    flags: u32,
) -> Result<()> {
    // SAFETY: The caller supplies the name/value memory contracts; Linux
    // validates descriptor, flags, and filesystem support.
    decode(unsafe {
        syscall5(
            SYS_FSETXATTR,
            fd as usize,
            name as usize,
            value as usize,
            length,
            flags as usize,
        )
    })
    .map(|_| ())
}

/// Reads an extended attribute without using libc or TLS `errno`.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings.
/// `value` must be writable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn getxattr_raw(
    path: *const u8,
    name: *const u8,
    value: *mut u8,
    length: usize,
) -> Result<usize> {
    // SAFETY: The caller supplies the pathname/name/output memory
    // contracts; Linux validates filesystem support.
    decode(unsafe {
        syscall4(
            SYS_GETXATTR,
            path as usize,
            name as usize,
            value as usize,
            length,
        )
    })
}

/// Reads a no-follow-path extended attribute without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// Same memory requirements as [`getxattr_raw`].
#[inline]
pub unsafe fn lgetxattr_raw(
    path: *const u8,
    name: *const u8,
    value: *mut u8,
    length: usize,
) -> Result<usize> {
    // SAFETY: The caller supplies the pathname/name/output memory
    // contracts; Linux validates filesystem support.
    decode(unsafe {
        syscall4(
            SYS_LGETXATTR,
            path as usize,
            name as usize,
            value as usize,
            length,
        )
    })
}

/// Reads a descriptor extended attribute without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated string. `value` must be
/// writable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn fgetxattr_raw(
    fd: RawFd,
    name: *const u8,
    value: *mut u8,
    length: usize,
) -> Result<usize> {
    // SAFETY: The caller supplies the name/output memory contracts; Linux
    // validates descriptor and filesystem support.
    decode(unsafe {
        syscall4(
            SYS_FGETXATTR,
            fd as usize,
            name as usize,
            value as usize,
            length,
        )
    })
}

/// Lists path extended attributes without using libc or TLS `errno`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string. `list` must be
/// writable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn listxattr_raw(path: *const u8, list: *mut u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies the pathname/output memory contracts.
    decode(unsafe { syscall3(SYS_LISTXATTR, path as usize, list as usize, length) })
}

/// Lists no-follow-path extended attributes without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// Same memory requirements as [`listxattr_raw`].
#[inline]
pub unsafe fn llistxattr_raw(path: *const u8, list: *mut u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies the pathname/output memory contracts.
    decode(unsafe { syscall3(SYS_LLISTXATTR, path as usize, list as usize, length) })
}

/// Lists descriptor extended attributes without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// `list` must be writable for `length` bytes unless `length` is zero.
#[inline]
pub unsafe fn flistxattr_raw(fd: RawFd, list: *mut u8, length: usize) -> Result<usize> {
    // SAFETY: The caller supplies the output memory contract; Linux
    // validates descriptor and filesystem support.
    decode(unsafe { syscall3(SYS_FLISTXATTR, fd as usize, list as usize, length) })
}

/// Removes a path extended attribute without using libc or TLS `errno`.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings.
#[inline]
pub unsafe fn removexattr_raw(path: *const u8, name: *const u8) -> Result<()> {
    // SAFETY: The caller supplies the pathname/name memory contracts.
    decode(unsafe { syscall2(SYS_REMOVEXATTR, path as usize, name as usize) }).map(|_| ())
}

/// Removes a no-follow-path extended attribute without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// Same memory requirements as [`removexattr_raw`].
#[inline]
pub unsafe fn lremovexattr_raw(path: *const u8, name: *const u8) -> Result<()> {
    // SAFETY: The caller supplies the pathname/name memory contracts.
    decode(unsafe { syscall2(SYS_LREMOVEXATTR, path as usize, name as usize) }).map(|_| ())
}

/// Removes a descriptor extended attribute without using libc or TLS
/// `errno`.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated string.
#[inline]
pub unsafe fn fremovexattr_raw(fd: RawFd, name: *const u8) -> Result<()> {
    // SAFETY: The caller supplies the name memory contract; Linux
    // validates descriptor and filesystem support.
    decode(unsafe { syscall2(SYS_FREMOVEXATTR, fd as usize, name as usize) }).map(|_| ())
}
