//! Hand-written libSystem declarations for the Darwin backend.
//!
//! This is the complete foreign surface used by the ported facade modules;
//! nothing here is public outside the crate. Each record carries compile-time
//! size, alignment and field-offset assertions taken from the macOS 27 SDK for
//! `aarch64-apple-darwin`. The constants are the SDK values for the same
//! target.
//!
//! `fcntl`, `ioctl` and `openat` are declared variadic because their C
//! prototypes are. Apple's AArch64 calling convention passes variadic
//! arguments on the stack rather than in registers, so a fixed-arity
//! declaration would place the argument where libSystem does not read it.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};

pub(crate) type mode_t = u16;
pub(crate) type dev_t = i32;
pub(crate) type off_t = i64;

pub(crate) const AT_FDCWD: c_int = -2;
pub(crate) const AT_EACCESS: c_int = 0x0010;
pub(crate) const AT_SYMLINK_NOFOLLOW: c_int = 0x0020;
pub(crate) const AT_SYMLINK_FOLLOW: c_int = 0x0040;
pub(crate) const AT_REMOVEDIR: c_int = 0x0080;

pub(crate) const O_RDONLY: c_int = 0x0000;
pub(crate) const O_WRONLY: c_int = 0x0001;
pub(crate) const O_RDWR: c_int = 0x0002;
pub(crate) const O_ACCMODE: c_int = 0x0003;
pub(crate) const O_NONBLOCK: c_int = 0x0000_0004;
pub(crate) const O_APPEND: c_int = 0x0000_0008;
pub(crate) const O_SHLOCK: c_int = 0x0000_0010;
pub(crate) const O_EXLOCK: c_int = 0x0000_0020;
pub(crate) const O_ASYNC: c_int = 0x0000_0040;
pub(crate) const O_SYNC: c_int = 0x0000_0080;
pub(crate) const O_NOFOLLOW: c_int = 0x0000_0100;
pub(crate) const O_CREAT: c_int = 0x0000_0200;
pub(crate) const O_TRUNC: c_int = 0x0000_0400;
pub(crate) const O_EXCL: c_int = 0x0000_0800;
pub(crate) const O_EVTONLY: c_int = 0x0000_8000;
pub(crate) const O_NOCTTY: c_int = 0x0002_0000;
pub(crate) const O_DIRECTORY: c_int = 0x0010_0000;
pub(crate) const O_SYMLINK: c_int = 0x0020_0000;
pub(crate) const O_DSYNC: c_int = 0x0040_0000;
pub(crate) const O_CLOEXEC: c_int = 0x0100_0000;
pub(crate) const O_CLOFORK: c_int = 0x0800_0000;
pub(crate) const O_NOFOLLOW_ANY: c_int = 0x2000_0000;
pub(crate) const O_EXEC: c_int = 0x4000_0000;

pub(crate) const F_DUPFD: c_int = 0;
pub(crate) const F_GETFD: c_int = 1;
pub(crate) const F_SETFD: c_int = 2;
pub(crate) const F_GETFL: c_int = 3;
pub(crate) const F_SETFL: c_int = 4;
pub(crate) const F_GETLK: c_int = 7;
pub(crate) const F_SETLK: c_int = 8;
pub(crate) const F_SETLKW: c_int = 9;
pub(crate) const F_DUPFD_CLOEXEC: c_int = 67;

pub(crate) const FD_CLOEXEC: c_int = 1;

/// `SEEK_SET` as stored in `struct flock`'s `short l_whence`.
pub(crate) const FLOCK_WHENCE_SET: i16 = 0;
pub(crate) const F_RDLCK: i16 = 1;
pub(crate) const F_UNLCK: i16 = 2;
pub(crate) const F_WRLCK: i16 = 3;

pub(crate) const SEEK_SET: c_int = 0;
pub(crate) const SEEK_CUR: c_int = 1;
pub(crate) const SEEK_END: c_int = 2;
pub(crate) const SEEK_HOLE: c_int = 3;
pub(crate) const SEEK_DATA: c_int = 4;

pub(crate) const UTIME_NOW: c_long = -1;
pub(crate) const UTIME_OMIT: c_long = -2;

pub(crate) const RENAME_SWAP: c_uint = 0x0000_0002;
pub(crate) const RENAME_EXCL: c_uint = 0x0000_0004;

pub(crate) const PIPE_BUF: usize = 512;

pub(crate) const FIOCLEX: c_ulong = 0x2000_6601;
pub(crate) const FIONCLEX: c_ulong = 0x2000_6602;
pub(crate) const FIONBIO: c_ulong = 0x8004_667e;
pub(crate) const FIONREAD: c_ulong = 0x4004_667f;

/// `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Iovec {
    pub(crate) iov_base: *mut u8,
    pub(crate) iov_len: usize,
}

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Timespec {
    pub(crate) tv_sec: i64,
    pub(crate) tv_nsec: c_long,
}

/// `struct stat` with 64-bit inodes, the only `stat` ABI on Apple AArch64.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Stat {
    pub(crate) st_dev: dev_t,
    pub(crate) st_mode: mode_t,
    pub(crate) st_nlink: u16,
    pub(crate) st_ino: u64,
    pub(crate) st_uid: u32,
    pub(crate) st_gid: u32,
    pub(crate) st_rdev: dev_t,
    pub(crate) st_atimespec: Timespec,
    pub(crate) st_mtimespec: Timespec,
    pub(crate) st_ctimespec: Timespec,
    pub(crate) st_birthtimespec: Timespec,
    pub(crate) st_size: off_t,
    pub(crate) st_blocks: i64,
    pub(crate) st_blksize: i32,
    pub(crate) st_flags: u32,
    pub(crate) st_gen: u32,
    pub(crate) st_lspare: i32,
    pub(crate) st_qspare: [i64; 2],
}

/// `struct flock`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Flock {
    pub(crate) l_start: off_t,
    pub(crate) l_len: off_t,
    pub(crate) l_pid: i32,
    pub(crate) l_type: i16,
    pub(crate) l_whence: i16,
}

/// `struct dirent` with 64-bit inodes.
#[repr(C)]
pub(crate) struct Dirent {
    pub(crate) d_ino: u64,
    pub(crate) d_seekoff: u64,
    pub(crate) d_reclen: u16,
    pub(crate) d_namlen: u16,
    pub(crate) d_type: u8,
    pub(crate) d_name: [c_char; 1024],
}

/// The opaque libSystem directory stream, `DIR`.
#[repr(C)]
pub(crate) struct Dir {
    _opaque: [u8; 0],
}

const _: () = {
    assert!(size_of::<Iovec>() == 16 && align_of::<Iovec>() == 8);
    assert!(offset_of!(Iovec, iov_base) == 0 && offset_of!(Iovec, iov_len) == 8);

    assert!(size_of::<Timespec>() == 16 && align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, tv_sec) == 0 && offset_of!(Timespec, tv_nsec) == 8);

    assert!(size_of::<Stat>() == 144 && align_of::<Stat>() == 8);
    assert!(offset_of!(Stat, st_dev) == 0);
    assert!(offset_of!(Stat, st_mode) == 4);
    assert!(offset_of!(Stat, st_nlink) == 6);
    assert!(offset_of!(Stat, st_ino) == 8);
    assert!(offset_of!(Stat, st_uid) == 16);
    assert!(offset_of!(Stat, st_gid) == 20);
    assert!(offset_of!(Stat, st_rdev) == 24);
    assert!(offset_of!(Stat, st_atimespec) == 32);
    assert!(offset_of!(Stat, st_mtimespec) == 48);
    assert!(offset_of!(Stat, st_ctimespec) == 64);
    assert!(offset_of!(Stat, st_birthtimespec) == 80);
    assert!(offset_of!(Stat, st_size) == 96);
    assert!(offset_of!(Stat, st_blocks) == 104);
    assert!(offset_of!(Stat, st_blksize) == 112);
    assert!(offset_of!(Stat, st_flags) == 116);
    assert!(offset_of!(Stat, st_gen) == 120);
    assert!(offset_of!(Stat, st_lspare) == 124);
    assert!(offset_of!(Stat, st_qspare) == 128);

    assert!(size_of::<Flock>() == 24 && align_of::<Flock>() == 8);
    assert!(FLOCK_WHENCE_SET as c_int == SEEK_SET);
    assert!(offset_of!(Flock, l_start) == 0);
    assert!(offset_of!(Flock, l_len) == 8);
    assert!(offset_of!(Flock, l_pid) == 16);
    assert!(offset_of!(Flock, l_type) == 20);
    assert!(offset_of!(Flock, l_whence) == 22);

    assert!(size_of::<Dirent>() == 1048 && align_of::<Dirent>() == 8);
    assert!(offset_of!(Dirent, d_ino) == 0);
    assert!(offset_of!(Dirent, d_seekoff) == 8);
    assert!(offset_of!(Dirent, d_reclen) == 16);
    assert!(offset_of!(Dirent, d_namlen) == 18);
    assert!(offset_of!(Dirent, d_type) == 20);
    assert!(offset_of!(Dirent, d_name) == 21);

    assert!(size_of::<mode_t>() == 2 && size_of::<dev_t>() == 4 && size_of::<off_t>() == 8);
    assert!(size_of::<c_long>() == 8);
};

unsafe extern "C" {
    pub(crate) safe fn __error() -> *mut c_int;

    pub(crate) unsafe fn close(fd: c_int) -> c_int;
    pub(crate) unsafe fn dup(fd: c_int) -> c_int;
    pub(crate) unsafe fn dup2(fd: c_int, fd2: c_int) -> c_int;
    pub(crate) unsafe fn dup3(fd: c_int, fd2: c_int, flags: c_int) -> c_int;
    pub(crate) unsafe fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub(crate) unsafe fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;

    pub(crate) unsafe fn read(fd: c_int, buf: *mut c_void, nbyte: usize) -> isize;
    pub(crate) unsafe fn readv(fd: c_int, iov: *const Iovec, iovcnt: c_int) -> isize;
    pub(crate) unsafe fn pread(fd: c_int, buf: *mut c_void, nbyte: usize, offset: off_t) -> isize;
    pub(crate) unsafe fn preadv(fd: c_int, iov: *const Iovec, iovcnt: c_int, offset: off_t) -> isize;
    pub(crate) unsafe fn write(fd: c_int, buf: *const c_void, nbyte: usize) -> isize;
    pub(crate) unsafe fn writev(fd: c_int, iov: *const Iovec, iovcnt: c_int) -> isize;
    pub(crate) unsafe fn pwrite(fd: c_int, buf: *const c_void, nbyte: usize, offset: off_t) -> isize;
    pub(crate) unsafe fn pwritev(fd: c_int, iov: *const Iovec, iovcnt: c_int, offset: off_t) -> isize;

    pub(crate) unsafe fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;

    pub(crate) unsafe fn access(path: *const c_char, mode: c_int) -> c_int;
    pub(crate) unsafe fn faccessat(fd: c_int, path: *const c_char, mode: c_int, flag: c_int) -> c_int;
    pub(crate) unsafe fn flock(fd: c_int, operation: c_int) -> c_int;
    pub(crate) unsafe fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t;
    pub(crate) unsafe fn openat(fd: c_int, path: *const c_char, oflag: c_int, ...) -> c_int;
    pub(crate) unsafe fn fstat(fd: c_int, buf: *mut Stat) -> c_int;
    pub(crate) unsafe fn fstatat(fd: c_int, path: *const c_char, buf: *mut Stat, flag: c_int) -> c_int;
    pub(crate) unsafe fn mkdirat(fd: c_int, path: *const c_char, mode: mode_t) -> c_int;
    pub(crate) unsafe fn mknodat(fd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int;
    pub(crate) unsafe fn unlinkat(fd: c_int, path: *const c_char, flag: c_int) -> c_int;
    pub(crate) unsafe fn linkat(
        fd1: c_int,
        path1: *const c_char,
        fd2: c_int,
        path2: *const c_char,
        flag: c_int,
    ) -> c_int;
    pub(crate) unsafe fn symlinkat(path1: *const c_char, fd: c_int, path2: *const c_char) -> c_int;
    pub(crate) unsafe fn renameatx_np(
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_uint,
    ) -> c_int;
    pub(crate) unsafe fn fchmod(fd: c_int, mode: mode_t) -> c_int;
    pub(crate) unsafe fn fchmodat(fd: c_int, path: *const c_char, mode: mode_t, flag: c_int) -> c_int;
    pub(crate) unsafe fn readlinkat(fd: c_int, path: *const c_char, buf: *mut c_char, size: usize)
        -> isize;
    pub(crate) unsafe fn ftruncate(fd: c_int, length: off_t) -> c_int;
    pub(crate) unsafe fn truncate(path: *const c_char, length: off_t) -> c_int;
    pub(crate) unsafe fn utimensat(
        fd: c_int,
        path: *const c_char,
        times: *const Timespec,
        flag: c_int,
    ) -> c_int;
    pub(crate) unsafe fn futimens(fd: c_int, times: *const Timespec) -> c_int;
    pub(crate) unsafe fn fsync(fd: c_int) -> c_int;
    pub(crate) safe fn sync();

    pub(crate) unsafe fn fdopendir(fd: c_int) -> *mut Dir;
    pub(crate) unsafe fn readdir(dirp: *mut Dir) -> *mut Dirent;
    pub(crate) unsafe fn rewinddir(dirp: *mut Dir);
    pub(crate) unsafe fn telldir(dirp: *mut Dir) -> c_long;
    pub(crate) unsafe fn seekdir(dirp: *mut Dir, loc: c_long);
    pub(crate) unsafe fn closedir(dirp: *mut Dir) -> c_int;

    pub(crate) unsafe fn getentropy(buffer: *mut c_void, size: usize) -> c_int;
}
