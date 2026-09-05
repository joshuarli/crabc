//! Opt-in Linux/x86-64 `ftw`/`nftw` filesystem-traversal boundary.
//!
//! This allocation-free directory client owns exactly the historical C
//! callback walk spellings `ftw` and `nftw`. It composes the selected private
//! x86 `DIR` mappings, private `struct stat` owner, current-directory leaves,
//! raw descriptor close, and initial-TLS errno slot. It deliberately does not
//! select `scandir`, malloc, generic filesystem policy, a public Rust facade,
//! pthread cancellation, libc.so, CRT, loader, sysroot, family completion, or
//! public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/legacy/ftw.c` maps to the distinct three-argument [`ftw`] callback
//!   entry below. Unlike musl's undefined callback cast, the x86 owner keeps
//!   the two callback ABIs separate.
//! - `src/misc/nftw.c` maps to [`nftw`] and the recursive stack/history,
//!   stat classification, `FTW_PHYS`, `FTW_MOUNT`, `FTW_DEPTH`, descriptor
//!   limit, and fixed `PATH_MAX` pathname logic below.
//!
//! Pinned musl intentionally ignores `FTW_CHDIR`; the frozen AArch64 profile
//! already selects it, including callback-visible directory CWD and restoration
//! after callbacks that change CWD or abort. This x86 package therefore keeps
//! that frozen `FTW_CHDIR` behavior as an explicit selected-profile addition:
//! every directory invocation saves its entry CWD by descriptor and restores
//! it along every normal/error/callback exit. Normal traversal behavior is
//! differentially checked against musl; `FTW_CHDIR` has separate frozen-profile
//! evidence. The standalone feature does not translate musl's cancellation
//! guard because it has no general selected pthread cancellation-state owner.
//! The owned static aggregate restores the pinned `nftw.c` source protocol:
//! it disables selected-worker deferred cancellation for the whole recursive
//! walk, including callbacks while a `DIR`, path buffer, or temporary CWD can
//! still be live, then restores the observed prior state only after the walk
//! releases that state. This is a cancellation-state guard, not an invented
//! syscall or public-entry cancellation point. `ftw` carries the same guard
//! because musl implements it through `nftw`. Callbacks must return normally:
//! C++ exceptions and C `longjmp` must not cross this Rust frame.

use core::ffi::{c_char, c_int};
use core::ptr;

use super::{
    directory_streams, errno, fchdir, pathname_lifecycle, raw_syscall, stat_compat,
};

const PATH_MAX: usize = 4_096;
const IO_PATH_MAX: usize = PATH_MAX * 2 + 2;
const DIRECTORY_NAME_MAX: usize = 255;
const LINUX_ERRNO_MAX: i64 = 4_095;

const EACCES: c_int = 13;
const EINVAL: c_int = 22;
const ENAMETOOLONG: c_int = 36;
const ENOENT: c_int = 2;

const AT_FDCWD: c_int = -100;
const O_CLOEXEC: c_int = 0x80_000;
const O_DIRECTORY: c_int = 0x1_0000;
const O_LARGEFILE: c_int = 0x8_000;
const O_RDONLY: c_int = 0;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFMT: u32 = 0o170_000;

const FTW_F: c_int = 1;
const FTW_D: c_int = 2;
const FTW_DNR: c_int = 3;
const FTW_NS: c_int = 4;
const FTW_SL: c_int = 5;
const FTW_DP: c_int = 6;
const FTW_SLN: c_int = 7;
const FTW_PHYS: c_int = 1;
const FTW_MOUNT: c_int = 2;
const FTW_CHDIR: c_int = 4;
const FTW_DEPTH: c_int = 8;

// Pinned musl's public pthread.h spelling. Keep this local to the
// feature-gated source translation rather than widening the traversal leaf's
// standalone contract with a general cancellation-state owner.
#[cfg(feature = "x86-owned-static-runtime")]
const PTHREAD_CANCEL_DISABLE: c_int = 1;

#[repr(C)]
pub(super) struct FtwInfo {
    base: c_int,
    level: c_int,
}

type FtwCallback = unsafe extern "C" fn(*const c_char, *const stat_compat::Stat, c_int) -> c_int;
type NftwCallback = unsafe extern "C" fn(
    *const c_char,
    *const stat_compat::Stat,
    c_int,
    *mut FtwInfo,
) -> c_int;

struct Callbacks {
    ftw: Option<FtwCallback>,
    nftw: Option<NftwCallback>,
}

struct History {
    chain: *const History,
    device: u64,
    inode: u64,
    level: c_int,
    base: c_int,
}

#[inline]
fn is_linux_error(result: i64) -> bool {
    result < 0 && result >= -LINUX_ERRNO_MAX
}

#[inline]
unsafe fn fail(error: c_int) -> c_int {
    // SAFETY: this selected C ABI owns publication of its concrete local and
    // raw Linux errors through the initial-TLS errno slot.
    unsafe { errno::set_errno(error) };
    -1
}

/// Run a complete `nftw`-style walk under pinned musl's state protocol.
///
/// `src/misc/nftw.c` disables cancellation immediately before `do_nftw` and
/// restores its prior state immediately after it returns. The x86 aggregate
/// has a deliberately narrower selected-worker cancellation owner: an
/// unselected caller receives `ENOTSUP` from `pthread_setcancelstate`, in which
/// case this leaves the standalone traversal behavior untouched. A selected
/// worker sees the source-faithful disable/walk/restore interval, so a callback
/// cannot deliver a deferred request while directory, allocation, or CWD
/// cleanup state is live.
#[cfg(feature = "x86-owned-static-runtime")]
#[inline]
unsafe fn owned_static_nftw_cancellation_guard(walk: impl FnOnce() -> c_int) -> c_int {
    let mut previous_state = 0;
    // SAFETY: the aggregate selects this exact current-worker cancellation
    // owner. Its C ABI accepts valid pinned `PTHREAD_CANCEL_DISABLE` and one
    // writable local `int` for the prior state.
    let guarded = unsafe {
        super::pthread_cancel::pthread_setcancelstate(
            PTHREAD_CANCEL_DISABLE,
            &mut previous_state,
        )
    } == 0;
    let result = walk();
    if guarded {
        // SAFETY: a successful transition wrote this exact prior state. The
        // walk has returned, so all of its directory/CWD cleanup state has
        // already been released before deferred delivery is enabled again.
        let _ = unsafe {
            super::pthread_cancel::pthread_setcancelstate(previous_state, ptr::null_mut())
        };
    }
    result
}

/// Return a caller-contract C-string length.
///
/// The public traversal entry points require a readable NUL-terminated path,
/// so an unterminated or inaccessible pointer is already outside this helper's
/// C ABI contract.
unsafe fn c_string_length(bytes: *const c_char) -> usize {
    let mut length = 0;
    while unsafe { *bytes.add(length) } != 0 {
        length += 1;
    }
    length
}

#[inline]
unsafe fn callback(
    callbacks: &Callbacks,
    path: *const c_char,
    metadata: &stat_compat::PathMetadata,
    kind: c_int,
    base: c_int,
    level: c_int,
) -> c_int {
    if let Some(function) = callbacks.nftw {
        let mut info = FtwInfo { base, level };
        // SAFETY: the public nftw contract requires a non-null callback that
        // returns normally; metadata and info live for this synchronous call.
        unsafe { function(path, metadata.as_stat_ptr(), kind, &mut info) }
    } else if let Some(function) = callbacks.ftw {
        // SAFETY: the public ftw contract requires a non-null callback that
        // returns normally; metadata lives for this synchronous call.
        unsafe { function(path, metadata.as_stat_ptr(), kind) }
    } else {
        // Only defensive: both public entries reject a missing callback before
        // this recursive core is entered.
        unsafe { fail(EINVAL) }
    }
}

/// Save the current directory as a descriptor without importing `open` into
/// the public traversal closure.
unsafe fn save_cwd() -> Result<c_int, c_int> {
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_OPENAT,
            i64::from(AT_FDCWD),
            b".\0".as_ptr() as i64,
            i64::from(O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_LARGEFILE),
            0,
        )
    };
    if is_linux_error(result) {
        Err(result.wrapping_neg() as c_int)
    } else {
        Ok(result as c_int)
    }
}

/// Restore a saved CWD and close the saved descriptor without replacing a
/// callback result. This is the frozen `FTW_CHDIR` cleanup invariant.
unsafe fn restore_cwd(saved_descriptor: c_int, result: c_int) -> c_int {
    if saved_descriptor < 0 {
        return result;
    }
    let restored = fchdir::fchdir(saved_descriptor);
    let closed = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(saved_descriptor))
    };
    if restored != 0 {
        return if result != 0 { result } else { -1 };
    }
    if is_linux_error(closed) {
        if result != 0 {
            return result;
        }
        // SAFETY: `closed` is a checked raw Linux error and this C ABI owns
        // publication of the close failure after otherwise successful work.
        unsafe { errno::set_errno(closed.wrapping_neg() as c_int) };
        return -1;
    }
    result
}

/// Close a retained directory stream before restoring a CWD. Musl does not
/// make close a second traversal-result channel, so this preserves a prior
/// callback/error result and leaves normal close diagnostics Linux-owned.
unsafe fn close_directory(stream: *mut directory_streams::DirectoryStream, result: c_int) -> c_int {
    if !stream.is_null() {
        // SAFETY: the recursive core exclusively owns this private stream and
        // closes it exactly once on every retained-stream exit.
        let _ = unsafe { directory_streams::closedir(stream) };
    }
    result
}

/// Finish this recursion frame in the only order that preserves the frozen
/// CWD restoration contract: child directory descriptor, then entry CWD.
unsafe fn finish(
    stream: *mut directory_streams::DirectoryStream,
    saved_descriptor: c_int,
    result: c_int,
) -> c_int {
    let result = unsafe { close_directory(stream, result) };
    unsafe { restore_cwd(saved_descriptor, result) }
}

#[inline]
unsafe fn root_base(path: *const u8, last: usize) -> c_int {
    let mut cursor = last;
    while cursor != 0 && unsafe { *path.add(cursor) } == b'/' {
        cursor -= 1;
    }
    while cursor != 0 && unsafe { *path.add(cursor - 1) } != b'/' {
        cursor -= 1;
    }
    cursor as c_int
}

unsafe fn classify(
    io_path: *const c_char,
    flags: c_int,
) -> Result<(stat_compat::PathMetadata, c_int), c_int> {
    let follow = flags & FTW_PHYS == 0;
    let metadata = match unsafe { stat_compat::path_metadata(io_path, follow) } {
        Ok(metadata) => metadata,
        Err(error) if follow && error == ENOENT => {
            match unsafe { stat_compat::path_metadata(io_path, false) } {
                Ok(metadata) => return Ok((metadata, FTW_SLN)),
                Err(lstat_error) if lstat_error == EACCES => {
                    return Ok((stat_compat::PathMetadata::zeroed(), FTW_NS));
                }
                Err(lstat_error) => return Err(lstat_error),
            }
        }
        Err(error) if error == EACCES => {
            return Ok((stat_compat::PathMetadata::zeroed(), FTW_NS));
        }
        Err(error) => return Err(error),
    };
    let kind = match metadata.mode() & S_IFMT {
        S_IFDIR => {
            if flags & FTW_DEPTH != 0 {
                FTW_DP
            } else {
                FTW_D
            }
        }
        S_IFLNK => {
            if flags & FTW_PHYS != 0 {
                FTW_SL
            } else {
                FTW_SLN
            }
        }
        _ => FTW_F,
    };
    Ok((metadata, kind))
}

#[inline]
fn is_directory_kind(kind: c_int) -> bool {
    kind == FTW_D || kind == FTW_DP
}

unsafe fn append_child(
    path: *mut u8,
    path_length: usize,
    path_capacity: usize,
    io_path: *mut u8,
    io_length: usize,
    io_capacity: usize,
    name: *const c_char,
    name_length: usize,
) -> Result<(usize, usize), c_int> {
    let path_last = if path_length != 0 && unsafe { *path.add(path_length - 1) } == b'/' {
        path_length - 1
    } else {
        path_length
    };
    let io_last = if io_length != 0 && unsafe { *io_path.add(io_length - 1) } == b'/' {
        io_length - 1
    } else {
        io_length
    };
    let child_path_length = path_last
        .checked_add(1)
        .and_then(|length| length.checked_add(name_length))
        .ok_or(ENAMETOOLONG)?;
    let child_io_length = io_last
        .checked_add(1)
        .and_then(|length| length.checked_add(name_length))
        .ok_or(ENAMETOOLONG)?;
    if child_path_length >= path_capacity || child_io_length >= io_capacity {
        return Err(ENAMETOOLONG);
    }
    // SAFETY: capacity checks leave room for the final NUL in both caller-
    // owned fixed buffers; `name` is a validated DIR-buffer borrow of exactly
    // name_length non-NUL bytes followed by its own NUL.
    unsafe {
        *path.add(path_last) = b'/';
        ptr::copy_nonoverlapping(name.cast::<u8>(), path.add(path_last + 1), name_length);
        *path.add(child_path_length) = 0;
        *io_path.add(io_last) = b'/';
        ptr::copy_nonoverlapping(
            name.cast::<u8>(),
            io_path.add(io_last + 1),
            name_length,
        );
        *io_path.add(child_io_length) = 0;
    }
    Ok((child_path_length, child_io_length))
}

unsafe fn restore_path(path: *mut u8, path_length: usize, io_path: *mut u8, io_length: usize) {
    // SAFETY: both locations are inside the fixed root buffers and were the
    // original NUL terminators for this recursion frame before append_child.
    unsafe {
        *path.add(path_length) = 0;
        *io_path.add(io_length) = 0;
    }
}

unsafe fn walk(
    path: *mut u8,
    path_length: usize,
    path_capacity: usize,
    io_path: *mut u8,
    io_length: usize,
    io_capacity: usize,
    callbacks: &Callbacks,
    fd_limit: c_int,
    flags: c_int,
    history: *const History,
) -> c_int {
    let last = if path_length != 0 && unsafe { *path.add(path_length - 1) } == b'/' {
        path_length - 1
    } else {
        path_length
    };
    let (metadata, mut kind) = match unsafe { classify(io_path.cast(), flags) } {
        Ok(classification) => classification,
        Err(error) => return unsafe { fail(error) },
    };

    if flags & FTW_MOUNT != 0
        && !history.is_null()
        && kind != FTW_NS
        && metadata.device() != unsafe { (*history).device }
    {
        return 0;
    }

    let base = if history.is_null() {
        unsafe { root_base(path, last) }
    } else {
        unsafe { (*history).base }
    };
    let level = if history.is_null() {
        0
    } else {
        unsafe { (*history).level + 1 }
    };
    let current = History {
        chain: history,
        device: metadata.device(),
        inode: metadata.inode(),
        level,
        base,
    };

    let directory_kind = is_directory_kind(kind);
    let mut saved_descriptor = -1;
    if flags & FTW_CHDIR != 0 && directory_kind {
        saved_descriptor = match unsafe { save_cwd() } {
            Ok(descriptor) => descriptor,
            Err(error) => return unsafe { fail(error) },
        };
    }

    let mut stream = ptr::null_mut();
    let mut directory_error = 0;
    if directory_kind {
        // SAFETY: io_path is a locally bounded NUL-terminated spelling that
        // remains valid for this recursive invocation.
        stream = unsafe { directory_streams::opendir(io_path.cast()) };
        if stream.is_null() {
            directory_error = unsafe { errno::get_errno() };
            if directory_error == EACCES {
                kind = FTW_DNR;
            }
        } else if fd_limit <= 0 {
            // Musl probes every reached directory even when no descriptor
            // budget remains, but closes it before it can recurse.
            let _ = unsafe { directory_streams::closedir(stream) };
            stream = ptr::null_mut();
        }
    }

    if saved_descriptor >= 0 && is_directory_kind(kind) && directory_error == 0 {
        // SAFETY: io_path is the absolute spelling prepared for CHDIR, or the
        // caller's original absolute path; chdir owns the process-global move.
        if unsafe { pathname_lifecycle::chdir(io_path.cast()) } != 0 {
            return unsafe { finish(stream, saved_descriptor, -1) };
        }
    }

    if flags & FTW_DEPTH == 0 {
        let callback_result = unsafe {
            callback(callbacks, path.cast(), &metadata, kind, base, level)
        };
        if callback_result != 0 {
            return unsafe { finish(stream, saved_descriptor, callback_result) };
        }
        if saved_descriptor >= 0 && is_directory_kind(kind) {
            // A callback may have changed CWD. Re-enter the current directory
            // before inspecting children, exactly as frozen FTW_CHDIR requires.
            if unsafe { pathname_lifecycle::chdir(io_path.cast()) } != 0 {
                return unsafe { finish(stream, saved_descriptor, -1) };
            }
        }
    }

    let mut cursor = history;
    while !cursor.is_null() {
        if unsafe { (*cursor).device } == metadata.device()
            && unsafe { (*cursor).inode } == metadata.inode()
        {
            return unsafe { finish(stream, saved_descriptor, 0) };
        }
        cursor = unsafe { (*cursor).chain };
    }

    if is_directory_kind(kind) && fd_limit > 0 {
        if stream.is_null() {
            // Preserve the error from the failed readability/ownership probe;
            // a DNR pre-order callback has already observed its FTW_DNR type.
            return unsafe { finish(stream, saved_descriptor, fail(directory_error)) };
        }
        loop {
            let entry = match unsafe { directory_streams::next_entry_name(stream) } {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => return unsafe { finish(stream, saved_descriptor, fail(error)) },
            };
            let is_dot = entry.length == 1 && unsafe { *entry.bytes } == b'.' as c_char;
            let is_dot_dot = entry.length == 2
                && unsafe { *entry.bytes } == b'.' as c_char
                && unsafe { *entry.bytes.add(1) } == b'.' as c_char;
            if is_dot || is_dot_dot {
                continue;
            }
            if saved_descriptor >= 0
                && unsafe { pathname_lifecycle::chdir(io_path.cast()) } != 0
            {
                // A preceding non-directory callback may have changed CWD.
                // Re-enter the parent before this child so every callback
                // observes the frozen FTW_CHDIR directory context.
                return unsafe { finish(stream, saved_descriptor, -1) };
            }
            debug_assert!(entry.length <= DIRECTORY_NAME_MAX);
            let (child_path_length, child_io_length) = match unsafe {
                append_child(
                    path,
                    path_length,
                    path_capacity,
                    io_path,
                    io_length,
                    io_capacity,
                    entry.bytes,
                    entry.length,
                )
            } {
                Ok(lengths) => lengths,
                Err(error) => return unsafe { finish(stream, saved_descriptor, fail(error)) },
            };
            let child_result = unsafe {
                walk(
                    path,
                    child_path_length,
                    path_capacity,
                    io_path,
                    child_io_length,
                    io_capacity,
                    callbacks,
                    fd_limit - 1,
                    flags,
                    &current,
                )
            };
            unsafe { restore_path(path, path_length, io_path, io_length) };
            if child_result != 0 {
                return unsafe { finish(stream, saved_descriptor, child_result) };
            }
        }
        // The parent stream must be closed before a post-order callback so the
        // callback may manipulate its directory without a retained iterator.
        let _ = unsafe { directory_streams::closedir(stream) };
        stream = ptr::null_mut();
    }

    if flags & FTW_DEPTH != 0 {
        if saved_descriptor >= 0 && is_directory_kind(kind)
            && unsafe { pathname_lifecycle::chdir(io_path.cast()) } != 0
        {
            return unsafe { finish(stream, saved_descriptor, -1) };
        }
        let callback_result = unsafe {
            callback(callbacks, path.cast(), &metadata, kind, base, level)
        };
        if callback_result != 0 {
            return unsafe { finish(stream, saved_descriptor, callback_result) };
        }
    }

    unsafe { finish(stream, saved_descriptor, 0) }
}

unsafe fn prepare_io_path(
    path: *const c_char,
    path_length: usize,
    output: *mut u8,
) -> Result<usize, c_int> {
    if path_length == 0 || unsafe { *path } == b'/' as c_char {
        if path_length >= IO_PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        // SAFETY: the checked fixed buffer has room for the source pathname
        // and its NUL; the public entry validated that exact C-string contract.
        unsafe { ptr::copy_nonoverlapping(path.cast::<u8>(), output, path_length + 1) };
        return Ok(path_length);
    }

    let mut cwd = [0u8; PATH_MAX + 1];
    // SAFETY: cwd is caller-owned complete storage for the selected getcwd
    // boundary; its error is already published through the current errno slot.
    if unsafe {
        pathname_lifecycle::getcwd(cwd.as_mut_ptr().cast(), cwd.len())
    }
    .is_null()
    {
        let error = unsafe { errno::get_errno() };
        return Err(if error == 0 { EINVAL } else { error });
    }
    let cwd_length = unsafe { c_string_length(cwd.as_ptr().cast()) };
    let io_length = cwd_length
        .checked_add(1)
        .and_then(|length| length.checked_add(path_length))
        .ok_or(ENAMETOOLONG)?;
    if io_length >= IO_PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    // SAFETY: the length checks reserve the final NUL in output; cwd and path
    // are both complete NUL-terminated byte paths with no overlap with output.
    unsafe {
        ptr::copy_nonoverlapping(cwd.as_ptr(), output, cwd_length);
        *output.add(cwd_length) = b'/';
        ptr::copy_nonoverlapping(path.cast::<u8>(), output.add(cwd_length + 1), path_length + 1);
    }
    Ok(io_length)
}

/// Walk a pathname tree with a four-argument callback.
///
/// # Safety
///
/// `path` must designate a readable NUL-terminated pathname for the call.
/// `callback` must be non-null and follow the C `nftw` callback ABI. It may
/// inspect only the supplied `struct stat`/`struct FTW` during the callback and
/// must return normally: C++ exceptions and C `longjmp` must not cross this
/// Rust frame. `FTW_CHDIR` changes process-global CWD during callbacks and
/// restores the entry CWD before return; callers retain external serialization
/// of every CWD-sensitive operation. In the owned static aggregate, pinned
/// musl's disable/walk/restore cancellation-state interval includes every
/// callback; the standalone feature selects no cancellation owner.
#[no_mangle]
pub unsafe extern "C" fn nftw(
    path: *const c_char,
    callback: Option<NftwCallback>,
    fd_limit: c_int,
    flags: c_int,
) -> c_int {
    if path.is_null() || callback.is_none() {
        return unsafe { fail(EINVAL) };
    }
    if fd_limit <= 0 {
        return 0;
    }
    let path_length = unsafe { c_string_length(path) };
    if path_length > PATH_MAX {
        return unsafe { fail(ENAMETOOLONG) };
    }
    let mut path_buffer = [0u8; PATH_MAX + 1];
    // SAFETY: the length limit leaves room for the source NUL in path_buffer.
    unsafe { ptr::copy_nonoverlapping(path.cast::<u8>(), path_buffer.as_mut_ptr(), path_length + 1) };
    let callbacks = Callbacks {
        ftw: None,
        nftw: callback,
    };
    let mut io_buffer = [0u8; IO_PATH_MAX];
    let (io_path, io_length, io_capacity) = if flags & FTW_CHDIR == 0 {
        (
            path_buffer.as_mut_ptr(),
            path_length,
            path_buffer.len(),
        )
    } else {
        let io_length = match unsafe {
            prepare_io_path(path, path_length, io_buffer.as_mut_ptr())
        } {
            Ok(length) => length,
            Err(error) => return unsafe { fail(error) },
        };
        (io_buffer.as_mut_ptr(), io_length, io_buffer.len())
    };
    #[cfg(feature = "x86-owned-static-runtime")]
    return unsafe {
        owned_static_nftw_cancellation_guard(|| unsafe {
            walk(
                path_buffer.as_mut_ptr(),
                path_length,
                path_buffer.len(),
                io_path,
                io_length,
                io_capacity,
                &callbacks,
                fd_limit,
                flags,
                ptr::null(),
            )
        })
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    unsafe {
        walk(
            path_buffer.as_mut_ptr(),
            path_length,
            path_buffer.len(),
            io_path,
            io_length,
            io_capacity,
            &callbacks,
            fd_limit,
            flags,
            ptr::null(),
        )
    }
}

/// Walk a pathname tree with the historical three-argument physical callback.
///
/// # Safety
///
/// `path` must designate a readable NUL-terminated pathname for the call.
/// `callback` must be non-null, follow the C `ftw` callback ABI, and return
/// normally; C++ exceptions and C `longjmp` must not cross this Rust frame.
/// Callback pointers and stat records are borrowed only for each synchronous
/// call. The owned static aggregate applies the same pinned-musl
/// disable/walk/restore cancellation-state interval as `nftw`; this standalone
/// feature selects no general cancellation owner.
#[no_mangle]
pub unsafe extern "C" fn ftw(
    path: *const c_char,
    callback: Option<FtwCallback>,
    fd_limit: c_int,
) -> c_int {
    if path.is_null() || callback.is_none() {
        return unsafe { fail(EINVAL) };
    }
    if fd_limit <= 0 {
        return 0;
    }
    let path_length = unsafe { c_string_length(path) };
    if path_length > PATH_MAX {
        return unsafe { fail(ENAMETOOLONG) };
    }
    let mut path_buffer = [0u8; PATH_MAX + 1];
    // SAFETY: the length limit leaves room for the source NUL in path_buffer.
    unsafe { ptr::copy_nonoverlapping(path.cast::<u8>(), path_buffer.as_mut_ptr(), path_length + 1) };
    let callbacks = Callbacks {
        ftw: callback,
        nftw: None,
    };
    #[cfg(feature = "x86-owned-static-runtime")]
    return unsafe {
        owned_static_nftw_cancellation_guard(|| unsafe {
            walk(
                path_buffer.as_mut_ptr(),
                path_length,
                path_buffer.len(),
                path_buffer.as_mut_ptr(),
                path_length,
                path_buffer.len(),
                &callbacks,
                fd_limit,
                FTW_PHYS,
                ptr::null(),
            )
        })
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    unsafe {
        walk(
            path_buffer.as_mut_ptr(),
            path_length,
            path_buffer.len(),
            path_buffer.as_mut_ptr(),
            path_length,
            path_buffer.len(),
            &callbacks,
            fd_limit,
            FTW_PHYS,
            ptr::null(),
        )
    }
}
