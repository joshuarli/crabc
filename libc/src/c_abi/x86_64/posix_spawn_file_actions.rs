//! Private Linux/x86-64 POSIX spawn file-actions lifecycle.
//!
//! This feature-local owner translates musl 1.2.6's seven file-actions
//! functions from `src/process/posix_spawn_file_actions_{init,addclose,
//! adddup2,addopen,addchdir,addfchdir,destroy}.c`.  Initialization remains in
//! the existing dependency-free x86 leaf; this module owns the six allocating
//! additions/destructor and uses the exact musl `struct fdop` shape.
//!
//! Musl prepends every new operation to `__actions`, links the former head's
//! `prev` pointer, and later executes in insertion order by walking to the
//! tail and following `prev`.  The list is intentionally opaque to the public
//! API but its first pointer is visible through the installed `spawn.h`
//! record, so preserving both links and the flexible-array offset is part of
//! this slice's ABI evidence.  This module does not execute the records.
//!
//! The six allocating functions use the already evidenced x86 C allocator
//! boundary through `malloc` and `free`; they do not introduce an allocator or
//! broaden the default static archive.  POSIX spawn execution, `posix_spawn`
//! and `posix_spawnp`, process creation, fork/vfork/clone, exec, attributes,
//! cancellation, atfork state, and child supervision remain outside scope.
//!
//! A valid initialized caller-owned record and valid NUL-terminated pathname
//! are required exactly as in musl.  Invalid file descriptors return the
//! source's positive `EBADF` without changing errno.  Allocation failure
//! returns positive `ENOMEM`; the allocator owns any errno publication on
//! that path.  Destruction frees the linked records but, like musl, does not
//! clear `fa->__actions`; callers must not reuse the record without a fresh
//! initialization.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

const EBADF: c_int = 9;
const ENOMEM: c_int = 12;

const FDOP_CLOSE: c_int = 1;
const FDOP_DUP2: c_int = 2;
const FDOP_OPEN: c_int = 3;
const FDOP_CHDIR: c_int = 4;
const FDOP_FCHDIR: c_int = 5;

#[repr(C)]
struct PosixSpawnFileActions {
    _pad0: [c_int; 2],
    actions: *mut c_void,
    _pad: [c_int; 16],
}

/// The fixed prefix of musl's flexible-array `struct fdop`.
///
/// On x86-64 this is 40 bytes, while the flexible `path[]` begins at byte
/// offset 36 after the two links, four integer fields, and the LP64 `mode_t`
/// word.  The trailing four bytes are struct padding included in musl's
/// `sizeof *op` allocation.  Keeping the explicit links is necessary even
/// though execution belongs to the future spawn aggregate.
#[repr(C)]
struct FdOp {
    next: *mut FdOp,
    prev: *mut FdOp,
    cmd: c_int,
    fd: c_int,
    srcfd: c_int,
    oflag: c_int,
    mode: c_uint,
}

const _: () = assert!(core::mem::size_of::<PosixSpawnFileActions>() == 80);
const _: () = assert!(core::mem::align_of::<PosixSpawnFileActions>() == 8);
const _: () = assert!(core::mem::offset_of!(PosixSpawnFileActions, actions) == 8);
const _: () = assert!(core::mem::size_of::<FdOp>() == 40);
const _: () = assert!(core::mem::align_of::<FdOp>() == 8);
const FDOP_PATH_OFFSET: usize = 36;
// Musl allocates `sizeof *op` for descriptor-only records and appends exactly
// `strlen(path) + 1` bytes only for OPEN/CHDIR records.  Keep this split
// explicit because the flexible-array member starts before the struct's
// trailing padding, while `sizeof *op` still includes that padding.
const _: () = assert!(core::mem::size_of::<FdOp>() + 0 == 40);
const _: () = assert!(core::mem::size_of::<FdOp>() + 1 == 41);

unsafe extern "C" {
    #[link_name = "malloc"]
    fn cabi_malloc(size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn cabi_free(pointer: *mut c_void);
}

/// Count one valid caller-owned C string, with an explicit representability
/// boundary for the flexible-array allocation size.
unsafe fn c_string_length(string: *const c_char) -> Option<usize> {
    let mut length = 0usize;
    loop {
        // SAFETY: callers retain musl's readable NUL-terminated string
        // precondition for every pathname argument.
        if unsafe { ptr::read(string.add(length).cast::<u8>()) } == 0 {
            return Some(length);
        }
        length = length.checked_add(1)?;
    }
}

/// Allocate and initialize one musl-shaped operation record.
unsafe fn allocate_operation(
    cmd: c_int,
    fd: c_int,
    srcfd: c_int,
    oflag: c_int,
    mode: c_uint,
    path: *const c_char,
) -> Result<*mut FdOp, c_int> {
    let has_path = matches!(cmd, FDOP_OPEN | FDOP_CHDIR);
    let path_length = if has_path {
        // SAFETY: the caller's pathname is a valid NUL-terminated C string.
        unsafe { c_string_length(path) }.ok_or(ENOMEM)?
    } else {
        0
    };
    let path_bytes = if has_path {
        path_length.checked_add(1).ok_or(ENOMEM)?
    } else {
        0
    };
    let allocation_size = core::mem::size_of::<FdOp>()
        .checked_add(path_bytes)
        .ok_or(ENOMEM)?;

    // SAFETY: this is the selected C allocator's ordinary allocation ABI.
    let operation = unsafe { cabi_malloc(allocation_size) }.cast::<FdOp>();
    if operation.is_null() {
        return Err(ENOMEM);
    }

    // SAFETY: allocation_size includes the complete fixed prefix and path
    // tail; each field below is within that allocated object.
    unsafe {
        ptr::addr_of_mut!((*operation).next).write(ptr::null_mut());
        ptr::addr_of_mut!((*operation).prev).write(ptr::null_mut());
        ptr::addr_of_mut!((*operation).cmd).write(cmd);
        ptr::addr_of_mut!((*operation).fd).write(fd);
        ptr::addr_of_mut!((*operation).srcfd).write(srcfd);
        ptr::addr_of_mut!((*operation).oflag).write(oflag);
        ptr::addr_of_mut!((*operation).mode).write(mode);
        if has_path {
            let destination = (operation.cast::<u8>()).add(FDOP_PATH_OFFSET);
            ptr::copy_nonoverlapping(
                path.cast::<u8>(),
                destination,
                path_bytes,
            );
        }
    }
    Ok(operation)
}

/// Prepend one operation using musl's doubly-linked head insertion.
unsafe fn prepend_operation(
    file_actions: *mut PosixSpawnFileActions,
    operation: *mut FdOp,
) {
    // SAFETY: the caller supplies one valid initialized file-actions record
    // and one live operation allocated by `allocate_operation`.
    unsafe {
        let old_head = (*file_actions).actions.cast::<FdOp>();
        (*operation).next = old_head;
        if !old_head.is_null() {
            (*old_head).prev = operation;
        }
        (*file_actions).actions = operation.cast::<c_void>();
    }
}

/// Add one operation after validating the source's descriptor rule.
unsafe fn add_operation(
    file_actions: *mut PosixSpawnFileActions,
    cmd: c_int,
    fd: c_int,
    srcfd: c_int,
    oflag: c_int,
    mode: c_uint,
    path: *const c_char,
) -> c_int {
    // SAFETY: this follows musl's direct caller-owned-record contract.
    let operation = match unsafe {
        allocate_operation(cmd, fd, srcfd, oflag, mode, path)
    } {
        Ok(operation) => operation,
        Err(error) => return error,
    };
    // SAFETY: `operation` is a newly allocated record and `file_actions` is a
    // valid initialized caller-owned object.
    unsafe { prepend_operation(file_actions, operation) };
    0
}

/// Add a close operation.
///
/// # Safety
///
/// `file_actions` must point to one live, initialized
/// `posix_spawn_file_actions_t` record with the installed x86-64 musl layout.
/// The caller must hold exclusive access to that record for the duration of
/// the call and until any later destroy operation. `fd` must name the intended
/// close action; a negative descriptor is rejected with `EBADF`.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(
    file_actions: *mut c_void,
    fd: c_int,
) -> c_int {
    if fd < 0 {
        return EBADF;
    }
    // SAFETY: the C ABI record begins with the installed 80-byte musl layout.
    unsafe {
        add_operation(
            file_actions.cast::<PosixSpawnFileActions>(),
            FDOP_CLOSE,
            fd,
            0,
            0,
            0,
            ptr::null(),
        )
    }
}

/// Add a dup2 operation.
///
/// # Safety
///
/// `file_actions` must point to one live, initialized
/// `posix_spawn_file_actions_t` record with the installed x86-64 musl layout.
/// The caller must hold exclusive access to that record for the duration of
/// the call and until any later destroy operation. `srcfd` and `fd` must name
/// the intended descriptor operation; either negative descriptor is rejected
/// with `EBADF`.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(
    file_actions: *mut c_void,
    srcfd: c_int,
    fd: c_int,
) -> c_int {
    if srcfd < 0 || fd < 0 {
        return EBADF;
    }
    // SAFETY: the C ABI record begins with the installed 80-byte musl layout.
    unsafe {
        add_operation(
            file_actions.cast::<PosixSpawnFileActions>(),
            FDOP_DUP2,
            fd,
            srcfd,
            0,
            0,
            ptr::null(),
        )
    }
}

/// Add an open operation with a copied pathname.
///
/// # Safety
///
/// `file_actions` must point to one live, initialized
/// `posix_spawn_file_actions_t` record with the installed x86-64 musl layout,
/// and the caller must hold exclusive access to it for this call. `path` must
/// be non-null and readable through its terminating NUL byte. The pathname is
/// copied before this function returns; it need not remain live afterward.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(
    file_actions: *mut c_void,
    fd: c_int,
    path: *const c_char,
    oflag: c_int,
    mode: c_uint,
) -> c_int {
    if fd < 0 {
        return EBADF;
    }
    // SAFETY: the C ABI record and pathname follow musl's valid-object
    // preconditions; `allocate_operation` copies the full string.
    unsafe {
        add_operation(
            file_actions.cast::<PosixSpawnFileActions>(),
            FDOP_OPEN,
            fd,
            0,
            oflag,
            mode,
            path,
        )
    }
}

/// Add a pathname chdir operation.
///
/// # Safety
///
/// `file_actions` must point to one live, initialized
/// `posix_spawn_file_actions_t` record with the installed x86-64 musl layout,
/// and the caller must hold exclusive access to it for this call. `path` must
/// be non-null and readable through its terminating NUL byte. The pathname is
/// copied before this function returns; it need not remain live afterward.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(
    file_actions: *mut c_void,
    path: *const c_char,
) -> c_int {
    // SAFETY: musl's source retains the valid pathname precondition and uses
    // the same flexible-array record as addopen.
    unsafe {
        add_operation(
            file_actions.cast::<PosixSpawnFileActions>(),
            FDOP_CHDIR,
            -1,
            0,
            0,
            0,
            path,
        )
    }
}

/// Add a descriptor fchdir operation.
///
/// # Safety
///
/// `file_actions` must point to one live, initialized
/// `posix_spawn_file_actions_t` record with the installed x86-64 musl layout.
/// The caller must hold exclusive access to that record for the duration of
/// the call and until any later destroy operation. `fd` must name the intended
/// directory descriptor; a negative descriptor is rejected with `EBADF`.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(
    file_actions: *mut c_void,
    fd: c_int,
) -> c_int {
    if fd < 0 {
        return EBADF;
    }
    // SAFETY: the C ABI record begins with the installed 80-byte musl layout.
    unsafe {
        add_operation(
            file_actions.cast::<PosixSpawnFileActions>(),
            FDOP_FCHDIR,
            fd,
            0,
            0,
            0,
            ptr::null(),
        )
    }
}

/// Destroy all action records, retaining musl's uncleared dangling head.
///
/// # Safety
///
/// `file_actions` must point to one live, initialized
/// `posix_spawn_file_actions_t` record with the installed x86-64 musl layout,
/// whose action list was produced by this lifecycle API and has not already
/// been destroyed. The caller must exclude concurrent access. On return the
/// record retains musl's dangling head pointer and must be reinitialized before
/// any reuse or a second destroy call.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(
    file_actions: *mut c_void,
) -> c_int {
    // SAFETY: the C ABI requires one valid initialized file-actions record;
    // each linked operation was allocated by this module's malloc boundary.
    unsafe {
        let mut operation = (*file_actions.cast::<PosixSpawnFileActions>())
            .actions
            .cast::<FdOp>();
        while !operation.is_null() {
            let next = (*operation).next;
            cabi_free(operation.cast::<c_void>());
            operation = next;
        }
    }
    0
}

/// Link-time witness for this opt-in provider object.
///
/// This is evidence glue only; it is not an installed libc interface and is
/// excluded from the seven-name POSIX roster by the local archive gate.
#[no_mangle]
pub extern "C" fn __crabc_x86_posix_spawn_file_actions_v1() -> usize {
    1
}
