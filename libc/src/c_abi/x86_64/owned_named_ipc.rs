//! Owned named POSIX semaphores and shared-memory objects.
//!
//! Pinned musl 1.2.6, commit 9fa28ece75d8a2191de7c5bb53bed224c5947417,
//! MIT (`COPYRIGHT`): src/thread/sem_open.c (including sem_close),
//! sem_unlink.c, src/mman/shm_open.c (including __shm_mapname/shm_unlink),
//! and src/thread/__lock.c/__unlock.c. Both object kinds use /dev/shm/name,
//! with no semaphore-specific prefix or private persistent record format.
//!
//! The source's lazily allocated SEM_NSEMS_MAX table reserves an empty slot
//! before file creation. No allocation can fail after the initialized temporary
//! file is atomically linked into the namespace. Completed opens deduplicate
//! by inode and count references; the final close removes the table entry
//! before unmapping. The fork owner holds this same lock across the kernel
//! snapshot and resets only its copied lock in the child.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use super::{allocator, c_result, c_status, errno, memory_mapping, posix_semaphore, pthread_cancel, raw_syscall, stat_compat};

const EINVAL: c_int = 22;
const EMFILE: c_int = 24;
const ENAMETOOLONG: c_int = 36;
const EEXIST: c_int = 17;
const ENOENT: c_int = 2;
const SEM_NSEMS_MAX: usize = 256;
const SEM_VALUE_MAX: u32 = 0x7fff_ffff;
const SEM_BYTES: usize = 32;
const NAME_MAX: usize = 255;
const O_CREAT: c_int = 0x40;
const O_EXCL: c_int = 0x80;
const O_LARGEFILE: c_int = 0x8000;
const OBJECT_FLAGS: c_int = 2 | 0x20000 | 0x80000 | 0x800; // RDWR/NOFOLLOW/CLOEXEC/NONBLOCK
const SHM_FLAGS: c_int = 0x20000 | 0x80000 | 0x800;
const AT_FDCWD: i64 = -100;
const FUTEX_WAIT_PRIVATE: i64 = 128;
const FUTEX_WAKE_PRIVATE: i64 = 129;
const LOCK_FLAG: i32 = i32::MIN;
const LOCKED_ONE: i32 = LOCK_FLAG + 1;
static SEM_OPEN_LOCK: AtomicI32 = AtomicI32::new(0);

#[repr(C)]
struct Entry {
    inode: u64,
    semaphore: *mut c_void,
    references: c_int,
}
static TABLE: AtomicPtr<Entry> = AtomicPtr::new(core::ptr::null_mut());
const RESERVED: *mut c_void = usize::MAX as *mut c_void;

#[inline]
unsafe fn futex_wait(value: i32) {
    // SAFETY: SEM_OPEN_LOCK is process-private, aligned, and remains live for
    // the process.  A spurious wake or signal only retries musl's lock loop.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            SEM_OPEN_LOCK.as_ptr() as i64,
            FUTEX_WAIT_PRIVATE,
            i64::from(value),
            0,
        )
    };
}

#[inline]
unsafe fn futex_wake() {
    // SAFETY: SEM_OPEN_LOCK is the matching private futex word.  Waking one
    // waiter is musl's `__unlock` policy for this congestion representation.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FUTEX,
            SEM_OPEN_LOCK.as_ptr() as i64,
            FUTEX_WAKE_PRIVATE,
            1,
        )
    };
}

/// Acquire the pinned musl one-word semaphore registry lock.
///
/// Cancellation is disabled by the callers that can otherwise reach a C
/// cancellation point.  `sem_close` matches musl and uses this raw-futex
/// lock without changing cancellation state.
#[inline]
unsafe fn lock() {
    let mut current = SEM_OPEN_LOCK
        .compare_exchange(0, LOCKED_ONE, Ordering::Acquire, Ordering::Relaxed)
        .unwrap_or_else(|value| value);
    if current == 0 {
        return;
    }

    for _ in 0..10 {
        if current < 0 {
            current = current.wrapping_sub(LOCKED_ONE);
        }
        // `__lock.c` writes `INT_MIN + (current + 1)`: the low-order
        // congestion count is separate from the locked-one fast-path value.
        let desired = LOCK_FLAG.wrapping_add(current.wrapping_add(1));
        match SEM_OPEN_LOCK.compare_exchange(
            current,
            desired,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(value) => current = value,
        }
    }

    current = SEM_OPEN_LOCK.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    loop {
        if current < 0 {
            unsafe { futex_wait(current) };
            current = current.wrapping_sub(LOCKED_ONE);
        }
        let desired = LOCK_FLAG.wrapping_add(current);
        match SEM_OPEN_LOCK.compare_exchange(
            current,
            desired,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(value) => current = value,
        }
    }
}

#[inline]
unsafe fn unlock() {
    if SEM_OPEN_LOCK.load(Ordering::Relaxed) < 0
        && SEM_OPEN_LOCK.fetch_add(LOCKED_ONE.wrapping_neg(), Ordering::Release) != LOCKED_ONE
    {
        unsafe { futex_wake() };
    }
}

/// Acquire musl's semaphore-table lock before the stdio/syslog/timezone locks.
/// # Safety
/// The fork owner blocks application signals and must complete exactly one
/// parent/error unlock or sole-child reset before running user callbacks.
pub(super) unsafe fn pthread_fork_prepare() { unsafe { lock() }; }
/// Release the original process's matching fork preparation, including error.
/// # Safety
/// This is the unique parent completion of an unmatched prepare in this task.
pub(super) unsafe fn pthread_fork_parent() { unsafe { unlock() }; }
/// Preserve table/mappings/refcounts and reset only the inherited lock.
/// # Safety
/// This is the sole child of a prepared fork, before callbacks. Never use in
/// a CLONE_VM child whose registry still belongs to the original process.
pub(super) unsafe fn pthread_fork_child() { SEM_OPEN_LOCK.store(0, Ordering::Relaxed); }

unsafe fn fail(error: c_int) {
    unsafe { errno::set_errno(error) };
}

/// Source namespace validation scans to slash/NUL before testing length:
/// an interior slash is EINVAL even when the preceding component is too long.
unsafe fn map_name(name: *const c_char, output: &mut [u8; NAME_MAX + 10]) -> bool {
    let mut name = name;
    while unsafe { name.read() } == b'/' as c_char { name = unsafe { name.add(1) }; }
    let mut length = 0;
    loop {
        let byte = unsafe { name.add(length).read() };
        if byte == b'/' as c_char { unsafe { fail(EINVAL) }; return false; }
        if byte == 0 { break; }
        length += 1;
    }
    if length == 0 || (length <= 2 && unsafe { name.read() } == b'.' as c_char
        && unsafe { name.add(length - 1).read() } == b'.' as c_char) {
        unsafe { fail(EINVAL) }; return false;
    }
    if length > NAME_MAX { unsafe { fail(ENAMETOOLONG) }; return false; }
    output[..9].copy_from_slice(b"/dev/shm/");
    unsafe { core::ptr::copy_nonoverlapping(name.cast::<u8>(), output.as_mut_ptr().add(9), length + 1) };
    true
}

unsafe fn open_file(path: *const u8, flags: c_int, mode: u32) -> c_int {
    c_status(unsafe { raw_syscall::syscall4(raw_syscall::SYS_OPENAT, AT_FDCWD,
        path as i64, (flags | O_LARGEFILE) as i64, mode as i64) })
}
unsafe fn close_file(fd: c_int) {
    c_status(unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, fd as i64) });
}
unsafe fn unlink_file(path: *const u8) -> c_int {
    c_status(unsafe { raw_syscall::syscall3(raw_syscall::SYS_UNLINKAT, AT_FDCWD, path as i64, 0) })
}
unsafe fn map_semaphore(fd: c_int) -> *mut c_void {
    c_result(unsafe { raw_syscall::syscall6(raw_syscall::SYS_MMAP,
        0, SEM_BYTES as i64, 3, 1, fd as i64, 0) }) as usize as *mut c_void
}
unsafe fn unmap_semaphore(semaphore: *mut c_void) {
    // Retain musl munmap's shared VM wait through the existing mapping owner.
    unsafe { memory_mapping::munmap(semaphore, SEM_BYTES); }
}

struct Cancellation(c_int);
impl Cancellation {
    unsafe fn disable() -> Option<Self> {
        let mut previous = 0;
        let result = unsafe { pthread_cancel::pthread_setcancelstate(1, &mut previous) };
        if result != 0 { unsafe { fail(result) }; None } else { Some(Self(previous)) }
    }
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        unsafe { pthread_cancel::pthread_setcancelstate(self.0, core::ptr::null_mut()); }
    }
}

/// Open a shared-memory namespace file with musl's fixed descriptor flags.
/// # Safety
/// `name` must be a readable NUL-terminated C string for this call. The caller
/// owns the resulting descriptor and any effects requested by flags/mode.
#[no_mangle]
pub unsafe extern "C" fn shm_open(name: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    let mut path = [0_u8; NAME_MAX + 10];
    if !unsafe { map_name(name, &mut path) } { return -1; }
    let Some(cancellation) = (unsafe { Cancellation::disable() }) else { return -1; };
    let result = unsafe { open_file(path.as_ptr(), flags | SHM_FLAGS, mode) };
    drop(cancellation);
    result
}

/// Unlink the shared namespace name without invalidating live mappings/fds.
/// # Safety
/// `name` must be a readable NUL-terminated C string for this call.
#[no_mangle]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    let mut path = [0_u8; NAME_MAX + 10];
    if !unsafe { map_name(name, &mut path) } { return -1; }
    unsafe { unlink_file(path.as_ptr()) }
}

/// Named semaphore names use exactly the shared-memory namespace.
/// # Safety
/// `name` must be a readable NUL-terminated C string for this call.
#[no_mangle]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    unsafe { shm_unlink(name) }
}

// sem_open without O_CREAT has exactly two C arguments. Only O_CREAT admits
// the promoted mode_t/unsigned values in edx/ecx; no dummy Rust parameters are
// imposed on legal two-argument callers.
core::arch::global_asm!(
    r#"
    .section .text.sem_open,"ax",@progbits
    .p2align 4
    .global sem_open
    .type sem_open,@function
sem_open:
    test esi, 64
    jnz {create}
    jmp {existing}
    .size sem_open, .-sem_open
    .section .note.GNU-stack,"",@progbits
"#,
    create = sym open_create,
    existing = sym open_existing,
);

#[derive(Clone, Copy)]
struct Creation { mode: u32, value: u32 }
#[inline(never)]
unsafe extern "C" fn open_existing(name: *const c_char, flags: c_int) -> *mut c_void {
    unsafe { open_named_semaphore(name, flags, None) }
}
#[inline(never)]
unsafe extern "C" fn open_create(name: *const c_char, flags: c_int, mode: c_uint, value: c_uint) -> *mut c_void {
    unsafe { open_named_semaphore(name, flags, Some(Creation { mode, value })) }
}

/// Reserve source table capacity before any file can be published.
unsafe fn reserve_slot() -> Option<(*mut Entry, usize)> {
    unsafe { lock() };
    let mut table = TABLE.load(Ordering::Relaxed);
    if table.is_null() {
        table = unsafe { allocator::allocate_internal(core::mem::size_of::<Entry>() * SEM_NSEMS_MAX) }.cast::<Entry>();
        if table.is_null() { unsafe { unlock() }; return None; }
        unsafe { core::ptr::write_bytes(table, 0, SEM_NSEMS_MAX) };
        TABLE.store(table, Ordering::Release);
    }
    let mut slot = None;
    let mut count = 0_i64;
    for index in 0..SEM_NSEMS_MAX {
        let entry = unsafe { &*table.add(index) };
        count += entry.references as i64;
        if entry.semaphore.is_null() && slot.is_none() { slot = Some(index); }
    }
    if count >= c_int::MAX as i64 || slot.is_none() {
        unsafe { fail(EMFILE); unlock(); }
        return None;
    }
    let slot = slot.unwrap();
    unsafe { (*table.add(slot)).semaphore = RESERVED; unlock(); }
    Some((table, slot))
}

#[repr(C)]
struct Timespec { seconds: i64, nanoseconds: i64 }

// Musl's temporary filename is just the realtime nanosecond field. This is
// collision-retried atomic file creation, not random/cryptographic generation.
fn temporary_name(nanoseconds: i64) -> [u8; 64] {
    let mut output = [0_u8; 64];
    output[..13].copy_from_slice(b"/dev/shm/tmp-");
    let mut digits = [0_u8; 10];
    let mut count = 0;
    let mut number = nanoseconds as u32;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 { break; }
    }
    for index in 0..count { output[13 + index] = digits[count - index - 1]; }
    output
}

/// File-open/mapping protocol from sem_open.c. Cleanup deliberately follows
/// source errno behavior, including stale success errno and unlink failures.
unsafe fn acquire_mapping(path: &[u8], flags: c_int, creation: Option<Creation>) -> Option<(*mut c_void, u64)> {
    if flags == O_CREAT | O_EXCL && c_status(unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_ACCESS, path.as_ptr() as i64, 0)
    }) == 0 {
        unsafe { fail(EEXIST) }; return None;
    }
    // sem_init defines three words. Zero reserved words before writing the
    // full public image, rather than exposing unspecified C stack contents.
    let mut initial = [0_u32; 8];
    let mut initialized = false;
    loop {
        if flags != O_CREAT | O_EXCL {
            let fd = unsafe { open_file(path.as_ptr(), OBJECT_FLAGS, 0) };
            if fd >= 0 {
                let inode = unsafe { stat_compat::fstat_inode(fd) };
                let mapping = if inode.is_some() { unsafe { map_semaphore(fd) } } else { RESERVED };
                unsafe { close_file(fd) };
                if mapping == RESERVED { return None; }
                return Some((mapping, inode.unwrap()));
            }
            if unsafe { errno::get_errno() } != ENOENT { return None; }
        }
        let Some(creation) = creation.filter(|_| flags & O_CREAT != 0) else { return None; };
        if !initialized {
            if creation.value > SEM_VALUE_MAX { unsafe { fail(EINVAL) }; return None; }
            unsafe { posix_semaphore::sem_init(initial.as_mut_ptr().cast(), 1, creation.value); }
            initialized = true;
        }
        let mut time = Timespec { seconds: 0, nanoseconds: 0 };
        c_status(unsafe { raw_syscall::syscall2(raw_syscall::SYS_CLOCK_GETTIME, 0, core::ptr::addr_of_mut!(time) as i64) });
        let temporary = temporary_name(time.nanoseconds);
        let fd = unsafe { open_file(temporary.as_ptr(), OBJECT_FLAGS | O_CREAT | O_EXCL, creation.mode & 0o666) };
        if fd < 0 {
            if unsafe { errno::get_errno() } == EEXIST { continue; }
            return None;
        }
        let written = c_result(unsafe { raw_syscall::syscall3(raw_syscall::SYS_WRITE,
            fd as i64, initial.as_ptr() as i64, SEM_BYTES as i64) });
        let inode = if written == SEM_BYTES as i64 { unsafe { stat_compat::fstat_inode(fd) } } else { None };
        let mapping = if inode.is_some() { unsafe { map_semaphore(fd) } } else { RESERVED };
        unsafe { close_file(fd) };
        if mapping == RESERVED { unsafe { unlink_file(temporary.as_ptr()); } return None; }
        let linked = c_status(unsafe { raw_syscall::syscall2(raw_syscall::SYS_LINK,
            temporary.as_ptr() as i64, path.as_ptr() as i64) });
        let error = if linked == 0 { 0 } else { unsafe { errno::get_errno() } };
        unsafe { unlink_file(temporary.as_ptr()); }
        if error == 0 { return Some((mapping, inode.unwrap())); }
        unsafe { unmap_semaphore(mapping) };
        if error != EEXIST || flags == O_CREAT | O_EXCL { return None; }
    }
}

unsafe fn open_named_semaphore(name: *const c_char, flags: c_int, creation: Option<Creation>) -> *mut c_void {
    let mut path = [0_u8; NAME_MAX + 10];
    if !unsafe { map_name(name, &mut path) } { return core::ptr::null_mut(); }
    let Some((table, reserved)) = (unsafe { reserve_slot() }) else { return core::ptr::null_mut(); };
    let cancellation = unsafe { Cancellation::disable() };
    let result = if cancellation.is_some() {
        unsafe { acquire_mapping(&path, flags & (O_CREAT | O_EXCL), creation) }
    } else { None };
    if let Some((mut mapping, inode)) = result {
        unsafe { lock() };
        let mut slot = reserved;
        for index in 0..SEM_NSEMS_MAX {
            if unsafe { (*table.add(index)).inode } == inode {
                unsafe { unmap_semaphore(mapping); (*table.add(reserved)).semaphore = core::ptr::null_mut(); }
                slot = index;
                mapping = unsafe { (*table.add(index)).semaphore };
                break;
            }
        }
        unsafe {
            let entry = &mut *table.add(slot);
            entry.references += 1;
            entry.semaphore = mapping;
            entry.inode = inode;
            unlock();
        }
        drop(cancellation);
        mapping
    } else {
        // The source restores cancellation before freeing a failed slot.
        drop(cancellation);
        unsafe { lock(); (*table.add(reserved)).semaphore = core::ptr::null_mut(); unlock(); }
        core::ptr::null_mut()
    }
}

/// Release one successful sem_open reference; only the final close unmaps.
/// # Safety
/// `semaphore` must be a live named-semaphore handle from sem_open with an
/// unmatched open reference in this process. The final close requires that
/// no caller still accesses or waits on this process's mapping.
#[no_mangle]
pub unsafe extern "C" fn sem_close(semaphore: *mut c_void) -> c_int {
    unsafe { lock() };
    let table = TABLE.load(Ordering::Relaxed);
    if !table.is_null() {
        for index in 0..SEM_NSEMS_MAX {
            let entry = unsafe { &mut *table.add(index) };
            if entry.semaphore == semaphore {
                entry.references -= 1;
                if entry.references != 0 { unsafe { unlock() }; return 0; }
                entry.semaphore = core::ptr::null_mut();
                entry.inode = 0;
                unsafe { unlock(); unmap_semaphore(semaphore); }
                return 0;
            }
        }
    }
    // An unmatched handle is outside sem_close's contract; do not dereference
    // past the table if one nevertheless reaches this ABI boundary.
    unsafe { unlock(); fail(EINVAL); }
    -1
}
