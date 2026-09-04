//! Bounded static Linux/x86-64 C process-environment boundary.
//!
//! This leaf owns the process-global `__environ` object, its musl-compatible
//! weak public spellings (`environ`, `_environ`, and `___environ`), and the
//! selected `getenv`/`setenv`/`putenv`/`unsetenv`/`clearenv` operations.  The
//! existing private static startup passes the validated initial `envp` vector
//! here before application code runs.  Reads retain that kernel/CRT-owned
//! vector until the first successful `setenv`/`putenv`/matching `unsetenv`
//! mutation.  Such a mutation copies only the pointer vector into a fixed
//! 128-entry private table; `setenv` copies every successful replacement
//! `name=value` string into a fixed 16 KiB private byte arena, while `putenv`
//! deliberately retains its caller-owned string pointer. Arena bytes are
//! never reclaimed by replacement, `unsetenv`, or `clearenv`; only the one
//! pre-application startup installation resets the bump offset.
//!
//! This is a real but deliberately bounded static-environment artifact, not
//! general environment parity. `getenv` will examine at most 1,048,576 vector
//! slots. `setenv`, `putenv`, and `unsetenv` return `-1` with `ENOMEM` before
//! changing state when the current vector has more than 128 entries;
//! `clearenv` remains the allocation-free exception and always publishes a
//! null vector. A new entry at capacity or a `setenv` after replacement-arena
//! exhaustion likewise returns `ENOMEM` without a partial mutation.
//!
//! The local spin lock serializes only calls through these five selected
//! functions. It does not stabilize a returned `getenv` pointer after the
//! call, synchronize direct foreign writes to `environ`, protect mutation or
//! lifetime of caller-owned `putenv` strings, provide fork recovery when a
//! different thread held the lock, or make any operation async-signal-safe.
//! Callers must coordinate all such access themselves. The private opt-in
//! `x86-process-exec` leaf consumes only `getenv` and `__environ` for direct
//! exec-family PATH/environment forwarding. That reuse does not establish
//! `posix_spawn`, fork, or general runtime integration. This artifact also has
//! no allocator, `secure_getenv`, auxv secure-execution decision, general
//! startup, dynamic libc, loader, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/env/__environ.c` supplies the internal/public environment-global
//!   ownership and weak-alias intent.
//! - `src/env/getenv.c` supplies name validation, first-match lookup, and the
//!   returned value-pointer contract.
//! - `src/env/setenv.c`, `putenv.c`, `unsetenv.c`, and `clearenv.c` supply the
//!   selected replacement, caller-owned pointer, duplicate-removal, and
//!   clear semantics.
//!
//! Musl allocates replacement strings and grows the pointer vector through its
//! allocator.  This static archive deliberately does not select that C
//! allocator.  The fixed table/arena below is therefore an explicit bounded
//! implementation difference, with normal `ENOMEM` failure rather than a
//! fabricated successful mutation.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 static environment leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use super::errno;

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;

// This is an artifact-local resource contract, not a public ABI constant.
const ENVIRONMENT_ENTRY_CAPACITY: usize = 128;
const ENVIRONMENT_STORAGE_BYTES: usize = 16 * 1024;
const ENVIRONMENT_LOOKUP_LIMIT: usize = 1 << 20;

/// The static-startup-owned initial environment pointer.
///
/// The public aliases below are ELF aliases of this exact object, so assignment
/// through the GNU `environ` spelling remains visible to the selected lookup
/// and mutation paths.  The caller owns a directly assigned vector's C-string
/// validity and lifetime, exactly as for musl's public global.
#[no_mangle]
pub static mut __environ: *mut *mut c_char = ptr::null_mut();

// Preserve musl's public global spelling as weak aliases of one object rather
// than maintaining four independent pointers that can silently diverge.  The
// private underscore spellings are not installed-header declarations; they
// exist only for the bounded static ABI/global compatibility check.
core::arch::global_asm!(
    r#"
    .weak environ
    .set environ, __environ

    .weak _environ
    .set _environ, __environ

    .weak ___environ
    .set ___environ, __environ

    .section .note.GNU-stack,"",@progbits
"#,
);

static ENVIRONMENT_LOCK: AtomicBool = AtomicBool::new(false);
static mut ENVIRONMENT_TABLE: [*mut c_char; ENVIRONMENT_ENTRY_CAPACITY + 1] =
    [ptr::null_mut(); ENVIRONMENT_ENTRY_CAPACITY + 1];
static mut ENVIRONMENT_STORAGE: [u8; ENVIRONMENT_STORAGE_BYTES] = [0; ENVIRONMENT_STORAGE_BYTES];
static mut ENVIRONMENT_STORAGE_USED: usize = 0;

/// One artifact-local lock held while reading or changing private environment
/// state.  The C process environment is inherently ambient and neither this
/// lock nor the selected API makes it async-signal-safe.
struct EnvironmentLock;

impl EnvironmentLock {
    #[inline]
    fn acquire() -> Self {
        while ENVIRONMENT_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        Self
    }
}

impl Drop for EnvironmentLock {
    #[inline]
    fn drop(&mut self) {
        ENVIRONMENT_LOCK.store(false, Ordering::Release);
    }
}

#[inline]
unsafe fn environment_pointer() -> *mut *mut c_char {
    // SAFETY: the selected global is a machine-word C pointer.  Calls through
    // this leaf hold `EnvironmentLock`; foreign direct global writes retain
    // the documented C caller coordination obligation.
    unsafe { ptr::read(ptr::addr_of!(__environ)) }
}

#[inline]
unsafe fn set_environment_pointer(environment: *mut *mut c_char) {
    // SAFETY: all public aliases name this exact object.  The caller holds the
    // artifact-local lock and publishes a pointer vector that remains live.
    unsafe { ptr::write(ptr::addr_of_mut!(__environ), environment) };
}

#[inline]
unsafe fn environment_table_pointer() -> *mut *mut c_char {
    // SAFETY: this returns a raw pointer only.  The fixed table is accessed
    // through checked indices while the artifact-local lock is held.
    ptr::addr_of_mut!(ENVIRONMENT_TABLE).cast::<*mut c_char>()
}

#[inline]
unsafe fn table_read(index: usize) -> *mut c_char {
    debug_assert!(index <= ENVIRONMENT_ENTRY_CAPACITY);
    // SAFETY: the index is bounded by the table's final terminator slot.
    unsafe { ptr::read(environment_table_pointer().add(index)) }
}

#[inline]
unsafe fn table_write(index: usize, value: *mut c_char) {
    debug_assert!(index <= ENVIRONMENT_ENTRY_CAPACITY);
    // SAFETY: the index is bounded by the table's final terminator slot.
    unsafe { ptr::write(environment_table_pointer().add(index), value) };
}

/// Return the byte length of a valid environment name, rejecting empty names
/// and names that contain `=`.  C callers own the non-null terminated-string
/// requirement; invalid public strings have the usual C undefined behavior.
unsafe fn environment_name_length(name: *const c_char) -> Option<usize> {
    if name.is_null() {
        return None;
    }
    let mut length = 0usize;
    loop {
        // SAFETY: the C caller provides a valid NUL-terminated name.
        let byte = unsafe { ptr::read(name.add(length).cast::<u8>()) };
        if byte == 0 {
            return (length != 0).then_some(length);
        }
        if byte == b'=' {
            return None;
        }
        length += 1;
    }
}

/// Split a valid `putenv` input at its first `=` without allocating.
unsafe fn entry_key_length(entry: *const c_char) -> (usize, bool) {
    let mut length = 0usize;
    loop {
        // SAFETY: the C caller provides a valid NUL-terminated entry.
        let byte = unsafe { ptr::read(entry.add(length).cast::<u8>()) };
        if byte == 0 {
            return (length, false);
        }
        if byte == b'=' {
            return (length, true);
        }
        length += 1;
    }
}

/// Return a valid C-string byte length.  The selected setenv boundary owns no
/// pointer validation beyond C's ordinary non-null terminated-string contract.
unsafe fn c_string_length(value: *const c_char) -> usize {
    let mut length = 0usize;
    loop {
        // SAFETY: the C caller provides a valid NUL-terminated string.
        if unsafe { ptr::read(value.add(length).cast::<u8>()) } == 0 {
            return length;
        }
        length += 1;
    }
}

#[inline]
unsafe fn entry_matches_name(entry: *const c_char, name: *const c_char, name_length: usize) -> bool {
    if entry.is_null() {
        return false;
    }
    for index in 0..name_length {
        // SAFETY: `entry` and `name` are valid C strings through their key
        // bytes under the selected public contract.
        if unsafe { ptr::read(entry.add(index).cast::<u8>()) }
            != unsafe { ptr::read(name.add(index).cast::<u8>()) }
        {
            return false;
        }
    }
    // SAFETY: a match can name an environment entry only when its next byte
    // is exactly the separator, never a longer-prefix byte.
    unsafe { ptr::read(entry.add(name_length).cast::<u8>()) == b'=' }
}

/// Count an environment vector for a potential mutation.
///
/// The initial kernel/CRT vector can be arbitrarily sized, but this private
/// artifact only materializes up to its fixed table capacity.  A null vector
/// is the empty environment.  The caller holds `EnvironmentLock`.
unsafe fn mutation_entry_count(environment: *mut *mut c_char) -> Result<usize, ()> {
    if environment.is_null() {
        return Ok(0);
    }
    for index in 0..=ENVIRONMENT_ENTRY_CAPACITY {
        // SAFETY: C's public environment global names a null-terminated
        // pointer vector.  The bounded read detects too many retained entries
        // before this artifact copies any of them into private state.
        if unsafe { ptr::read(environment.add(index)) }.is_null() {
            return Ok(index);
        }
    }
    Err(())
}

/// Locate the first matching entry in an arbitrary public environment vector.
///
/// Lookup does not require the fixed mutation-table capacity.  The finite cap
/// prevents a malformed directly assigned public vector from causing an
/// unbounded walk through process memory; a well-formed kernel/CRT vector is
/// expected to terminate far below it.
unsafe fn find_entry(
    environment: *mut *mut c_char,
    name: *const c_char,
    name_length: usize,
) -> Option<usize> {
    if environment.is_null() {
        return None;
    }
    for index in 0..ENVIRONMENT_LOOKUP_LIMIT {
        // SAFETY: C callers own vector validity through the null terminator.
        let entry = unsafe { ptr::read(environment.add(index)) };
        if entry.is_null() {
            return None;
        }
        if unsafe { entry_matches_name(entry, name, name_length) } {
            return Some(index);
        }
    }
    None
}

/// Copy the current public vector into the private fixed table if a mutation
/// needs it.  The caller must have already checked its bounded entry count.
unsafe fn materialize_mutation_table(environment: *mut *mut c_char, count: usize) {
    let table = unsafe { environment_table_pointer() };
    if environment != table {
        for index in 0..count {
            // SAFETY: `count` was bounded and each source pointer belongs to
            // the caller-owned null-terminated public environment vector.
            unsafe { table_write(index, ptr::read(environment.add(index))) };
        }
        unsafe { table_write(count, ptr::null_mut()) };
        // SAFETY: the private table now has a complete terminating pointer.
        unsafe { set_environment_pointer(table) };
    }
}

unsafe fn reserve_setenv_storage(name_length: usize, value_length: usize) -> Option<*mut c_char> {
    let required = name_length.checked_add(value_length)?.checked_add(2)?;
    // SAFETY: the caller holds `EnvironmentLock`, so the bump offset cannot
    // change between this checked read and its later publication.
    let offset = unsafe { ptr::read(ptr::addr_of!(ENVIRONMENT_STORAGE_USED)) };
    let end = offset.checked_add(required)?;
    if end > ENVIRONMENT_STORAGE_BYTES {
        return None;
    }
    // SAFETY: the checked range lies wholly inside the fixed static arena.
    Some(unsafe { ptr::addr_of_mut!(ENVIRONMENT_STORAGE).cast::<u8>().add(offset).cast() })
}

unsafe fn commit_setenv_storage(name_length: usize, value_length: usize) {
    let required = name_length + value_length + 2;
    // SAFETY: `reserve_setenv_storage` proved this addition fits before the
    // bytes were copied and the caller still owns the lock.
    unsafe { ENVIRONMENT_STORAGE_USED += required };
}

#[inline]
unsafe fn environment_failure(error: c_int) -> c_int {
    // SAFETY: this selected C ABI path owns the direct local error result.
    unsafe { errno::set_errno(error) };
    -1
}

/// Install the validated initial `envp` from the selected private static
/// startup handoff.
///
/// This is not an exported application-startup ABI.  The bounded static CRT
/// calls it once after vector validation and before `init`/`main`; direct
/// freestanding evidence writes the same global from its untouched entry
/// stack.  Resetting the private mutation arena is sound at that one startup
/// transition because no prior environment value has been published.
pub(crate) unsafe fn install_initial(environment: *const *const c_char) {
    let _lock = EnvironmentLock::acquire();
    // SAFETY: the static startup validator established the pointer-vector
    // delimiters.  The public C ABI uses mutable pointer spelling only because
    // historical C globals permit caller reassignment.
    unsafe { set_environment_pointer(environment.cast_mut().cast()) };
    // SAFETY: before application code runs, no selected value pointer can
    // refer into this private replacement arena.
    unsafe { ENVIRONMENT_STORAGE_USED = 0 };
}

/// Return the value portion of the first matching environment entry.
#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    let Some(name_length) = (unsafe { environment_name_length(name) }) else {
        return ptr::null_mut();
    };
    let _lock = EnvironmentLock::acquire();
    let environment = unsafe { environment_pointer() };
    let Some(index) = (unsafe { find_entry(environment, name, name_length) }) else {
        return ptr::null_mut();
    };
    // SAFETY: `find_entry` returned an in-bounds live entry with a separator
    // at `name_length`; the returned value pointer remains caller-observable
    // until the next environment mutation, as with musl.
    unsafe { ptr::read(environment.add(index)).add(name_length + 1) }
}

/// Set one name/value entry, copying the replacement into private static
/// storage on success.
#[no_mangle]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    let Some(name_length) = (unsafe { environment_name_length(name) }) else {
        return unsafe { environment_failure(EINVAL) };
    };
    if value.is_null() {
        return unsafe { environment_failure(EINVAL) };
    }
    let value_length = unsafe { c_string_length(value) };
    let _lock = EnvironmentLock::acquire();
    let environment = unsafe { environment_pointer() };
    let entry_count = match unsafe { mutation_entry_count(environment) } {
        Ok(count) => count,
        Err(()) => return unsafe { environment_failure(ENOMEM) },
    };
    let matched = unsafe { find_entry(environment, name, name_length) };
    if overwrite == 0 && matched.is_some() {
        return 0;
    }
    if matched.is_none() && entry_count == ENVIRONMENT_ENTRY_CAPACITY {
        return unsafe { environment_failure(ENOMEM) };
    }
    let Some(replacement) = (unsafe { reserve_setenv_storage(name_length, value_length) }) else {
        return unsafe { environment_failure(ENOMEM) };
    };
    // SAFETY: the reserved arena range is disjoint from its uncommitted tail;
    // inputs are the caller's valid C strings through the measured lengths.
    unsafe {
        ptr::copy_nonoverlapping(name.cast::<u8>(), replacement.cast::<u8>(), name_length);
        ptr::write(replacement.cast::<u8>().add(name_length), b'=');
        ptr::copy_nonoverlapping(
            value.cast::<u8>(),
            replacement.cast::<u8>().add(name_length + 1),
            value_length + 1,
        );
    }
    unsafe { materialize_mutation_table(environment, entry_count) };
    if let Some(index) = matched {
        unsafe { table_write(index, replacement) };
    } else {
        unsafe {
            table_write(entry_count, replacement);
            table_write(entry_count + 1, ptr::null_mut());
        }
    }
    unsafe { commit_setenv_storage(name_length, value_length) };
    0
}

/// Insert or replace one caller-owned `name=value` entry without copying it.
#[no_mangle]
pub unsafe extern "C" fn putenv(entry: *mut c_char) -> c_int {
    if entry.is_null() {
        return unsafe { environment_failure(EINVAL) };
    }
    let (name_length, has_separator) = unsafe { entry_key_length(entry) };
    if name_length == 0 || !has_separator {
        // SAFETY: this preserves musl's `putenv("NAME")` removal spelling.
        return unsafe { unsetenv(entry.cast_const()) };
    }
    let _lock = EnvironmentLock::acquire();
    let environment = unsafe { environment_pointer() };
    let entry_count = match unsafe { mutation_entry_count(environment) } {
        Ok(count) => count,
        Err(()) => return unsafe { environment_failure(ENOMEM) },
    };
    let matched = unsafe { find_entry(environment, entry.cast_const(), name_length) };
    if matched.is_none() && entry_count == ENVIRONMENT_ENTRY_CAPACITY {
        return unsafe { environment_failure(ENOMEM) };
    }
    unsafe { materialize_mutation_table(environment, entry_count) };
    if let Some(index) = matched {
        unsafe { table_write(index, entry) };
    } else {
        unsafe {
            table_write(entry_count, entry);
            table_write(entry_count + 1, ptr::null_mut());
        }
    }
    0
}

/// Remove every matching name from the current environment.
#[no_mangle]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    let Some(name_length) = (unsafe { environment_name_length(name) }) else {
        return unsafe { environment_failure(EINVAL) };
    };
    let _lock = EnvironmentLock::acquire();
    let environment = unsafe { environment_pointer() };
    let entry_count = match unsafe { mutation_entry_count(environment) } {
        Ok(count) => count,
        Err(()) => return unsafe { environment_failure(ENOMEM) },
    };
    let mut any_match = false;
    for index in 0..entry_count {
        // SAFETY: `entry_count` came from the caller's terminated vector.
        let entry = unsafe { ptr::read(environment.add(index)) };
        if unsafe { entry_matches_name(entry.cast_const(), name, name_length) } {
            any_match = true;
            break;
        }
    }
    if !any_match {
        return 0;
    }
    unsafe { materialize_mutation_table(environment, entry_count) };
    let mut write_index = 0usize;
    for read_index in 0..entry_count {
        let entry = unsafe { table_read(read_index) };
        if !unsafe { entry_matches_name(entry, name, name_length) } {
            unsafe { table_write(write_index, entry) };
            write_index += 1;
        }
    }
    unsafe { table_write(write_index, ptr::null_mut()) };
    0
}

/// Clear the public process environment pointer.
#[no_mangle]
pub unsafe extern "C" fn clearenv() -> c_int {
    let _lock = EnvironmentLock::acquire();
    // SAFETY: musl's selected clear result exposes a null environment global;
    // retained private strings remain intentionally unreclaimed because the
    // artifact owns no allocator or returned-pointer invalidation protocol.
    unsafe { set_environment_pointer(ptr::null_mut()) };
    0
}
