//! Allocator-backed Linux/x86-64 C process-environment runtime.
//!
//! This is the opt-in environment owner used with the existing
//! `x86-allocator-runtime` composition.  It deliberately follows musl 1.2.6
//! `src/env/{__environ,getenv,setenv,putenv,unsetenv,clearenv}.c`: one public
//! `__environ` object has weak aliases, externally supplied vectors are
//! mutated in place for replacement and removal, only `setenv` strings are
//! owned, and the vector allocated for append remains musl's `oldenv` only
//! while active; a later append after direct reassignment retires that vector.
//!
//! The allocator boundary is the already evidenced x86 C `malloc`/`realloc`/
//! `free` wrapper.  This leaf does not invent an allocator or export a second
//! allocation API.  It remains deliberately narrower than a completed process
//! lifecycle: callers retain C's ordinary synchronization, signal-safety,
//! fork, exec/spawn, direct-`environ`, and borrowed-pointer obligations.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/env/__environ.c` supplies the single global and weak-alias shape.
//! - `src/env/getenv.c` supplies first-match borrowed lookup.
//! - `src/env/setenv.c` and its `__env_rm_add` helper supply copied-string
//!   ownership tracking and replacement reclamation.
//! - `src/env/putenv.c` supplies the `oldenv` vector rule and caller-owned
//!   `putenv` storage rule.
//! - `src/env/unsetenv.c` and `src/env/clearenv.c` supply in-place removal and
//!   tracked-string reclamation without freeing direct caller vectors.
//!
//! Intentional integration differences are narrow: this owner is selected
//! only by `x86-environment-runtime`, uses the existing mixed x86 allocation
//! composition, and safely reports `ENOMEM` for unrepresentable allocation
//! arithmetic. Null or unterminated pointers, invalid direct vectors, and
//! aliases a caller creates to internally owned strings remain outside the C
//! API's valid-object contract rather than supported compatibility behavior.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 environment runtime requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::ptr;

use super::errno;

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;

// Keep allocation ownership at the established x86 C allocator boundary. The
// feature-built archive resolves these calls to its own weak wrappers and the
// bundled backend; this module must never name that backend directly.
unsafe extern "C" {
    #[link_name = "malloc"]
    fn cabi_allocator_malloc(size: usize) -> *mut c_void;
    #[link_name = "realloc"]
    fn cabi_allocator_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn cabi_allocator_free(pointer: *mut c_void);
}

/// The process-global environment pointer installed by static startup or
/// assigned directly through the historical public aliases.
#[no_mangle]
pub static mut __environ: *mut *mut c_char = ptr::null_mut();

// Preserve musl's public spelling as weak aliases of one writable object.
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

// This is musl's `static char **oldenv`: only a vector allocated by an append
// belongs to this owner. A direct public `environ` assignment is never freed.
static mut OWNED_ENVIRONMENT_VECTOR: *mut *mut c_char = ptr::null_mut();

// This is musl's `env_alloced` / `env_alloced_n` registry. It tracks only
// successful `setenv` allocations, never caller-owned `putenv` strings.
static mut OWNED_ENVIRONMENT_STRINGS: *mut *mut c_char = ptr::null_mut();
static mut OWNED_ENVIRONMENT_STRING_COUNT: usize = 0;

#[inline]
unsafe fn environment_pointer() -> *mut *mut c_char {
    // SAFETY: every public alias names this machine-word object. The C API
    // deliberately permits direct callers to assign it.
    unsafe { ptr::read(ptr::addr_of!(__environ)) }
}

#[inline]
unsafe fn set_environment_pointer(environment: *mut *mut c_char) {
    // SAFETY: callers publish only a valid null-terminated C pointer vector,
    // exactly as required by musl's public `environ` object.
    unsafe { ptr::write(ptr::addr_of_mut!(__environ), environment) };
}

#[inline]
unsafe fn environment_failure(error: c_int) -> c_int {
    // SAFETY: this C ABI leaf owns its calling thread's errno translation.
    unsafe { errno::set_errno(error) };
    -1
}

/// Return the byte length of a valid environment name, rejecting an empty
/// name and any name containing `=`.
///
/// A null `name` receives musl `setenv`'s EINVAL result. Other invalid C
/// string pointers remain outside the C ABI contract.
unsafe fn environment_name_length(name: *const c_char) -> Option<usize> {
    if name.is_null() {
        return None;
    }
    let mut length = 0usize;
    loop {
        // SAFETY: C callers provide a NUL-terminated name through this byte.
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

/// Return the first `=` position in a caller-owned `putenv` string.
unsafe fn putenv_key_length(entry: *const c_char) -> (usize, bool) {
    let mut length = 0usize;
    loop {
        // SAFETY: `putenv` retains C's NUL-terminated-string precondition.
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

/// Return a caller-provided C string's byte length excluding its terminator.
unsafe fn c_string_length(value: *const c_char) -> usize {
    let mut length = 0usize;
    loop {
        // SAFETY: `setenv` retains C's valid NUL-terminated value contract.
        if unsafe { ptr::read(value.add(length).cast::<u8>()) } == 0 {
            return length;
        }
        length += 1;
    }
}

/// Match an environment entry's complete `NAME=` prefix.
unsafe fn entry_matches_name(
    entry: *const c_char,
    name: *const c_char,
    name_length: usize,
) -> bool {
    if entry.is_null() {
        return false;
    }
    for index in 0..name_length {
        // SAFETY: this checked prefix remains inside both valid C strings.
        if unsafe { ptr::read(entry.add(index).cast::<u8>()) }
            != unsafe { ptr::read(name.add(index).cast::<u8>()) }
        {
            return false;
        }
    }
    // SAFETY: the final prefix byte is the entry separator, not a longer key.
    unsafe { ptr::read(entry.add(name_length).cast::<u8>()) == b'=' }
}

/// Match the `NAME=` prefix in the same way musl's `strncmp(s, *e, l+1)` does.
unsafe fn entry_matches_key(
    entry: *const c_char,
    key: *const c_char,
    key_length: usize,
) -> bool {
    for index in 0..=key_length {
        // SAFETY: `key` has its separator at `key_length`; a shorter entry
        // mismatches at its terminator before any byte beyond that terminator
        // is read, matching `strncmp`'s C-string contract.
        if unsafe { ptr::read(entry.add(index).cast::<u8>()) }
            != unsafe { ptr::read(key.add(index).cast::<u8>()) }
        {
            return false;
        }
    }
    true
}

/// Record a `setenv` allocation replacement/removal exactly like musl's
/// `__env_rm_add`: a registry allocation failure leaks only the untracked new
/// string after the public environment operation has already succeeded.
unsafe fn update_owned_string(old: *mut c_char, mut new: *mut c_char) {
    // SAFETY: the count and pointer are changed only by this no-lock musl
    // shaped state machine; concurrent environment mutation is a caller race.
    let count = unsafe { OWNED_ENVIRONMENT_STRING_COUNT };
    for index in 0..count {
        // SAFETY: `count` records initialized registry slots.
        let slot = unsafe { OWNED_ENVIRONMENT_STRINGS.add(index) };
        // SAFETY: every initialized slot stores one nullable C string pointer.
        let tracked = unsafe { ptr::read(slot) };
        if tracked == old {
            // SAFETY: this replaces the registry identity before releasing the
            // old `setenv` allocation, preserving the source ownership order.
            unsafe { ptr::write(slot, new) };
            // SAFETY: only a tracked `setenv` string reaches this release.
            unsafe { cabi_allocator_free(old.cast()) };
            return;
        }
        if tracked.is_null() && !new.is_null() {
            // SAFETY: reuse one released tracked-string slot before growing.
            unsafe { ptr::write(slot, new) };
            new = ptr::null_mut();
        }
    }
    if new.is_null() {
        return;
    }

    let Some(next_count) = count.checked_add(1) else {
        return;
    };
    let Some(bytes) = next_count.checked_mul(size_of::<*mut c_char>()) else {
        return;
    };
    // SAFETY: C realloc accepts the nullable prior registry pointer.
    let replacement = unsafe {
        cabi_allocator_realloc(OWNED_ENVIRONMENT_STRINGS.cast::<c_void>(), bytes)
            .cast::<*mut c_char>()
    };
    if replacement.is_null() {
        // Preserve musl's post-success leak behavior if bookkeeping cannot
        // grow. The allocator's errno is intentionally observable here.
        return;
    }
    // SAFETY: the successful allocation has room for the appended slot.
    unsafe {
        OWNED_ENVIRONMENT_STRINGS = replacement;
        ptr::write(replacement.add(count), new);
        OWNED_ENVIRONMENT_STRING_COUNT = next_count;
    }
}

#[inline]
unsafe fn vector_bytes(entry_count: usize) -> Option<usize> {
    entry_count
        .checked_add(2)
        .and_then(|count| count.checked_mul(size_of::<*mut c_char>()))
}

/// Musl-shaped `__putenv`: replace the first matching entry in place, or grow
/// only this leaf's retained vector. `owned_replacement` is non-null only for
/// a `setenv` string that this leaf may later free.
unsafe fn put_entry(
    entry: *mut c_char,
    key_length: usize,
    owned_replacement: *mut c_char,
) -> c_int {
    let environment = unsafe { environment_pointer() };
    let mut entry_count = 0usize;
    if !environment.is_null() {
        loop {
            // SAFETY: C callers retain the public null-terminated vector
            // contract, including vectors directly assigned through environ.
            let current = unsafe { ptr::read(environment.add(entry_count)) };
            if current.is_null() {
                break;
            }
            if unsafe { entry_matches_key(current, entry, key_length) } {
                // SAFETY: musl replaces just this first matching slot without
                // changing a direct caller-owned vector's identity.
                unsafe { ptr::write(environment.add(entry_count), entry) };
                unsafe { update_owned_string(current, owned_replacement) };
                return 0;
            }
            entry_count += 1;
        }
    }

    let Some(bytes) = (unsafe { vector_bytes(entry_count) }) else {
        if !owned_replacement.is_null() {
            // SAFETY: this is the not-yet-published setenv allocation.
            unsafe { cabi_allocator_free(owned_replacement.cast()) };
        }
        return unsafe { environment_failure(ENOMEM) };
    };

    // SAFETY: `OWNED_ENVIRONMENT_VECTOR` is either null or the one prior
    // append vector owned by this leaf. Direct external vectors are copied.
    let new_environment = if environment == unsafe { OWNED_ENVIRONMENT_VECTOR } {
        unsafe {
            cabi_allocator_realloc(OWNED_ENVIRONMENT_VECTOR.cast::<c_void>(), bytes)
                .cast::<*mut c_char>()
        }
    } else {
        unsafe { cabi_allocator_malloc(bytes).cast::<*mut c_char>() }
    };
    if new_environment.is_null() {
        if !owned_replacement.is_null() {
            // SAFETY: release an unpublished setenv allocation on vector OOM.
            unsafe { cabi_allocator_free(owned_replacement.cast()) };
        }
        return -1;
    }

    if environment != unsafe { OWNED_ENVIRONMENT_VECTOR } {
        if entry_count != 0 {
            // SAFETY: the new vector holds all retained pointers plus two
            // slots; external strings remain externally owned.
            unsafe { ptr::copy_nonoverlapping(environment, new_environment, entry_count) };
        }
        // SAFETY: only the last vector allocated by this leaf is ours.
        unsafe { cabi_allocator_free(OWNED_ENVIRONMENT_VECTOR.cast()) };
    }
    // SAFETY: the new vector reserves the append and terminator slots.
    unsafe {
        ptr::write(new_environment.add(entry_count), entry);
        ptr::write(new_environment.add(entry_count + 1), ptr::null_mut());
        OWNED_ENVIRONMENT_VECTOR = new_environment;
        set_environment_pointer(new_environment);
        update_owned_string(ptr::null_mut(), owned_replacement);
    }
    0
}

/// Install the validated initial `envp` before constructors and application
/// callbacks. Startup owns this one-time handoff; it does not reset runtime
/// allocations because no prior user environment operation is valid then.
pub(crate) unsafe fn install_initial(environment: *const *const c_char) {
    // SAFETY: static startup validated the vector delimiters. The mutable type
    // is required only by historical C's writable `environ` global ABI.
    unsafe { set_environment_pointer(environment.cast_mut().cast()) };
}

/// Return a borrowed value for the first matching `NAME=` entry.
///
/// # Safety
///
/// `name` must be a valid NUL-terminated C string. The published environment
/// vector and returned entry storage must remain valid until the caller stops
/// using the returned pointer; concurrent mutation is a C data race.
#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    let Some(name_length) = (unsafe { environment_name_length(name) }) else {
        return ptr::null_mut();
    };
    let mut environment = unsafe { environment_pointer() };
    if environment.is_null() {
        return ptr::null_mut();
    }
    loop {
        // SAFETY: the caller owns the published null-terminated vector.
        let entry = unsafe { ptr::read(environment) };
        if entry.is_null() {
            return ptr::null_mut();
        }
        if unsafe { entry_matches_name(entry, name, name_length) } {
            // SAFETY: a matched entry has its separator at `name_length`.
            return unsafe { entry.add(name_length + 1) };
        }
        // SAFETY: the next slot remains inside the caller's terminated vector.
        environment = unsafe { environment.add(1) };
    }
}

/// Copy one `NAME=value` string and replace or append it.
///
/// # Safety
///
/// `name` and `value` must be valid NUL-terminated C strings. Callers must
/// externally synchronize all environment access, including direct aliases.
#[no_mangle]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    let Some(name_length) = (unsafe { environment_name_length(name) }) else {
        return unsafe { environment_failure(EINVAL) };
    };
    if overwrite == 0 && !unsafe { getenv(name) }.is_null() {
        return 0;
    }
    let value_length = unsafe { c_string_length(value) };
    let Some(allocation_size) = name_length
        .checked_add(value_length)
        .and_then(|size| size.checked_add(2))
    else {
        return unsafe { environment_failure(ENOMEM) };
    };
    // SAFETY: the established allocator owns ordinary allocation failure errno.
    let replacement = unsafe { cabi_allocator_malloc(allocation_size).cast::<c_char>() };
    if replacement.is_null() {
        return -1;
    }
    // SAFETY: the exact allocation covers name, separator, value, and NUL.
    unsafe {
        ptr::copy_nonoverlapping(name.cast::<u8>(), replacement.cast::<u8>(), name_length);
        ptr::write(replacement.cast::<u8>().add(name_length), b'=');
        ptr::copy_nonoverlapping(
            value.cast::<u8>(),
            replacement.cast::<u8>().add(name_length + 1),
            value_length + 1,
        );
        put_entry(replacement, name_length, replacement)
    }
}

/// Retain a caller-owned `NAME=value` string, or route `NAME` removal to
/// `unsetenv` exactly as musl does.
///
/// # Safety
///
/// `entry` must remain a valid writable NUL-terminated string while it is
/// published through the environment. Callers synchronize direct mutation.
#[no_mangle]
pub unsafe extern "C" fn putenv(entry: *mut c_char) -> c_int {
    if entry.is_null() {
        return unsafe { environment_failure(EINVAL) };
    }
    let (key_length, has_separator) = unsafe { putenv_key_length(entry) };
    if key_length == 0 || !has_separator {
        // SAFETY: `entry` is a valid C string and unsetenv validates its key.
        return unsafe { unsetenv(entry.cast_const()) };
    }
    unsafe { put_entry(entry, key_length, ptr::null_mut()) }
}

/// Remove every matching `NAME=` entry in place, preserving all nonmatching
/// pointer order and freeing only tracked `setenv` strings.
///
/// # Safety
///
/// `name` and the currently published environment vector must be valid C
/// objects. Callers synchronize all concurrent/direct access.
#[no_mangle]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    let Some(name_length) = (unsafe { environment_name_length(name) }) else {
        return unsafe { environment_failure(EINVAL) };
    };
    let mut current = unsafe { environment_pointer() };
    if current.is_null() {
        return 0;
    }
    loop {
        // SAFETY: the public vector is null terminated under the C contract.
        let entry = unsafe { ptr::read(current) };
        if entry.is_null() {
            return 0;
        }
        if !unsafe { entry_matches_name(entry, name, name_length) } {
            // SAFETY: the next vector slot remains valid through its terminator.
            current = unsafe { current.add(1) };
            continue;
        }
        let mut shift = current;
        loop {
            // SAFETY: copying through the terminating null pointer compacts
            // this caller-visible vector in place, exactly as musl does.
            let next = unsafe { ptr::read(shift.add(1)) };
            unsafe { ptr::write(shift, next) };
            if next.is_null() {
                break;
            }
            // SAFETY: the next source slot remains before that terminator.
            shift = unsafe { shift.add(1) };
        }
        // SAFETY: this releases only a matching tracked setenv allocation.
        unsafe { update_owned_string(entry, ptr::null_mut()) };
        // Do not advance `current`: the following entry just shifted into it.
    }
}

/// Publish an empty environment and release each tracked `setenv` string.
///
/// # Safety
///
/// The published environment vector must be valid and null terminated.
/// Callers synchronize all concurrent/direct access.
#[no_mangle]
pub unsafe extern "C" fn clearenv() -> c_int {
    let mut current = unsafe { environment_pointer() };
    // SAFETY: publish null before invoking the ownership bookkeeping, matching
    // musl's observable clear transition.
    unsafe { set_environment_pointer(ptr::null_mut()) };
    if current.is_null() {
        return 0;
    }
    loop {
        // SAFETY: the former published vector remains caller-valid here.
        let entry = unsafe { ptr::read(current) };
        if entry.is_null() {
            return 0;
        }
        // SAFETY: only tracked setenv strings are released.
        unsafe { update_owned_string(entry, ptr::null_mut()) };
        // SAFETY: advance within the former null-terminated vector.
        current = unsafe { current.add(1) };
    }
}

/// Link-time witness for the opt-in allocator-backed environment owner.
///
/// The mixed-runtime evidence uses this private symbol to prove it did not
/// accidentally select the legacy fixed-table environment object instead.
#[no_mangle]
pub extern "C" fn __crabc_x86_environment_runtime_v1() -> usize {
    1
}
