//! Linux/x86-64 pthread attribute-record metadata.
//!
//! This private selected-static leaf ports the record-only behavior from the
//! pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license
//! recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_attr_init.c` and `src/thread/default_attr.c` define
//!   the exact initial 128 KiB stack and 8 KiB guard record image.
//! - `src/thread/pthread_attr_destroy.c` is the intentional no-op destructor.
//! - `src/thread/pthread_attr_setdetachstate.c`,
//!   `src/thread/pthread_attr_setstacksize.c`,
//!   `src/thread/pthread_attr_setstack.c`, and
//!   `src/thread/pthread_attr_setguardsize.c` define field updates and their
//!   unsigned range checks.
//! - `src/thread/pthread_attr_setscope.c`,
//!   `src/thread/pthread_attr_setinheritsched.c`,
//!   `src/thread/pthread_attr_setschedpolicy.c`, and
//!   `src/thread/pthread_attr_setschedparam.c` define the system-scope and
//!   scheduler record rules.
//! - `src/thread/pthread_attr_get.c` defines every selected getter, including
//!   the `pthread_attr_getstack` no-address `EINVAL` result.
//!
//! On SysV AMD64, musl's public `pthread_attr_t` is a 56-byte, align-8 union.
//! Its seven unsigned-long words carry stack size, guard size, a caller stack's
//! one-past-top address, and packed pairs of `int` detach/inherit and
//! policy/priority fields. This module owns exactly the eighteen standard
//! lifecycle and metadata entry points over that record.
//!
//! `pthread_create_join.rs` decodes this exact record only for its selected
//! worker policy.  That sibling consumes detached-at-create, a supplied stack
//! or a private guarded stack, and the requested stack size.  It rejects an
//! explicit scheduler request with `ENOTSUP`; it does not claim scheduler,
//! GNU default-attribute, affinity-attribute, live-thread inspection, or
//! general pthread behavior.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread attribute leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::mem::{align_of, size_of};

const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;
const PTHREAD_CREATE_DETACHED: u32 = 1;
const PTHREAD_SCOPE_SYSTEM: c_int = 0;
const PTHREAD_SCOPE_PROCESS: c_int = 1;
const PTHREAD_EXPLICIT_SCHED: u32 = 1;
const PTHREAD_STACK_MIN: usize = 2_048;

const DEFAULT_STACK_SIZE: usize = 131_072;
const DEFAULT_GUARD_SIZE: usize = 8_192;

const ATTR_WORDS: usize = 7;
const STACK_SIZE_WORD_INDEX: usize = 0;
const GUARD_SIZE_WORD_INDEX: usize = 1;
const STACK_TOP_WORD_INDEX: usize = 2;
const DETACH_INHERIT_WORD_INDEX: usize = 3;
const POLICY_PRIORITY_WORD_INDEX: usize = 4;
const LOW_C_INT_MASK: usize = u32::MAX as usize;

/// The creation-relevant portion of one initialized public record.
///
/// This is a private, plain-Copy decode boundary shared with the selected
/// worker seam.  Keeping the source-shaped record layout and the decode next
/// to its setters/getters prevents the clone owner from guessing public
/// `pthread_attr_t` offsets.  A scheduler request remains outside that
/// bounded seam and is represented explicitly rather than silently ignored.
#[derive(Clone, Copy)]
pub(super) struct SelectedWorkerAttributes {
    pub(super) stack_size: usize,
    pub(super) guard_size: usize,
    pub(super) caller_stack_top: Option<usize>,
    pub(super) detached: bool,
    pub(super) scheduler_requested: bool,
}

/// Owned-runtime default when `pthread_create` receives a null attribute
/// pointer and when the C11 adapter creates a worker.
///
/// This is the same 128 KiB stack and 8 KiB guard selected by musl's default
/// attribute record. The old one-megabyte/zero-guard private-fixture policy
/// was neither a public POSIX default nor an owned-runtime guarantee, so it
/// must not leak into ordinary installed consumers.
#[inline]
pub(super) const fn selected_worker_default_attributes() -> SelectedWorkerAttributes {
    SelectedWorkerAttributes {
        stack_size: DEFAULT_STACK_SIZE,
        guard_size: DEFAULT_GUARD_SIZE,
        caller_stack_top: None,
        detached: false,
        scheduler_requested: false,
    }
}

/// Exact public `pthread_attr_t` storage on Linux/x86-64 LP64.
#[derive(Clone, Copy)]
#[repr(C)]
struct PublicPthreadAttr {
    words: [usize; ATTR_WORDS],
}

const _: () = {
    assert!(size_of::<PublicPthreadAttr>() == 56);
    assert!(align_of::<PublicPthreadAttr>() == 8);
};

impl PublicPthreadAttr {
    const fn musl_default() -> Self {
        Self {
            words: [DEFAULT_STACK_SIZE, DEFAULT_GUARD_SIZE, 0, 0, 0, 0, 0],
        }
    }

    #[inline]
    const fn low_c_int(word: usize) -> c_int {
        word as u32 as c_int
    }

    #[inline]
    fn replace_low_c_int(word: &mut usize, value: c_int) {
        *word = (*word & !LOW_C_INT_MASK) | value as u32 as usize;
    }

    #[inline]
    fn replace_high_c_int(word: &mut usize, value: c_int) {
        *word = (*word & LOW_C_INT_MASK) | ((value as u32 as usize) << 32);
    }

    #[inline]
    const fn stack_size(self) -> usize {
        self.words[STACK_SIZE_WORD_INDEX]
    }

    #[inline]
    fn set_stack_size(&mut self, size: usize) {
        self.words[STACK_SIZE_WORD_INDEX] = size;
        // Musl's stack-size setter clears a previously stored caller-stack
        // address, returning the record to no-caller-stack state.
        self.words[STACK_TOP_WORD_INDEX] = 0;
    }

    #[inline]
    const fn guard_size(self) -> usize {
        self.words[GUARD_SIZE_WORD_INDEX]
    }

    #[inline]
    fn set_guard_size(&mut self, size: usize) {
        self.words[GUARD_SIZE_WORD_INDEX] = size;
    }

    #[inline]
    const fn stack_top(self) -> usize {
        self.words[STACK_TOP_WORD_INDEX]
    }

    #[inline]
    fn set_stack(&mut self, address: usize, size: usize) {
        self.words[STACK_SIZE_WORD_INDEX] = size;
        // Musl stores `address + size` as size_t. Preserve that defined
        // unsigned wraparound representation even though this metadata-only
        // slice never creates a worker from the record.
        self.words[STACK_TOP_WORD_INDEX] = address.wrapping_add(size);
    }

    #[inline]
    const fn detach_state(self) -> c_int {
        Self::low_c_int(self.words[DETACH_INHERIT_WORD_INDEX])
    }

    #[inline]
    fn set_detach_state(&mut self, state: c_int) {
        Self::replace_low_c_int(&mut self.words[DETACH_INHERIT_WORD_INDEX], state);
    }

    #[inline]
    const fn inherit_sched(self) -> c_int {
        Self::low_c_int(self.words[DETACH_INHERIT_WORD_INDEX] >> 32)
    }

    #[inline]
    fn set_inherit_sched(&mut self, inherit: c_int) {
        Self::replace_high_c_int(&mut self.words[DETACH_INHERIT_WORD_INDEX], inherit);
    }

    #[inline]
    const fn sched_policy(self) -> c_int {
        Self::low_c_int(self.words[POLICY_PRIORITY_WORD_INDEX])
    }

    #[inline]
    fn set_sched_policy(&mut self, policy: c_int) {
        Self::replace_low_c_int(&mut self.words[POLICY_PRIORITY_WORD_INDEX], policy);
    }

    #[inline]
    const fn sched_priority(self) -> c_int {
        Self::low_c_int(self.words[POLICY_PRIORITY_WORD_INDEX] >> 32)
    }

    #[inline]
    fn set_sched_priority(&mut self, priority: c_int) {
        Self::replace_high_c_int(&mut self.words[POLICY_PRIORITY_WORD_INDEX], priority);
    }

    #[inline]
    const fn selected_worker_attributes(self) -> SelectedWorkerAttributes {
        SelectedWorkerAttributes {
            stack_size: self.stack_size(),
            guard_size: self.guard_size(),
            caller_stack_top: match self.stack_top() {
                0 => None,
                top => Some(top),
            },
            detached: self.detach_state() != 0,
            // Musl enters its scheduler-control handshake only when this
            // selector asks for explicit scheduling. Policy/priority fields
            // may be recorded while inheriting and are then source-ignored;
            // preserve that distinction instead of rejecting inert metadata.
            // The selected clone seam has no explicit scheduler ownership, so
            // its caller rejects this one source-visible request.
            scheduler_requested: self.inherit_sched() != 0,
        }
    }
}

/// Decode one initialized `pthread_attr_t` for the selected worker seam.
///
/// # Safety
///
/// `attributes` must designate a readable, initialized, properly aligned
/// public `pthread_attr_t`.  That is the same C API precondition as
/// `pthread_create`; this private helper does not make a raw or corrupted
/// record valid.
#[inline]
pub(super) unsafe fn selected_worker_attributes(
    attributes: *const c_void,
) -> SelectedWorkerAttributes {
    // SAFETY: the caller retains the public pthread_create precondition
    // documented above, and `PublicPthreadAttr` has the exact x86 LP64 ABI.
    unsafe {
        core::ptr::read(attributes.cast::<PublicPthreadAttr>()).selected_worker_attributes()
    }
}

#[inline]
const fn valid_stack_size(size: usize) -> bool {
    size.wrapping_sub(PTHREAD_STACK_MIN) <= usize::MAX / 4
}

#[inline]
const fn valid_guard_size(size: usize) -> bool {
    size <= usize::MAX / 8
}

/// Initialize one exact musl-shaped pthread attribute record.
///
/// # Safety
///
/// `attributes` must designate writable, properly aligned `pthread_attr_t`
/// storage. Null or otherwise invalid pointers are outside the C API contract.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_init(attributes: *mut c_void) -> c_int {
    // SAFETY: the caller supplies the writable public object documented above;
    // the representation assertions preserve its exact LP64 ABI.
    unsafe {
        core::ptr::write(
            attributes.cast::<PublicPthreadAttr>(),
            PublicPthreadAttr::musl_default(),
        )
    };
    0
}

/// Destroy one pthread attribute record without modifying its storage.
///
/// # Safety
///
/// `attributes` must be an initialized `pthread_attr_t` according to the C
/// API. Musl does not dereference it for this no-op operation.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_destroy(_attributes: *mut c_void) -> c_int {
    0
}

/// Set the joinable or detached record bit.
///
/// # Safety
///
/// `attributes` must designate writable, initialized, properly aligned
/// `pthread_attr_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setdetachstate(
    attributes: *mut c_void,
    state: c_int,
) -> c_int {
    if (state as u32) > PTHREAD_CREATE_DETACHED {
        return EINVAL;
    }
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_detach_state(state);
    // SAFETY: this writes the same caller-owned public record after the
    // successful source-defined field update.
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Copy the stored detach-state integer.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage,
/// and `state` must designate writable `int` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attributes: *const c_void,
    state: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable result.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    unsafe { core::ptr::write(state, value.detach_state()) };
    0
}

/// Store a valid stack size and clear any caller-stack address.
///
/// # Safety
///
/// `attributes` must designate writable, initialized, properly aligned
/// `pthread_attr_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setstacksize(
    attributes: *mut c_void,
    size: usize,
) -> c_int {
    if !valid_stack_size(size) {
        return EINVAL;
    }
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_stack_size(size);
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Copy the stored stack size.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage,
/// and `size` must designate writable `size_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attributes: *const c_void,
    size: *mut usize,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable result.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    unsafe { core::ptr::write(size, value.stack_size()) };
    0
}

/// Store a caller stack using musl's one-past-top representation.
///
/// # Safety
///
/// `attributes` must designate writable, initialized, properly aligned
/// `pthread_attr_t` storage. `address` and `size` are retained only as record
/// metadata in this slice; no worker is created from them here.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setstack(
    attributes: *mut c_void,
    address: *mut c_void,
    size: usize,
) -> c_int {
    if !valid_stack_size(size) {
        return EINVAL;
    }
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_stack(address as usize, size);
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Recover a caller-stack base and size from the stored top representation.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage;
/// `address` and `size` must designate writable pointer and `size_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getstack(
    attributes: *const c_void,
    address: *mut *mut c_void,
    size: *mut usize,
) -> c_int {
    // SAFETY: the caller supplies a readable public record.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    let stack_top = value.stack_top();
    if stack_top == 0 {
        // Musl leaves both outputs untouched on this error path.
        return EINVAL;
    }
    let stack_size = value.stack_size();
    // SAFETY: the caller supplies both writable output slots.
    unsafe {
        core::ptr::write(size, stack_size);
        core::ptr::write(
            address,
            stack_top.wrapping_sub(stack_size) as *mut c_void,
        );
    }
    0
}

/// Store a valid guard-size request.
///
/// # Safety
///
/// `attributes` must designate writable, initialized, properly aligned
/// `pthread_attr_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setguardsize(
    attributes: *mut c_void,
    size: usize,
) -> c_int {
    if !valid_guard_size(size) {
        return EINVAL;
    }
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_guard_size(size);
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Copy the stored guard-size request.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage,
/// and `size` must designate writable `size_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getguardsize(
    attributes: *const c_void,
    size: *mut usize,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable result.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    unsafe { core::ptr::write(size, value.guard_size()) };
    0
}

/// Select musl's only supported system contention scope.
///
/// # Safety
///
/// `attributes` must be an initialized `pthread_attr_t` according to the C
/// API. Musl does not dereference it for this scope-status operation.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setscope(
    _attributes: *mut c_void,
    scope: c_int,
) -> c_int {
    match scope {
        PTHREAD_SCOPE_SYSTEM => 0,
        PTHREAD_SCOPE_PROCESS => ENOTSUP,
        _ => EINVAL,
    }
}

/// Report musl's fixed system contention scope.
///
/// # Safety
///
/// `attributes` must be an initialized `pthread_attr_t` according to the C
/// API, and `scope` must designate writable `int` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getscope(
    _attributes: *const c_void,
    scope: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the writable result slot.
    unsafe { core::ptr::write(scope, PTHREAD_SCOPE_SYSTEM) };
    0
}

/// Store the inherited or explicit scheduling selector.
///
/// # Safety
///
/// `attributes` must designate writable, initialized, properly aligned
/// `pthread_attr_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setinheritsched(
    attributes: *mut c_void,
    inherit: c_int,
) -> c_int {
    if (inherit as u32) > PTHREAD_EXPLICIT_SCHED {
        return EINVAL;
    }
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_inherit_sched(inherit);
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Copy the stored scheduling-inheritance selector.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage,
/// and `inherit` must designate writable `int` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getinheritsched(
    attributes: *const c_void,
    inherit: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable result.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    unsafe { core::ptr::write(inherit, value.inherit_sched()) };
    0
}

/// Store a scheduler policy without prevalidating the raw integer.
///
/// # Safety
///
/// `attributes` must designate writable, initialized, properly aligned
/// `pthread_attr_t` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(
    attributes: *mut c_void,
    policy: c_int,
) -> c_int {
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_sched_policy(policy);
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Copy the stored raw scheduler policy.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage,
/// and `policy` must designate writable `int` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(
    attributes: *const c_void,
    policy: *mut c_int,
) -> c_int {
    // SAFETY: the caller supplies the readable record and writable result.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    unsafe { core::ptr::write(policy, value.sched_policy()) };
    0
}

/// Store only `struct sched_param::sched_priority`.
///
/// # Safety
///
/// `attributes` must designate writable initialized `pthread_attr_t` storage,
/// and `parameters` must designate a readable `struct sched_param` whose
/// first field is its C `int` scheduling priority.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_setschedparam(
    attributes: *mut c_void,
    parameters: *const c_void,
) -> c_int {
    // SAFETY: the public sched_param ABI places its priority int first.
    let priority = unsafe { core::ptr::read(parameters.cast::<c_int>()) };
    // SAFETY: the caller supplies a valid writable public record.
    let mut value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    value.set_sched_priority(priority);
    unsafe { core::ptr::write(attributes.cast::<PublicPthreadAttr>(), value) };
    0
}

/// Copy the stored priority into only `struct sched_param::sched_priority`.
///
/// # Safety
///
/// `attributes` must designate readable initialized `pthread_attr_t` storage,
/// and `parameters` must designate writable `struct sched_param` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_attr_getschedparam(
    attributes: *const c_void,
    parameters: *mut c_void,
) -> c_int {
    // SAFETY: the caller supplies the readable record and sched_param output.
    let value = unsafe { core::ptr::read(attributes.cast::<PublicPthreadAttr>()) };
    // SAFETY: the public sched_param ABI places its priority int first; musl
    // leaves the rest of the caller's record untouched.
    unsafe { core::ptr::write(parameters.cast::<c_int>(), value.sched_priority()) };
    0
}
