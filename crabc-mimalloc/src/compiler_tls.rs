// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/prim-tls.h:12-275`,
// `src/prim/prim-tls.c:15-34,211-252`, and `src/threadlocal.c:23-214`.
// This bounded slice supplies source-shaped compiler-TLS roots, the regular
// dynamic flexible header, and allocation-free root access. `thread_local`
// owns the current-thread regular backing allocation, growth, teardown, and
// one Rust-only persistent-owner cell embedded beside the source pointer roots
// in the runtime's compiler-TLS record.
// That cell makes an exclusive in-place Rust borrow explicit; it neither
// changes the source TLS layout nor introduces a scheduler or owner registry.
// `main_theap` alone uses default/fast publication for ticket zero, while
// `dynamic_theap` owns one canonical-empty cached-root store/refcount pair.
// General cached switching, process initialization, libc/pthread hooks, and
// full thread lifecycle integration remain separate work.

//! Private Linux/musl compiler-TLS roots for the configured AArch64 and x86-64 profiles.
//!
//! Pinned mimalloc selects `MI_TLS_MODEL_LOCAL` on Linux. Its hot theap roots
//! use compiler TLS with the initial-exec model, while the regular dynamic
//! backing and fast slot are separate compiler-TLS variables. Rust's TLS
//! model is a crate codegen choice rather than a source attribute. The
//! `tls-codegen-probe` feature therefore retains test-only witnesses for the
//! pinned-target ELF judge; production integration must use the same proven
//! `-Z tls-model=initial-exec` setting and may not infer safety from these
//! declarations alone.

use core::mem::size_of;
use core::ptr::NonNull;

use crate::bootstrap::empty_default_theap_ptr;
use crate::thread_local::ThreadLocalSlot;
use crate::types::{LiveThreadId, MemoryId, Theap};

/// Fixed prefix and source-declared first slot of `mi_thread_locals_t`.
///
/// A live dynamically grown image has additional contiguous slots after
/// `slots[0]`. The allocation owner lives in `thread_local`; it must use
/// [`Self::allocation_size`] rather than Rust's fixed-prefix size when it
/// obtains the source flexible layout from the detached metadata theap.
#[repr(C)]
pub(crate) struct DynamicThreadLocalBacking {
    count: usize,
    memid: MemoryId,
    slots: [ThreadLocalSlot; 1],
}

impl DynamicThreadLocalBacking {
    const EMPTY: Self = Self {
        count: 0,
        memid: MemoryId::none(),
        slots: [ThreadLocalSlot::EMPTY; 1],
    };

    #[inline]
    pub(crate) const fn count(&self) -> usize {
        self.count
    }

    /// Returns the exact source request for `count` usable TLS slots.
    ///
    /// Pinned `mi_thread_locals_expand` deliberately asks for
    /// `sizeof(mi_thread_locals_t) + count * sizeof(mi_tls_slot_t)`, even
    /// though its declared C prefix already contains `slots[1]`. Keep that
    /// byte contract rather than normalizing it to a Rust flexible-array
    /// helper. A capacity of 65,535 is the largest source-valid count: it
    /// addresses indices zero through 65,534, while a request for index
    /// 65,535 must reject the derived count 65,536.
    #[inline]
    pub(crate) const fn allocation_size(count: usize) -> Option<usize> {
        if count == 0 || count > u16::MAX as usize {
            return None;
        }
        match count.checked_mul(size_of::<ThreadLocalSlot>()) {
            Some(slots) => size_of::<Self>().checked_add(slots),
            None => None,
        }
    }

    /// Returns the aligned source header address for one owned dynamic image.
    ///
    /// The caller holds the unique [`crate::meta::MetaAllocation`] capability
    /// whose exact request size was checked by its narrow typed projection.
    /// Writing `memid` before `count` keeps the root unpublished until both
    /// header fields describe the replacement image, as in `threadlocal.c`.
    #[inline]
    pub(crate) unsafe fn initialize_owned_header(&mut self, memid: MemoryId, count: usize) {
        debug_assert!(Self::allocation_size(count).is_some());
        // SAFETY: the owner has checked the exact flexible allocation size;
        // these fields are in its fixed prefix. `memid` is written first so
        // no caller can observe a positive count with stale provenance when
        // the compiler-TLS root is finally installed.
        unsafe {
            core::ptr::addr_of_mut!(self.memid).write(memid);
            core::ptr::addr_of_mut!(self.count).write(count);
        }
    }

    /// Views the live flexible slot suffix under the dynamic owner's unique
    /// current-thread authority.
    ///
    /// # Safety
    ///
    /// The backing must have been projected from a `MetaAllocation` whose
    /// exact request matches `allocation_size(self.count)`, and no other
    /// thread may read or write the slots. `ThreadLocalBackingOwner` is the
    /// sole caller; this is not a general compiler-TLS raw-parts API.
    #[inline]
    pub(crate) unsafe fn slots_mut(&mut self) -> &mut [ThreadLocalSlot] {
        // SAFETY: upheld by the caller's exact flexible-allocation proof.
        unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(self.slots).cast::<ThreadLocalSlot>(),
                self.count,
            )
        }
    }

    #[inline]
    pub(crate) const fn memory_id(&self) -> MemoryId {
        self.memid
    }

    #[cfg(test)]
    const fn test_image(count: usize) -> Self {
        Self {
            count,
            memid: MemoryId::none(),
            slots: [ThreadLocalSlot::EMPTY; 1],
        }
    }
}

// The source declares its empty dynamic-backing image as process static. This
// wrapper permits immutable sharing even though its exact C layout contains
// raw pointers. No API exposes mutable authority derived from this image.
#[repr(transparent)]
struct ImmutableEmptyDynamicBacking(DynamicThreadLocalBacking);

// SAFETY: every field remains immutable for the process lifetime. The raw
// pointer bits are null and are never projected as mutable references.
unsafe impl Sync for ImmutableEmptyDynamicBacking {}

static EMPTY_DYNAMIC_BACKING: ImmutableEmptyDynamicBacking =
    ImmutableEmptyDynamicBacking(DynamicThreadLocalBacking::EMPTY);

#[inline]
const fn empty_dynamic_backing_ptr() -> *mut DynamicThreadLocalBacking {
    core::ptr::addr_of!(EMPTY_DYNAMIC_BACKING.0).cast_mut()
}

/// Whether a root still names the source's immutable count-zero image.
#[inline]
pub(crate) fn is_empty_dynamic_backing(backing: NonNull<DynamicThreadLocalBacking>) -> bool {
    core::ptr::eq(backing.as_ptr(), empty_dynamic_backing_ptr())
}

// These five roots deliberately remain private Rust statics. In a normal
// build they have no stable ABI spelling or dynamic export. The codegen probe
// reaches them only through feature-gated witness functions and verifies that
// every emitted root is an ELF STT_TLS/GLOBAL/HIDDEN symbol. Hidden visibility
// is rustc's private cross-section representation; the roots never enter
// dynsym.
#[thread_local]
static mut DYNAMIC_BACKING_ROOT: *mut DynamicThreadLocalBacking =
    empty_dynamic_backing_ptr();

#[thread_local]
static mut FAST_SLOT_ROOT: *mut () = core::ptr::null_mut();

#[thread_local]
static mut DEFAULT_THEAP_ROOT: *mut Theap = empty_default_theap_ptr();

#[thread_local]
static mut CACHED_THEAP_ROOT: *mut Theap = empty_default_theap_ptr();

// `src/prim/prim-tls.c` defines this root on every platform, but the selected
// Linux/musl paths do not use its address for identity. Musl disables the
// compiler builtin, after which `prim-tls.h` selects direct `TPIDR_EL0` reads
// on AArch64 and `%fs:0` reads on x86-64. Retain the helper root for
// source-shape completeness and for any later configuration inventory; do not
// route live ownership through it on either selected native profile.
#[thread_local]
static mut THREAD_ID_HELPER_ROOT: *mut () = core::ptr::null_mut();

/// Rust-side state of one inline persistent allocator owner in compiler TLS.
///
/// Pinned mimalloc stores its source Theap roots directly in compiler TLS and
/// relies on the source lifecycle to avoid overlapping local operations. The
/// Rust owner cell in `thread_local` additionally records its temporary
/// projection states: this prevents recursive entry from forming two mutable
/// references to the same TLD/Theap. The payload itself remains inline in its
/// runtime-owned compiler-TLS record; no state here is a pointer, scheduler,
/// process registry, page owner, or per-allocation ledger.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistentCompilerTlsOwnerState {
    /// No owner payload has ever been installed in this native-thread cell.
    Vacant,
    /// The payload is pinned in place but its source roots are not published.
    Initializing,
    /// The complete payload is installed and available for local operations.
    Active,
    /// One synchronous local-operation closure owns the only mutable projection.
    Borrowed,
    /// Source-ordered consuming teardown owns the only mutable projection.
    Exiting,
    /// Initialization or teardown failed while the exact payload stayed pinned.
    Retained,
    /// Teardown succeeded, the payload was dropped in place, and reuse is forbidden.
    TornDown,
}

/// Peeks at the regular dynamically allocated TLS image.
///
/// A fresh thread sees the immutable count-zero image. Thread teardown sets
/// the root to null after releasing a live image; null is deliberately not
/// translated back to the empty image because source callers use it to reject
/// stale post-teardown access.
#[inline(always)]
pub(crate) fn dynamic_backing_peek() -> Option<NonNull<DynamicThreadLocalBacking>> {
    // SAFETY: each calling thread alone reads its compiler-TLS pointer root.
    NonNull::new(unsafe { DYNAMIC_BACKING_ROOT })
}

/// Installs an already-live regular dynamic TLS image for the calling thread.
///
/// This root never dereferences the address. The allocation/lifecycle owner
/// must keep it live until it first resets the root or replaces it with an
/// equally live image. That later owner also performs source-shaped metadata
/// reclamation; this operation itself is allocation-free.
#[inline(always)]
pub(crate) fn install_dynamic_backing(backing: NonNull<DynamicThreadLocalBacking>) {
    // SAFETY: each calling thread alone writes its compiler-TLS pointer root.
    unsafe { DYNAMIC_BACKING_ROOT = backing.as_ptr() };
}

/// Clears only the regular dynamic-backing root after its lifecycle owner has
/// attempted source-ordered metadata release. This intentionally leaves the
/// fast/default/cached/helper roots untouched; their lifecycle is separate.
#[inline(always)]
pub(crate) fn clear_dynamic_backing() {
    // SAFETY: each calling thread alone writes its compiler-TLS pointer root.
    unsafe { DYNAMIC_BACKING_ROOT = core::ptr::null_mut() };
}

/// Peeks at mimalloc's dedicated fast dynamic slot.
#[inline(always)]
pub(crate) fn fast_slot_peek() -> Option<NonNull<()>> {
    // SAFETY: each calling thread alone reads its compiler-TLS pointer root.
    NonNull::new(unsafe { FAST_SLOT_ROOT })
}

/// Sets mimalloc's dedicated fast dynamic slot without allocating.
#[inline(always)]
pub(crate) fn set_fast_slot(value: Option<NonNull<()>>) {
    // SAFETY: each calling thread alone writes its compiler-TLS pointer root.
    unsafe { FAST_SLOT_ROOT = value.map_or(core::ptr::null_mut(), NonNull::as_ptr) };
}

/// Returns the calling thread's non-null default-theap pointer.
#[inline(always)]
pub(crate) fn default_theap() -> NonNull<Theap> {
    // SAFETY: both the ELF initializer and the sole private setter below
    // preserve a non-null pointer. Thread reset restores the same invariant.
    unsafe { NonNull::new_unchecked(DEFAULT_THEAP_ROOT) }
}

/// Installs a live default theap for the calling thread.
///
/// This is only the pointer-store half of upstream `_mi_theap_default_set`.
/// The later lifecycle owner must validate thread association and publication
/// order before calling it and retain the theap through reset.
#[inline(always)]
pub(crate) fn set_default_theap(theap: NonNull<Theap>) {
    // SAFETY: each calling thread alone writes its compiler-TLS pointer root.
    unsafe { DEFAULT_THEAP_ROOT = theap.as_ptr() };
}

/// Returns the calling thread's non-null cached-theap pointer.
#[inline(always)]
pub(crate) fn cached_theap() -> NonNull<Theap> {
    // SAFETY: the initializer, setter, and reset preserve non-nullness.
    unsafe { NonNull::new_unchecked(CACHED_THEAP_ROOT) }
}

/// Installs a live cached theap for the calling thread.
///
/// This is the pointer-store half of upstream `_mi_theap_cached_set`.
/// `DynamicTheapAttachment` owns the paired source-ordered reference-count
/// transition; no generic caller may use this store as a refcount API.
#[inline(always)]
pub(crate) fn set_cached_theap(theap: NonNull<Theap>) {
    // SAFETY: each calling thread alone writes its compiler-TLS pointer root.
    unsafe { CACHED_THEAP_ROOT = theap.as_ptr() };
}

/// Checks the exact untouched compiler-TLS root state required before the
/// process-static ticket-zero TLD/theap transition may consume a sequence.
///
/// The dynamic root deliberately remains the immutable count-zero source
/// image. A null post-teardown root is not interchangeable with that image,
/// and a nonempty backing/fast/default/cached root could retain an alias to a
/// different lifecycle. Callers must reject this state before issuing a
/// `thread_total_count` ticket.
#[inline(always)]
pub(crate) fn roots_are_pristine_for_main_static_attachment() -> bool {
    matches!(dynamic_backing_peek(), Some(backing) if is_empty_dynamic_backing(backing))
        && fast_slot_peek().is_none()
        && core::ptr::eq(default_theap().as_ptr(), empty_default_theap_ptr())
        && core::ptr::eq(cached_theap().as_ptr(), empty_default_theap_ptr())
}

/// Clears only the roots owned by the bounded static default-theap lifecycle.
///
/// This preserves the source split between `mi_thread_theaps_done` and
/// `_mi_thread_locals_thread_done`: fast is cleared, default and cached are
/// restored to the immutable empty theap, while the untouched count-zero
/// dynamic backing remains installed. Do not replace this with
/// [`reset_for_thread_teardown`], which would incorrectly turn that empty
/// dynamic source image into null.
#[inline(always)]
pub(crate) fn clear_main_static_attachment_roots() {
    set_fast_slot(None);
    // SAFETY: the current-thread attachment owner has already checked the
    // root identity and is now executing its explicit teardown path.
    unsafe {
        DEFAULT_THEAP_ROOT = empty_default_theap_ptr();
        CACHED_THEAP_ROOT = empty_default_theap_ptr();
    }
}

/// Returns the selected Linux/musl source identity for this thread.
///
/// `MI_LIBC_MUSL` disables `__builtin_thread_pointer`; the pinned GCC
/// inline-assembly branch then reads `TPIDR_EL0` on AArch64 or `%fs:0` on
/// x86-64. The source-declared helper TLS root belongs only to the later
/// `MI_NO_THREAD_POINTER` fallback and is not either target's live allocator
/// identity.
#[inline(always)]
pub(crate) fn current_thread_identity() -> Option<LiveThreadId> {
    LiveThreadId::new(crate::os::thread_pointer_identity())
}

/// Returns the address of the source-declared identity-helper TLS root.
///
/// This is a source-shape/codegen observation only. It is aligned and unique
/// per thread, but the selected Linux/musl paths use [`current_thread_identity`]
/// instead because their direct thread-pointer register is available.
#[inline(always)]
fn thread_id_helper_address() -> Option<LiveThreadId> {
    LiveThreadId::new(core::ptr::addr_of_mut!(THREAD_ID_HELPER_ROOT) as usize)
}

/// Resets all source pointer roots at the allocation-free thread-teardown boundary.
///
/// The dynamic backing becomes null only after its lifecycle owner has freed
/// any nonempty image. The fast slot is cleared, while default and cached
/// theaps return to the immutable empty image. This function performs no
/// metadata reclamation, theap decref, page abandonment, or pthread work.
/// It deliberately cannot reset a `thread_local::PersistentCompilerTlsOwnerCell`
/// embedded in a runtime compiler-TLS record. The runtime must first complete
/// that owner's explicit source teardown transition, so resetting source
/// roots cannot make a live page-bearing owner look vacant.
#[inline(always)]
pub(crate) fn reset_for_thread_teardown() {
    // SAFETY: each calling thread alone writes all five source pointer roots,
    // including the otherwise-unused helper root. The immutable process image
    // remains live forever.
    unsafe {
        DYNAMIC_BACKING_ROOT = core::ptr::null_mut();
        FAST_SLOT_ROOT = core::ptr::null_mut();
        DEFAULT_THEAP_ROOT = empty_default_theap_ptr();
        CACHED_THEAP_ROOT = empty_default_theap_ptr();
        THREAD_ID_HELPER_ROOT = core::ptr::null_mut();
    }
}

// The named witnesses exist only in the dedicated codegen instrument. They
// intentionally expose pointer values rather than allocator operations and
// are absent from every normal rlib/static/shared production build.
#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_dynamic_get() -> usize {
    dynamic_backing_peek().map_or(0, |pointer| pointer.as_ptr() as usize)
}

#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_fast_get() -> usize {
    fast_slot_peek().map_or(0, |pointer| pointer.as_ptr() as usize)
}

#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_default_get() -> usize {
    default_theap().as_ptr() as usize
}

#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_cached_get() -> usize {
    cached_theap().as_ptr() as usize
}

#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_identity_get() -> usize {
    current_thread_identity().map_or(0, LiveThreadId::get)
}

#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_identity_helper_address() -> usize {
    thread_id_helper_address().map_or(0, LiveThreadId::get)
}

#[cfg(feature = "tls-codegen-probe")]
#[no_mangle]
pub extern "C" fn crabc_mimalloc_tls_probe_reset() {
    reset_for_thread_teardown();
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::bootstrap::empty_default_theap;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    fn assert_fresh_thread_roots() {
        let backing = dynamic_backing_peek().expect("fresh TLS names the immutable empty image");
        assert_eq!(backing.as_ptr(), empty_dynamic_backing_ptr());
        // SAFETY: this exact pointer names the immutable process-lifetime
        // image, so reading its count cannot race or outlive the object.
        assert_eq!(unsafe { backing.as_ref() }.count(), 0);
        assert!(fast_slot_peek().is_none());
        assert_eq!(default_theap().as_ptr(), empty_default_theap_ptr());
        assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
        let identity = current_thread_identity().expect("the aligned native thread pointer is live");
        assert_eq!(identity.get() & crate::types::PAGE_FLAG_MASK, 0);
        let helper_address = thread_id_helper_address()
            .expect("the unused source helper root still has an aligned TLS address");
        assert_eq!(helper_address.get() & crate::types::PAGE_FLAG_MASK, 0);
    }

    #[test]
    fn fresh_native_thread_starts_with_the_source_root_images() {
        thread::spawn(assert_fresh_thread_roots)
            .join()
            .expect("the native root check completes");
    }

    #[test]
    fn native_thread_roots_install_and_reset_without_a_stale_fallback() {
        thread::spawn(|| {
            assert_fresh_thread_roots();
            let identity_before = current_thread_identity().expect("the identity root is valid");
            let mut backing = DynamicThreadLocalBacking::test_image(7);
            let backing_pointer = NonNull::from(&mut backing);
            let mut payload = 0xfeed_faceusize;
            let fast_pointer = NonNull::from(&mut payload).cast();
            let mut default_image = Theap::empty();
            let mut cached_image = Theap::empty();
            let default_pointer = NonNull::from(&mut default_image);
            let cached_pointer = NonNull::from(&mut cached_image);

            install_dynamic_backing(backing_pointer);
            set_fast_slot(Some(fast_pointer));
            set_default_theap(default_pointer);
            set_cached_theap(cached_pointer);

            assert_eq!(dynamic_backing_peek(), Some(backing_pointer));
            assert_eq!(fast_slot_peek(), Some(fast_pointer));
            assert_eq!(default_theap(), default_pointer);
            assert_eq!(cached_theap(), cached_pointer);

            reset_for_thread_teardown();
            assert!(
                dynamic_backing_peek().is_none(),
                "post-teardown regular access remains null instead of reviving the initial image"
            );
            assert!(fast_slot_peek().is_none());
            assert_eq!(default_theap().as_ptr(), empty_default_theap() as *const Theap as *mut Theap);
            assert_eq!(cached_theap().as_ptr(), empty_default_theap_ptr());
            assert_eq!(current_thread_identity(), Some(identity_before));
        })
        .join()
        .expect("the native install/reset check completes");
    }

    #[test]
    fn compiler_tls_roots_are_isolated_while_native_threads_overlap() {
        let installed = Arc::new(Barrier::new(3));
        let first_reset = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::channel();
        let mut workers = std::vec::Vec::new();

        for worker_index in 0..2usize {
            let worker_installed = Arc::clone(&installed);
            let worker_first_reset = Arc::clone(&first_reset);
            let worker_sender = sender.clone();
            workers.push(thread::spawn(move || {
                assert_fresh_thread_roots();
                let identity = current_thread_identity()
                    .expect("each native thread has a valid direct thread-pointer identity");
                let helper_address = thread_id_helper_address()
                    .expect("each native thread has a valid source-helper TLS address");
                let mut backing = DynamicThreadLocalBacking::test_image(worker_index + 1);
                let backing_pointer = NonNull::from(&mut backing);
                let mut payload = worker_index + 0x100;
                let fast_pointer = NonNull::from(&mut payload).cast();
                let mut theap = Theap::empty();
                let theap_pointer = NonNull::from(&mut theap);

                install_dynamic_backing(backing_pointer);
                set_fast_slot(Some(fast_pointer));
                set_default_theap(theap_pointer);
                set_cached_theap(theap_pointer);
                worker_sender
                    .send((
                        worker_index,
                        identity.get(),
                        helper_address.get(),
                        backing_pointer.as_ptr() as usize,
                    ))
                    .expect("the collector remains live");
                worker_installed.wait();

                if worker_index == 0 {
                    reset_for_thread_teardown();
                    worker_first_reset.wait();
                } else {
                    worker_first_reset.wait();
                    assert_eq!(dynamic_backing_peek(), Some(backing_pointer));
                    assert_eq!(fast_slot_peek(), Some(fast_pointer));
                    assert_eq!(default_theap(), theap_pointer);
                    assert_eq!(cached_theap(), theap_pointer);
                    reset_for_thread_teardown();
                }
            }));
        }
        drop(sender);

        installed.wait();
        let mut observations = receiver.iter().collect::<std::vec::Vec<_>>();
        observations.sort_unstable_by_key(|observation| observation.0);
        assert_eq!(observations.len(), 2);
        assert_ne!(
            observations[0].1,
            observations[1].1,
            "direct thread-pointer identities distinguish native threads"
        );
        assert_ne!(
            observations[0].2,
            observations[1].2,
            "source-helper TLS addresses distinguish native threads"
        );
        assert_ne!(
            observations[0].3,
            observations[1].3,
            "dynamic backing roots remain per-thread"
        );

        for worker in workers {
            worker.join().expect("the overlapping root check completes");
        }
    }
}
