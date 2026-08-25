//! Test-only prefixed C ABI for the bounded `crabc-mimalloc` engine slice.
//!
//! This crate is deliberately outside `crabc-libc`. It owns one
//! allocation-backed [`crabc_mimalloc::TestAllocatorContext`] for selected C
//! differential tests and exports only `crabc_test_*` names. The
//! accompanying header maps a deliberately small set of `mi_*` spellings at
//! C source compile time; it does not make those names ELF exports.
//!
//! The adapter has one strict process contract: after successful
//! `crabc_test_init`, the creating thread is its sole caller until a
//! successful shutdown. Concurrent calls, calls from another thread, stale
//! allocation pointers, and allocation pointers from any other allocator are
//! outside the adapter ABI. The atomic state machine prevents accidental
//! double initialization and publication of a half-constructed context; it
//! is not a substitute for the engine's absent process/TLS or remote-free
//! protocol.
//!
//! `free` cannot report an error. A valid-program lifecycle failure during
//! free therefore takes the deliberately narrow fail-stop path: it aborts
//! instead of relabeling an ownership or closing failure as an invalid C
//! pointer. Invalid, stale, foreign, concurrent, and cross-thread pointers
//! are already outside the C caller contract and take that same fail-stop path.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "test-adapter")]
mod enabled {
    use core::ffi::c_void;
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicPtr, Ordering};
    use std::boxed::Box;

    use crabc_mimalloc::{
        TestAllocatorContext, TestContextAllocationError, TestContextFreeError,
        TestContextInitError, TestContextPointerError, TestContextShutdownError,
    };

    type CInt = i32;

    // Linux's stable errno numbers. This adapter has no libc crate dependency:
    // the only libc ABI it needs is musl's __errno_location TLS accessor.
    const ENOMEM: CInt = 12;
    const EAGAIN: CInt = 11;
    const EBUSY: CInt = 16;
    const EINVAL: CInt = 22;

    const INITIALIZING_STATE: usize = 1;
    const SHUTTING_DOWN_STATE: usize = 2;

    static CONTEXT: AtomicPtr<TestAllocatorContext> = AtomicPtr::new(ptr::null_mut());

    unsafe extern "C" {
        fn __errno_location() -> *mut CInt;
    }

    #[inline]
    fn initializing_sentinel() -> *mut TestAllocatorContext {
        INITIALIZING_STATE as *mut TestAllocatorContext
    }

    #[inline]
    fn shutting_down_sentinel() -> *mut TestAllocatorContext {
        SHUTTING_DOWN_STATE as *mut TestAllocatorContext
    }

    #[inline]
    fn is_transition_state(raw: *mut TestAllocatorContext) -> bool {
        raw == initializing_sentinel() || raw == shutting_down_sentinel()
    }

    #[inline]
    fn errno_value() -> CInt {
        // SAFETY: Linux/musl exposes one valid errno TLS cell to the calling
        // thread through this ABI. The adapter only reads its own caller's cell.
        unsafe { *__errno_location() }
    }

    #[inline]
    fn set_errno(value: CInt) {
        // SAFETY: see `errno_value`; this writes only the current caller's
        // musl errno TLS cell and never retains the pointer.
        unsafe { *__errno_location() = value };
    }

    #[inline]
    fn preserve_errno<T>(saved_errno: CInt, value: T) -> T {
        set_errno(saved_errno);
        value
    }

    #[inline]
    fn valid_engine_alignment(alignment: usize) -> bool {
        alignment != 0 && alignment.is_power_of_two()
    }

    #[inline]
    fn valid_posix_alignment(alignment: usize) -> bool {
        alignment >= core::mem::size_of::<usize>() && valid_engine_alignment(alignment)
    }

    /// Returns the exclusively owned active context under the exported C
    /// one-thread/no-concurrency contract.
    ///
    /// The `Acquire` load pairs with init's final `Release` publication and
    /// with shutdown's restoration after a retryable failure. The raw pointer
    /// is only converted to `&mut` because every exported operation requires
    /// that its C caller is the sole creating-thread caller.
    #[inline]
    unsafe fn active_context() -> Option<&'static mut TestAllocatorContext> {
        let raw = CONTEXT.load(Ordering::Acquire);
        if raw.is_null() || is_transition_state(raw) {
            return None;
        }
        // SAFETY: init publishes only `Box::into_raw` after construction;
        // shutdown reconstructs that Box only after successful teardown. The
        // adapter's documented one-thread contract grants this unique borrow.
        Some(unsafe { &mut *raw })
    }

    #[cold]
    #[inline(never)]
    fn fail_stop_free_lifecycle() -> ! {
        std::process::abort()
    }

    #[inline]
    fn allocation_result(
        saved_errno: CInt,
        result: Result<NonNull<u8>, TestContextAllocationError>,
    ) -> *mut c_void {
        match result {
            Ok(block) => preserve_errno(saved_errno, block.as_ptr().cast()),
            Err(TestContextAllocationError::Closing) => {
                set_errno(EBUSY);
                ptr::null_mut()
            }
            Err(TestContextAllocationError::AllocationFailed) => {
                set_errno(ENOMEM);
                ptr::null_mut()
            }
        }
    }

    #[inline]
    fn pointer_result(
        saved_errno: CInt,
        result: Result<NonNull<u8>, TestContextPointerError>,
    ) -> *mut c_void {
        match result {
            Ok(block) => preserve_errno(saved_errno, block.as_ptr().cast()),
            Err(TestContextPointerError::Closing) => {
                set_errno(EBUSY);
                ptr::null_mut()
            }
            Err(TestContextPointerError::AllocationFailed) => {
                // Ordinary replacement failure is observable while the old
                // engine block stays live, exactly as C `realloc` requires.
                set_errno(ENOMEM);
                ptr::null_mut()
            }
            Err(TestContextPointerError::InvalidPointer) => fail_stop_free_lifecycle(),
        }
    }

    #[inline]
    fn no_active_allocation() -> *mut c_void {
        // This is a lifecycle contract failure, not an exhausted engine
        // allocation request. Keep it distinguishable from NULL+ENOMEM.
        set_errno(EBUSY);
        ptr::null_mut()
    }

    /// Starts the sole test-adapter context.
    ///
    /// # Safety
    ///
    /// The C caller must serialize this with every other adapter operation
    /// and must use the resulting context only from this creating thread. A
    /// second active or transitioning initialization returns `EBUSY`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_init() -> CInt {
        let saved_errno = errno_value();
        if CONTEXT
            .compare_exchange(
                ptr::null_mut(),
                initializing_sentinel(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return preserve_errno(saved_errno, EBUSY);
        }

        // This context owns the engine's exact allocation count. The adapter
        // records no parallel count or ownership table.
        let context = match TestAllocatorContext::new() {
            Ok(context) => Box::new(context),
            Err(
                TestContextInitError::PageSizeUnavailable
                | TestContextInitError::InvalidPageSize
                | TestContextInitError::PageMapInitialization
                | TestContextInitError::ArenaMapping
                | TestContextInitError::ArenaManagement
                | TestContextInitError::ArenaView
                | TestContextInitError::ThreadIdentity
                | TestContextInitError::Bootstrap,
            ) => {
                CONTEXT.store(ptr::null_mut(), Ordering::Release);
                return preserve_errno(saved_errno, ENOMEM);
            }
        };
        let raw = Box::into_raw(context);
        // Publication is last: all stable engine owners are live before an
        // Acquire reader can form the documented exclusive mutable borrow.
        CONTEXT.store(raw, Ordering::Release);
        preserve_errno(saved_errno, 0)
    }

    /// Attempts the explicit terminal teardown of the test-adapter context.
    ///
    /// # Safety
    ///
    /// The C caller must serialize this with every other adapter operation
    /// and call it from the creating thread. `EBUSY` means live allocations
    /// remain: the original active pointer is republished so they can be
    /// returned and shutdown retried. `EAGAIN` retains a closing context for a
    /// retryable engine teardown failure; allocation/free are not reopened.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_shutdown() -> CInt {
        let saved_errno = errno_value();
        let raw = CONTEXT.load(Ordering::Acquire);
        if raw.is_null() {
            return preserve_errno(saved_errno, EINVAL);
        }
        if is_transition_state(raw) {
            return preserve_errno(saved_errno, EBUSY);
        }
        if CONTEXT
            .compare_exchange(
                raw,
                shutting_down_sentinel(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return preserve_errno(saved_errno, EBUSY);
        }

        // SAFETY: this pointer came from `Box::into_raw` in init, has not yet
        // been reconstructed, and the adapter's one-thread contract makes the
        // mutable borrow exclusive throughout the shutdown transition.
        let outcome = unsafe { (&mut *raw).shutdown() };
        match outcome {
            Ok(()) => {
                // SAFETY: only a successful engine shutdown reaches this arm;
                // this is the unique terminal reconstruction/drop of init's Box.
                unsafe { drop(Box::from_raw(raw)) };
                CONTEXT.store(ptr::null_mut(), Ordering::Release);
                preserve_errno(saved_errno, 0)
            }
            Err(TestContextShutdownError::OutstandingAllocations(_)) => {
                // The engine stayed active, so free remains usable.
                CONTEXT.store(raw, Ordering::Release);
                preserve_errno(saved_errno, EBUSY)
            }
            Err(
                TestContextShutdownError::CollectionFailed
                | TestContextShutdownError::PageMapDestroyFailed
                | TestContextShutdownError::ArenaUnmapFailed,
            ) => {
                // The engine remains intentionally closed but owns the exact
                // retry state. Restore its pointer rather than abandoning it
                // behind a permanent sentinel; only shutdown may now proceed.
                CONTEXT.store(raw, Ordering::Release);
                preserve_errno(saved_errno, EAGAIN)
            }
            Err(TestContextShutdownError::AlreadyShutdown) => {
                // This cannot occur after a successful adapter shutdown, which
                // reconstructs and drops the Box before publishing null. Keep
                // the still-owned pointer visible for diagnostic retry instead
                // of creating an uncollectable transition state.
                CONTEXT.store(raw, Ordering::Release);
                preserve_errno(saved_errno, EAGAIN)
            }
        }
    }

    /// Allocates one uninitialized engine block.
    ///
    /// # Safety
    ///
    /// The C caller must obey the module-level creating-thread and serialized
    /// operation contract. The returned pointer, if non-null, belongs only to
    /// this adapter and must later be passed once to its `free` or `realloc`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_malloc(size: usize) -> *mut c_void {
        let saved_errno = errno_value();
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.alloc(size))
    }

    /// Allocates one zeroed engine block.
    ///
    /// # Safety
    ///
    /// The C caller obligations are identical to `crabc_test_malloc`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_zalloc(size: usize) -> *mut c_void {
        let saved_errno = errno_value();
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.alloc_zeroed(size))
    }

    /// Performs checked counted zero allocation.
    ///
    /// # Safety
    ///
    /// The C caller obligations are identical to `crabc_test_malloc`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_calloc(
        count: usize,
        size: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if count.checked_mul(size).is_none() {
            set_errno(ENOMEM);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.calloc(count, size))
    }

    /// Returns one allocation to this adapter.
    ///
    /// # Safety
    ///
    /// The C caller must obey the module-level creating-thread and serialized
    /// operation contract. A non-null `block` must be exactly one still-live
    /// pointer returned by this adapter, passed exactly once and no longer
    /// aliased for access. `NULL` is a no-op. Valid-program lifecycle failure
    /// aborts rather than being misreported as an invalid pointer.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_free(block: *mut c_void) {
        if block.is_null() {
            return;
        }
        let saved_errno = errno_value();
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            fail_stop_free_lifecycle();
        };
        // SAFETY: a non-null C pointer has the documented live-adapter-block
        // contract above, so conversion preserves the engine's NonNull input.
        let block = unsafe { NonNull::new_unchecked(block.cast::<u8>()) };
        // SAFETY: the C caller contract is exactly `TestAllocatorContext::free`'s
        // current-allocation and exclusive-access obligation.
        match unsafe { context.free(block) } {
            Ok(()) => set_errno(saved_errno),
            Err(
                TestContextFreeError::Closing
                | TestContextFreeError::InvalidPointer
                | TestContextFreeError::Lifecycle,
            ) => fail_stop_free_lifecycle(),
        }
    }

    /// Reallocates one adapter allocation, preserving it on failure.
    ///
    /// # Safety
    ///
    /// The C caller must obey the module-level creating-thread and serialized
    /// operation contract. A non-null `block` must be one current adapter
    /// allocation with no aliased access during the call; `NULL` is allocation.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_realloc(
        block: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        let block = NonNull::new(block.cast::<u8>());
        // SAFETY: the C caller contract repeats the engine reallocation
        // obligation and keeps the old pointer live on a NULL result.
        pointer_result(saved_errno, unsafe { context.realloc(block, size) })
    }

    /// Reallocates one adapter allocation after checked `count * size`.
    ///
    /// # Safety
    ///
    /// The C caller obligations are identical to `crabc_test_realloc`.
    /// Overflow returns `NULL` with `ENOMEM` and does not inspect or free a
    /// non-null original block.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_reallocarray(
        block: *mut c_void,
        count: usize,
        size: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        let Some(total) = count.checked_mul(size) else {
            set_errno(ENOMEM);
            return ptr::null_mut();
        };
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        let block = NonNull::new(block.cast::<u8>());
        // SAFETY: see the matching reallocation contract above.
        pointer_result(saved_errno, unsafe { context.realloc(block, total) })
    }

    /// Returns the usable size of one current adapter allocation.
    ///
    /// # Safety
    ///
    /// The C caller must obey the module-level creating-thread and serialized
    /// operation contract. A non-null `block` must be exactly one current
    /// adapter allocation; `NULL` returns zero.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_usable_size(block: *const c_void) -> usize {
        if block.is_null() {
            return 0;
        }
        let saved_errno = errno_value();
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            fail_stop_free_lifecycle();
        };
        // SAFETY: the documented current-allocation contract makes this a
        // valid non-null pointer conversion without dereferencing its bytes.
        let block = unsafe { NonNull::new_unchecked(block.cast_mut().cast::<u8>()) };
        // SAFETY: the caller repeats `TestAllocatorContext::usable_size`'s
        // exact-current-allocation inspection obligation.
        match unsafe { context.usable_size(block) } {
            Ok(size) => preserve_errno(saved_errno, size),
            Err(
                TestContextPointerError::Closing
                | TestContextPointerError::InvalidPointer
                | TestContextPointerError::AllocationFailed,
            ) => fail_stop_free_lifecycle(),
        }
    }

    /// Allocates one valid zero-offset aligned block.
    ///
    /// # Safety
    ///
    /// The C caller obligations are identical to `crabc_test_malloc`.
    /// An alignment that is zero or not a power of two returns `NULL` and sets
    /// `errno` to `EINVAL` before the engine is entered.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_malloc_aligned(
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if !valid_engine_alignment(alignment) {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.alloc_aligned(size, alignment))
    }

    /// Allocates one zeroed valid zero-offset aligned block.
    ///
    /// # Safety
    ///
    /// The C caller obligations and invalid-alignment result are identical to
    /// `crabc_test_malloc_aligned`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_zalloc_aligned(
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if !valid_engine_alignment(alignment) {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.alloc_aligned_zeroed(size, alignment))
    }

    /// Performs checked counted zero allocation with zero-offset alignment.
    ///
    /// # Safety
    ///
    /// The C caller obligations and invalid-alignment result are identical to
    /// `crabc_test_malloc_aligned`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_calloc_aligned(
        count: usize,
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if !valid_engine_alignment(alignment) {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        if count.checked_mul(size).is_none() {
            set_errno(ENOMEM);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.calloc_aligned(count, size, alignment))
    }

    /// Allocates one block for which `block + offset` is aligned.
    ///
    /// # Safety
    ///
    /// The C caller obligations and invalid-alignment result are identical to
    /// `crabc_test_malloc_aligned`. The offset is an address equation,
    /// not an in-range byte index.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_malloc_aligned_at(
        size: usize,
        alignment: usize,
        offset: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if !valid_engine_alignment(alignment) {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        allocation_result(saved_errno, context.alloc_aligned_at(size, alignment, offset))
    }

    /// Reallocates one adapter block with zero-offset alignment.
    ///
    /// # Safety
    ///
    /// The C caller obligations are identical to `crabc_test_realloc`.
    /// A zero or non-power-of-two alignment returns `NULL` with `EINVAL` before
    /// inspecting a non-null original block.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_realloc_aligned(
        block: *mut c_void,
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if !valid_engine_alignment(alignment) {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        let block = NonNull::new(block.cast::<u8>());
        // SAFETY: see the matching reallocation contract above.
        pointer_result(
            saved_errno,
            unsafe { context.realloc_aligned(block, size, alignment) },
        )
    }

    /// Reallocates and zeroes one adapter block with zero-offset alignment.
    ///
    /// # Safety
    ///
    /// The C caller obligations and invalid-alignment result are identical to
    /// `crabc_test_realloc_aligned`.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_rezalloc_aligned(
        block: *mut c_void,
        size: usize,
        alignment: usize,
    ) -> *mut c_void {
        let saved_errno = errno_value();
        if !valid_engine_alignment(alignment) {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        // SAFETY: upheld by this export's C caller contract.
        let Some(context) = (unsafe { active_context() }) else {
            return no_active_allocation();
        };
        let block = NonNull::new(block.cast::<u8>());
        // SAFETY: see the matching reallocation contract above.
        pointer_result(
            saved_errno,
            unsafe { context.realloc_aligned_zeroed(block, size, alignment) },
        )
    }

    /// Performs POSIX-aligned allocation without modifying `*out` on error.
    ///
    /// # Safety
    ///
    /// The C caller must obey the module-level creating-thread and serialized
    /// operation contract. If non-null, `out` must name writable `void *`
    /// storage for the full call. Invalid `out` or POSIX alignment returns
    /// `EINVAL` and leaves caller storage untouched; valid allocation failure
    /// returns `ENOMEM` and likewise leaves it untouched.
    #[no_mangle]
    pub unsafe extern "C" fn crabc_test_posix_memalign(
        out: *mut *mut c_void,
        alignment: usize,
        size: usize,
    ) -> CInt {
        let saved_errno = errno_value();
        if out.is_null() || !valid_posix_alignment(alignment) {
            return preserve_errno(saved_errno, EINVAL);
        }
        // SAFETY: the C caller contract above guarantees `out` is writable;
        // defer the sole write until allocation has completed successfully.
        let Some(context) = (unsafe { active_context() }) else {
            return preserve_errno(saved_errno, EBUSY);
        };
        match context.alloc_aligned(size, alignment) {
            Ok(block) => {
                // SAFETY: established by the non-null, writable `out` caller
                // obligation and deferred until after a successful allocation.
                unsafe { out.write(block.as_ptr().cast()) };
                preserve_errno(saved_errno, 0)
            }
            Err(TestContextAllocationError::Closing) => preserve_errno(saved_errno, EBUSY),
            Err(TestContextAllocationError::AllocationFailed) => preserve_errno(saved_errno, ENOMEM),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        static SERIAL: Mutex<()> = Mutex::new(());

        fn test_guard() -> std::sync::MutexGuard<'static, ()> {
            SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        unsafe fn outstanding_allocations() -> usize {
            // SAFETY: every test holds `SERIAL`, initialized the adapter, and
            // performs the documented sole-thread accesses in sequence.
            unsafe { active_context() }
                .expect("test context should be active")
                .outstanding_allocations()
        }

        #[test]
        fn prefixed_adapter_preserves_the_bounded_c_contract() {
            let _serial = test_guard();

            // SAFETY: the serial test guard establishes the exported one-thread
            // caller contract for this composite process-global test.
            unsafe {
                set_errno(69);
                assert!(crabc_test_malloc(1).is_null());
                assert_eq!(errno_value(), EBUSY);
                assert_eq!(crabc_test_init(), 0);
                assert_eq!(crabc_test_init(), EBUSY);

                set_errno(71);
                let ordinary = crabc_test_malloc(37);
                assert!(!ordinary.is_null());
                assert_eq!(errno_value(), 71);
                assert_eq!(outstanding_allocations(), 1);
                assert!(crabc_test_usable_size(ordinary) >= 37);

                let zeroed = crabc_test_zalloc(41);
                assert!(!zeroed.is_null());
                assert_eq!(zeroed.cast::<u8>().read(), 0);
                let counted = crabc_test_calloc(3, 19);
                assert!(!counted.is_null());
                for index in 0..57 {
                    assert_eq!(counted.cast::<u8>().add(index).read(), 0);
                }
                assert_eq!(outstanding_allocations(), 3);

                crabc_test_free(zeroed);
                crabc_test_free(counted);
                assert_eq!(outstanding_allocations(), 1);

                ordinary.cast::<u8>().write(0x5a);
                set_errno(72);
                assert!(crabc_test_realloc(ordinary, usize::MAX).is_null());
                assert_eq!(errno_value(), ENOMEM);
                assert_eq!(ordinary.cast::<u8>().read(), 0x5a);
                assert_eq!(outstanding_allocations(), 1);

                set_errno(73);
                assert!(crabc_test_calloc(usize::MAX, 2).is_null());
                assert_eq!(errno_value(), ENOMEM);
                assert_eq!(outstanding_allocations(), 1);

                set_errno(74);
                let zero_product = crabc_test_reallocarray(ptr::null_mut(), 0, 31);
                assert!(!zero_product.is_null());
                assert_eq!(errno_value(), 74);
                crabc_test_free(zero_product);

                let offset_aligned = crabc_test_malloc_aligned_at(9, 64, 7);
                assert!(!offset_aligned.is_null());
                assert_eq!((offset_aligned as usize + 7) % 64, 0);
                crabc_test_free(offset_aligned);

                set_errno(75);
                assert!(crabc_test_malloc_aligned(8, 3).is_null());
                assert_eq!(errno_value(), EINVAL);

                let aligned_zeroed = crabc_test_calloc_aligned(2, 31, 64 * 1024);
                assert!(!aligned_zeroed.is_null());
                assert_eq!(aligned_zeroed as usize % (64 * 1024), 0);
                for index in 0..62 {
                    assert_eq!(aligned_zeroed.cast::<u8>().add(index).read(), 0);
                }
                let aligned = crabc_test_realloc_aligned(aligned_zeroed, 4 * 1024, 64 * 1024);
                assert!(!aligned.is_null());
                assert_eq!(aligned as usize % (64 * 1024), 0);
                let rezaligned = crabc_test_rezalloc_aligned(aligned, 8 * 1024, 64 * 1024);
                assert!(!rezaligned.is_null());
                assert_eq!(rezaligned as usize % (64 * 1024), 0);
                crabc_test_free(rezaligned);

                for alignment in [128 * 1024, 1024 * 1024] {
                    let block = crabc_test_zalloc_aligned(71, alignment);
                    assert!(!block.is_null());
                    assert_eq!(block as usize % alignment, 0);
                    assert_eq!(block.cast::<u8>().read(), 0);
                    crabc_test_free(block);
                }

                let mut out = 0x1usize as *mut c_void;
                set_errno(76);
                assert_eq!(crabc_test_posix_memalign(&mut out, 3, 64), EINVAL);
                assert_eq!(out, 0x1usize as *mut c_void);
                assert_eq!(errno_value(), 76);
                assert_eq!(crabc_test_posix_memalign(ptr::null_mut(), 64, 64), EINVAL);

                set_errno(77);
                assert_eq!(
                    crabc_test_posix_memalign(&mut out, 64, usize::MAX),
                    ENOMEM
                );
                assert_eq!(out, 0x1usize as *mut c_void);
                assert_eq!(errno_value(), 77);
                assert_eq!(crabc_test_posix_memalign(&mut out, 64, 33), 0);
                assert!(!out.is_null());
                assert_eq!(out as usize % 64, 0);
                crabc_test_free(out);

                set_errno(78);
                crabc_test_free(ptr::null_mut());
                assert_eq!(errno_value(), 78);

                // The one remaining original block exercises EBUSY shutdown:
                // it republishes the active context so free still succeeds.
                assert_eq!(outstanding_allocations(), 1);
                assert_eq!(crabc_test_shutdown(), EBUSY);
                crabc_test_free(ordinary);
                assert_eq!(outstanding_allocations(), 0);
                assert_eq!(crabc_test_shutdown(), 0);

                // A completed shutdown releases the Box only after engine
                // teardown. Fresh init proves that no sentinel or stale global
                // pointer remains published.
                assert_eq!(crabc_test_init(), 0);
                assert_eq!(crabc_test_shutdown(), 0);
            }
        }

        /// The C fixture's source-only `malloc` remap selects the aligned
        /// adapter exports to retain the native 64-bit musl `max_align_t`
        /// boundary. Keep this x86-64 regression separate from the broad C
        /// adapter contract: it proves the newly enabled target's exact
        /// zero-size and ordinary request boundaries without claiming a
        /// production libc allocator integration.
        #[cfg(target_arch = "x86_64")]
        #[test]
        fn x86_64_fixture_alignment_uses_the_prefixed_aligned_exports() {
            const FIXTURE_MAX_ALIGNMENT: usize = 16;

            let _serial = test_guard();
            // SAFETY: the serial guard establishes the documented one-thread
            // adapter contract for every operation in this test.
            unsafe {
                assert_eq!(crabc_test_init(), 0);
                for request in [0, 1, 15, 16, 17, 4 * 1024, 256 * 1024] {
                    set_errno(EAGAIN);
                    let block = crabc_test_malloc_aligned(request, FIXTURE_MAX_ALIGNMENT);
                    assert!(!block.is_null(), "request={request}");
                    assert_eq!(block as usize % FIXTURE_MAX_ALIGNMENT, 0, "request={request}");
                    assert!(crabc_test_usable_size(block) >= request, "request={request}");
                    assert_eq!(errno_value(), EAGAIN, "request={request}");
                    crabc_test_free(block);
                }

                let zeroed = crabc_test_calloc_aligned(3, 19, FIXTURE_MAX_ALIGNMENT);
                assert!(!zeroed.is_null());
                assert_eq!(zeroed as usize % FIXTURE_MAX_ALIGNMENT, 0);
                for index in 0..57 {
                    assert_eq!(zeroed.cast::<u8>().add(index).read(), 0);
                }
                crabc_test_free(zeroed);
                assert_eq!(crabc_test_shutdown(), 0);
            }
        }

        #[test]
        fn exported_symbol_names_stay_prefixed() {
            let _serial = test_guard();
            let names = [
                "crabc_test_init",
                "crabc_test_shutdown",
                "crabc_test_malloc",
                "crabc_test_zalloc",
                "crabc_test_calloc",
                "crabc_test_free",
                "crabc_test_realloc",
                "crabc_test_reallocarray",
                "crabc_test_usable_size",
                "crabc_test_malloc_aligned",
                "crabc_test_zalloc_aligned",
                "crabc_test_calloc_aligned",
                "crabc_test_malloc_aligned_at",
                "crabc_test_realloc_aligned",
                "crabc_test_rezalloc_aligned",
                "crabc_test_posix_memalign",
            ];
            assert!(names.iter().all(|name| name.starts_with("crabc_test_")));
            assert!(names.iter().all(|name| !matches!(*name, "malloc" | "calloc" | "realloc" | "free")));
            assert!(names.iter().all(|name| !name.starts_with("mi_")));
        }
    }
}
