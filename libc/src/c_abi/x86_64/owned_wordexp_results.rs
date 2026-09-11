//! Private staged `wordexp_t` result-record ownership for Linux/x86-64.
//!
//! This module is deliberately unselected. `owned_wordexp.rs` remains the
//! selected C ABI provider; a later integration must replace its local record
//! mutation as one coherent change rather than create a second exported C ABI
//! layout. This owner supplies only the record transaction behind that later
//! adapter.
//!
//! POSIX.1-2024 permits `WRDE_NOSPACE` to expose words completed before the
//! allocation failure, while an `WRDE_APPEND` call that reaches any other
//! error must retain its original record. A transaction therefore copies old
//! pointers into a separate C-allocated vector. It never reallocates or
//! writes the old vector while a later evaluator error can still roll back.
//! A successful or `WRDE_NOSPACE` caller commits the staged prefix without a
//! further allocation; dropping for every other result frees only staged
//! strings and that private vector.
//!
//! The selected allocator remains the production boundary. The injected
//! `WordexpResultAllocator` makes that boundary explicit for the standalone
//! no-C-export ownership harness; it is not an allocator abstraction or a
//! public API.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("owned wordexp result records require little-endian Linux/x86-64");

use core::{
    ffi::{c_char, c_void},
    mem::size_of,
    ptr,
};

// This is musl's `SIZE_MAX / sizeof(void *) / 4` offset guard from
// `src/misc/wordexp.c::do_wordexp`. The additional `isize::MAX` checks below
// are required for Rust pointer arithmetic even after this source guard.
const MUSL_MAX_OFFSETS: usize = usize::MAX / size_of::<*mut c_char>() / 4;

/// The offset form selected by the C call flags.
///
/// `Leading` corresponds to `WRDE_DOOFFS`; `None` is the non-`DOOFFS` form.
/// The caller supplies `Leading(record.we_offs)` for a fresh request, and the
/// same form for an append request. POSIX makes inconsistent `DOOFFS` use
/// across an append sequence a caller contract; the record cannot retain a
/// distinct flag bit when the offset count is zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WordexpResultOffsets {
    None,
    Leading(usize),
}

impl WordexpResultOffsets {
    #[inline]
    pub(super) const fn count(self) -> usize {
        match self {
            Self::None => 0,
            Self::Leading(count) => count,
        }
    }
}

/// Ownership state selected by the C adapter after it has interpreted flags.
///
/// `Fresh` does not inspect a prior vector. `Append` borrows a valid prior
/// result record until `commit_completed` transfers the old string pointers
/// to its private vector and releases only the old vector allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WordexpResultMode {
    Fresh { offsets: WordexpResultOffsets },
    Append { offsets: WordexpResultOffsets },
}

/// Private mirror of the x86 LP64 `wordexp_t` record.
///
/// This is `repr(C)` so a later one-owner integration can use the exact C
/// layout. It is not an additional C ABI declaration: no symbol in this
/// module is exported, and selection must unify this type with the selected
/// adapter's record definition.
#[repr(C)]
pub(super) struct WordexpResultRecord {
    pub(super) word_count: usize,
    pub(super) words: *mut *mut c_char,
    pub(super) offsets: usize,
}

impl WordexpResultRecord {
    #[inline]
    pub(super) const fn zero() -> Self {
        Self { word_count: 0, words: ptr::null_mut(), offsets: 0 }
    }

    #[inline]
    const fn zero_with_offsets(offsets: usize) -> Self {
        Self { word_count: 0, words: ptr::null_mut(), offsets }
    }
}

/// Private failures at the result-record boundary.
///
/// A later C adapter maps `NoSpace` to `WRDE_NOSPACE`. `InteriorNul` maps to
/// the engine's unrepresentable-output error, and every non-`NoSpace` error
/// leaves a transaction to drop rather than commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WordexpResultError {
    NoSpace,
    InteriorNul,
    ByteLengthMismatch,
    InvalidAppendRecord,
}

/// The selected C allocation domain used by one transaction.
///
/// This intentionally stays a three-operation, move-free value. Result words,
/// staging vectors, and an appended prior record must all use this exact
/// domain, because commit releases the old vector through it and `wordfree`
/// releases all published strings through it.
#[derive(Clone, Copy)]
pub(super) struct WordexpResultAllocator {
    allocate: unsafe fn(usize) -> *mut c_void,
    reallocate: unsafe fn(*mut c_void, usize) -> *mut c_void,
    deallocate: unsafe fn(*mut c_void),
}

impl WordexpResultAllocator {
    /// Construct a private allocation-domain handle.
    ///
    /// # Safety
    /// The three hooks must obey C `malloc`/`realloc`/`free` ownership and
    /// failure rules, share one allocation domain, and remain valid for every
    /// transaction and record released through this handle. `reallocate` must
    /// leave its old allocation live and unchanged when it returns null.
    pub(super) const unsafe fn new(
        allocate: unsafe fn(usize) -> *mut c_void,
        reallocate: unsafe fn(*mut c_void, usize) -> *mut c_void,
        deallocate: unsafe fn(*mut c_void),
    ) -> Self {
        Self { allocate, reallocate, deallocate }
    }

    #[inline]
    unsafe fn allocate(self, size: usize) -> *mut c_void {
        // SAFETY: `new` establishes this hook's C-allocation contract.
        unsafe { (self.allocate)(size) }
    }

    #[inline]
    unsafe fn reallocate(self, pointer: *mut c_void, size: usize) -> *mut c_void {
        // SAFETY: callers pass only this domain's live staging allocation.
        unsafe { (self.reallocate)(pointer, size) }
    }

    #[inline]
    unsafe fn deallocate(self, pointer: *mut c_void) {
        // SAFETY: callers pass null or one live allocation from this domain.
        unsafe { (self.deallocate)(pointer) }
    }

    /// Return the selected libc allocation domain for eventual production use.
    #[inline]
    #[allow(dead_code)] // This private candidate is intentionally unselected.
    pub(super) const fn selected() -> Self {
        Self {
            allocate: selected_malloc,
            reallocate: selected_realloc,
            deallocate: selected_free,
        }
    }
}

#[allow(dead_code)] // Reached only when the later selected adapter chooses `selected`.
unsafe extern "C" {
    #[link_name = "malloc"]
    fn result_malloc(size: usize) -> *mut c_void;
    #[link_name = "realloc"]
    fn result_realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "free"]
    fn result_free(pointer: *mut c_void);
}

#[allow(dead_code)] // Reached through the intentionally unselected selector.
unsafe fn selected_malloc(size: usize) -> *mut c_void {
    // SAFETY: this is the selected libc C allocation boundary.
    unsafe { result_malloc(size) }
}

#[allow(dead_code)] // Reached through the intentionally unselected selector.
unsafe fn selected_realloc(pointer: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: callers preserve C realloc ownership through the transaction.
    unsafe { result_realloc(pointer, size) }
}

#[allow(dead_code)] // Reached through the intentionally unselected selector.
unsafe fn selected_free(pointer: *mut c_void) {
    // SAFETY: callers pass selected-domain allocations or null.
    unsafe { result_free(pointer) }
}

#[inline]
fn checked_vector_bytes(slots: usize) -> Option<usize> {
    let bytes = slots.checked_mul(size_of::<*mut c_char>())?;
    if bytes > isize::MAX as usize { return None; }
    Some(bytes)
}

#[inline]
fn checked_word_end(offsets: usize, word_count: usize) -> Option<usize> {
    if offsets > MUSL_MAX_OFFSETS { return None; }
    let end = offsets.checked_add(word_count)?;
    checked_vector_bytes(end)?;
    Some(end)
}

#[inline]
fn checked_string_bytes(byte_len: usize) -> Option<usize> {
    let bytes = byte_len.checked_add(1)?;
    if bytes > isize::MAX as usize { return None; }
    Some(bytes)
}

#[inline]
unsafe fn reset_fresh_record(record: *mut WordexpResultRecord, offsets: usize) {
    // SAFETY: `begin` validates its caller-supplied record pointer first.
    unsafe { ptr::write(record, WordexpResultRecord::zero_with_offsets(offsets)); }
}

/// Stages a fresh or appended C result record without mutating its caller.
///
/// The transaction owns `vector` and only its newly appended string pointers.
/// In append mode, copied old pointers remain borrowed until commit; drop
/// never frees them or their original vector.
pub(super) struct WordexpResultTransaction {
    record: *mut WordexpResultRecord,
    allocator: WordexpResultAllocator,
    vector: *mut *mut c_char,
    capacity: usize,
    offsets: usize,
    // This count starts with borrowed append words and advances only after a
    // fully validated new C string and sentinel have been accepted.
    word_count: usize,
    old_vector: *mut *mut c_char,
    append: bool,
    first_new_slot: usize,
    next_word_slot: usize,
}

impl WordexpResultTransaction {
    /// Start a private staged result vector.
    ///
    /// # Safety
    /// `record` must be a non-null, writable, exclusively owned x86 LP64
    /// wordexp record for the whole transaction. For `Fresh`, `offsets` is
    /// already copied from the caller's initialized `we_offs` when `DOOFFS`
    /// was selected; no prior record field is read. For `Append`, `record`
    /// must be a valid result from this same allocator domain: its vector and
    /// every string remain live, are not aliased for mutation/free, and its
    /// offset count matches `mode`. The C adapter owns `WRDE_REUSE` and must
    /// release any prior record before choosing `Fresh`.
    ///
    /// On fresh setup `NoSpace`, this function writes a releasable zero record
    /// with the requested offset count. On append setup `NoSpace`, it leaves
    /// all three original record fields and all old allocations untouched.
    pub(super) unsafe fn begin(
        record: *mut WordexpResultRecord,
        mode: WordexpResultMode,
        allocator: WordexpResultAllocator,
    ) -> Result<Self, WordexpResultError> {
        if record.is_null() { return Err(WordexpResultError::InvalidAppendRecord); }

        let (offsets, old_count, old_vector, append) = match mode {
            WordexpResultMode::Fresh { offsets } => {
                (offsets.count(), 0, ptr::null_mut(), false)
            }
            WordexpResultMode::Append { offsets } => {
                // SAFETY: append callers provide an initialized valid prior record.
                let prior = unsafe { &*record };
                let expected_offsets = offsets.count();
                if prior.offsets != expected_offsets ||
                    (prior.word_count != 0 && prior.words.is_null())
                {
                    return Err(WordexpResultError::InvalidAppendRecord);
                }
                (expected_offsets, prior.word_count, prior.words, true)
            }
        };

        let Some(first_new_slot) = checked_word_end(offsets, old_count) else {
            if !append { unsafe { reset_fresh_record(record, offsets); } }
            return Err(WordexpResultError::NoSpace);
        };
        let Some(initial_capacity) = first_new_slot.checked_add(1) else {
            if !append { unsafe { reset_fresh_record(record, offsets); } }
            return Err(WordexpResultError::NoSpace);
        };
        let Some(bytes) = checked_vector_bytes(initial_capacity) else {
            if !append { unsafe { reset_fresh_record(record, offsets); } }
            return Err(WordexpResultError::NoSpace);
        };
        // SAFETY: `bytes` is nonzero and belongs to the injected C domain.
        let vector = unsafe { allocator.allocate(bytes) }.cast::<*mut c_char>();
        if vector.is_null() {
            if !append { unsafe { reset_fresh_record(record, offsets); } }
            return Err(WordexpResultError::NoSpace);
        }

        // Leading offsets are always null in the staged C result layout.
        for slot in 0..offsets {
            // SAFETY: `initial_capacity` includes all checked offset slots.
            unsafe { ptr::write(vector.add(slot), ptr::null_mut()); }
        }
        if old_count != 0 {
            for word_index in 0..old_count {
                let Some(slot) = offsets.checked_add(word_index) else {
                    // The checked end above proves this impossible for a valid
                    // record; retain the rollback boundary if a caller breaks
                    // its unsafe record contract.
                    unsafe { allocator.deallocate(vector.cast()); }
                    return Err(WordexpResultError::InvalidAppendRecord);
                };
                // SAFETY: append preconditions make the old slot readable and
                // the checked staging slot writable. This copies, not moves,
                // the prior string pointer.
                let word = unsafe { ptr::read(old_vector.add(slot)) };
                unsafe { ptr::write(vector.add(slot), word); }
            }
        }
        // SAFETY: the checked initial allocation always has the sentinel slot.
        unsafe { ptr::write(vector.add(first_new_slot), ptr::null_mut()); }

        Ok(Self {
            record,
            allocator,
            vector,
            capacity: initial_capacity,
            offsets,
            word_count: old_count,
            old_vector,
            append,
            first_new_slot,
            next_word_slot: first_new_slot,
        })
    }

    fn reserve_word_and_sentinel(&mut self) -> Result<(), WordexpResultError> {
        let Some(required_slots) = self.next_word_slot.checked_add(2) else {
            return Err(WordexpResultError::NoSpace);
        };
        if checked_vector_bytes(required_slots).is_none() {
            return Err(WordexpResultError::NoSpace);
        }
        if required_slots <= self.capacity { return Ok(()); }

        let Some(growth_step) = self.capacity.checked_div(2).and_then(|half| half.checked_add(10)) else {
            return Err(WordexpResultError::NoSpace);
        };
        let Some(grown_capacity) = self.capacity.checked_add(growth_step) else {
            return Err(WordexpResultError::NoSpace);
        };
        let new_capacity = if grown_capacity < required_slots {
            required_slots
        } else {
            grown_capacity
        };
        let Some(bytes) = checked_vector_bytes(new_capacity) else {
            return Err(WordexpResultError::NoSpace);
        };
        // SAFETY: `vector` is this live transaction's sole staging allocation;
        // C realloc preserves it unchanged on a null result.
        let grown = unsafe { self.allocator.reallocate(self.vector.cast(), bytes) }
            .cast::<*mut c_char>();
        if grown.is_null() { return Err(WordexpResultError::NoSpace); }
        self.vector = grown;
        self.capacity = new_capacity;
        Ok(())
    }

    /// Copy one NUL-free result word from a linear byte iterator.
    ///
    /// `byte_len` and `bytes` deliberately avoid an indexed result view: one
    /// pass fills the exact C string, so atom-backed engine results do not
    /// become quadratic. A mismatch is an internal producer-contract error;
    /// it has no partial C word acceptance. An interior NUL is likewise kept
    /// out of the C string and leaves this transaction for normal rollback.
    pub(super) fn append_word_bytes<I>(
        &mut self,
        byte_len: usize,
        mut bytes: I,
    ) -> Result<(), WordexpResultError>
    where
        I: Iterator<Item = u8>,
    {
        let Some(string_bytes) = checked_string_bytes(byte_len) else {
            return Err(WordexpResultError::NoSpace);
        };
        let Some(next_word_slot) = self.next_word_slot.checked_add(1) else {
            return Err(WordexpResultError::NoSpace);
        };
        let Some(next_word_count) = self.word_count.checked_add(1) else {
            return Err(WordexpResultError::NoSpace);
        };
        // Reserve both the current string pointer slot and the following null
        // sentinel before allocating the string. A failed reserve accepts no
        // word and leaves the already completed staged prefix valid.
        self.reserve_word_and_sentinel()?;
        // SAFETY: `string_bytes` is nonzero and bounded for pointer arithmetic.
        let word = unsafe { self.allocator.allocate(string_bytes) }.cast::<c_char>();
        if word.is_null() { return Err(WordexpResultError::NoSpace); }

        let mut copied = 0usize;
        while copied < byte_len {
            let Some(byte) = bytes.next() else {
                // SAFETY: this unpublished C string belongs only to this call.
                unsafe { self.allocator.deallocate(word.cast()); }
                return Err(WordexpResultError::ByteLengthMismatch);
            };
            if byte == 0 {
                // SAFETY: this unpublished C string belongs only to this call.
                unsafe { self.allocator.deallocate(word.cast()); }
                return Err(WordexpResultError::InteriorNul);
            }
            // SAFETY: copied stays below checked `byte_len` and string_bytes.
            unsafe { ptr::write(word.add(copied), byte as c_char); }
            let Some(next_copied) = copied.checked_add(1) else {
                // This cannot occur after checked_string_bytes and the loop
                // condition, but retain the unpublished-word rollback if a
                // producer ever violates that arithmetic contract.
                unsafe { self.allocator.deallocate(word.cast()); }
                return Err(WordexpResultError::NoSpace);
            };
            copied = next_copied;
        }
        if bytes.next().is_some() {
            // SAFETY: this unpublished C string belongs only to this call.
            unsafe { self.allocator.deallocate(word.cast()); }
            return Err(WordexpResultError::ByteLengthMismatch);
        }

        // Acceptance is one contiguous write sequence after the string is
        // complete: either both the new word and replacement sentinel become
        // visible to the staged owner, or neither does.
        unsafe {
            ptr::write(word.add(byte_len), 0);
            ptr::write(self.vector.add(self.next_word_slot), word);
            ptr::write(self.vector.add(next_word_slot), ptr::null_mut());
        }
        self.next_word_slot = next_word_slot;
        self.word_count = next_word_count;
        Ok(())
    }

    /// Publish the completed staged prefix infallibly and without allocating.
    ///
    /// # Safety
    /// The caller selects this only after a successful evaluation or an error
    /// already classified as `WRDE_NOSPACE`. On any other evaluation error it
    /// must drop this transaction instead, which retains an append record
    /// byte-for-byte and frees only newly owned storage. The record pointer and
    /// old append allocations must remain exclusively owned until this returns.
    pub(super) unsafe fn commit_completed(mut self) {
        // First publish the replacement vector, whose old string pointers are
        // already copied. Only then retire the old vector allocation; there is
        // no allocation or fallible operation between these steps. word_count
        // was checked at each accepted word, so publishing cannot fail.
        unsafe {
            (*self.record).word_count = self.word_count;
            (*self.record).offsets = self.offsets;
            (*self.record).words = self.vector;
        }
        let old_vector = self.old_vector;
        self.vector = ptr::null_mut();
        if self.append && !old_vector.is_null() {
            // SAFETY: commit transferred all old string pointers into the
            // published vector, leaving the old vector itself solely owned.
            unsafe { self.allocator.deallocate(old_vector.cast()); }
        }
    }

    unsafe fn discard_staging(&mut self) {
        if self.vector.is_null() { return; }
        for slot in self.first_new_slot..self.next_word_slot {
            // SAFETY: accepted staged words occupy this checked initialized
            // range; old borrowed pointers are strictly before first_new_slot.
            let word = unsafe { ptr::read(self.vector.add(slot)) };
            if !word.is_null() {
                // SAFETY: each non-null accepted staged word is owned once.
                unsafe { self.allocator.deallocate(word.cast()); }
            }
        }
        // SAFETY: this is the transaction's private staging vector.
        unsafe { self.allocator.deallocate(self.vector.cast()); }
        self.vector = ptr::null_mut();
    }
}

impl Drop for WordexpResultTransaction {
    fn drop(&mut self) {
        // SAFETY: only this transaction owns its staging vector and new words.
        unsafe { self.discard_staging(); }
    }
}

/// Release a published or partial-completion result record.
///
/// # Safety
/// `record` is null or an exclusively owned record published by this owner,
/// including a fresh/append `WRDE_NOSPACE` prefix. Its vector and non-null
/// words use `allocator`'s exact allocation domain and have not been copied,
/// separately freed, or mutated. A later C ABI adapter may expose this through
/// `wordfree`; it must not use it to release an in-flight transaction.
pub(super) unsafe fn release_wordexp_result_record(
    record: *mut WordexpResultRecord,
    allocator: WordexpResultAllocator,
) {
    if record.is_null() { return; }
    // SAFETY: the caller provides exclusive access to a valid result record.
    let vector = unsafe { (*record).words };
    let word_count = unsafe { (*record).word_count };
    let offsets = unsafe { (*record).offsets };
    // Match the selected `wordfree`: a null vector is inert, including the
    // fresh `WRDE_NOSPACE` zero record, so caller-supplied offsets survive.
    if vector.is_null() { return; }
    let Some(word_end) = checked_word_end(offsets, word_count) else {
        // A caller violating the unsafe record contract must not make this
        // helper perform unchecked pointer arithmetic or discard ownership.
        return;
    };
    for slot in offsets..word_end {
        // SAFETY: a valid record initializes every word slot in this range.
        let word = unsafe { ptr::read(vector.add(slot)) };
        if !word.is_null() {
            // SAFETY: every non-null published word uses this allocation domain.
            unsafe { allocator.deallocate(word.cast()); }
        }
    }
    // SAFETY: the vector is the record's final selected-domain allocation.
    unsafe { allocator.deallocate(vector.cast()); }
    // Match selected wordfree by retiring ownership fields while retaining
    // caller-supplied offsets for a later REUSE + DOOFFS call.
    unsafe {
        (*record).words = ptr::null_mut();
        (*record).word_count = 0;
    }
}
