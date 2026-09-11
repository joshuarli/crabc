//! Focused native test root for the private x86 `wordexp_t` result transaction.
//!
//! This imports only the unselected record owner. Its allocator is injected
//! through ordinary Rust function pointers, so the harness never exports or
//! interposes `malloc`, `realloc`, or `free` used by Rust's standard test
//! runtime.

use std::{
    alloc::{alloc, dealloc, realloc, Layout},
    collections::{BTreeMap, BTreeSet},
    ffi::{c_char, c_void, CStr},
    ptr,
    sync::{Mutex, MutexGuard, OnceLock},
};

#[path = "../../libc/src/c_abi/x86_64/owned_wordexp_results.rs"]
mod owned_wordexp_results;

use owned_wordexp_results::{
    release_wordexp_result_record, WordexpResultAllocator, WordexpResultError,
    WordexpResultMode, WordexpResultOffsets, WordexpResultRecord,
    WordexpResultTransaction,
};

#[derive(Default)]
struct AllocationState {
    attempts: usize,
    fail_at: Option<usize>,
    live: BTreeMap<usize, Layout>,
    double_frees: usize,
}

fn state() -> &'static Mutex<AllocationState> {
    static STATE: OnceLock<Mutex<AllocationState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(AllocationState::default()))
}

fn lock_state() -> MutexGuard<'static, AllocationState> {
    match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn allocation_layout(size: usize) -> Layout {
    // The owner only allocates byte strings and pointer vectors, but this
    // keeps the injected boundary as aligned as ordinary C allocation.
    Layout::from_size_align(size.max(1), 16).unwrap()
}

unsafe fn tracking_malloc(size: usize) -> *mut c_void {
    let mut tracker = lock_state();
    tracker.attempts += 1;
    if tracker.fail_at == Some(tracker.attempts) { return ptr::null_mut(); }
    let layout = allocation_layout(size);
    // SAFETY: `layout` is nonzero and valid.
    let allocation = unsafe { alloc(layout) };
    if allocation.is_null() { return ptr::null_mut(); }
    assert!(tracker.live.insert(allocation as usize, layout).is_none());
    allocation.cast()
}

unsafe fn tracking_realloc(pointer: *mut c_void, size: usize) -> *mut c_void {
    if pointer.is_null() {
        // SAFETY: this preserves C `realloc(NULL, size)` allocation behavior.
        return unsafe { tracking_malloc(size) };
    }
    let mut tracker = lock_state();
    tracker.attempts += 1;
    if tracker.fail_at == Some(tracker.attempts) { return ptr::null_mut(); }
    let Some(old_layout) = tracker.live.get(&(pointer as usize)).copied() else {
        panic!("owner reallocated an allocation it does not own");
    };
    let new_layout = allocation_layout(size);
    // SAFETY: the tracker holds the exact layout for this live allocation.
    let grown = unsafe { realloc(pointer.cast(), old_layout, size.max(1)) };
    if grown.is_null() { return ptr::null_mut(); }
    assert!(tracker.live.remove(&(pointer as usize)).is_some());
    assert!(tracker.live.insert(grown as usize, new_layout).is_none());
    grown.cast()
}

unsafe fn tracking_free(pointer: *mut c_void) {
    if pointer.is_null() { return; }
    let mut tracker = lock_state();
    let Some(layout) = tracker.live.remove(&(pointer as usize)) else {
        tracker.double_frees += 1;
        return;
    };
    // SAFETY: the tracker removes exactly the allocation's recorded layout.
    unsafe { dealloc(pointer.cast(), layout); }
}

fn allocator() -> WordexpResultAllocator {
    // SAFETY: these hooks implement one stable C-like allocation domain for
    // each serialized test run.
    unsafe { WordexpResultAllocator::new(tracking_malloc, tracking_realloc, tracking_free) }
}

fn reset_allocator(fail_at: Option<usize>) {
    let mut tracker = lock_state();
    assert!(tracker.live.is_empty(), "a prior test leaked owner storage");
    assert_eq!(tracker.double_frees, 0, "a prior test double-freed owner storage");
    *tracker = AllocationState { attempts: 0, fail_at, live: BTreeMap::new(), double_frees: 0 };
}

fn fail_next_allocation() {
    let mut tracker = lock_state();
    tracker.fail_at = Some(tracker.attempts + 1);
}

fn fail_after_additional_allocations(additional: usize) {
    let mut tracker = lock_state();
    tracker.fail_at = Some(tracker.attempts + additional);
}

fn allocation_attempts() -> usize { lock_state().attempts }

fn live_pointers() -> BTreeSet<usize> {
    lock_state().live.keys().copied().collect()
}

fn allocation_is_live(pointer: *mut c_void) -> bool {
    lock_state().live.contains_key(&(pointer as usize))
}

fn assert_allocator_clean() {
    let tracker = lock_state();
    assert!(tracker.live.is_empty(), "owner allocations remain live: {:?}", tracker.live.keys());
    assert_eq!(tracker.double_frees, 0, "owner performed a double free");
}

fn fresh_mode(offsets: usize) -> WordexpResultMode {
    let offsets = if offsets == 0 {
        WordexpResultOffsets::None
    } else {
        WordexpResultOffsets::Leading(offsets)
    };
    WordexpResultMode::Fresh { offsets }
}

fn append_mode(offsets: usize) -> WordexpResultMode {
    let offsets = if offsets == 0 {
        WordexpResultOffsets::None
    } else {
        WordexpResultOffsets::Leading(offsets)
    };
    WordexpResultMode::Append { offsets }
}

fn begin(record: &mut WordexpResultRecord, mode: WordexpResultMode) -> WordexpResultTransaction {
    // SAFETY: each test supplies a writable record; append fixtures below are
    // valid records allocated by the same injected allocation domain.
    match unsafe { WordexpResultTransaction::begin(record, mode, allocator()) } {
        Ok(transaction) => transaction,
        Err(error) => panic!("unexpected transaction setup error: {error:?}"),
    }
}

fn append(transaction: &mut WordexpResultTransaction, bytes: &[u8]) -> Result<(), WordexpResultError> {
    transaction.append_word_bytes(bytes.len(), bytes.iter().copied())
}

fn commit(transaction: WordexpResultTransaction) {
    // SAFETY: the tests call this only for the successful or `NoSpace`
    // completion states that POSIX permits the caller to publish.
    unsafe { transaction.commit_completed(); }
}

fn release(record: &mut WordexpResultRecord) {
    // SAFETY: fixtures are records published by this owner or its documented
    // fresh `NoSpace` zero state, and the allocator matches their provenance.
    unsafe { release_wordexp_result_record(record, allocator()); }
}

unsafe fn record_snapshot(record: &WordexpResultRecord) -> (usize, usize, usize) {
    (record.words as usize, record.word_count, record.offsets)
}

unsafe fn result_word(record: &WordexpResultRecord, index: usize) -> Vec<u8> {
    assert!(index < record.word_count);
    // SAFETY: published records initialize every word slot through word_count.
    let pointer = unsafe { *record.words.add(record.offsets + index) };
    assert!(!pointer.is_null());
    // SAFETY: the owner allocated and NUL-terminated this C string.
    unsafe { CStr::from_ptr(pointer).to_bytes().to_vec() }
}

unsafe fn word_pointer(record: &WordexpResultRecord, index: usize) -> *mut c_char {
    assert!(index < record.word_count);
    // SAFETY: published records initialize every word slot through word_count.
    unsafe { *record.words.add(record.offsets + index) }
}

unsafe fn assert_releasable_record(record: &WordexpResultRecord) {
    if record.words.is_null() {
        assert_eq!(record.word_count, 0);
        return;
    }
    for offset in 0..record.offsets {
        // SAFETY: the record owns all requested leading offset slots.
        assert!(unsafe { (*record.words.add(offset)).is_null() });
    }
    // SAFETY: the owner keeps a sentinel immediately after published words.
    assert!(unsafe { (*record.words.add(record.offsets + record.word_count)).is_null() });
}

fn make_record(offsets: usize, words: &[&[u8]]) -> WordexpResultRecord {
    let mut record = WordexpResultRecord::zero();
    let mut transaction = begin(&mut record, fresh_mode(offsets));
    for word in words {
        append(&mut transaction, word).unwrap();
    }
    commit(transaction);
    record
}

#[test]
fn first_vector_allocation_failure_leaves_fresh_record_releasable() {
    reset_allocator(Some(1));
    let mut record = WordexpResultRecord::zero();
    let result = unsafe { WordexpResultTransaction::begin(&mut record, fresh_mode(2), allocator()) };
    assert_eq!(result.err(), Some(WordexpResultError::NoSpace));
    assert_eq!(unsafe { record_snapshot(&record) }, (0, 0, 2));
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn append_setup_failure_preserves_the_original_record_exactly() {
    reset_allocator(None);
    let mut record = make_record(2, &[b"old"]);
    let before = unsafe { record_snapshot(&record) };
    let live_before = live_pointers();
    fail_next_allocation();

    let result = unsafe { WordexpResultTransaction::begin(&mut record, append_mode(2), allocator()) };
    assert_eq!(result.err(), Some(WordexpResultError::NoSpace));
    assert_eq!(unsafe { record_snapshot(&record) }, before);
    assert_eq!(live_pointers(), live_before);
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn later_string_allocation_failure_publishes_a_releasable_zero_prefix() {
    reset_allocator(None);
    let mut record = WordexpResultRecord::zero();
    let mut transaction = begin(&mut record, fresh_mode(0));
    // The first append reserves its vector slot first, then obtains the C
    // string. Fail that second allocation rather than vector growth.
    fail_after_additional_allocations(2);
    assert_eq!(append(&mut transaction, b"new"), Err(WordexpResultError::NoSpace));
    commit(transaction);

    assert_eq!(record.word_count, 0);
    assert!(!record.words.is_null());
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn vector_growth_failure_accepts_no_current_word() {
    reset_allocator(None);
    let mut record = WordexpResultRecord::zero();
    let mut transaction = begin(&mut record, fresh_mode(0));
    fail_next_allocation();
    assert_eq!(append(&mut transaction, b"new"), Err(WordexpResultError::NoSpace));
    commit(transaction);

    assert_eq!(record.word_count, 0);
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn fresh_zero_word_success_owns_an_allocated_sentinel_vector() {
    reset_allocator(None);
    let mut record = WordexpResultRecord::zero();
    let transaction = begin(&mut record, fresh_mode(2));
    commit(transaction);

    assert_eq!(record.word_count, 0);
    assert_eq!(record.offsets, 2);
    assert!(!record.words.is_null());
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    // The helper clears words/count, retains caller offsets, and makes a
    // second wordfree inert.
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn wordfree_retains_offsets_for_successful_partial_and_zero_nospace_records() {
    // The selected `owned_wordexp.rs::wordfree` is the source control: after
    // a non-null vector it clears only words/count, and its null-vector path
    // returns without changing the record. REUSE can therefore reuse we_offs.
    reset_allocator(None);
    let mut successful = make_record(3, &[b"complete"]);
    release(&mut successful);
    assert_eq!(unsafe { record_snapshot(&successful) }, (0, 0, 3));
    release(&mut successful);
    assert_eq!(unsafe { record_snapshot(&successful) }, (0, 0, 3));
    assert_allocator_clean();

    reset_allocator(None);
    let mut partial = WordexpResultRecord::zero();
    let mut transaction = begin(&mut partial, fresh_mode(3));
    append(&mut transaction, b"completed-prefix").unwrap();
    fail_next_allocation();
    assert_eq!(append(&mut transaction, b"unaccepted"), Err(WordexpResultError::NoSpace));
    commit(transaction);
    assert_eq!(partial.word_count, 1);
    release(&mut partial);
    assert_eq!(unsafe { record_snapshot(&partial) }, (0, 0, 3));
    assert_allocator_clean();

    reset_allocator(Some(1));
    let mut zero_nospace = WordexpResultRecord::zero();
    let result = unsafe {
        WordexpResultTransaction::begin(&mut zero_nospace, fresh_mode(3), allocator())
    };
    assert_eq!(result.err(), Some(WordexpResultError::NoSpace));
    release(&mut zero_nospace);
    assert_eq!(unsafe { record_snapshot(&zero_nospace) }, (0, 0, 3));
    assert_allocator_clean();
}

#[test]
fn append_copies_only_vector_ownership_and_preserves_offsets() {
    reset_allocator(None);
    let mut record = make_record(2, &[b"old"]);
    let old_vector = record.words;
    let old_string = unsafe { word_pointer(&record, 0) };
    let mut transaction = begin(&mut record, append_mode(2));
    append(&mut transaction, b"new").unwrap();
    commit(transaction);

    assert_eq!(record.word_count, 2);
    assert_eq!(record.offsets, 2);
    assert_ne!(record.words, old_vector);
    assert_eq!(unsafe { word_pointer(&record, 0) }, old_string);
    assert_eq!(unsafe { result_word(&record, 0) }, b"old");
    assert_eq!(unsafe { result_word(&record, 1) }, b"new");
    assert!(!allocation_is_live(old_vector.cast()));
    assert!(allocation_is_live(old_string.cast()));
    assert!(allocation_is_live(unsafe { word_pointer(&record, 1) }.cast()));
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn nospace_commits_the_completed_prefix_without_another_allocation() {
    reset_allocator(None);
    let mut record = WordexpResultRecord::zero();
    let mut transaction = begin(&mut record, fresh_mode(0));
    append(&mut transaction, b"first").unwrap();
    fail_next_allocation();
    assert_eq!(append(&mut transaction, b"second"), Err(WordexpResultError::NoSpace));
    commit(transaction);

    assert_eq!(record.word_count, 1);
    assert_eq!(unsafe { result_word(&record, 0) }, b"first");
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

#[test]
fn malformed_linear_result_stream_never_accepts_its_current_word() {
    reset_allocator(None);
    let mut record = WordexpResultRecord::zero();
    let mut transaction = begin(&mut record, fresh_mode(0));
    append(&mut transaction, b"kept").unwrap();
    let prefix_live = live_pointers();

    assert_eq!(
        transaction.append_word_bytes(2, [b'x'].into_iter()),
        Err(WordexpResultError::ByteLengthMismatch),
    );
    assert_eq!(live_pointers(), prefix_live);
    assert_eq!(
        transaction.append_word_bytes(1, [b'x', b'y'].into_iter()),
        Err(WordexpResultError::ByteLengthMismatch),
    );
    assert_eq!(live_pointers(), prefix_live);
    assert_eq!(
        transaction.append_word_bytes(1, [0].into_iter()),
        Err(WordexpResultError::InteriorNul),
    );
    assert_eq!(live_pointers(), prefix_live);

    // These are non-NOSPACE producer errors, so dropping rolls back even the
    // previously staged prefix and leaves the fresh caller record untouched.
    drop(transaction);
    assert_eq!(unsafe { record_snapshot(&record) }, (0, 0, 0));
    assert_allocator_clean();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimulatedEvaluationError {
    UndefinedVariable,
}

#[test]
fn late_non_nospace_error_rolls_back_only_new_storage() {
    reset_allocator(None);
    let mut record = make_record(2, &[b"old"]);
    let before = unsafe { record_snapshot(&record) };
    let old_vector = record.words;
    let old_string = unsafe { word_pointer(&record, 0) };
    let live_before = live_pointers();

    let outcome = {
        let mut transaction = begin(&mut record, append_mode(2));
        append(&mut transaction, b"new").unwrap();
        Err::<(), SimulatedEvaluationError>(SimulatedEvaluationError::UndefinedVariable)
    };
    assert_eq!(outcome, Err(SimulatedEvaluationError::UndefinedVariable));

    assert_eq!(unsafe { record_snapshot(&record) }, before);
    assert_eq!(live_pointers(), live_before);
    assert!(allocation_is_live(old_vector.cast()));
    assert!(allocation_is_live(old_string.cast()));
    unsafe { assert_releasable_record(&record); }
    release(&mut record);
    assert_allocator_clean();
}

fn run_two_word_failure_case(fail_at: Option<usize>) -> (bool, usize, usize) {
    reset_allocator(fail_at);
    let mut record = WordexpResultRecord::zero();
    let mut no_space = false;
    match unsafe { WordexpResultTransaction::begin(&mut record, fresh_mode(0), allocator()) } {
        Err(WordexpResultError::NoSpace) => no_space = true,
        Err(other) => panic!("unexpected setup error: {other:?}"),
        Ok(mut transaction) => {
            for word in [b"first".as_slice(), b"second".as_slice()] {
                match append(&mut transaction, word) {
                    Ok(()) => {}
                    Err(WordexpResultError::NoSpace) => {
                        no_space = true;
                        break;
                    }
                    Err(other) => panic!("unexpected append error: {other:?}"),
                }
            }
            commit(transaction);
        }
    }
    unsafe { assert_releasable_record(&record); }
    let word_count = record.word_count;
    let attempts = allocation_attempts();
    release(&mut record);
    assert_allocator_clean();
    (no_space, word_count, attempts)
}

#[test]
fn bounded_allocation_failure_sweep_preserves_each_publishable_prefix() {
    let (no_space, word_count, attempts) = run_two_word_failure_case(None);
    assert!(!no_space);
    assert_eq!(word_count, 2);
    assert!(attempts > 0 && attempts <= 8, "unexpectedly broad allocation path: {attempts}");

    for failing_attempt in 1..=attempts {
        let (no_space, word_count, observed_attempts) =
            run_two_word_failure_case(Some(failing_attempt));
        assert!(no_space, "failure injection {failing_attempt} did not report NoSpace");
        assert!(word_count <= 1, "failure injection {failing_attempt} accepted an uncompleted word");
        assert!(observed_attempts >= failing_attempt);
    }
}

#[test]
fn musl_offset_guard_rejects_before_any_allocator_request() {
    reset_allocator(None);
    let too_many_offsets = usize::MAX / core::mem::size_of::<*mut c_char>() / 4 + 1;
    let mut record = WordexpResultRecord::zero();
    let result = unsafe {
        WordexpResultTransaction::begin(
            &mut record,
            WordexpResultMode::Fresh {
                offsets: WordexpResultOffsets::Leading(too_many_offsets),
            },
            allocator(),
        )
    };
    assert_eq!(result.err(), Some(WordexpResultError::NoSpace));
    assert_eq!(allocation_attempts(), 0);
    assert_eq!(unsafe { record_snapshot(&record) }, (0, 0, too_many_offsets));
    release(&mut record);
    assert_allocator_clean();
}
