// Copyright (c) 2018-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/atomic.h:65-157`,
// `379-401`. This is a narrow, concrete facade over the exact C11 atomic
// operation/order pairs used by later allocator slices. It deliberately does
// not make the allocator generic: protocol modules call these functions
// directly, and a future modeled-test backend can replace this module's one
// private `core::sync::atomic` import without entering the engine API.
//
// The omitted `mi_lock_*` and `_mi_atomic_once_*` surfaces belong to their
// source-owning lifecycle/lock slices. No allocator operation is exposed here.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicI64, AtomicIsize, AtomicPtr, AtomicUsize, Ordering};

pub(crate) type AtomicWord = AtomicUsize;
pub(crate) type AtomicSignedWord = AtomicIsize;
pub(crate) type AtomicI64Value = AtomicI64;
pub(crate) type AtomicPointer<T> = AtomicPtr<T>;
pub(crate) type AtomicGuardWord = AtomicWord;

#[inline]
pub(crate) fn word_load_acquire(word: &AtomicWord) -> usize {
    word.load(Ordering::Acquire)
}

#[inline]
pub(crate) fn word_load_relaxed(word: &AtomicWord) -> usize {
    word.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn word_store_release(word: &AtomicWord, value: usize) {
    word.store(value, Ordering::Release);
}

#[inline]
pub(crate) fn word_store_relaxed(word: &AtomicWord, value: usize) {
    word.store(value, Ordering::Relaxed);
}

#[inline]
pub(crate) fn word_exchange_relaxed(word: &AtomicWord, value: usize) -> usize {
    word.swap(value, Ordering::Relaxed)
}

#[inline]
pub(crate) fn word_exchange_release(word: &AtomicWord, value: usize) -> usize {
    word.swap(value, Ordering::Release)
}

#[inline]
pub(crate) fn word_exchange_acq_rel(word: &AtomicWord, value: usize) -> usize {
    word.swap(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn word_cas_weak_relaxed(
    word: &AtomicWord,
    expected: &mut usize,
    desired: usize,
) -> bool {
    word.compare_exchange_weak(*expected, desired, Ordering::Relaxed, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn word_cas_weak_release(
    word: &AtomicWord,
    expected: &mut usize,
    desired: usize,
) -> bool {
    word.compare_exchange_weak(*expected, desired, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn word_cas_weak_acq_rel(
    word: &AtomicWord,
    expected: &mut usize,
    desired: usize,
) -> bool {
    word.compare_exchange_weak(*expected, desired, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn word_cas_strong_relaxed(
    word: &AtomicWord,
    expected: &mut usize,
    desired: usize,
) -> bool {
    word.compare_exchange(*expected, desired, Ordering::Relaxed, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn word_cas_strong_release(
    word: &AtomicWord,
    expected: &mut usize,
    desired: usize,
) -> bool {
    word.compare_exchange(*expected, desired, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn word_cas_strong_acq_rel(
    word: &AtomicWord,
    expected: &mut usize,
    desired: usize,
) -> bool {
    word.compare_exchange(*expected, desired, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn word_add_relaxed(word: &AtomicWord, value: usize) -> usize {
    word.fetch_add(value, Ordering::Relaxed)
}

#[inline]
pub(crate) fn word_add_acq_rel(word: &AtomicWord, value: usize) -> usize {
    word.fetch_add(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn word_sub_relaxed(word: &AtomicWord, value: usize) -> usize {
    word.fetch_sub(value, Ordering::Relaxed)
}

#[inline]
pub(crate) fn word_sub_acq_rel(word: &AtomicWord, value: usize) -> usize {
    word.fetch_sub(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn word_and_relaxed(word: &AtomicWord, value: usize) -> usize {
    word.fetch_and(value, Ordering::Relaxed)
}

#[inline]
pub(crate) fn word_and_acq_rel(word: &AtomicWord, value: usize) -> usize {
    word.fetch_and(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn word_or_relaxed(word: &AtomicWord, value: usize) -> usize {
    word.fetch_or(value, Ordering::Relaxed)
}

#[inline]
pub(crate) fn word_or_acq_rel(word: &AtomicWord, value: usize) -> usize {
    word.fetch_or(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn word_increment_relaxed(word: &AtomicWord) -> usize {
    word_add_relaxed(word, 1)
}

#[inline]
pub(crate) fn word_decrement_relaxed(word: &AtomicWord) -> usize {
    word_sub_relaxed(word, 1)
}

#[inline]
pub(crate) fn word_increment_acq_rel(word: &AtomicWord) -> usize {
    word_add_acq_rel(word, 1)
}

#[inline]
pub(crate) fn word_decrement_acq_rel(word: &AtomicWord) -> usize {
    word_sub_acq_rel(word, 1)
}

#[inline]
pub(crate) fn signed_word_add_acq_rel(word: &AtomicSignedWord, value: isize) -> isize {
    word.fetch_add(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn signed_word_sub_acq_rel(word: &AtomicSignedWord, value: isize) -> isize {
    word.fetch_sub(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn pointer_load_acquire<T>(pointer: &AtomicPointer<T>) -> *mut T {
    pointer.load(Ordering::Acquire)
}

#[inline]
pub(crate) fn pointer_load_relaxed<T>(pointer: &AtomicPointer<T>) -> *mut T {
    pointer.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn pointer_store_release<T>(pointer: &AtomicPointer<T>, value: *mut T) {
    pointer.store(value, Ordering::Release);
}

#[inline]
pub(crate) fn pointer_store_relaxed<T>(pointer: &AtomicPointer<T>, value: *mut T) {
    pointer.store(value, Ordering::Relaxed);
}

#[inline]
pub(crate) fn pointer_cas_weak_release<T>(
    pointer: &AtomicPointer<T>,
    expected: &mut *mut T,
    desired: *mut T,
) -> bool {
    pointer
        .compare_exchange_weak(*expected, desired, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn pointer_cas_weak_acq_rel<T>(
    pointer: &AtomicPointer<T>,
    expected: &mut *mut T,
    desired: *mut T,
) -> bool {
    pointer
        .compare_exchange_weak(*expected, desired, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn pointer_cas_strong_release<T>(
    pointer: &AtomicPointer<T>,
    expected: &mut *mut T,
    desired: *mut T,
) -> bool {
    pointer
        .compare_exchange(*expected, desired, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn pointer_cas_strong_acq_rel<T>(
    pointer: &AtomicPointer<T>,
    expected: &mut *mut T,
    desired: *mut T,
) -> bool {
    pointer
        .compare_exchange(*expected, desired, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn pointer_exchange_relaxed<T>(pointer: &AtomicPointer<T>, value: *mut T) -> *mut T {
    pointer.swap(value, Ordering::Relaxed)
}

#[inline]
pub(crate) fn pointer_exchange_release<T>(pointer: &AtomicPointer<T>, value: *mut T) -> *mut T {
    pointer.swap(value, Ordering::Release)
}

#[inline]
pub(crate) fn pointer_exchange_acq_rel<T>(pointer: &AtomicPointer<T>, value: *mut T) -> *mut T {
    pointer.swap(value, Ordering::AcqRel)
}

#[inline]
pub(crate) fn i64_load_acquire(value: &AtomicI64Value) -> i64 {
    value.load(Ordering::Acquire)
}

#[inline]
pub(crate) fn i64_load_relaxed(value: &AtomicI64Value) -> i64 {
    value.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn i64_store_release(value: &AtomicI64Value, replacement: i64) {
    value.store(replacement, Ordering::Release);
}

#[inline]
pub(crate) fn i64_store_relaxed(value: &AtomicI64Value, replacement: i64) {
    value.store(replacement, Ordering::Relaxed);
}

#[inline]
pub(crate) fn i64_cas_strong_acq_rel(
    value: &AtomicI64Value,
    expected: &mut i64,
    desired: i64,
) -> bool {
    value
        .compare_exchange(*expected, desired, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|actual| *expected = actual)
        .is_ok()
}

#[inline]
pub(crate) fn i64_add_relaxed(value: &AtomicI64Value, addend: i64) -> i64 {
    value.fetch_add(addend, Ordering::Relaxed)
}

#[inline]
pub(crate) fn i64_add_acq_rel(value: &AtomicI64Value, addend: i64) -> i64 {
    value.fetch_add(addend, Ordering::AcqRel)
}

#[inline]
pub(crate) fn i64_add_from_relaxed(value: &AtomicI64Value, addend: &AtomicI64Value) {
    let addend = i64_load_relaxed(addend);
    if addend != 0 {
        i64_add_relaxed(value, addend);
    }
}

#[inline]
pub(crate) fn i64_max_relaxed(value: &AtomicI64Value, maximum: i64) {
    let mut current = i64_load_relaxed(value);
    while current < maximum
        && value
            .compare_exchange_weak(current, maximum, Ordering::Release, Ordering::Relaxed)
            .map_err(|actual| current = actual)
            .is_err()
    {}
}

/// A successful `mi_atomic_guard` acquisition. Dropping it performs the
/// source macro's release store; it is deliberately neither `Send` nor `Sync`
/// so the lexical acquire/release pairing stays on its acquiring thread.
pub(crate) struct AtomicGuard<'a> {
    word: &'a AtomicGuardWord,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// Attempts the non-blocking `mi_atomic_guard` acquisition.
#[inline]
pub(crate) fn try_atomic_guard(word: &AtomicGuardWord) -> Option<AtomicGuard<'_>> {
    let mut expected = 0;
    word_cas_strong_acq_rel(word, &mut expected, 1).then_some(AtomicGuard {
        word,
        _not_send_or_sync: PhantomData,
    })
}

impl Drop for AtomicGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        word_store_release(self.word, 0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn release_store_and_acquire_load_publish_prior_relaxed_writes() {
        let payload = Arc::new(AtomicWord::new(0));
        let published = Arc::new(AtomicWord::new(0));
        let publisher_payload = Arc::clone(&payload);
        let publisher_published = Arc::clone(&published);
        let publisher = thread::spawn(move || {
            word_store_relaxed(&publisher_payload, 0xfeed_face);
            word_store_release(&publisher_published, 1);
        });

        while word_load_acquire(&published) == 0 {
            core::hint::spin_loop();
        }
        assert_eq!(word_load_relaxed(&payload), 0xfeed_face);
        publisher.join().unwrap();
    }

    #[test]
    fn word_compare_exchange_preserves_each_upstream_order_pair_and_updates_expected() {
        let word = AtomicWord::new(4);

        let mut expected = 3;
        assert!(!word_cas_weak_relaxed(&word, &mut expected, 5));
        assert_eq!(expected, 4);

        while !word_cas_weak_release(&word, &mut expected, 5) {
            assert_eq!(expected, 4);
        }
        assert_eq!(word_load_relaxed(&word), 5);

        expected = 5;
        while !word_cas_weak_acq_rel(&word, &mut expected, 6) {
            assert_eq!(expected, 5);
        }
        assert_eq!(word_load_acquire(&word), 6);

        expected = 6;
        assert!(word_cas_strong_relaxed(&word, &mut expected, 7));
        expected = 7;
        assert!(word_cas_strong_release(&word, &mut expected, 8));
        expected = 8;
        assert!(word_cas_strong_acq_rel(&word, &mut expected, 9));
        assert_eq!(word_load_relaxed(&word), 9);
    }

    #[test]
    fn word_fetch_operations_return_the_previous_value_for_each_supported_ordering() {
        let word = AtomicWord::new(0b1100);

        assert_eq!(word_add_relaxed(&word, 2), 0b1100);
        assert_eq!(word_add_acq_rel(&word, 2), 0b1110);
        assert_eq!(word_sub_relaxed(&word, 3), 0b1_0000);
        assert_eq!(word_sub_acq_rel(&word, 1), 0b1101);
        assert_eq!(word_and_relaxed(&word, 0b1110), 0b1100);
        assert_eq!(word_or_relaxed(&word, 0b10), 0b1100);
        assert_eq!(word_and_acq_rel(&word, 0b1110), 0b1110);
        assert_eq!(word_or_acq_rel(&word, 0b1), 0b1110);
        assert_eq!(word_increment_relaxed(&word), 0b1111);
        assert_eq!(word_decrement_relaxed(&word), 0b1_0000);
        assert_eq!(word_increment_acq_rel(&word), 0b1111);
        assert_eq!(word_decrement_acq_rel(&word), 0b1_0000);
        assert_eq!(word_load_relaxed(&word), 0b1111);
    }

    #[test]
    fn word_exchange_and_signed_word_arithmetic_return_the_old_value() {
        let word = AtomicWord::new(1);
        assert_eq!(word_exchange_relaxed(&word, 2), 1);
        assert_eq!(word_exchange_release(&word, 3), 2);
        assert_eq!(word_exchange_acq_rel(&word, 4), 3);

        let signed = AtomicSignedWord::new(-2);
        assert_eq!(signed_word_add_acq_rel(&signed, 5), -2);
        assert_eq!(signed_word_sub_acq_rel(&signed, 4), 3);
        assert_eq!(signed.load(Ordering::Relaxed), -1);
    }

    #[test]
    fn pointer_operations_keep_the_typed_pointer_and_expected_value() {
        let mut first = 1u8;
        let mut second = 2u8;
        let first_pointer = core::ptr::from_mut(&mut first);
        let second_pointer = core::ptr::from_mut(&mut second);
        let pointer = AtomicPointer::new(first_pointer);

        assert_eq!(pointer_load_relaxed(&pointer), first_pointer);
        pointer_store_release(&pointer, second_pointer);
        assert_eq!(pointer_load_acquire(&pointer), second_pointer);
        pointer_store_relaxed(&pointer, first_pointer);

        let mut expected = first_pointer;
        while !pointer_cas_weak_release(&pointer, &mut expected, second_pointer) {
            assert_eq!(expected, first_pointer);
        }
        expected = second_pointer;
        while !pointer_cas_weak_acq_rel(&pointer, &mut expected, first_pointer) {
            assert_eq!(expected, second_pointer);
        }
        expected = first_pointer;
        assert!(pointer_cas_strong_release(&pointer, &mut expected, second_pointer));
        expected = second_pointer;
        assert!(pointer_cas_strong_acq_rel(&pointer, &mut expected, first_pointer));

        assert_eq!(pointer_exchange_relaxed(&pointer, second_pointer), first_pointer);
        assert_eq!(pointer_exchange_release(&pointer, first_pointer), second_pointer);
        assert_eq!(pointer_exchange_acq_rel(&pointer, second_pointer), first_pointer);
    }

    #[test]
    fn signed_i64_statistics_operations_are_atomic_and_max_never_decreases() {
        let value = AtomicI64Value::new(4);
        let addend = AtomicI64Value::new(3);

        assert_eq!(i64_add_relaxed(&value, 2), 4);
        i64_add_from_relaxed(&value, &addend);
        i64_max_relaxed(&value, 20);
        i64_max_relaxed(&value, 19);
        assert_eq!(i64_load_relaxed(&value), 20);
        assert_eq!(i64_load_acquire(&value), 20);
        i64_store_relaxed(&value, 11);
        i64_store_release(&value, 12);
        let mut expected = 12;
        assert!(i64_cas_strong_acq_rel(&value, &mut expected, 13));
        assert_eq!(i64_add_acq_rel(&value, 7), 13);
        assert_eq!(i64_load_relaxed(&value), 20);
    }

    #[test]
    fn atomic_guard_excludes_a_second_entrant_and_releases_at_scope_exit() {
        let guard = AtomicGuardWord::new(0);
        let held = try_atomic_guard(&guard).expect("an unlocked guard is acquired");
        assert!(try_atomic_guard(&guard).is_none());
        drop(held);
        assert!(try_atomic_guard(&guard).is_some());
    }
}
