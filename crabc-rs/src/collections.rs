//! Typed search and context-aware sorting operations.
//!
//! These operations are the native counterparts to the legacy `bsearch`,
//! `lfind`, `lsearch`, and `qsort_r` exports.  They operate on Rust slices and
//! values, so the comparator cannot observe untyped byte pointers and no C
//! `errno` or allocator contract is involved.  The alloc-gated insertion
//! operation exposes `Vec::try_reserve` failure as a typed error.

use core::cmp::Ordering;

/// A zero-sized namespace for search operations over borrowed slices.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Search;

impl Search {
    /// Returns the index of an element equivalent to `key` using binary
    /// search, or `None` when the ordered slice has no match.
    #[must_use]
    pub fn binary<T, F>(slice: &[T], key: &T, mut compare: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        slice.binary_search_by(|element| compare(element, key)).ok()
    }

    /// Descriptive alias for [`Self::binary`].
    #[must_use]
    pub fn binary_search<T, F>(slice: &[T], key: &T, compare: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::binary(slice, key, compare)
    }

    /// Returns the standard `Result` form of [`Self::binary`], retaining the
    /// insertion point for a missing key.
    pub fn binary_search_by<T, F>(slice: &[T], key: &T, mut compare: F) -> Result<usize, usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        slice.binary_search_by(|element| compare(element, key))
    }

    /// Returns a borrowed binary-search match.
    #[must_use]
    pub fn binary_find<'a, T, F>(slice: &'a [T], key: &T, compare: F) -> Option<&'a T>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::binary(slice, key, compare).map(|index| &slice[index])
    }

    /// Returns the first linearly found index whose comparator reports equal.
    #[must_use]
    pub fn linear<T, F>(slice: &[T], key: &T, mut compare: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        slice
            .iter()
            .position(|element| compare(element, key) == Ordering::Equal)
    }

    /// Descriptive alias for [`Self::linear`].
    #[must_use]
    pub fn linear_search<T, F>(slice: &[T], key: &T, compare: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::linear(slice, key, compare)
    }

    /// Returns a borrowed linear-search match.
    #[must_use]
    pub fn linear_find<'a, T, F>(slice: &'a [T], key: &T, compare: F) -> Option<&'a T>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::linear(slice, key, compare).map(|index| &slice[index])
    }

    /// Names the linear operation after the C function it replaces.
    #[must_use]
    pub fn lfind<T, F>(slice: &[T], key: &T, compare: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::linear(slice, key, compare)
    }

    /// Names the binary operation after the C function it replaces.
    #[must_use]
    pub fn bsearch<T, F>(slice: &[T], key: &T, compare: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::binary(slice, key, compare)
    }

    /// Searches a vector and appends `value` if it is absent.
    ///
    /// This is the alloc-gated, ownership-preserving counterpart to
    /// `lsearch`: reserve is attempted before the value is moved into the
    /// vector, and allocation failure returns the original value in
    /// [`InsertError`].
    #[cfg(feature = "alloc")]
    pub fn try_insert<T, F>(
        values: &mut alloc::vec::Vec<T>,
        value: T,
        mut compare: F,
    ) -> Result<InsertOutcome, InsertError<T>>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        if let Some(index) = Self::linear(values, &value, &mut compare) {
            return Ok(InsertOutcome::Found { index });
        }

        if let Err(error) = values.try_reserve(1) {
            return Err(InsertError { value, error });
        }
        let index = values.len();
        values.push(value);
        Ok(InsertOutcome::Inserted { index })
    }

    /// Explicitly names the operation after `lsearch`.
    #[cfg(feature = "alloc")]
    pub fn try_lsearch<T, F>(
        values: &mut alloc::vec::Vec<T>,
        value: T,
        compare: F,
    ) -> Result<InsertOutcome, InsertError<T>>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::try_insert(values, value, compare)
    }

    /// Descriptive alias for [`Self::try_insert`].
    #[cfg(feature = "alloc")]
    pub fn linear_search_or_insert<T, F>(
        values: &mut alloc::vec::Vec<T>,
        value: T,
        compare: F,
    ) -> Result<InsertOutcome, InsertError<T>>
    where
        F: FnMut(&T, &T) -> Ordering,
    {
        Self::try_insert(values, value, compare)
    }
}

/// The result of searching a collection which may append a missing value.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InsertOutcome {
    /// The value compared equal to an existing element.
    Found { index: usize },
    /// The value was appended at this index.
    Inserted { index: usize },
}

#[cfg(feature = "alloc")]
impl InsertOutcome {
    /// Returns the matching or inserted index.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Found { index } | Self::Inserted { index } => index,
        }
    }

    /// Returns whether the operation appended a new element.
    #[must_use]
    pub const fn inserted(self) -> bool {
        matches!(self, Self::Inserted { .. })
    }

    /// Returns whether an equal element was already present.
    #[must_use]
    pub const fn found(self) -> bool {
        matches!(self, Self::Found { .. })
    }
}

/// An allocation failure together with the value which was not inserted.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct InsertError<T> {
    value: T,
    error: alloc::collections::TryReserveError,
}

#[cfg(feature = "alloc")]
impl<T> InsertError<T> {
    /// Returns the uninserted value, consuming the error.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Returns the allocator's typed reserve failure.
    #[must_use]
    pub fn error(&self) -> &alloc::collections::TryReserveError {
        &self.error
    }
}

/// A zero-sized namespace for unstable sorting with explicit callback state.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CallbackSort;

impl CallbackSort {
    /// Sorts `values` in place with an explicit mutable comparator context.
    ///
    /// The ordering is intentionally unstable, matching the useful contract
    /// of `qsort_r`: equal elements have no preserved relative-order promise.
    pub fn unstable<T, Context, F>(values: &mut [T], context: &mut Context, mut compare: F)
    where
        F: FnMut(&mut Context, &T, &T) -> Ordering,
    {
        values.sort_unstable_by(|left, right| compare(context, left, right));
    }

    /// Descriptive alias for [`Self::unstable`].
    pub fn sort_unstable_with<T, Context, F>(values: &mut [T], context: &mut Context, compare: F)
    where
        F: FnMut(&mut Context, &T, &T) -> Ordering,
    {
        Self::unstable(values, context, compare);
    }

    /// Standard-library-shaped spelling for context-aware unstable sorting.
    pub fn sort_unstable<T, Context, F>(values: &mut [T], context: &mut Context, compare: F)
    where
        F: FnMut(&mut Context, &T, &T) -> Ordering,
    {
        Self::unstable(values, context, compare);
    }

    /// Alias using the standard slice operation's naming.
    pub fn sort_unstable_by_context<T, Context, F>(
        values: &mut [T],
        context: &mut Context,
        compare: F,
    ) where
        F: FnMut(&mut Context, &T, &T) -> Ordering,
    {
        Self::unstable(values, context, compare);
    }
}

/// Free-function spelling for context-aware unstable sorting.
pub fn sort_unstable_with_context<T, Context, F>(
    values: &mut [T],
    context: &mut Context,
    compare: F,
) where
    F: FnMut(&mut Context, &T, &T) -> Ordering,
{
    CallbackSort::unstable(values, context, compare);
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use super::{CallbackSort, Search};

    #[test]
    fn binary_and_linear_search_keep_comparator_order_explicit() {
        let values = [1, 3, 5, 7, 9];
        assert_eq!(
            Search::binary(&values, &5, |left, right| left.cmp(right)),
            Some(2)
        );
        assert_eq!(
            Search::linear(&values, &7, |left, right| left.cmp(right)),
            Some(3)
        );
        assert_eq!(
            Search::bsearch(&values, &4, |left, right| left.cmp(right)),
            None
        );
    }

    #[test]
    fn context_sort_can_change_comparison_without_global_state() {
        let mut values = [1, 4, 2, 3];
        let mut descending = true;
        CallbackSort::unstable(&mut values, &mut descending, |reverse, left, right| {
            if *reverse {
                right.cmp(left)
            } else {
                left.cmp(right)
            }
        });
        assert_eq!(values, [4, 3, 2, 1]);
        descending = false;
        CallbackSort::unstable(&mut values, &mut descending, |reverse, left, right| {
            if *reverse {
                right.cmp(left)
            } else {
                left.cmp(right)
            }
        });
        assert_eq!(values, [1, 2, 3, 4]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn try_insert_reports_found_or_inserted_without_duplicate_values() {
        let mut values = alloc::vec![2, 4];
        let result = Search::try_insert(&mut values, 3, |left, right| left.cmp(right)).unwrap();
        assert_eq!(result.index(), 2);
        assert!(result.inserted());
        let found = Search::try_lsearch(&mut values, 3, |left, right| left.cmp(right)).unwrap();
        assert_eq!(found.index(), 2);
        assert!(found.found());
        assert_eq!(values, [2, 4, 3]);
    }

    #[test]
    fn comparator_context_can_accumulate_observations() {
        let mut values = [3, 1, 2];
        let mut calls = 0usize;
        CallbackSort::unstable(&mut values, &mut calls, |calls, left, right| {
            *calls += 1;
            left.cmp(right)
        });
        assert!(calls > 0);
        assert_eq!(values, [1, 2, 3]);
        assert_eq!(Ordering::Less, 1.cmp(&2));
    }
}
