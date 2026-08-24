// Copyright (c) 2019-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/threadlocal.c:18-315` and
// `include/mimalloc/prim-tls.h:41-50,193-229`. This first slice preserves
// the AArch64 key encoding and caller-owned slot semantics only. The source's
// global free-index bitmap, lock, metadata allocation, compiler TLS access,
// process initialization, and thread teardown remain separate lifecycle work.

//! Dynamic versioned-thread-local slot substrate.

/// The low key-field width used by pinned mimalloc on 64-bit targets.
///
/// The sole production target is AArch64, so a key is one 64-bit word with a
/// 16-bit index and a 48-bit version. This is an encoding fact, not a chosen
/// limit for a future registry's metadata allocation strategy.
const TLS_INDEX_BITS: u32 = 16;
const TLS_VERSION_BITS: u32 = 64 - TLS_INDEX_BITS;
const TLS_INDEX_MASK: u64 = (1_u64 << TLS_INDEX_BITS) - 1;
const TLS_VERSION_MAX: u64 = (1_u64 << TLS_VERSION_BITS) - 1;

const _: [(); 64] = [(); usize::BITS as usize];

/// A slot index that can be represented in a pinned AArch64 TLS key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadLocalSlotIndex(u16);

impl ThreadLocalSlotIndex {
    /// Validates an index before it is packed into the low 16 key bits.
    #[inline]
    pub(crate) const fn new(index: usize) -> Option<Self> {
        if index <= TLS_INDEX_MASK as usize {
            Some(Self(index as u16))
        } else {
            None
        }
    }

    /// Returns the index used to address caller-owned slot storage.
    #[inline]
    pub(crate) const fn get(self) -> usize {
        self.0 as usize
    }
}

/// A dynamic TLS key with one index field and one reuse-generation field.
///
/// Key value zero is impossible: version zero is reserved to make an empty
/// caller-owned [`ThreadLocalSlot`] reject every valid key. The source key
/// constructor accepts the complete nonzero 48-bit range; only a registry
/// claim advances versions according to the source's wrap rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadLocalKey(u64);

impl ThreadLocalKey {
    /// Forms one key from a representable slot index and a nonzero version.
    #[inline]
    pub(crate) const fn from_parts(index: ThreadLocalSlotIndex, version: u64) -> Option<Self> {
        if version == 0 || version > TLS_VERSION_MAX {
            return None;
        }

        Some(Self((version << TLS_INDEX_BITS) | index.get() as u64))
    }

    /// Returns the source-compatible packed 64-bit representation.
    #[inline]
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the low 16-bit caller-owned slot index.
    #[inline]
    pub(crate) const fn index(self) -> ThreadLocalSlotIndex {
        ThreadLocalSlotIndex((self.0 & TLS_INDEX_MASK) as u16)
    }

    /// Returns the high 48-bit reuse generation.
    #[inline]
    pub(crate) const fn version(self) -> u64 {
        self.0 >> TLS_INDEX_BITS
    }
}

/// Source-compatible version state for a future global key registry.
///
/// The registry must hold its own private lock, choose a currently free index,
/// and invoke [`Self::claim`] while holding that lock. This type intentionally
/// does not contain the source's global free-index bitmap or allocate its
/// 1024-bit metadata growth: both require allocator-metadata ownership that
/// this no-`alloc` slice does not have. It exists so that future growth can
/// retain the exact generation transition rather than inventing one.
pub(crate) struct ThreadLocalKeyVersions {
    last_claimed: u64,
}

impl ThreadLocalKeyVersions {
    /// Creates the source's initially zero global version state.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self { last_claimed: 0 }
    }

    /// Issues the next generation for one index selected by the registry.
    ///
    /// This is exactly `src/threadlocal.c:249-256`: increment first, then
    /// replace a value greater than or equal to the 48-bit maximum with one.
    /// Version zero therefore remains reserved. As in the source, the maximum
    /// encodable version can be decoded and constructed but is not issued by
    /// this advancement path.
    #[inline]
    pub(crate) fn claim(&mut self, index: ThreadLocalSlotIndex) -> ThreadLocalKey {
        self.last_claimed += 1;
        if self.last_claimed >= TLS_VERSION_MAX {
            self.last_claimed = 1;
        }

        // `last_claimed` is initialized to zero and the source transition
        // above keeps it in 1..TLS_VERSION_MAX, so this cannot fail.
        match ThreadLocalKey::from_parts(index, self.last_claimed) {
            Some(key) => key,
            None => unreachable!("the source version transition always forms a valid key"),
        }
    }
}

/// One caller-owned per-thread dynamic-TLS slot.
///
/// This mirrors the source's `(version, value)` pair. It is not compiler TLS:
/// the integrating thread/runtime retains its backing storage, presents it to
/// [`ThreadLocalSlots`], and owns its allocation and teardown.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ThreadLocalSlot {
    version: u64,
    value: *mut (),
}

impl ThreadLocalSlot {
    /// The source's all-zero initial slot image.
    pub(crate) const EMPTY: Self = Self {
        version: 0,
        value: core::ptr::null_mut(),
    };
}

/// A caller-owned per-thread view of dynamic TLS slot storage.
///
/// The caller must retain exclusive mutable access while using this view.
/// Cross-thread synchronization, compiler TLS access, storage allocation, and
/// thread teardown remain outside this type. A failed non-null set names the
/// exact index whose backing storage must be provided before retrying.
pub(crate) struct ThreadLocalSlots<'slots> {
    slots: &'slots mut [ThreadLocalSlot],
}

/// The caller must grow its per-thread backing storage before retrying a set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadLocalSlotExpansion {
    least_index: ThreadLocalSlotIndex,
}

impl ThreadLocalSlotExpansion {
    /// The least caller-owned slot count needed to address the pending key.
    #[inline]
    pub(crate) const fn required_slot_count(self) -> usize {
        self.least_index.get() + 1
    }

    /// The key index that triggered the storage-growth request.
    #[inline]
    pub(crate) const fn least_index(self) -> ThreadLocalSlotIndex {
        self.least_index
    }
}

impl ThreadLocalSlots<'_> {
    /// Binds an existing per-thread slot slice without allocating or
    /// installing compiler TLS state.
    #[inline]
    pub(crate) fn new(slots: &mut [ThreadLocalSlot]) -> ThreadLocalSlots<'_> {
        ThreadLocalSlots { slots }
    }

    /// Looks up one value only when its slot contains the key's generation.
    ///
    /// A missing slot, an uninitialized slot, and a stale generation all
    /// return null, exactly matching `_mi_thread_local_get`'s regular path.
    #[inline]
    pub(crate) fn get(&self, key: ThreadLocalKey) -> *mut () {
        match self.slots.get(key.index().get()) {
            Some(slot) if slot.version == key.version() => slot.value,
            Some(_) | None => core::ptr::null_mut(),
        }
    }

    /// Writes a value and generation into caller-owned storage.
    ///
    /// An out-of-range null write succeeds without growing storage, matching
    /// `mi_thread_local_set_expand`'s early null return. A non-null write
    /// reports the exact missing capacity instead of allocating: later
    /// allocator-metadata-backed per-thread growth owns the source's
    /// reallocation policy and may retry this operation after replacing its
    /// caller-owned backing storage.
    #[inline]
    pub(crate) fn set(
        &mut self,
        key: ThreadLocalKey,
        value: *mut (),
    ) -> Result<(), ThreadLocalSlotExpansion> {
        match self.slots.get_mut(key.index().get()) {
            Some(slot) => {
                slot.value = value;
                slot.version = key.version();
                Ok(())
            }
            None if value.is_null() => Ok(()),
            None => Err(ThreadLocalSlotExpansion {
                least_index: key.index(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_index_rejects_the_previous_generation_until_rewritten() {
        let index = ThreadLocalSlotIndex::new(2).expect("the index fits the AArch64 key field");
        let mut versions = ThreadLocalKeyVersions::new();
        let old_key = versions.claim(index);
        let replacement_key = versions.claim(index);
        let mut backing = [ThreadLocalSlot::EMPTY; 4];
        let mut slots = ThreadLocalSlots::new(&mut backing);
        let mut old_payload = 0x1111usize;
        let mut replacement_payload = 0x2222usize;
        let old_value = (&mut old_payload as *mut usize).cast();
        let replacement_value = (&mut replacement_payload as *mut usize).cast();

        slots
            .set(old_key, old_value)
            .expect("the supplied caller storage covers the key");
        assert_eq!(slots.get(old_key), old_value);

        assert_eq!(
            slots.get(replacement_key),
            core::ptr::null_mut(),
            "a reused index must not expose the previous key generation's value"
        );
        slots
            .set(replacement_key, replacement_value)
            .expect("the replacement generation uses the same caller slot");
        assert_eq!(slots.get(old_key), core::ptr::null_mut());
        assert_eq!(slots.get(replacement_key), replacement_value);
    }

    #[test]
    fn packed_key_uses_the_complete_aarch64_16_bit_index_and_48_bit_version_fields() {
        let first_index = ThreadLocalSlotIndex::new(0).expect("zero is a valid index");
        let first = ThreadLocalKey::from_parts(first_index, 1).expect("one is the first valid version");
        assert_eq!(first.raw(), 1_u64 << TLS_INDEX_BITS);
        assert_eq!(first.index(), first_index);
        assert_eq!(first.version(), 1);

        let final_index = ThreadLocalSlotIndex::new(TLS_INDEX_MASK as usize)
            .expect("the complete 16-bit index field is valid");
        let final_key = ThreadLocalKey::from_parts(final_index, TLS_VERSION_MAX)
            .expect("the complete nonzero 48-bit version field decodes");
        assert_eq!(final_key.raw(), u64::MAX);
        assert_eq!(final_key.index(), final_index);
        assert_eq!(final_key.version(), TLS_VERSION_MAX);

        assert!(ThreadLocalKey::from_parts(first_index, 0).is_none());
        assert!(ThreadLocalSlotIndex::new(TLS_INDEX_MASK as usize + 1).is_none());
    }

    #[test]
    fn source_version_wrap_reserves_zero_and_restarts_at_one() {
        let index = ThreadLocalSlotIndex::new(7).expect("the index is representable");
        let mut versions = ThreadLocalKeyVersions {
            last_claimed: TLS_VERSION_MAX - 1,
        };

        let wrapped = versions.claim(index);
        assert_eq!(wrapped.version(), 1);
        assert_eq!(wrapped.raw(), (1_u64 << TLS_INDEX_BITS) | index.get() as u64);

        let following = versions.claim(index);
        assert_eq!(following.version(), 2);
        assert_ne!(following, wrapped);
    }

    #[test]
    fn out_of_range_null_set_needs_no_storage_but_nonnull_set_reports_the_exact_retry_capacity() {
        let index = ThreadLocalSlotIndex::new(6).expect("the index is representable");
        let key = ThreadLocalKey::from_parts(index, 1).expect("the key is valid");
        let mut backing = [ThreadLocalSlot::EMPTY; 2];
        let mut slots = ThreadLocalSlots::new(&mut backing);
        let mut payload = 0xfeed_faceusize;
        let value = (&mut payload as *mut usize).cast();

        assert_eq!(slots.set(key, core::ptr::null_mut()), Ok(()));
        assert_eq!(slots.get(key), core::ptr::null_mut());

        let expansion = slots
            .set(key, value)
            .expect_err("the caller must provide backing storage for a non-null value");
        assert_eq!(expansion.least_index(), index);
        assert_eq!(expansion.required_slot_count(), 7);
        assert_eq!(slots.get(key), core::ptr::null_mut());
    }
}
