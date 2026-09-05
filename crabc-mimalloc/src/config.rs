// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
//
// Copyright (c) 2019-2024 Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `include/mimalloc/types.h:37-250,
// 463-492,545-557,612,716-718` (normal-release constants),
// `include/mimalloc/bits.h:33-145` and
// `include/mimalloc/internal.h:717-719` (word and two-level page-map
// constants), `src/bitmap.h:94-105` (bitmap-bounded arena constants), and
// `CMakeLists.txt:7-24,161-192,280-340,361-454,647-693,769-774` (selected
// normal-release switches and the deliberately excluded Armv8.3-a path).
// The selected M1 branch is LP64, little-endian Linux/AArch64 normal release:
// debug, secure, guarded, padding, tracking, checked-free, free-small, flat
// page-map, and SIMD branches are all inactive; separate page metadata and
// large pages are active. `MI_ARENA_SLICE_SHIFT` and
// `MI_BCHUNK_BITS_SHIFT` are C/Rust checked as the actual selected macros, not
// re-derived formulas. The C oracle deliberately keeps the project Armv8.0
// baseline instead of CMake's optional Armv8.3-a path. This module is not a
// runtime configuration mechanism or a port of unselected CMake modes.

pub(crate) const WORD_SIZE: usize = core::mem::size_of::<usize>();
pub(crate) const KIB: usize = 1024;
pub(crate) const MIB: usize = KIB * KIB;
pub(crate) const GIB: usize = MIB * KIB;

pub(crate) const MAX_ALIGN_SIZE: usize = 16;

/// The fixed source temporary used by `mi_option_init`.
///
/// `src/options.c:625-646` accepts at most 64 value bytes plus the trailing
/// NUL copied by `_mi_prim_getenv`.  Keeping the bound here lets the real
/// process-start reader retain the same `EAGAIN`/retry distinction for a
/// truncated environment value without allocating or calling libc.
const SOURCE_OPTION_VALUE_BYTES: usize = 64;
const SOURCE_ENVIRONMENT_ENTRY_LIMIT: usize = 10_000;

// `CMakeLists.txt` Release defaults plus `types.h` defaults. An unset C
// preprocessor option evaluates to zero in the upstream `#if` expressions.
pub(crate) const SECURE_LEVEL: usize = 0;
pub(crate) const DEBUG_LEVEL: usize = 0;
pub(crate) const STAT_LEVEL: usize = 0;
pub(crate) const FREE_IS_CHECKED: bool = false;
pub(crate) const FREE_USE_PAGEMAP: bool = false;
pub(crate) const OPT_FREE_SMALL: bool = false;
pub(crate) const ENABLE_LARGE_PAGES: bool = true;
pub(crate) const ENCODE_FREELIST: bool = false;
pub(crate) const GUARDED: bool = false;
pub(crate) const OPT_SIMD: bool = false;
pub(crate) const PADDING_SIZE: usize = 0;
pub(crate) const PADDING_WSIZE: usize = 0;
pub(crate) const PAGE_KEY_COUNT: usize = 1;

pub(crate) const ARENA_SLICE_SHIFT: usize = 13 + 3;
pub(crate) const BCHUNK_BITS_SHIFT: usize = 6 + 3;
pub(crate) const BCHUNK_BITS: usize = 1 << BCHUNK_BITS_SHIFT;
pub(crate) const ARENA_SLICE_SIZE: usize = 1 << ARENA_SLICE_SHIFT;
pub(crate) const ARENA_SLICE_ALIGN: usize = ARENA_SLICE_SIZE;
pub(crate) const ARENA_CHUNK_SIZE: usize = BCHUNK_BITS * ARENA_SLICE_SIZE;

pub(crate) const ARENA_MIN_OBJ_SLICES: usize = 1;
pub(crate) const ARENA_MAX_CHUNK_OBJ_SLICES: usize = BCHUNK_BITS;
pub(crate) const ARENA_MIN_OBJ_SIZE: usize = ARENA_MIN_OBJ_SLICES * ARENA_SLICE_SIZE;
pub(crate) const ARENA_MAX_CHUNK_OBJ_SIZE: usize = ARENA_MAX_CHUNK_OBJ_SLICES * ARENA_SLICE_SIZE;

pub(crate) const SMALL_PAGE_SIZE: usize = ARENA_MIN_OBJ_SIZE;
pub(crate) const MEDIUM_PAGE_SIZE: usize = 8 * SMALL_PAGE_SIZE;
pub(crate) const LARGE_PAGE_SIZE: usize = WORD_SIZE * MEDIUM_PAGE_SIZE;

pub(crate) const BIN_HUGE: usize = 73;
pub(crate) const BIN_FULL: usize = BIN_HUGE + 1;
pub(crate) const BIN_COUNT: usize = BIN_FULL + 1;
pub(crate) const MAX_ALLOC_SIZE: usize = isize::MAX as usize;
pub(crate) const PAGE_MIN_COMMIT_SIZE: usize = 16 * KIB;

pub(crate) const PAGE_META_IS_SEPARATED: bool = true;
pub(crate) const PAGE_META_IS_ALIGNED: bool = true;
pub(crate) const PAGE_META_ALIGNED_CHUNKS: usize = WORD_SIZE;
pub(crate) const PAGE_META_ALIGNED_COUNT: usize = PAGE_META_ALIGNED_CHUNKS * BCHUNK_BITS;
pub(crate) const PAGE_META_ALIGNMENT: usize = PAGE_META_ALIGNED_COUNT * ARENA_SLICE_SIZE;
pub(crate) const ARENA_ALIGNMENT: usize = PAGE_META_ALIGNMENT;

pub(crate) const PAGE_ALIGN: usize = ARENA_SLICE_ALIGN;
pub(crate) const PAGE_MIN_START_BLOCK_ALIGN: usize = MAX_ALIGN_SIZE;
pub(crate) const PAGE_MAX_START_BLOCK_ALIGN2: usize = 4 * KIB;
pub(crate) const PAGE_OSPAGE_BLOCK_ALIGN2: usize = 4 * KIB;
pub(crate) const PAGE_MAX_OVERALLOC_ALIGN: usize = ARENA_SLICE_SIZE;

pub(crate) const SMALL_WSIZE_MAX: usize = 128;
pub(crate) const SMALL_SIZE_MAX: usize = SMALL_WSIZE_MAX * WORD_SIZE;
pub(crate) const SMALL_MAX_OBJ_SIZE: usize = (SMALL_PAGE_SIZE - PAGE_OSPAGE_BLOCK_ALIGN2) / 6;
pub(crate) const MEDIUM_MAX_OBJ_SIZE: usize = (MEDIUM_PAGE_SIZE - PAGE_OSPAGE_BLOCK_ALIGN2) / 6;
pub(crate) const LARGE_MAX_OBJ_SIZE: usize = LARGE_PAGE_SIZE / 8;
pub(crate) const LARGE_MAX_OBJ_WSIZE: usize = LARGE_MAX_OBJ_SIZE / WORD_SIZE;
pub(crate) const MAX_SINGLETON_BIN: usize = 60;

pub(crate) const PAGES_DIRECT: usize = SMALL_WSIZE_MAX + PADDING_WSIZE + 1;
pub(crate) const MAX_ARENAS: usize = 160;
pub(crate) const ARENA_BIN_COUNT: usize = MAX_SINGLETON_BIN + 1;
pub(crate) const BITMAP_MAX_BIT_COUNT: usize = BCHUNK_BITS * BCHUNK_BITS;
pub(crate) const ARENA_MIN_SIZE: usize = BCHUNK_BITS * ARENA_SLICE_SIZE;
pub(crate) const ARENA_MAX_SIZE: usize = BITMAP_MAX_BIT_COUNT * ARENA_SLICE_SIZE;

// `bits.h` selects 48 virtual-address bits for AArch64 and 47 for x86-64;
// `internal.h` uses the two-level map when page metadata is separated.
#[cfg(target_arch = "aarch64")]
pub(crate) const MAX_VABITS: usize = 48;
#[cfg(target_arch = "x86_64")]
pub(crate) const MAX_VABITS: usize = 47;
pub(crate) const MIN_VABITS: usize = 43;
pub(crate) const PAGE_MAP_FLAT: bool = false;
pub(crate) const PAGE_MAP_SUB_SHIFT: usize = 13;
pub(crate) const PAGE_MAP_SUB_COUNT: usize = 1 << PAGE_MAP_SUB_SHIFT;
pub(crate) const PAGE_MAP_SHIFT: usize = MAX_VABITS - PAGE_MAP_SUB_SHIFT - ARENA_SLICE_SHIFT;

/// The VM-affecting subset of pinned `src/options.c` descriptors.
///
/// These are not a new allocator configuration language.  They retain the
/// source descriptors that `src/os.c` observes, including their individual
/// default values and lazy `UNINIT -> DEFAULTED | INITIALIZED` transition.
/// A process-start owner must supply the environment observation: this
/// allocation-free crate deliberately has no ambient `environ` reader.
#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VmOption {
    PurgeDecommits = 0,
    AllowLargeOsPages = 1,
    ReserveHugeOsPages = 2,
    ReserveHugeOsPagesAt = 3,
    PurgeDelay = 4,
    UseNumaNodes = 5,
    AllowThp = 6,
    ArenaEagerCommit = 7,
    ArenaReserve = 8,
    ArenaPurgeMult = 9,
    ArenaMaxObjectSize = 10,
    DisallowArenaAlloc = 11,
    DisallowOsAlloc = 12,
    PageCommitOnDemand = 13,
    ArenaIsNumaLocal = 14,
    MinimalPurgeSize = 15,
}

impl VmOption {
    pub(crate) const ALL: [Self; 16] = [
        // Keep the selected descriptors in their `src/options.c:111-177`
        // order.  The source initializes every descriptor in declaration
        // order at process start; the omitted non-VM descriptors stay outside
        // this bounded process-policy owner rather than being silently
        // reordered around it.
        Self::ArenaEagerCommit,
        Self::PurgeDecommits,
        Self::AllowLargeOsPages,
        Self::ReserveHugeOsPages,
        Self::ReserveHugeOsPagesAt,
        Self::PurgeDelay,
        Self::UseNumaNodes,
        Self::DisallowOsAlloc,
        Self::ArenaReserve,
        Self::ArenaPurgeMult,
        Self::DisallowArenaAlloc,
        Self::PageCommitOnDemand,
        Self::AllowThp,
        Self::MinimalPurgeSize,
        Self::ArenaMaxObjectSize,
        Self::ArenaIsNumaLocal,
    ];

    /// The source descriptor name without its `mimalloc_` environment prefix.
    #[inline]
    const fn source_name(self) -> &'static [u8] {
        match self {
            Self::PurgeDecommits => b"purge_decommits",
            Self::AllowLargeOsPages => b"allow_large_os_pages",
            Self::ReserveHugeOsPages => b"reserve_huge_os_pages",
            Self::ReserveHugeOsPagesAt => b"reserve_huge_os_pages_at",
            Self::PurgeDelay => b"purge_delay",
            Self::UseNumaNodes => b"use_numa_nodes",
            Self::AllowThp => b"allow_thp",
            Self::ArenaEagerCommit => b"arena_eager_commit",
            Self::ArenaReserve => b"arena_reserve",
            Self::ArenaPurgeMult => b"arena_purge_mult",
            Self::ArenaMaxObjectSize => b"arena_max_object_size",
            Self::DisallowArenaAlloc => b"disallow_arena_alloc",
            Self::DisallowOsAlloc => b"disallow_os_alloc",
            Self::PageCommitOnDemand => b"page_commit_on_demand",
            Self::ArenaIsNumaLocal => b"arena_is_numa_local",
            Self::MinimalPurgeSize => b"minimal_purge_size",
        }
    }

    /// The deprecated source descriptor name, if this selected descriptor has
    /// one.  It is queried only when the canonical spelling is absent.
    #[inline]
    const fn legacy_source_name(self) -> Option<&'static [u8]> {
        match self {
            Self::PurgeDecommits => Some(b"reset_decommits"),
            Self::AllowLargeOsPages => Some(b"large_os_pages"),
            Self::PurgeDelay => Some(b"reset_delay"),
            Self::ArenaEagerCommit => Some(b"eager_region_commit"),
            Self::DisallowOsAlloc => Some(b"limit_os_alloc"),
            Self::ReserveHugeOsPages
            | Self::ReserveHugeOsPagesAt
            | Self::UseNumaNodes
            | Self::AllowThp
            | Self::ArenaReserve
            | Self::ArenaPurgeMult
            | Self::ArenaMaxObjectSize
            | Self::DisallowArenaAlloc
            | Self::PageCommitOnDemand
            | Self::ArenaIsNumaLocal
            | Self::MinimalPurgeSize => None,
        }
    }

    #[inline]
    const fn default_value(self) -> i64 {
        match self {
            // `src/options.c:112-114`.
            Self::PurgeDecommits => 1,
            // `MI_DEFAULT_ALLOW_LARGE_OS_PAGES` and
            // `MI_DEFAULT_RESERVE_HUGE_OS_PAGES` on normal Linux.
            Self::AllowLargeOsPages | Self::ReserveHugeOsPages => 0,
            // `src/options.c:117`.
            Self::ReserveHugeOsPagesAt => -1,
            // `src/options.c:122`.
            Self::PurgeDelay => 1_000,
            // `src/options.c:123`.
            Self::UseNumaNodes => 0,
            // `MI_DEFAULT_ALLOW_THP` on non-Android Linux.
            Self::AllowThp => 1,
            // `MI_DEFAULT_ARENA_EAGER_COMMIT` in `src/options.c:46-48`.
            Self::ArenaEagerCommit => 2,
            // `MI_DEFAULT_ARENA_RESERVE` is expressed in KiB.
            Self::ArenaReserve => 1024 * 1024,
            // `src/options.c:149` applies this source multiplier to the
            // configured arena purge delay.
            Self::ArenaPurgeMult => 4,
            // `MI_SIZE_BITS * MI_ARENA_MAX_CHUNK_OBJ_SIZE / MI_KiB`:
            // `(64 * 32 MiB) / KiB == 2 GiB`, stored in KiB.
            Self::ArenaMaxObjectSize => 2 * 1024 * 1024,
            // `src/options.c:143,151,168,177`.
            Self::DisallowArenaAlloc
            | Self::DisallowOsAlloc
            | Self::PageCommitOnDemand
            | Self::ArenaIsNumaLocal => 0,
            // `src/options.c:174`, expressed in KiB like the two arena-size
            // descriptors.
            Self::MinimalPurgeSize => 0,
        }
    }

    #[inline]
    const fn has_size_in_kib(self) -> bool {
        matches!(
            self,
            Self::ArenaReserve | Self::ArenaMaxObjectSize | Self::MinimalPurgeSize
        )
    }
}

/// The source state of one lazy option descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VmOptionState {
    /// No environment observation has completed; upstream retries on a later
    /// `mi_option_get` when `getenv` was temporarily unavailable.
    Uninitialized,
    /// Environment was absent or malformed, so the pinned descriptor value is
    /// retained without a programmatic mutation.
    Defaulted,
    /// A valid environment value or `mi_option_set` supplied this descriptor.
    Initialized,
}

/// One process-owner observation for a lazy VM option.
///
/// `Unavailable` is distinct from `Absent`: the former leaves the descriptor
/// uninitialized so a later source lookup may retry, while the latter records
/// the source's `ENOENT -> DEFAULTED` transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VmOptionEnvironment<'a> {
    Absent,
    Value(&'a [u8]),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VmOptionSlot {
    value: i64,
    state: VmOptionState,
}

impl VmOptionSlot {
    const fn new(value: i64) -> Self {
        Self {
            value,
            state: VmOptionState::Uninitialized,
        }
    }
}

/// Allocation-free VM option descriptors with the source's lazy timing.
///
/// This value deliberately has no global instance.  A future process-start
/// owner must retain it, provide bounded environment observations, and decide
/// when all descriptors are ready before constructing [`crate::os::VmPolicy`].
/// Keeping that owner explicit prevents tests or a second linked allocator
/// copy from silently changing process policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VmOptions {
    slots: [VmOptionSlot; 16],
}

impl VmOptions {
    /// Constructs the exact uninitialized source descriptor image.
    #[inline]
    pub(crate) const fn uninitialized() -> Self {
        Self {
            slots: [
                VmOptionSlot::new(VmOption::PurgeDecommits.default_value()),
                VmOptionSlot::new(VmOption::AllowLargeOsPages.default_value()),
                VmOptionSlot::new(VmOption::ReserveHugeOsPages.default_value()),
                VmOptionSlot::new(VmOption::ReserveHugeOsPagesAt.default_value()),
                VmOptionSlot::new(VmOption::PurgeDelay.default_value()),
                VmOptionSlot::new(VmOption::UseNumaNodes.default_value()),
                VmOptionSlot::new(VmOption::AllowThp.default_value()),
                VmOptionSlot::new(VmOption::ArenaEagerCommit.default_value()),
                VmOptionSlot::new(VmOption::ArenaReserve.default_value()),
                VmOptionSlot::new(VmOption::ArenaPurgeMult.default_value()),
                VmOptionSlot::new(VmOption::ArenaMaxObjectSize.default_value()),
                VmOptionSlot::new(VmOption::DisallowArenaAlloc.default_value()),
                VmOptionSlot::new(VmOption::DisallowOsAlloc.default_value()),
                VmOptionSlot::new(VmOption::PageCommitOnDemand.default_value()),
                VmOptionSlot::new(VmOption::ArenaIsNumaLocal.default_value()),
                VmOptionSlot::new(VmOption::MinimalPurgeSize.default_value()),
            ],
        }
    }

    /// Initializes every VM descriptor once, like `_mi_options_init`.
    ///
    /// The callback is the process owner's bounded replacement for the C
    /// `getenv` call. It is invoked only for still-uninitialized descriptors,
    /// preserving both source retry and source programmatic-set timing.
    pub(crate) fn initialize_all<'environment>(
        &mut self,
        mut environment: impl FnMut(VmOption) -> VmOptionEnvironment<'environment>,
    ) {
        for option in VmOption::ALL {
            // The source iterates descriptors but only calls `mi_option_init`
            // for an `UNINIT` entry. Do not even observe the environment for
            // a source-set/defaulted slot: an observation can be fallible and
            // must not become an unowned side effect after its descriptor is
            // already terminal.
            if self.state(option) == VmOptionState::Uninitialized {
                self.initialize_one(option, environment(option));
            }
        }
    }

    /// Resolves this selected source-option image directly from the Unix
    /// process environment.
    ///
    /// This is the allocation-free `MI_USE_ENVIRON` path from pinned
    /// `src/prim/unix/prim.c:874-905`, followed by the canonical/legacy
    /// lookup ordering in `src/options.c:624-646`.  It reads no libc helper:
    /// process startup owns the supplied environment-vector lifetime and
    /// invokes this before constructors can mutate it.  A null vector or an
    /// overlong selected value maps to `Unavailable`, leaving exactly that
    /// descriptor lazy-uninitialized for a later source attempt.
    ///
    /// # Safety
    ///
    /// `environment` must be null or point to a NUL-terminated pointer vector
    /// whose non-null entries are valid NUL-terminated C strings for every
    /// byte observed here.  The caller must keep that vector and its strings
    /// stable for this call, and must coordinate direct environment mutation.
    /// Those are the same raw `environ` obligations as the pinned C primitive.
    pub(crate) unsafe fn initialize_from_source_environment(
        &mut self,
        environment: *const *const core::ffi::c_char,
    ) {
        let mut value = [0u8; SOURCE_OPTION_VALUE_BYTES + 1];
        for option in VmOption::ALL {
            if self.state(option) != VmOptionState::Uninitialized {
                continue;
            }
            let observation = unsafe {
                source_environment_option(
                    environment,
                    option.source_name(),
                    option.legacy_source_name(),
                    &mut value,
                )
            };
            self.initialize_one(option, observation);
        }
    }

    /// Performs one source lazy initialization attempt.
    pub(crate) fn initialize_one(&mut self, option: VmOption, environment: VmOptionEnvironment<'_>) {
        let slot = &mut self.slots[option as usize];
        if slot.state != VmOptionState::Uninitialized {
            return;
        }
        match environment {
            VmOptionEnvironment::Unavailable => {}
            VmOptionEnvironment::Absent => slot.state = VmOptionState::Defaulted,
            VmOptionEnvironment::Value(value) => match parse_source_option_value(option, value) {
                Some(value) => {
                    slot.value = value;
                    slot.state = VmOptionState::Initialized;
                }
                None => slot.state = VmOptionState::Defaulted,
            },
        }
    }

    /// Mirrors `mi_option_set`: replace the value and prevent lazy lookup.
    #[inline]
    pub(crate) fn set(&mut self, option: VmOption, value: i64) {
        self.slots[option as usize] = VmOptionSlot {
            value,
            state: VmOptionState::Initialized,
        };
    }

    /// Mirrors `mi_option_set_default`: an explicit source set wins, while an
    /// uninitialized/defaulted descriptor keeps its lazy-state marker.
    #[inline]
    pub(crate) fn set_default(&mut self, option: VmOption, value: i64) {
        let slot = &mut self.slots[option as usize];
        if slot.state != VmOptionState::Initialized {
            slot.value = value;
        }
    }

    #[inline]
    pub(crate) const fn state(&self, option: VmOption) -> VmOptionState {
        self.slots[option as usize].state
    }

    /// Returns a resolved source value, rejecting a descriptor whose source
    /// environment lookup may still be retried.
    #[inline]
    pub(crate) const fn value(&self, option: VmOption) -> Option<i64> {
        let slot = self.slots[option as usize];
        match slot.state {
            VmOptionState::Uninitialized => None,
            VmOptionState::Defaulted | VmOptionState::Initialized => Some(slot.value),
        }
    }

    #[inline]
    pub(crate) const fn all_resolved(&self) -> bool {
        let mut index = 0;
        while index < self.slots.len() {
            if matches!(self.slots[index].state, VmOptionState::Uninitialized) {
                return false;
            }
            index += 1;
        }
        true
    }
}

/// Resolve one source `mimalloc_<descriptor>` variable with its legacy
/// fallback.  A matching but overlong canonical value is an unavailable C
/// primitive result, not an absence that permits consulting the old spelling.
unsafe fn source_environment_option<'value>(
    environment: *const *const core::ffi::c_char,
    canonical_name: &[u8],
    legacy_name: Option<&[u8]>,
    value: &'value mut [u8; SOURCE_OPTION_VALUE_BYTES + 1],
) -> VmOptionEnvironment<'value> {
    let canonical = unsafe { source_environment_lookup(environment, canonical_name, value) };
    match canonical {
        SourceEnvironmentLookup::Absent => match legacy_name {
            Some(legacy_name) => match unsafe {
                source_environment_lookup(environment, legacy_name, value)
            } {
                SourceEnvironmentLookup::Absent => VmOptionEnvironment::Absent,
                SourceEnvironmentLookup::Value(length) => VmOptionEnvironment::Value(&value[..length]),
                SourceEnvironmentLookup::Unavailable => VmOptionEnvironment::Unavailable,
            },
            None => VmOptionEnvironment::Absent,
        },
        SourceEnvironmentLookup::Value(length) => VmOptionEnvironment::Value(&value[..length]),
        SourceEnvironmentLookup::Unavailable => VmOptionEnvironment::Unavailable,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceEnvironmentLookup {
    Absent,
    Value(usize),
    Unavailable,
}

/// The raw `environ` scan from `src/prim/unix/prim.c:_mi_prim_getenv`.
unsafe fn source_environment_lookup(
    environment: *const *const core::ffi::c_char,
    descriptor_name: &[u8],
    value: &mut [u8; SOURCE_OPTION_VALUE_BYTES + 1],
) -> SourceEnvironmentLookup {
    if environment.is_null() {
        return SourceEnvironmentLookup::Unavailable;
    }

    for entry_index in 0..SOURCE_ENVIRONMENT_ENTRY_LIMIT {
        // SAFETY: `initialize_from_source_environment` carries the exact
        // source `environ` vector validity and stability obligations.
        let entry = unsafe { core::ptr::read(environment.add(entry_index)) };
        if entry.is_null() {
            return SourceEnvironmentLookup::Absent;
        }
        if !unsafe { source_environment_name_matches(entry, descriptor_name) } {
            continue;
        }
        // SAFETY: a matching `name=` prefix remains inside the caller-owned
        // valid C string. The bounded copy below mirrors `_mi_strlcpy`.
        let entry_value = unsafe { entry.add(b"mimalloc_".len() + descriptor_name.len() + 1) };
        for value_index in 0..=SOURCE_OPTION_VALUE_BYTES {
            // SAFETY: the caller's C-string validity covers the byte read.
            let byte = unsafe { core::ptr::read(entry_value.add(value_index).cast::<u8>()) };
            if byte == 0 {
                return SourceEnvironmentLookup::Value(value_index);
            }
            if value_index == SOURCE_OPTION_VALUE_BYTES {
                return SourceEnvironmentLookup::Unavailable;
            }
            value[value_index] = byte;
        }
        unreachable!("the bounded source environment copy returns in-loop");
    }
    // `_mi_prim_getenv` scans at most 10,000 live entries. Reaching that
    // bound without a terminator is indistinguishable from source absence.
    SourceEnvironmentLookup::Absent
}

unsafe fn source_environment_name_matches(
    entry: *const core::ffi::c_char,
    descriptor_name: &[u8],
) -> bool {
    const PREFIX: &[u8] = b"mimalloc_";
    for (index, expected) in PREFIX.iter().chain(descriptor_name).enumerate() {
        // SAFETY: the caller owns the same C-string precondition as the
        // pinned `_mi_strnicmp` comparison through this bounded name length.
        let found = unsafe { core::ptr::read(entry.add(index).cast::<u8>()) };
        if !found.eq_ignore_ascii_case(expected) {
            return false;
        }
    }
    // SAFETY: the source reads precisely the byte after its compared name.
    unsafe {
        core::ptr::read(entry.add(PREFIX.len() + descriptor_name.len()).cast::<u8>()) == b'='
    }
}

/// Parses the value grammar used by `src/options.c:636-674` for the selected
/// VM and arena options. The C path uppercases its bounded temporary buffer,
/// treats an empty value as enabled, accepts four boolean spellings, and then
/// applies its `strtol` and (for named size options) KiB/suffix conversion.
fn parse_source_option_value(option: VmOption, input: &[u8]) -> Option<i64> {
    if input.is_empty() || ascii_eq_ignore_case(input, b"1") || ascii_eq_ignore_case(input, b"TRUE")
        || ascii_eq_ignore_case(input, b"YES") || ascii_eq_ignore_case(input, b"ON")
    {
        return Some(1);
    }
    if ascii_eq_ignore_case(input, b"0") || ascii_eq_ignore_case(input, b"FALSE")
        || ascii_eq_ignore_case(input, b"NO") || ascii_eq_ignore_case(input, b"OFF")
    {
        return Some(0);
    }

    let (parsed, mut index) = parse_source_decimal(input)?;
    if !option.has_size_in_kib() {
        return (index == input.len()).then_some(parsed);
    }

    // `mi_option_get_size` options first parse their signed source `long`,
    // then turn a negative input into zero before applying K/M/G/T suffixes.
    // A suffix-free number names bytes and rounds up to KiB; boolean spelling
    // above intentionally bypasses this conversion just as the C source does.
    let limit = MAX_ALLOC_SIZE / KIB;
    let mut size = if parsed < 0 { 0usize } else { usize::try_from(parsed).ok()? };
    let mut overflow = false;
    // `mi_option_get` uppercases its bounded source buffer before this size
    // conversion. Keep boolean and suffix parsing equally case-insensitive.
    let suffix = input
        .get(index)
        .copied()
        .map(|suffix| suffix.to_ascii_uppercase());
    match suffix {
        Some(b'K') => index += 1,
        Some(b'M') => {
            match size.checked_mul(KIB) {
                Some(product) => size = product,
                None => overflow = true,
            }
            index += 1;
        }
        Some(b'G') => {
            match size.checked_mul(MIB) {
                Some(product) => size = product,
                None => overflow = true,
            }
            index += 1;
        }
        Some(b'T') => {
            match size.checked_mul(GIB) {
                Some(product) => size = product,
                None => overflow = true,
            }
            index += 1;
        }
        _ => size = size.checked_add(KIB - 1)? / KIB,
    }
    if input
        .get(index..)
        .and_then(|tail| tail.get(..2))
        .is_some_and(|suffix| ascii_eq_ignore_case(suffix, b"IB"))
    {
        index += 2;
    } else if input
        .get(index)
        .copied()
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(&b'B'))
    {
        index += 1;
    }
    if index != input.len() {
        return None;
    }
    let size = if overflow || size > limit { limit } else { size };
    i64::try_from(size).ok()
}

fn parse_source_decimal(value: &[u8]) -> Option<(i64, usize)> {
    let mut index = 0;
    while index < value.len() && matches!(value[index], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        index += 1;
    }
    let negative = match value.get(index) {
        Some(b'+') => {
            index += 1;
            false
        }
        Some(b'-') => {
            index += 1;
            true
        }
        _ => false,
    };
    let digits_start = index;
    let mut magnitude = 0u64;
    while let Some(digit) = value.get(index).and_then(|byte| byte.checked_sub(b'0')) {
        if digit > 9 {
            break;
        }
        magnitude = magnitude.checked_mul(10)?.checked_add(u64::from(digit))?;
        index += 1;
    }
    if index == digits_start {
        return None;
    }
    let parsed = if negative {
        let minimum_magnitude = (i64::MAX as u64) + 1;
        if magnitude == minimum_magnitude {
            Some(i64::MIN)
        } else {
            i64::try_from(magnitude).ok().map(|value| -value)
        }
    } else {
        i64::try_from(magnitude).ok()
    }?;
    Some((parsed, index))
}

#[inline]
fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(&left, &right)| {
            let left = if left.is_ascii_lowercase() { left - (b'a' - b'A') } else { left };
            left == right
        })
}

const _: [(); 8] = [(); WORD_SIZE];
const _: [(); 1] = [(); ENABLE_LARGE_PAGES as usize];
const _: [(); 1] = [(); (!ENCODE_FREELIST) as usize];
const _: [(); 1] = [(); (!GUARDED) as usize];
const _: [(); 1] = [(); (!OPT_SIMD) as usize];
const _: [(); 1] = [(); PAGE_META_IS_SEPARATED as usize];
const _: [(); 1] = [(); PAGE_META_IS_ALIGNED as usize];
const _: [(); 75] = [(); BIN_COUNT];
const _: [(); 256 * MIB] = [(); PAGE_META_ALIGNMENT];
const _: [(); 16 * GIB] = [(); ARENA_MAX_SIZE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_release_constants_match_the_pinned_linux_64_profiles() {
        assert_eq!(WORD_SIZE, 8);
        assert_eq!(MAX_ALIGN_SIZE, 16);
        assert_eq!(SECURE_LEVEL, 0);
        assert_eq!(DEBUG_LEVEL, 0);
        assert_eq!(STAT_LEVEL, 0);
        assert!(!FREE_IS_CHECKED);
        assert!(!FREE_USE_PAGEMAP);
        assert!(!OPT_FREE_SMALL);
        assert!(!ENCODE_FREELIST);
        assert!(!GUARDED);
        assert!(!OPT_SIMD);
        assert_eq!(PADDING_SIZE, 0);
        assert_eq!(PADDING_WSIZE, 0);
        assert_eq!(PAGE_KEY_COUNT, 1);
        assert!(ENABLE_LARGE_PAGES);
        assert!(PAGE_META_IS_SEPARATED);
        assert!(PAGE_META_IS_ALIGNED);
        assert_eq!(PAGE_META_ALIGNED_CHUNKS, WORD_SIZE);
        assert_eq!(PAGE_META_ALIGNED_COUNT, WORD_SIZE * BCHUNK_BITS);

        assert_eq!(ARENA_SLICE_SHIFT, 16);
        assert_eq!(BCHUNK_BITS_SHIFT, 9);
        assert_eq!(ARENA_SLICE_SIZE, 64 * KIB);
        assert_eq!(BCHUNK_BITS, 512);
        assert_eq!(ARENA_CHUNK_SIZE, 32 * MIB);
        assert_eq!(SMALL_PAGE_SIZE, 64 * KIB);
        assert_eq!(MEDIUM_PAGE_SIZE, 512 * KIB);
        assert_eq!(LARGE_PAGE_SIZE, 4 * MIB);
        assert_eq!(PAGE_META_ALIGNMENT, 256 * MIB);
        assert_eq!(ARENA_ALIGNMENT, PAGE_META_ALIGNMENT);

        assert_eq!(BIN_HUGE, 73);
        assert_eq!(BIN_FULL, 74);
        assert_eq!(BIN_COUNT, 75);
        assert_eq!(PAGES_DIRECT, 129);
        assert_eq!(MAX_SINGLETON_BIN, 60);
        assert_eq!(MAX_ALLOC_SIZE, isize::MAX as usize);
        assert!(!PAGE_MAP_FLAT);
        assert_eq!(PAGE_MAP_SUB_COUNT, 8192);
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(MAX_VABITS, 48);
            assert_eq!(PAGE_MAP_SHIFT, 19);
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(MAX_VABITS, 47);
            assert_eq!(PAGE_MAP_SHIFT, 18);
        }
    }

    #[test]
    fn size_boundaries_are_the_source_derived_values() {
        assert_eq!(SMALL_SIZE_MAX, 1024);
        assert_eq!(SMALL_MAX_OBJ_SIZE, 10 * KIB);
        assert_eq!(MEDIUM_MAX_OBJ_SIZE, 86_698);
        assert_eq!(LARGE_MAX_OBJ_SIZE, 512 * KIB);
        assert_eq!(LARGE_MAX_OBJ_WSIZE, 65_536);
        assert_eq!(ARENA_MIN_SIZE, 32 * MIB);
        assert_eq!(ARENA_MAX_SIZE, 16 * GIB);
    }

    #[test]
    fn vm_options_preserve_source_defaults_and_lazy_environment_states() {
        let mut options = VmOptions::uninitialized();
        assert!(!options.all_resolved());
        assert_eq!(
            options.state(VmOption::AllowLargeOsPages),
            VmOptionState::Uninitialized
        );
        assert_eq!(options.value(VmOption::AllowLargeOsPages), None);

        options.initialize_one(VmOption::AllowLargeOsPages, VmOptionEnvironment::Absent);
        options.initialize_one(VmOption::PurgeDelay, VmOptionEnvironment::Value(b"250"));
        options.initialize_one(VmOption::AllowThp, VmOptionEnvironment::Value(b"off"));
        options.initialize_one(VmOption::UseNumaNodes, VmOptionEnvironment::Unavailable);
        options.initialize_one(VmOption::ReserveHugeOsPages, VmOptionEnvironment::Value(b"bogus"));

        assert_eq!(options.value(VmOption::AllowLargeOsPages), Some(0));
        assert_eq!(options.state(VmOption::AllowLargeOsPages), VmOptionState::Defaulted);
        assert_eq!(options.value(VmOption::PurgeDelay), Some(250));
        assert_eq!(options.state(VmOption::PurgeDelay), VmOptionState::Initialized);
        assert_eq!(options.value(VmOption::AllowThp), Some(0));
        assert_eq!(options.state(VmOption::AllowThp), VmOptionState::Initialized);
        assert_eq!(options.value(VmOption::UseNumaNodes), None);
        assert_eq!(options.state(VmOption::UseNumaNodes), VmOptionState::Uninitialized);
        assert_eq!(options.value(VmOption::ReserveHugeOsPages), Some(0));
        assert_eq!(options.state(VmOption::ReserveHugeOsPages), VmOptionState::Defaulted);
        assert_eq!(options.value(VmOption::ArenaPurgeMult), None);
        assert_eq!(options.value(VmOption::ArenaIsNumaLocal), None);

        // The C descriptor ignores a later environment lookup after either
        // a valid value or an absent/invalid result finalized it.
        options.initialize_one(VmOption::AllowThp, VmOptionEnvironment::Value(b"1"));
        assert_eq!(options.value(VmOption::AllowThp), Some(0));
    }

    #[test]
    fn vm_options_retain_the_arena_purge_and_numa_local_descriptors() {
        let mut options = VmOptions::uninitialized();
        options.initialize_all(|_| VmOptionEnvironment::Absent);

        assert_eq!(options.value(VmOption::ArenaPurgeMult), Some(4));
        assert_eq!(options.value(VmOption::ArenaIsNumaLocal), Some(0));

        options.set(VmOption::ArenaPurgeMult, -3);
        options.set(VmOption::ArenaIsNumaLocal, 1);
        assert_eq!(options.value(VmOption::ArenaPurgeMult), Some(-3));
        assert_eq!(options.value(VmOption::ArenaIsNumaLocal), Some(1));
    }

    #[test]
    fn vm_option_set_and_set_default_keep_source_mutation_precedence() {
        let mut options = VmOptions::uninitialized();
        options.set_default(VmOption::PurgeDelay, 5);
        assert_eq!(options.value(VmOption::PurgeDelay), None);
        options.initialize_one(VmOption::PurgeDelay, VmOptionEnvironment::Absent);
        assert_eq!(options.value(VmOption::PurgeDelay), Some(5));

        options.set(VmOption::PurgeDelay, -1);
        options.set_default(VmOption::PurgeDelay, 1000);
        options.initialize_one(VmOption::PurgeDelay, VmOptionEnvironment::Value(b"1000"));
        assert_eq!(options.value(VmOption::PurgeDelay), Some(-1));
        assert_eq!(options.state(VmOption::PurgeDelay), VmOptionState::Initialized);
    }

    #[test]
    fn vm_options_initialize_all_does_not_observe_preinitialized_descriptors() {
        let mut options = VmOptions::uninitialized();
        options.set(VmOption::AllowThp, 0);
        let mut observed = 0usize;
        options.initialize_all(|option| {
            assert_ne!(
                option,
                VmOption::AllowThp,
                "a source-set descriptor must not invoke its environment observer"
            );
            observed += 1;
            VmOptionEnvironment::Absent
        });
        assert_eq!(observed, VmOption::ALL.len() - 1);
        assert!(options.all_resolved());
        assert_eq!(options.value(VmOption::AllowThp), Some(0));
    }

    #[test]
    fn vm_options_resolve_the_selected_source_environment_in_descriptor_order() {
        let entries = [
            b"MIMALLOC_ARENA_EAGER_COMMIT=1\0".as_ptr().cast(),
            b"mimalloc_reset_decommits=off\0".as_ptr().cast(),
            b"mimalloc_allow_large_os_pages=0\0".as_ptr().cast(),
            b"MIMALLOC_LARGE_OS_PAGES=1\0".as_ptr().cast(),
            b"MIMALLOC_ALLOW_THP=0\0".as_ptr().cast(),
            b"mimalloc_arena_reserve=2MiB\0".as_ptr().cast(),
            b"mimalloc_allow_thp_not_a_descriptor=1\0".as_ptr().cast(),
            core::ptr::null(),
        ];
        let mut options = VmOptions::uninitialized();
        // SAFETY: the test owns a null-terminated environment-pointer vector
        // and every selected entry is a stable NUL-terminated C string.
        unsafe { options.initialize_from_source_environment(entries.as_ptr()) };

        assert!(options.all_resolved());
        assert_eq!(options.value(VmOption::ArenaEagerCommit), Some(1));
        assert_eq!(options.value(VmOption::PurgeDecommits), Some(0));
        assert_eq!(
            options.value(VmOption::AllowLargeOsPages),
            Some(0),
            "the canonical spelling wins before a legacy spelling is considered"
        );
        assert_eq!(options.value(VmOption::AllowThp), Some(0));
        assert_eq!(options.value(VmOption::ArenaReserve), Some(2 * 1024));
        assert_eq!(options.state(VmOption::UseNumaNodes), VmOptionState::Defaulted);
    }

    #[test]
    fn vm_options_keep_an_overlong_canonical_environment_value_uninitialized() {
        const NAME: &[u8] = b"mimalloc_allow_large_os_pages=";
        let mut oversized = [0u8; NAME.len() + SOURCE_OPTION_VALUE_BYTES + 2];
        oversized[..NAME.len()].copy_from_slice(NAME);
        oversized[NAME.len()..NAME.len() + SOURCE_OPTION_VALUE_BYTES + 1].fill(b'1');
        let entries = [
            oversized.as_ptr().cast(),
            b"mimalloc_large_os_pages=1\0".as_ptr().cast(),
            core::ptr::null(),
        ];
        let mut options = VmOptions::uninitialized();
        // SAFETY: `oversized` and the legacy entry are stable NUL-terminated
        // C strings for this bounded observation.
        unsafe { options.initialize_from_source_environment(entries.as_ptr()) };

        assert_eq!(
            options.state(VmOption::AllowLargeOsPages),
            VmOptionState::Uninitialized,
            "a source EAGAIN from the canonical read must not consult the legacy name"
        );
        assert_eq!(options.value(VmOption::AllowLargeOsPages), None);
        assert_eq!(options.state(VmOption::AllowThp), VmOptionState::Defaulted);
    }

    #[test]
    fn vm_option_selected_descriptor_order_matches_pinned_options_c() {
        assert_eq!(
            VmOption::ALL,
            [
                VmOption::ArenaEagerCommit,
                VmOption::PurgeDecommits,
                VmOption::AllowLargeOsPages,
                VmOption::ReserveHugeOsPages,
                VmOption::ReserveHugeOsPagesAt,
                VmOption::PurgeDelay,
                VmOption::UseNumaNodes,
                VmOption::DisallowOsAlloc,
                VmOption::ArenaReserve,
                VmOption::ArenaPurgeMult,
                VmOption::DisallowArenaAlloc,
                VmOption::PageCommitOnDemand,
                VmOption::AllowThp,
                VmOption::MinimalPurgeSize,
                VmOption::ArenaMaxObjectSize,
                VmOption::ArenaIsNumaLocal,
            ],
            "the bounded VM owner follows the selected source declaration order"
        );
    }

    #[test]
    fn vm_option_parser_matches_the_non_size_source_grammar() {
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b""), Some(1));
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b"YeS"), Some(1));
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b"OFF"), Some(0));
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b" \t-42"), Some(-42));
        assert_eq!(
            parse_source_option_value(VmOption::AllowThp, b"+9223372036854775807"),
            Some(i64::MAX)
        );
        assert_eq!(
            parse_source_option_value(VmOption::AllowThp, b"-9223372036854775808"),
            Some(i64::MIN)
        );
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b"9223372036854775808"), None);
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b"12x"), None);
        assert_eq!(parse_source_option_value(VmOption::AllowThp, b" + "), None);
    }

    #[test]
    fn vm_size_options_preserve_the_source_kib_suffix_rules() {
        assert_eq!(
            parse_source_option_value(VmOption::ArenaReserve, b"2"),
            Some(1),
            "a suffix-free source size is bytes rounded to KiB"
        );
        assert_eq!(parse_source_option_value(VmOption::ArenaReserve, b"2K"), Some(2));
        assert_eq!(parse_source_option_value(VmOption::ArenaReserve, b"2MiB"), Some(2 * 1024));
        assert_eq!(
            parse_source_option_value(VmOption::ArenaReserve, b"2GIB"),
            Some(2 * 1024 * 1024)
        );
        assert_eq!(parse_source_option_value(VmOption::ArenaReserve, b"-7M"), Some(0));
        assert_eq!(
            parse_source_option_value(VmOption::ArenaReserve, b"9223372036854775807T"),
            Some((MAX_ALLOC_SIZE / KIB) as i64),
            "a valid source long that overflows a suffix conversion saturates"
        );
        assert_eq!(
            parse_source_option_value(VmOption::ArenaReserve, b"999999999999999999999T"),
            None,
            "strtol overflow rejects the source value before size saturation"
        );
    }
}
