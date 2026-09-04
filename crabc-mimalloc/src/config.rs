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
}
