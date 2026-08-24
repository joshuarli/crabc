// Copyright (c) 2019-2021, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license is recorded in `UPSTREAM.md`.
// SPDX-License-Identifier: MIT
//
// Semantic port of pinned mimalloc v3.5.0 `src/random.c`: original-ChaCha
// context initialization, block generation, output consumption, splitting,
// direct entropy acquisition, and weak-context reinitialization. RustCrypto
// `ChaCha20LegacyCore` performs every ChaCha permutation; this module owns only
// the source state machine and its exact `mi_random_ctx_t` storage image.

use chacha20::{
    ChaCha20LegacyCore, Key, LegacyNonce,
    cipher::{KeyIvInit, StreamCipherCore, array::Array},
};
use zeroize::Zeroize;

use crate::os;

const OUTPUT_WORDS: usize = 16;
const OUTPUT_WORDS_I32: i32 = OUTPUT_WORDS as i32;
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

// This is a domain separator for weak observation expansion, not a random
// counter or a locally implemented permutation. It keeps the one RustCrypto
// block used to expand degraded seed observations disjoint from the allocator
// context's source counter stream.
const WEAK_EXPANSION_BLOCK: u64 = 0x6372_6162_635f_776b;

/// Caller-owned entropy material for a deterministic `TheapRandomImage` test.
///
/// `src/random.c:mi_random_init_ex` obtains exactly 32 key bytes before
/// creating a context. Production initialization now acquires it directly;
/// this owner remains only for deterministic source-vector fixtures and marks
/// their intended strong or weak classification.
#[cfg(test)]
pub(crate) struct EntropyMaterial {
    key: [u8; 32],
    weak: bool,
}

#[cfg(test)]
impl EntropyMaterial {
    /// Records entropy accepted from the source's normal OS-random path.
    ///
    /// The key is moved by swapping zeroes into the caller's acquisition
    /// buffer. This makes the source's temporary-key clearing an interface
    /// invariant rather than a convention vulnerable to a copied array.
    #[inline]
    pub(crate) fn secure(key: &mut [u8; 32]) -> Self {
        Self::take(key, false)
    }

    /// Records caller-supplied material for a deterministic weak-image test.
    #[inline]
    pub(crate) fn weak(key: &mut [u8; 32]) -> Self {
        Self::take(key, true)
    }

    #[inline]
    fn take(key: &mut [u8; 32], weak: bool) -> Self {
        let mut material = Self {
            key: [0; 32],
            weak,
        };
        core::mem::swap(&mut material.key, key);
        material
    }
}

#[cfg(test)]
impl Drop for EntropyMaterial {
    fn drop(&mut self) {
        // This is a bounded stack-only analogue of the source's final
        // `_mi_memzero(key, sizeof(key))`; the live context retains its key,
        // just as the C `input[4..12]` state does.
        self.key.zeroize();
    }
}

/// Exact source-layout image of pinned `mi_random_ctx_t`.
///
/// This is the sole live allocator random state. Its `input` words preserve
/// source order: sigma at `0..4`, key at `4..12`, 64-bit counter at `12..14`,
/// and the 64-bit address-derived nonce at `14..16`. The `Theap::random` field
/// stores this image directly; there is no compressed sidecar representation.
///
/// `initialize`, `initialize_weak`, and `split_into` derive their nonce from
/// the address of this image, as `src/random.c` does. Their caller must retain
/// the initialized image at that address until it is cleared or destroyed. A
/// future theap owner satisfies that by operating on the random field of its
/// pinned metadata allocation before the theap is published.
#[repr(C)]
pub(crate) struct TheapRandomImage {
    input: [u32; 16],
    output: [u32; OUTPUT_WORDS],
    output_available: i32,
    weak: bool,
}

impl Drop for TheapRandomImage {
    fn drop(&mut self) {
        self.clear();
    }
}

impl TheapRandomImage {
    /// Source's inert `_mi_theap_empty.random` image.
    #[inline]
    pub(crate) const fn empty_weak() -> Self {
        Self {
            input: [0; 16],
            output: [0; OUTPUT_WORDS],
            output_available: 0,
            weak: true,
        }
    }

    /// Performs `_mi_random_init` for this already address-stable image.
    ///
    /// A direct Linux `getrandom` success creates a strong context. A short
    /// result or error continues with the source's degraded lifecycle instead
    /// of leaving an unpublished theap without random state. The replacement
    /// weak key expansion is dependency-owned; see [`WeakObservations`].
    #[inline]
    pub(crate) fn initialize(&mut self) {
        self.initialize_ex(false, 0);
    }

    /// Performs `_mi_random_init_weak` for this already address-stable image.
    ///
    /// The pinned source uses this only where the caller explicitly requests a
    /// weak context. It never attempts OS entropy first.
    #[inline]
    pub(crate) fn initialize_weak(&mut self, extra_seed: usize) {
        self.initialize_ex(true, extra_seed);
    }

    /// Port of `_mi_random_reinit_if_weak`.
    ///
    /// A strong context makes no entropy call. A weak context always retries
    /// the normal direct entropy path and remains weak if that retry again
    /// fails, exactly preserving the source's continuation behavior.
    #[inline]
    pub(crate) fn reinitialize_if_weak(&mut self) -> bool {
        if !self.weak {
            return false;
        }
        self.initialize();
        true
    }

    /// Reports whether initialization took the source's weak-random path.
    #[inline]
    pub(crate) const fn is_weak(&self) -> bool { self.weak }

    /// Reports the source debug initialization predicate.
    #[inline]
    pub(crate) const fn is_initialized(&self) -> bool { self.input[0] != 0 }

    /// Returns one source-order 32-bit output word and immediately clears it.
    #[inline]
    fn next32(&mut self) -> u32 {
        if self.output_available <= 0 {
            self.refill();
            // Preserve the source's deliberately repeated assignment after
            // `chacha_block`; it documents the full output-buffer invariant.
            self.output_available = OUTPUT_WORDS_I32;
        }

        let index = OUTPUT_WORDS - self.output_available as usize;
        let word = core::mem::replace(&mut self.output[index], 0);
        self.output_available -= 1;
        word
    }

    /// Returns two source-order words as the AArch64 `uintptr_t` result.
    ///
    /// `_mi_random_next` shifts its first `chacha_next32` result into the
    /// high half and places the second in the low half. This raw helper keeps
    /// that ordering; [`Self::next`] supplies the C API's retry on
    /// a zero whole-word result.
    #[inline]
    fn next64_raw(&mut self) -> u64 {
        (u64::from(self.next32()) << 32) | u64::from(self.next32())
    }

    /// Port of AArch64 `_mi_random_next`'s nonzero-result contract.
    #[inline]
    pub(crate) fn next(&mut self) -> u64 {
        debug_assert!(self.is_initialized());
        loop {
            let value = self.next64_raw();
            if value != 0 {
                return value;
            }
        }
    }

    /// Port of `_mi_random_split` into an address-stable destination image.
    ///
    /// Returning a newly constructed Rust value would be incorrect: the
    /// source derives the child nonce from the address of the destination
    /// `mi_random_ctx_t`, not from a transient stack image. The future theap
    /// owner must call this only once both parent and child fields are pinned.
    #[inline]
    pub(crate) fn split_into(&mut self, child: &mut Self) {
        debug_assert!(self.is_initialized());
        let nonce = child.identity() ^ self.next();
        debug_assert!(
            self.input[14] != nonce as u32 || self.input[15] != (nonce >> 32) as u32,
            "split contexts must not reuse a nonce"
        );

        // `chacha_split` first clears the destination, including a previous
        // key/output image, then copies only the source input matrix and
        // replaces its counter and nonce before eagerly producing one block.
        child.clear();
        child.weak = self.weak;
        child.input = self.input;
        child.input[12] = 0;
        child.input[13] = 0;
        child.input[14] = nonce as u32;
        child.input[15] = (nonce >> 32) as u32;
        child.refill();
    }

    /// Copies the source local `mi_random_ctx_t head_random` snapshot used by
    /// `_mi_theap_init` before it splits a newly linked theap.
    ///
    /// The C implementation copies this complete fixed image while holding
    /// the TLD list lock, then mutates the local copy outside the lock. This
    /// is not a second PRNG state representation: the returned value is the
    /// same source image and its `Drop` clears that temporary on scope exit.
    #[inline]
    pub(crate) fn snapshot_for_split(&self) -> Self {
        Self {
            input: self.input,
            output: self.output,
            output_available: self.output_available,
            weak: self.weak,
        }
    }

    /// Clears all source state before an owning metadata allocation is
    /// released. Manual metadata release does not run Rust `Drop`, so a future
    /// theap/TLD teardown owner must call this before handing its image back.
    #[inline]
    pub(crate) fn clear(&mut self) {
        self.input.zeroize();
        self.output.zeroize();
        self.output_available.zeroize();
        self.weak = false;
    }

    #[inline]
    fn initialize_ex(&mut self, force_weak: bool, extra_seed: usize) {
        let mut key = [0; 32];
        let weak = force_weak || !matches!(os::entropy_fill(&mut key), Ok(true));
        if weak {
            // A failing kernel call may have written a partial key. It is not
            // entropy accepted by `_mi_prim_random_buf`, so wipe it before the
            // dependency-owned weak expansion overwrites all 32 bytes.
            key.zeroize();
            WeakObservations::current(self.identity(), extra_seed).expand_into(&mut key);
        }

        self.chacha_init(&key, self.identity(), weak);
        key.zeroize();
    }

    #[cfg(test)]
    #[inline]
    fn initialize_from_material(&mut self, entropy: EntropyMaterial, nonce: u64) {
        self.chacha_init(&entropy.key, nonce, entropy.weak);
    }

    #[inline]
    fn chacha_init(&mut self, key: &[u8; 32], nonce: u64, weak: bool) {
        self.output_available = 0;
        self.output.zeroize();
        self.input[..4].copy_from_slice(&SIGMA);
        for (word, bytes) in self.input[4..12].iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        self.input[12] = 0;
        self.input[13] = 0;
        self.input[14] = nonce as u32;
        self.input[15] = (nonce >> 32) as u32;
        self.weak = weak;
    }

    #[inline]
    fn refill(&mut self) {
        debug_assert!(self.output_available <= 0);

        let mut key_bytes = [0; 32];
        for (bytes, word) in key_bytes.chunks_exact_mut(4).zip(&self.input[4..12]) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        let mut nonce_bytes = [0; 8];
        nonce_bytes[..4].copy_from_slice(&self.input[14].to_le_bytes());
        nonce_bytes[4..].copy_from_slice(&self.input[15].to_le_bytes());
        let counter = u64::from(self.input[12]) | (u64::from(self.input[13]) << 32);
        let mut block = Array::default();
        {
            let key: &Key = (&key_bytes).into();
            let nonce: &LegacyNonce = (&nonce_bytes).into();
            let mut core = ChaCha20LegacyCore::new(key, nonce);
            core.set_block_pos(counter);
            core.write_keystream_block(&mut block);
        }
        for (word, bytes) in self.output.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        // The library core clears its internal key/state on Drop under the
        // selected `zeroize` feature; clear copied key/nonce/block storage too.
        key_bytes.zeroize();
        nonce_bytes.zeroize();
        block.as_mut_slice().zeroize();
        self.output_available = OUTPUT_WORDS_I32;
        self.increment_counter();
    }

    #[inline]
    fn increment_counter(&mut self) {
        self.input[12] = self.input[12].wrapping_add(1);
        if self.input[12] == 0 {
            self.input[13] = self.input[13].wrapping_add(1);
            if self.input[13] == 0 {
                // C increments `input[14]` directly. A low nonce wrap does
                // not carry into `input[15]`.
                self.input[14] = self.input[14].wrapping_add(1);
            }
        }
    }

    #[inline]
    fn identity(&self) -> u64 {
        core::ptr::addr_of!(*self) as usize as u64
    }
}

/// Direct, non-secret observations used only after source entropy fails.
///
/// Pinned `src/random.c:_mi_os_random_weak` combines an ASLR address and a
/// monotonic clock, then feeds its local `_mi_random_shuffle` PRNG into a key.
/// Project policy forbids translating that PRNG. We retain the same degraded
/// lifecycle and gather its direct observables plus Linux process/thread
/// identities and the source extra seed. `expand_into` passes those bytes to a
/// domain-separated RustCrypto original-ChaCha block; it does not claim to add
/// entropy or implement a new cryptographic primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WeakObservations {
    context_identity: u64,
    thread_pointer_identity: u64,
    monotonic_milliseconds: u64,
    extra_seed: u64,
    process_id: u32,
    thread_id: u32,
}

impl WeakObservations {
    #[inline]
    fn current(context_identity: u64, extra_seed: usize) -> Self {
        Self {
            context_identity,
            thread_pointer_identity: os::thread_pointer_identity() as u64,
            // The source's weak path continues even when its clock gives a
            // poor value. Linux's direct clock error becomes the transparent
            // zero observation rather than a second fallback mechanism.
            monotonic_milliseconds: os::monotonic_milliseconds().unwrap_or(0) as u64,
            extra_seed: extra_seed as u64,
            process_id: os::process_id() as u32,
            thread_id: os::thread_id() as u32,
        }
    }

    #[inline]
    fn expand_into(self, output: &mut [u8; 32]) {
        let mut seed_key = [0; 32];
        seed_key[..8].copy_from_slice(&self.context_identity.to_le_bytes());
        seed_key[8..16].copy_from_slice(&self.thread_pointer_identity.to_le_bytes());
        seed_key[16..24].copy_from_slice(&self.monotonic_milliseconds.to_le_bytes());
        seed_key[24..].copy_from_slice(&self.extra_seed.to_le_bytes());
        let mut observation_nonce = [0; 8];
        observation_nonce[..4].copy_from_slice(&self.process_id.to_le_bytes());
        observation_nonce[4..].copy_from_slice(&self.thread_id.to_le_bytes());

        let mut block = Array::default();
        {
            let key: &Key = (&seed_key).into();
            let nonce: &LegacyNonce = (&observation_nonce).into();
            let mut core = ChaCha20LegacyCore::new(key, nonce);
            core.set_block_pos(WEAK_EXPANSION_BLOCK);
            core.write_keystream_block(&mut block);
        }
        output.copy_from_slice(&block[..32]);
        seed_key.zeroize();
        observation_nonce.zeroize();
        block.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, needs_drop, offset_of, size_of};

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    const NONCE: u64 = 0x0000_0000_4a00_0000;
    const COUNTER: u64 = 0x0900_0000_0000_0001;
    // Pinned C `src/random.c:chacha_test`'s original-ChaCha block vector.
    const PINNED_C_BLOCK: [u32; OUTPUT_WORDS] = [
        0xe4e7_f110, 0x1559_3bd1, 0x1fdd_0f50, 0xc471_20a3, 0xc7f4_d1c7, 0x0368_c033,
        0x9aaa_2204, 0x4e6c_d4c3, 0x4664_82d2, 0x09aa_9f07, 0x05d7_c214, 0xa202_8bd9,
        0xd19c_12b5, 0xb94e_16de, 0xe883_d0cb, 0x4e3c_50a2,
    ];

    fn secure_material(mut key: [u8; 32]) -> EntropyMaterial {
        let material = EntropyMaterial::secure(&mut key);
        assert_eq!(key, [0; 32]);
        material
    }

    fn weak_material(mut key: [u8; 32]) -> EntropyMaterial {
        let material = EntropyMaterial::weak(&mut key);
        assert_eq!(key, [0; 32]);
        material
    }

    fn context() -> TheapRandomImage {
        let mut context = TheapRandomImage::empty_weak();
        context.initialize_from_material(secure_material(KEY), NONCE);
        context.input[12] = COUNTER as u32;
        context.input[13] = (COUNTER >> 32) as u32;
        context
    }

    #[test]
    fn source_layout_and_chacha_initialization_keep_all_words_authoritative() {
        assert_eq!(size_of::<TheapRandomImage>(), 136);
        assert_eq!(align_of::<TheapRandomImage>(), 4);
        assert_eq!(offset_of!(TheapRandomImage, input), 0);
        assert_eq!(offset_of!(TheapRandomImage, output), 64);
        assert_eq!(offset_of!(TheapRandomImage, output_available), 128);
        assert_eq!(offset_of!(TheapRandomImage, weak), 132);
        assert!(needs_drop::<TheapRandomImage>());

        let mut context = TheapRandomImage::empty_weak();
        context.initialize_from_material(secure_material(KEY), NONCE);
        assert_eq!(context.input[..4], SIGMA);
        assert_eq!(
            context.input[4..12],
            [
                0x0302_0100,
                0x0706_0504,
                0x0b0a_0908,
                0x0f0e_0d0c,
                0x1312_1110,
                0x1716_1514,
                0x1b1a_1918,
                0x1f1e_1d1c,
            ]
        );
        assert_eq!(context.input[12], 0);
        assert_eq!(context.input[13], 0);
        assert_eq!(context.input[14], NONCE as u32);
        assert_eq!(context.input[15], (NONCE >> 32) as u32);
        assert_eq!(context.output, [0; OUTPUT_WORDS]);
        assert_eq!(context.output_available, 0);
        assert!(!context.weak);
        assert!(context.is_initialized());
        context.clear();
        assert_eq!(context.input, [0; 16]);
        assert_eq!(context.output, [0; OUTPUT_WORDS]);
        assert_eq!(context.output_available, 0);
        assert!(!context.weak);
    }

    #[test]
    fn pinned_c_block_vector_uses_the_original_chacha_word_layout() {
        let mut context = context();
        let mut actual = [0; OUTPUT_WORDS];
        for word in &mut actual {
            *word = context.next32();
        }

        assert_eq!(actual, PINNED_C_BLOCK);
        assert_eq!(
            u64::from(context.input[12]) | (u64::from(context.input[13]) << 32),
            COUNTER.wrapping_add(1)
        );
        assert_eq!(context.input[14], NONCE as u32);
        assert_eq!(context.input[15], (NONCE >> 32) as u32);
        assert_eq!(context.output_available, 0);
        assert_eq!(context.output, [0; OUTPUT_WORDS]);
    }

    #[test]
    fn next64_places_the_first_consumed_word_in_the_high_half() {
        let mut context = context();

        assert_eq!(
            context.next64_raw(),
            (u64::from(PINNED_C_BLOCK[0]) << 32) | u64::from(PINNED_C_BLOCK[1])
        );
        assert_eq!(context.output_available, 14);
        assert_eq!(context.output[0], 0);
        assert_eq!(context.output[1], 0);
        assert_eq!(&context.output[2..], &PINNED_C_BLOCK[2..]);
        assert_eq!(context.next32(), PINNED_C_BLOCK[2]);
        assert_eq!(context.output[2], 0);
    }

    #[test]
    fn public_next_retries_a_zero_whole_word_and_clears_both_attempts() {
        let mut context = context();
        context.output = [0; OUTPUT_WORDS];
        context.output[2] = 0x1122_3344;
        context.output[3] = 0x5566_7788;
        context.output_available = OUTPUT_WORDS_I32;

        assert_eq!(context.next(), 0x1122_3344_5566_7788);
        assert_eq!(context.output_available, 12);
        assert_eq!(&context.output[..4], &[0; 4]);
    }

    #[test]
    fn buffer_exhaustion_clears_the_old_block_before_refilling() {
        let mut context = context();
        for expected in PINNED_C_BLOCK {
            assert_eq!(context.next32(), expected);
        }

        assert_eq!(context.output_available, 0);
        assert_eq!(context.output, [0; OUTPUT_WORDS]);

        // Pinned release C oracle, with the context state above, emits this
        // as the seventeenth `chacha_next32` result.
        let first_word_of_next_block = context.next32();
        assert_eq!(first_word_of_next_block, 0x7783_880a);
        assert_eq!(
            u64::from(context.input[12]) | (u64::from(context.input[13]) << 32),
            COUNTER.wrapping_add(2)
        );
        assert_eq!(context.output_available, 15);
        assert_eq!(context.output[0], 0);
    }

    #[test]
    fn counter_wrap_increments_only_the_low_nonce_word() {
        let mut context = TheapRandomImage::empty_weak();
        context.initialize_from_material(secure_material(KEY), 0x89ab_cdef_ffff_ffff);
        context.input[12] = u32::MAX;
        context.input[13] = u32::MAX;

        let _ = context.next32();

        assert_eq!(context.input[12], 0);
        assert_eq!(context.input[13], 0);
        assert_eq!(context.input[14], 0);
        assert_eq!(context.input[15], 0x89ab_cdef);
    }

    #[test]
    fn low_counter_word_wraps_into_the_high_counter_word_before_the_nonce() {
        let mut context = TheapRandomImage::empty_weak();
        context.initialize_from_material(secure_material(KEY), NONCE);
        context.input[12] = u32::MAX;
        context.input[13] = 0;

        let _ = context.next32();

        assert_eq!(context.input[12], 0);
        assert_eq!(context.input[13], 1);
        assert_eq!(context.input[14], NONCE as u32);
        assert_eq!(context.input[15], (NONCE >> 32) as u32);
    }

    #[test]
    fn split_uses_the_already_stable_destination_field_address() {
        let mut parent = context();
        let mut child = TheapRandomImage::empty_weak();
        let child_identity = child.identity();
        parent.split_into(&mut child);

        assert_eq!(parent.output_available, 14);
        assert_eq!(parent.output[0], 0);
        assert_eq!(parent.output[1], 0);
        assert_eq!(child.input[12], 1);
        assert_eq!(child.input[13], 0);
        assert_eq!(child.output_available, OUTPUT_WORDS_I32);
        assert_eq!(child.weak, parent.weak);
        // The pinned source derives exactly this nonce from the actual
        // destination image address and its first parent random value.
        assert_eq!(
            u64::from(child.input[14]) | (u64::from(child.input[15]) << 32),
            child_identity ^ 0xe4e7_f110_1559_3bd1
        );

        let parent_next = parent.next64_raw();
        let child_first = child.next64_raw();
        assert_eq!(parent_next, 0x1fdd_0f50_c471_20a3);
        assert_ne!(child_first, 0);
        assert_eq!(parent.output_available, 12);
        assert_eq!(child.output_available, 14);
    }

    #[test]
    fn weak_observations_have_a_dependency_owned_deterministic_expansion() {
        let observations = WeakObservations {
            context_identity: 0x0123_4567_89ab_cdef,
            thread_pointer_identity: 0xfedc_ba98_7654_3210,
            monotonic_milliseconds: 0x0f1e_2d3c_4b5a_6978,
            extra_seed: 0x8877_6655_4433_2211,
            process_id: 0x1020_3040,
            thread_id: 0x5060_7080,
        };
        let mut actual = [0; 32];
        observations.expand_into(&mut actual);
        assert_eq!(
            actual,
            [
                0xac, 0x24, 0x9c, 0xc4, 0xf6, 0x7b, 0x3f, 0xd4, 0x1a, 0x11, 0xa7, 0x2a,
                0x26, 0x8b, 0x7d, 0xe0, 0xc2, 0xaf, 0xba, 0x67, 0xf6, 0x60, 0x53, 0x16,
                0x49, 0xb5, 0xa4, 0xd9, 0xb7, 0xa9, 0x29, 0x7c,
            ]
        );
        actual.zeroize();
    }

    #[test]
    fn entropy_success_initializes_a_strong_source_image() {
        let _fault = os::fault::install(os::fault::Plan::disabled());
        let mut context = TheapRandomImage::empty_weak();
        let identity = context.identity();
        context.initialize();

        assert!(context.is_initialized());
        assert!(!context.is_weak(), "Linux getrandom must initialize strongly");
        assert_eq!(context.input[14], identity as u32);
        assert_eq!(context.input[15], (identity >> 32) as u32);
        assert_ne!(context.next(), 0);
    }

    #[test]
    fn entropy_failure_continues_with_a_weak_source_image() {
        let fault = os::fault::install(os::fault::Plan::at(
            os::fault::Point::Entropy,
            1,
            crabc_core::Errno::NOMEM,
        ));
        let mut context = TheapRandomImage::empty_weak();
        context.initialize();

        assert_eq!(fault.observed(), 1);
        assert!(context.is_initialized());
        assert!(context.is_weak());
        assert_ne!(context.next(), 0);
    }

    #[test]
    fn forced_weak_initialization_skips_entropy_and_uses_its_extra_seed() {
        let fault = os::fault::install(os::fault::Plan::at(
            os::fault::Point::Entropy,
            1,
            crabc_core::Errno::NOMEM,
        ));
        let mut context = TheapRandomImage::empty_weak();
        context.initialize_weak(0xfeed_face_cafe_beef);

        assert_eq!(fault.observed(), 0, "source weak init must skip getrandom");
        assert!(context.is_initialized());
        assert!(context.is_weak());
    }

    #[test]
    fn weak_reinitialization_retries_entropy_but_strong_contexts_do_not() {
        let fault = os::fault::install(os::fault::Plan::at(
            os::fault::Point::Entropy,
            1,
            crabc_core::Errno::NOMEM,
        ));

        let mut strong = TheapRandomImage::empty_weak();
        strong.initialize_from_material(secure_material(KEY), NONCE);
        assert!(!strong.reinitialize_if_weak());
        assert_eq!(fault.observed(), 0, "strong state must skip getrandom");

        let mut weak = TheapRandomImage::empty_weak();
        weak.initialize_from_material(weak_material(KEY), NONCE);
        assert!(weak.reinitialize_if_weak());
        assert_eq!(fault.observed(), 1, "weak state must retry getrandom");
        assert!(weak.is_weak(), "failed retry continues through weak initialization");
        assert!(weak.is_initialized());
    }

    #[test]
    fn successful_weak_reinitialization_becomes_strong_once() {
        let _fault = os::fault::install(os::fault::Plan::disabled());
        let mut weak = TheapRandomImage::empty_weak();
        weak.initialize_from_material(weak_material(KEY), NONCE);

        assert!(weak.reinitialize_if_weak());
        assert!(!weak.is_weak());
        assert!(!weak.reinitialize_if_weak());
    }
}
