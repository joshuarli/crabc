// Copyright (c) 2019-2021, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license is recorded in `UPSTREAM.md`.
// SPDX-License-Identifier: MIT
//
// Semantic port of pinned mimalloc v3.5.0 `src/random.c`: original-ChaCha
// context initialization, block generation, output consumption, and context
// splitting. The RustCrypto `ChaCha20LegacyCore` performs the original
// ChaCha20 block operation; this module retains the source-owned buffering,
// 64-bit counter, 64-bit nonce-word layout, and rollover transition.

use chacha20::{
    ChaCha20LegacyCore, Key, LegacyNonce,
    cipher::{KeyIvInit, StreamCipherCore, array::Array},
};
use zeroize::Zeroize;

const OUTPUT_WORDS: usize = 16;
const LOW_NONCE_WORD_MASK: u64 = 0xffff_ffff;

/// Caller-owned entropy material for one [`RandomContext`] initialization.
///
/// `src/random.c:mi_random_init_ex` obtains exactly 32 key bytes before
/// creating a context. This type models that completed acquisition without
/// acquiring entropy itself: the runtime owner chooses the source and marks
/// whether it had to use the C source's weak path. It is deliberately not an
/// OS interface, fallback, or global initializer.
pub(crate) struct EntropyMaterial {
    key: [u8; 32],
    weak: bool,
}

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

    /// Records caller-supplied material from the source's weak-init path.
    ///
    /// This constructor does not synthesize the source's timer/ASLR fallback;
    /// that lifecycle and entropy policy remains outside this bounded state
    /// slice. Its `weak` classification is retained by context splitting.
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

impl Drop for EntropyMaterial {
    fn drop(&mut self) {
        // This is a bounded stack-only analogue of the source's final
        // `_mi_memzero(key, sizeof(key))`; the live context retains its key,
        // just as the C `input[4..12]` state does.
        self.key.zeroize();
    }
}

/// One allocator-private port of `mi_random_ctx_t`.
///
/// The original C structure retains a full ChaCha input matrix. Constants are
/// fixed and RustCrypto reconstructs them from the key, so this representation
/// stores only the source-varying key, 64-bit counter, and 64-bit nonce. The
/// nonce is logically two little-endian words: when the counter wraps, only
/// its low word advances, exactly as `input[14] += 1` in `chacha_block`.
pub(crate) struct RandomContext {
    key: [u8; 32],
    counter: u64,
    nonce: u64,
    output: [u32; OUTPUT_WORDS],
    output_available: u8,
    weak: bool,
}

impl Drop for RandomContext {
    fn drop(&mut self) {
        self.key.zeroize();
        self.counter.zeroize();
        self.nonce.zeroize();
        self.output.zeroize();
        self.output_available.zeroize();
        self.weak = false;
    }
}

impl RandomContext {
    /// Initializes one state from material acquired by the caller.
    ///
    /// `nonce` is the source's 64-bit original-ChaCha nonce, conventionally
    /// the address of the C context. The integrating runtime supplies its
    /// corresponding state identity; this module neither takes an address nor
    /// reaches into process-start or OS entropy state.
    #[inline]
    pub(crate) fn from_entropy(mut entropy: EntropyMaterial, nonce: u64) -> Self {
        let mut context = Self {
            key: [0; 32],
            counter: 0,
            nonce,
            output: [0; OUTPUT_WORDS],
            output_available: 0,
            weak: entropy.weak,
        };
        // Move the caller's temporary key directly into the persistent state;
        // the zero value swapped back into `entropy` is still zeroized by its
        // Drop implementation, matching `mi_random_init_ex`'s temporary-key
        // cleanup without leaving a second ordinary Rust array copy.
        core::mem::swap(&mut context.key, &mut entropy.key);
        context
    }

    /// Reports whether initialization took the source's weak-random path.
    #[inline]
    pub(crate) const fn is_weak(&self) -> bool {
        self.weak
    }

    /// Replaces this state only if it remains weak.
    ///
    /// This is `_mi_random_reinit_if_weak` with entropy acquisition injected
    /// at the runtime boundary. A `true` result means replacement occurred;
    /// `false` means the current strong state was left untouched.
    #[inline]
    pub(crate) fn reinitialize_if_weak(
        &mut self,
        acquire: impl FnOnce() -> (EntropyMaterial, u64),
    ) -> bool {
        if !self.weak {
            return false;
        }
        let (entropy, nonce) = acquire();
        *self = Self::from_entropy(entropy, nonce);
        true
    }

    /// Returns one source-order 32-bit output word and immediately clears it.
    #[inline]
    fn next32(&mut self) -> u32 {
        if self.output_available == 0 {
            self.refill();
            // Preserve the source's deliberately repeated assignment after
            // `chacha_block`; it documents the full output-buffer invariant.
            self.output_available = OUTPUT_WORDS as u8;
        }

        let index = OUTPUT_WORDS - usize::from(self.output_available);
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
        loop {
            let value = self.next64_raw();
            if value != 0 {
                return value;
            }
        }
    }

    /// Splits a fresh context using the source's random nonce derivation.
    ///
    /// `new_context_identity` is the caller-supplied AArch64 value that
    /// corresponds to `(uintptr_t)ctx_new` in `_mi_random_split`. Returning a
    /// new Rust value makes `ctx != ctx_new` structural. As in the C source,
    /// the caller must ensure the derived nonce is not the parent's nonce;
    /// the source checks that invariant only through `mi_assert_internal`.
    #[inline]
    pub(crate) fn split(&mut self, new_context_identity: u64) -> Self {
        let nonce = new_context_identity ^ self.next();
        debug_assert_ne!(self.nonce, nonce, "split contexts must not reuse a nonce");

        let mut child = Self {
            key: self.key,
            counter: 0,
            nonce,
            output: [0; OUTPUT_WORDS],
            output_available: 0,
            weak: self.weak,
        };
        // `chacha_split` eagerly creates the child block so the split context
        // starts with 16 available words and a counter already advanced once.
        child.refill();
        child
    }

    #[inline]
    fn refill(&mut self) {
        debug_assert_eq!(self.output_available, 0);

        let key: &Key = (&self.key).into();
        let nonce_bytes = self.nonce.to_le_bytes();
        let nonce: &LegacyNonce = (&nonce_bytes).into();
        let mut core = ChaCha20LegacyCore::new(key, nonce);
        core.set_block_pos(self.counter);
        let mut block = Array::default();
        core.write_keystream_block(&mut block);

        for index in 0..OUTPUT_WORDS {
            let offset = index * 4;
            self.output[index] = u32::from_le_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        // The library core clears its internal key/state on Drop under the
        // selected `zeroize` feature; clear the copied keystream block too.
        block.as_mut_slice().zeroize();
        self.output_available = OUTPUT_WORDS as u8;
        self.increment_counter();
    }

    #[inline]
    fn increment_counter(&mut self) {
        self.counter = self.counter.wrapping_add(1);
        if self.counter == 0 {
            // C increments `input[14]` directly rather than adding one to
            // the whole nonce. A low-nonce wrap therefore does *not* carry
            // into `input[15]`.
            self.nonce = (self.nonce & !LOW_NONCE_WORD_MASK)
                | u64::from((self.nonce as u32).wrapping_add(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn context() -> RandomContext {
        let mut context = RandomContext::from_entropy(secure_material(KEY), NONCE);
        context.counter = COUNTER;
        context
    }

    #[test]
    fn pinned_c_block_vector_uses_the_original_chacha_word_layout() {
        let mut context = context();
        let mut actual = [0; OUTPUT_WORDS];
        for word in &mut actual {
            *word = context.next32();
        }

        assert_eq!(actual, PINNED_C_BLOCK);
        assert_eq!(context.counter, COUNTER.wrapping_add(1));
        assert_eq!(context.nonce, NONCE);
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
        context.output_available = OUTPUT_WORDS as u8;

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
        assert_eq!(context.counter, COUNTER.wrapping_add(2));
        assert_eq!(context.output_available, 15);
        assert_eq!(context.output[0], 0);
    }

    #[test]
    fn counter_wrap_increments_only_the_low_nonce_word() {
        let mut context = RandomContext::from_entropy(
            secure_material(KEY),
            0x89ab_cdef_ffff_ffff,
        );
        context.counter = u64::MAX;

        let _ = context.next32();

        assert_eq!(context.counter, 0);
        assert_eq!(context.nonce, 0x89ab_cdef_0000_0000);
    }

    #[test]
    fn low_counter_word_wraps_into_the_high_counter_word_before_the_nonce() {
        let mut context = RandomContext::from_entropy(secure_material(KEY), NONCE);
        context.counter = 0x0000_0000_ffff_ffff;

        let _ = context.next32();

        assert_eq!(context.counter, 0x0000_0001_0000_0000);
        assert_eq!(context.nonce, NONCE);
    }

    #[test]
    fn split_consumes_a_nonzero_parent_word_and_prepares_an_independent_child() {
        let mut parent = context();
        let child = parent.split(0x0123_4567_89ab_cdef);

        assert_eq!(parent.output_available, 14);
        assert_eq!(parent.output[0], 0);
        assert_eq!(parent.output[1], 0);
        assert_eq!(child.counter, 1);
        assert_eq!(child.output_available, OUTPUT_WORDS as u8);
        assert_eq!(child.weak, parent.weak);
        // Pinned C `random.c` with this injected context identity.
        assert_eq!(child.nonce, 0xe5c4_b477_9cf2_f63e);

        let parent_next = parent.next64_raw();
        let mut child = child;
        let child_first = child.next64_raw();
        assert_eq!(parent_next, 0x1fdd_0f50_c471_20a3);
        assert_eq!(child_first, 0x8db9_bf23_0db0_a5f0);
        assert_eq!(parent.output_available, 12);
        assert_eq!(child.output_available, 14);
    }

    #[test]
    fn weak_contexts_remain_weak_across_split_and_only_reinitialize_when_weak() {
        let mut weak = RandomContext::from_entropy(weak_material(KEY), NONCE);
        assert!(weak.is_weak());
        let _ = weak.next32();
        assert_eq!(weak.output_available, 15);
        assert!(weak.reinitialize_if_weak(|| (secure_material([0x5a; 32]), 0x41)));
        assert!(!weak.is_weak());
        assert_eq!(weak.counter, 0);
        assert_eq!(weak.nonce, 0x41);
        assert_eq!(weak.output_available, 0);
        assert_eq!(weak.output, [0; OUTPUT_WORDS]);
        let mut acquired = false;
        assert!(!weak.reinitialize_if_weak(|| {
            acquired = true;
            (weak_material([0xa5; 32]), 0x42)
        }));
        assert!(!acquired, "strong contexts must not acquire replacement entropy");
        assert_eq!(weak.nonce, 0x41);

        let mut weak = RandomContext::from_entropy(weak_material(KEY), NONCE);
        assert!(weak.split(0xfeed_face_cafe_beef).is_weak());
    }
}
