//! Selected static Linux/x86-64 legacy rand48 C ABI provider.
//!
//! This is a source-faithful port of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT):
//! `src/prng/__seed48.c`, `__rand48_step.c`, `drand48.c`, `lrand48.c`,
//! `mrand48.c`, `lcong48.c`, `seed48.c`, and `srand48.c`. It owns exactly
//! `drand48`, `erand48`, `jrand48`, `lcong48`, `lrand48`, `mrand48`,
//! `nrand48`, `seed48`, and `srand48`.
//!
//! Musl's seven-word `__seed48` and seed48's three-word returned buffer are
//! process-global and intentionally unsynchronized. They are private to this
//! x86 provider, not TLS, and concurrent conflicting access has the same data
//! race boundary as musl. There is no errno, allocation, syscall, entropy,
//! locale, cancellation, or general random-family dependency.

use core::ffi::c_long;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 rand48 provider requires little-endian Linux/x86-64");

#[inline(always)]
unsafe fn global_state() -> *mut u16 {
    static mut SEED48: [u16; 7] = [0, 0, 0, 0xe66d, 0xdeec, 0x0005, 0x000b];
    // Address formation does not access the mutable global.
    core::ptr::addr_of_mut!(SEED48).cast()
}

#[inline(always)]
unsafe fn old_state() -> *mut u16 {
    static mut SEED48_OLD: [u16; 3] = [0; 3];
    // Address formation does not access the mutable global.
    core::ptr::addr_of_mut!(SEED48_OLD).cast()
}

#[inline(always)]
unsafe fn step(state: *mut u16, parameters: *const u16) -> u64 {
    // SAFETY: musl's source directly dereferences all seven valid caller/global
    // u16 words. Its pointer and concurrent-access preconditions are retained.
    unsafe {
        let value = core::ptr::read_unaligned(state) as u64
            | (core::ptr::read_unaligned(state.add(1)) as u64) << 16
            | (core::ptr::read_unaligned(state.add(2)) as u64) << 32;
        let multiplier = core::ptr::read_unaligned(parameters) as u64
            | (core::ptr::read_unaligned(parameters.add(1)) as u64) << 16
            | (core::ptr::read_unaligned(parameters.add(2)) as u64) << 32;
        let next = multiplier
            .wrapping_mul(value)
            .wrapping_add(core::ptr::read_unaligned(parameters.add(3)) as u64);
        core::ptr::write_unaligned(state, next as u16);
        core::ptr::write_unaligned(state.add(1), (next >> 16) as u16);
        core::ptr::write_unaligned(state.add(2), (next >> 32) as u16);
        next & 0x0000_ffff_ffff_ffff
    }
}

#[inline(always)]
unsafe fn global_parameters() -> *const u16 {
    // SAFETY: global_state only forms the process-global storage address.
    unsafe { global_state().add(3).cast_const() }
}

/// Advance caller-owned rand48 state and return its nonnegative 31-bit value.
///
/// # Safety
/// `state` must point to three valid writable `unsigned short` words.
#[no_mangle]
pub unsafe extern "C" fn nrand48(state: *mut u16) -> c_long {
    unsafe { (step(state, global_parameters()) >> 17) as c_long }
}

/// Advance the private global rand48 state and return its nonnegative value.
#[no_mangle]
pub unsafe extern "C" fn lrand48() -> c_long {
    unsafe { (step(global_state(), global_parameters()) >> 17) as c_long }
}

/// Advance caller-owned rand48 state and return its signed 32-bit value.
///
/// # Safety
/// `state` must point to three valid writable `unsigned short` words.
#[no_mangle]
pub unsafe extern "C" fn jrand48(state: *mut u16) -> c_long {
    unsafe { (step(state, global_parameters()) >> 16) as u32 as i32 as c_long }
}

/// Advance the private global rand48 state and return its signed value.
#[no_mangle]
pub unsafe extern "C" fn mrand48() -> c_long {
    unsafe { (step(global_state(), global_parameters()) >> 16) as u32 as i32 as c_long }
}

/// Set the private rand48 state from musl's historical signed-long seed form.
#[no_mangle]
pub unsafe extern "C" fn srand48(seed: c_long) {
    unsafe {
        let state = global_state();
        core::ptr::write_unaligned(state, 0x330e);
        core::ptr::write_unaligned(state.add(1), seed as u16);
        core::ptr::write_unaligned(state.add(2), (seed >> 16) as u16);
    }
}

/// Replace the private state and return the prior state through musl's one
/// shared three-word result buffer.
///
/// # Safety
/// `state` must point to three valid readable `unsigned short` words.
#[no_mangle]
pub unsafe extern "C" fn seed48(state: *mut u16) -> *mut u16 {
    unsafe {
        let seed = global_state();
        let old = old_state();
        for index in 0..3 {
            core::ptr::write_unaligned(old.add(index), core::ptr::read_unaligned(seed.add(index)));
        }
        for index in 0..3 {
            core::ptr::write_unaligned(seed.add(index), core::ptr::read_unaligned(state.add(index)));
        }
        old
    }
}

/// Advance caller-owned rand48 state and return the exact musl binary64 value.
///
/// # Safety
/// `state` must point to three valid writable `unsigned short` words.
#[no_mangle]
pub unsafe extern "C" fn erand48(state: *mut u16) -> f64 {
    unsafe { f64::from_bits(0x3ff0_0000_0000_0000 | (step(state, global_parameters()) << 4)) - 1.0 }
}

/// Advance the private global rand48 state and return the exact binary64 value.
#[no_mangle]
pub unsafe extern "C" fn drand48() -> f64 {
    unsafe { f64::from_bits(0x3ff0_0000_0000_0000 | (step(global_state(), global_parameters()) << 4)) - 1.0 }
}

/// Replace both private state and LCG parameters from seven caller-owned words.
///
/// # Safety
/// `parameters` must point to seven valid readable `unsigned short` words.
#[no_mangle]
pub unsafe extern "C" fn lcong48(parameters: *mut u16) {
    unsafe {
        let seed = global_state();
        for index in 0..7 {
            core::ptr::write_unaligned(seed.add(index), core::ptr::read_unaligned(parameters.add(index)));
        }
    }
}
