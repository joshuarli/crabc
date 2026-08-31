//! Selected static Linux/x86-64 `getloadavg` C ABI boundary.
//!
//! This leaf owns exactly the historical GNU/BSD `int getloadavg(double *,
//! int)` spelling. Pinned musl obtains one Linux `sysinfo` snapshot, clamps a
//! positive request to three entries, and scales its three fixed-point load
//! words by `2^-16`. A zero request returns zero and a negative request returns
//! `-1` without reading or writing caller storage. It is not `/proc` or
//! system-file parsing, CPU-affinity or topology policy, general `sysconf`, a
//! system-information framework, or a Rust-facing load API.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/legacy/getloadavg.c::getloadavg` maps directly to [`getloadavg`]. Its
//! local public `struct sysinfo` and `sysinfo(&si)` call map to the existing
//! private [`super::system_observation::SysInfo`] and `sysinfo_raw` seam. The
//! raw status still travels through the shared C error translator just as
//! musl's public `sysinfo` wrapper does. With the function's valid local
//! record, Linux 5.10 completes that syscall; musl's subsequent read after a
//! failed `sysinfo` has no usable output contract. This safe Rust leaf returns
//! `-1` after publishing that raw errno instead of materializing arbitrary
//! failed-call load values, and does not select that source-undefined path.
//!
//! This private compatibility artifact does not select public `sysinfo` or
//! `uname`, processor/page-count helpers, `/proc`, `sysconf`, allocation,
//! locale, loader, libc.so, CRT, sysroot, family completion, promotion, or
//! public x86 support.

use core::{ffi::c_int, mem::MaybeUninit};

use super::{c_status, system_observation};

const MAX_LOAD_AVERAGES: c_int = 3;
const SI_LOAD_SCALE: f64 = 1.0 / 65_536.0;

/// Copy up to musl's three Linux load averages into caller-owned storage.
///
/// # Safety
///
/// When `count` is positive, `output` must designate at least
/// `min(count, 3)` writable `double` slots for the complete call. For zero or
/// negative `count`, this function neither reads nor writes `output`.
#[no_mangle]
pub unsafe extern "C" fn getloadavg(output: *mut f64, count: c_int) -> c_int {
    if count <= 0 {
        return if count == 0 { 0 } else { -1 };
    }

    let returned_count = count.min(MAX_LOAD_AVERAGES);
    let mut info = MaybeUninit::<system_observation::SysInfo>::zeroed();
    // SAFETY: this private all-zero record has the complete public x86
    // `struct sysinfo` layout. Linux writes its fixed ABI prefix through a
    // valid stack pointer, exactly as musl's local source record does.
    let raw_result = unsafe { system_observation::sysinfo_raw(info.as_mut_ptr()) };
    // Keep musl's public sysinfo error translation. Its C source subsequently
    // reads an uninitialized local record on failure, so it has no usable
    // output contract; retain the errno but make that unselected path safe.
    if c_status(raw_result) != 0 {
        return -1;
    }
    // SAFETY: all bytes were initialized to zero before Linux populated the
    // prefix containing `loads`; every field type accepts its all-zero value.
    let info = unsafe { info.assume_init() };

    let mut index = 0usize;
    while index < returned_count as usize {
        // SAFETY: the positive-count contract retains this in-range output
        // slot, and `returned_count` is clamped to musl's three load words.
        unsafe {
            output
                .add(index)
                .write(SI_LOAD_SCALE * info.loads[index] as f64);
        }
        index += 1;
    }
    returned_count
}
