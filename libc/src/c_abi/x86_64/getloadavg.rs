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
//! local public `struct sysinfo` and `sysinfo(&si)` call retain musl's source
//! spelling: the archive leaves it available to an application override, and
//! the shared final link resolves it to the localized `__lsysinfo` body. With
//! the function's valid local record, Linux 5.10 completes that syscall;
//! musl's subsequent read after a failed `sysinfo` has no usable output
//! contract. This safe Rust leaf returns `-1` after the C boundary publishes
//! that errno instead of materializing arbitrary failed-call load values, and
//! does not select that source-undefined path.
//!
//! This private compatibility artifact reaches the separately selected public
//! `sysinfo` alias; it does not select `uname`, processor/page-count helpers,
//! `/proc`, `sysconf`, allocation,
//! locale, loader, libc.so, CRT, sysroot, family completion, promotion, or
//! public x86 support.

use core::{ffi::c_int, mem::MaybeUninit};

use super::system_observation;

unsafe extern "C" {
    // getloadavg.c names public sysinfo. Preserve its archive override point;
    // the checked shared-libc dynamic list localizes that ordinary source call.
    #[link_name = "sysinfo"]
    fn public_sysinfo(output: *mut system_observation::SysInfo) -> c_int;
}

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
    // SAFETY: the local all-zero Rust record is a valid complete x86 public
    // sysinfo object. The selected C call retains the source's public/shared
    // ownership split and writes its fixed ABI prefix through this stack slot.
    if unsafe { public_sysinfo(info.as_mut_ptr()) } != 0 {
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
