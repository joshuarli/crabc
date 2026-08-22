//! Link-free no-std proof for the M10 native supplementary-group seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::process::{self, Gid};

const PROBE_GROUP_CAPACITY: usize = 64;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_getgroups_direct_probe() -> i32 {
    let count = match process::getgroups_count() {
        Ok(count) => count,
        Err(error) => return -error.raw(),
    };
    if count > PROBE_GROUP_CAPACITY {
        return 1;
    }

    let mut groups = [MaybeUninit::<Gid>::uninit(); PROBE_GROUP_CAPACITY];
    let (initialized, untouched) = match process::getgroups(&mut groups) {
        Ok(groups) => groups,
        Err(error) => return -error.raw(),
    };
    if initialized.len() != count || untouched.len() != PROBE_GROUP_CAPACITY - count {
        return 2;
    }
    for group in initialized {
        if group.as_raw() == u32::MAX {
            return 3;
        }
    }
    0
}
