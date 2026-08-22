//! Link-free no-std proof for the M10 native `copy_file_range` seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags};

const INPUT_PATH: &[u8] = b"/tmp/crabc-rs-m10-copy-file-range-probe-input";
const OUTPUT_PATH: &[u8] = b"/tmp/crabc-rs-m10-copy-file-range-probe-output";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_copy_file_range_direct_probe() -> i32 {
    let _ = fs::unlink(INPUT_PATH);
    let _ = fs::unlink(OUTPUT_PATH);
    let input = match fs::open(
        INPUT_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    let output = match fs::open(
        OUTPUT_PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    let mut input_offset = 0;
    let mut output_offset = 0;
    let status = match fs::copy_file_range(
        &input,
        Some(&mut input_offset),
        &output,
        Some(&mut output_offset),
        0,
    ) {
        Ok(0) => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    };

    drop(output);
    drop(input);
    let _ = fs::unlink(INPUT_PATH);
    let _ = fs::unlink(OUTPUT_PATH);
    status
}
