//! Link-free no-std proof for the owned POSIX message-queue syscall seam.

#![no_std]
#![crate_type = "staticlib"]

use core::ffi::CStr;

use crabc_rs::fs::Mode;
use crabc_rs::ipc::{self, CreateFlags, MessagePriority, OpenFlags, QueueAttributes};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ipc_direct_probe() -> i32 {
    let name = unsafe { CStr::from_bytes_with_nul_unchecked(b"/crabc-rs-ipc-probe\0") };
    let _ = ipc::unlink(name);
    let attributes = match QueueAttributes::new(2, 32) {
        Ok(attributes) => attributes,
        Err(error) => return -error.raw(),
    };
    let queue = match ipc::create(
        name,
        OpenFlags::RDWR | OpenFlags::NONBLOCK | OpenFlags::CLOEXEC,
        CreateFlags::EXCLUSIVE,
        Mode::RUSR | Mode::WUSR,
        attributes,
    ) {
        Ok(queue) => queue,
        Err(error) => return -error.raw(),
    };
    if queue.attributes().is_err()
        || queue
            .send(b"probe", MessagePriority::new(1).unwrap())
            .is_err()
    {
        let _ = queue.close();
        let _ = ipc::unlink(name);
        return 1;
    }
    let mut buffer = [0_u8; 32];
    if queue.receive(&mut buffer).is_err() {
        let _ = queue.close();
        let _ = ipc::unlink(name);
        return 2;
    }
    let _ = queue.close();
    let _ = ipc::unlink(name);
    0
}
