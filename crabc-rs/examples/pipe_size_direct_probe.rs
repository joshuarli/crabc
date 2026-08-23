#![no_std]

//! Link-free no-std proof for the native pipe-capacity observation.

use crabc_rs::pipe;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_pipe_size_direct_probe() -> i32 {
    let (reader, writer) = match pipe::pipe() {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    let reader_size = match pipe::fcntl_getpipe_size(&reader) {
        Ok(size) => size,
        Err(error) => return -error.raw(),
    };
    let writer_size = match pipe::fcntl_getpipe_size(&writer) {
        Ok(size) => size,
        Err(error) => return -error.raw(),
    };
    if reader_size == 0 || reader_size != writer_size {
        return 1;
    }
    0
}
