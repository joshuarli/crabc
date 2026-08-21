//! Runtime proof for M8's owned native buffered memory-stream boundary.
//!
//! This archive is linked into a C fixture running under crabc's loader. It
//! reaches the private singleton table rather than importing public stdio or
//! errno symbols, while Drop repeatedly closes libc-owned stream allocations.

#![cfg_attr(not(feature = "std"), no_std)]

use crabc_rs::cfile::{CFile, FileMode, SeekFrom};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m8_cfile_direct_probe(buffer: *mut u8, length: usize) -> i32 {
    if buffer.is_null() || length < 4 {
        return 22;
    }
    // SAFETY: The C runtime fixture passes a valid mutable array that remains
    // live for this synchronous probe. CFile retains its exclusive borrow
    // until every close-on-drop iteration completes.
    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, length) };
    for iteration in 0..1024 {
        let mut stream = match CFile::from_memory(buffer, FileMode::WriteUpdate) {
            Ok(stream) => stream,
            Err(error) => return -error.raw(),
        };
        if stream.write(b"M8") != Ok(2) {
            return 1;
        }
        if stream.flush().is_err() {
            return 2;
        }
        if stream.seek(SeekFrom::Start(0)) != Ok(0) {
            return 3;
        }
        let mut read = [0; 2];
        if stream.read(&mut read) != Ok(2) || read != *b"M8" {
            return 4;
        }
        let mut eof = [0; 1];
        if stream.read(&mut eof) != Ok(0) || !matches!(stream.eof(), Ok(true)) {
            return 5;
        }
        if stream.reset().is_err() || stream.tell() != Ok(0) {
            return 6;
        }
        // Drop closes the first 1,023 iterations and exercises the libc-owned
        // FILE and cookie reclamation path. Close the final iteration
        // explicitly so its final flush status is also observable.
        if iteration == 1023 && stream.close().is_err() {
            return 7;
        }
    }
    0
}
