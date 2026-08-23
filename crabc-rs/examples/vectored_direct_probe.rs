//! Link-free no-std proof for the native vectored descriptor-I/O seam.
//!
//! The source is intentionally unregistered in the focused slice. The
//! verifier can compile it as a static library and call the exported symbol
//! without routing through the public C ABI or TLS `errno`.

#![no_std]

use crabc_rs::{io, pipe};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_vectored_direct_probe() -> i32 {
    let (reader, writer) = match pipe::pipe() {
        Ok(pipe) => pipe,
        Err(error) => return -error.raw(),
    };

    let no_writes: [io::IoSlice<'static>; 0] = [];
    if io::writev(&writer, &no_writes) != Ok(0) {
        return 1;
    }

    let writes = [io::IoSlice::new(b"pro"), io::IoSlice::new(b"be")];
    if io::writev(&writer, &writes) != Ok(5) {
        return 2;
    }

    let mut first = [0_u8; 3];
    let mut second = [0xa5_u8; 3];
    let read = {
        let mut reads = [
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
        ];
        match io::readv(&reader, &mut reads) {
            Ok(read) => read,
            Err(error) => return -error.raw(),
        }
    };

    if read != 5 || first != *b"pro" || second[..2] != *b"be" || second[2] != 0xa5 {
        return 3;
    }
    0
}
