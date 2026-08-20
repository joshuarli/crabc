//! Link-free assembly probe for the M3 direct core-OS boundary.
//!
//! This no-std static library monomorphizes the first verified vertical slice
//! of pipes, random bytes, known clocks, event polling, local sockets, and
//! virtual memory. Its verifier proves that these paths contain the expected
//! Linux/AArch64 syscalls and no public C ABI or TLS-errno call.

#![cfg_attr(not(feature = "std"), no_std)]

use core::mem::MaybeUninit;

use crabc_rs::{event, mm, net, pipe, rand, time};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m3_direct_probe() -> i32 {
    let (reader, writer) = match pipe::pipe_with(pipe::PipeFlags::CLOEXEC) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    drop(reader);
    drop(writer);

    let mut random = [MaybeUninit::uninit(); 1];
    if let Err(error) = rand::getrandom(&mut random, rand::GetRandomFlags::empty()) {
        return -error.raw();
    }
    let _ = time::clock_getres(time::ClockId::Monotonic);
    let _ = time::clock_gettime(time::ClockId::Monotonic);

    let counter = match event::eventfd(0, event::EventfdFlags::CLOEXEC) {
        Ok(counter) => counter,
        Err(error) => return -error.raw(),
    };
    let mut fds = [event::PollFd::new(&counter, event::PollFlags::IN)];
    if let Err(error) = event::poll(&mut fds, Some(&time::Timespec::default())) {
        return -error.raw();
    }
    drop(counter);

    let (sender, receiver) = match net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = net::send(&sender, b"M3", net::SendFlags::empty()) {
        return -error.raw();
    }
    let mut received = [MaybeUninit::uninit(); 2];
    if let Err(error) = net::recv(&receiver, &mut received, net::RecvFlags::empty()) {
        return -error.raw();
    }
    drop(sender);
    drop(receiver);

    let mapping = match unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            4096,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    } {
        Ok(mapping) => mapping,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = unsafe { mm::mprotect(mapping, 4096, mm::MprotectFlags::READ) } {
        return -error.raw();
    }
    if let Err(error) = unsafe { mm::munmap(mapping, 4096) } {
        return -error.raw();
    }
    0
}
