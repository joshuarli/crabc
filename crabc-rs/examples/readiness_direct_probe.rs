//! Link-free no-std proof for the direct readiness slice.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::{event, pipe, time};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_readiness_direct_probe() -> i32 {
    let (reader, _writer) = match pipe::pipe() {
        Ok(pipe) => pipe,
        Err(error) => return -error.raw(),
    };
    let epoll = match event::epoll::create_legacy(1) {
        Ok(epoll) => epoll,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(1),
        event::epoll::EventFlags::IN,
    ) {
        return -error.raw();
    }

    let timeout = time::Timespec::default();
    let empty = crabc_rs::signal::SignalSet::EMPTY;
    let mut events = [MaybeUninit::uninit(); 1];
    match event::epoll::wait_with_mask(&epoll, &mut events, Some(&timeout), Some(&empty)) {
        Ok((ready, _)) if ready.is_empty() => {}
        Ok(_) => return 1,
        Err(error) => return -error.raw(),
    }

    let nfds = reader.as_raw_fd() + 1;
    let mut readfds = [event::FdSetElement::default(); 16];
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    // SAFETY: `reader` remains open and the one-element bit vector contains
    // every descriptor below `nfds` used by this probe.
    match unsafe { event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) } {
        Ok(0) => {}
        Ok(_) => return 2,
        Err(error) => return -error.raw(),
    }
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    // SAFETY: The same descriptor and initialized bit vector remain valid for
    // the direct pselect6 call.
    match unsafe {
        event::pselect(
            nfds,
            Some(&mut readfds),
            None,
            None,
            Some(&timeout),
            Some(&empty),
        )
    } {
        Ok(0) => 0,
        Ok(_) => 3,
        Err(error) => -error.raw(),
    }
}
