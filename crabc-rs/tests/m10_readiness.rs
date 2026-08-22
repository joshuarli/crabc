use core::mem::MaybeUninit;

use crabc_rs::{event, io, pipe, time, Errno};

#[test]
fn legacy_epoll_create_and_masked_wait_use_direct_linux_seams() {
    assert!(matches!(event::epoll::create_legacy(0), Err(Errno::INVAL)));
    let epoll = event::epoll::create_legacy(1).expect("legacy epoll constructor");
    let (reader, writer) = pipe::pipe().expect("readiness pipe");
    event::epoll::add(
        &epoll,
        &reader,
        event::epoll::EventData::new_u64(0xfeed),
        event::epoll::EventFlags::IN,
    )
    .expect("register pipe reader");

    let timeout = time::Timespec::default();
    let empty = crabc_rs::signal::SignalSet::EMPTY;
    let mut events = [MaybeUninit::uninit(); 2];
    let (ready, _) = event::epoll::wait_with_mask(
        &epoll,
        &mut events,
        Some(&timeout),
        Some(&empty),
    )
    .expect("masked empty epoll wait");
    assert!(ready.is_empty());

    assert_eq!(io::write(&writer, b"r").expect("write readiness byte"), 1);
    let (ready, _) = event::epoll::wait_with_mask(
        &epoll,
        &mut events,
        Some(&timeout),
        Some(&empty),
    )
    .expect("masked epoll wait for readable pipe");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].data.u64(), 0xfeed);
}

#[test]
fn select_sets_are_rustix_shaped_and_pselect_preserves_timeout() {
    let (reader, writer) = pipe::pipe().expect("select pipe");
    let nfds = reader.as_raw_fd() + 1;
    let elements = event::fd_set_num_elements(0, nfds);
    let mut readfds = std::vec![event::FdSetElement::default(); elements];
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    assert_eq!(event::fd_set_bound(&readfds), nfds);
    assert_eq!(event::FdSetIter::new(&readfds).collect::<std::vec::Vec<_>>(), vec![reader.as_raw_fd()]);

    let timeout = time::Timespec::default();
    // SAFETY: The pipe reader remains owned and open, and the set has enough
    // storage for every descriptor below nfds.
    let ready = unsafe { event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) }
        .expect("empty select");
    assert_eq!(ready, 0);

    assert_eq!(io::write(&writer, b"s").expect("write select byte"), 1);
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    let timeout = time::Timespec::default();
    // SAFETY: The descriptor and set remain valid for this direct syscall.
    let ready = unsafe {
        event::pselect(
            nfds,
            Some(&mut readfds),
            None,
            None,
            Some(&timeout),
            Some(&crabc_rs::signal::SignalSet::EMPTY),
        )
    }
    .expect("masked pselect");
    assert_eq!(ready, 1);
    assert_eq!(event::FdSetIter::new(&readfds).collect::<std::vec::Vec<_>>(), vec![reader.as_raw_fd()]);

    event::fd_set_remove(&mut readfds, reader.as_raw_fd());
    assert_eq!(event::fd_set_bound(&readfds), 0);
}
