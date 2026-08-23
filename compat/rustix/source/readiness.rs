use api::fd::{AsFd, AsRawFd};
use api::{event, io, pipe};

fn main() {
    let (reader, writer) = pipe::pipe().expect("create readiness pipe");
    let borrowed_reader = reader.as_fd();
    let raw_reader = AsRawFd::as_raw_fd(&borrowed_reader);
    let nfds = raw_reader + 1;
    let elements = event::fd_set_num_elements(0, nfds);
    let mut readfds = vec![event::FdSetElement::default(); elements];
    event::fd_set_insert(&mut readfds, raw_reader);
    let timeout = event::Timespec::default();
    // SAFETY: The pipe remains open and the descriptor set has enough storage
    // for every descriptor below `nfds`.
    assert_eq!(
        unsafe { event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) },
        Ok(0)
    );

    assert_eq!(io::write(&writer, b"r"), Ok(1));
    event::fd_set_insert(&mut readfds, raw_reader);
    let timeout = event::Timespec::default();
    // SAFETY: The same descriptor and set remain valid for this direct wait.
    assert_eq!(
        unsafe { event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) },
        Ok(1)
    );
    assert_eq!(event::FdSetIter::new(&readfds).collect::<Vec<_>>(), vec![raw_reader]);
    println!("native-readiness ok");
}
