use api::{event, io, time};

fn main() {
    let counter = event::eventfd(0, event::EventfdFlags::CLOEXEC).expect("eventfd");
    assert_eq!(io::write(&counter, &1_u64.to_ne_bytes()).unwrap(), 8);

    let mut fds = [event::PollFd::new(&counter, event::PollFlags::IN)];
    assert_eq!(event::poll(&mut fds, Some(&time::Timespec::default())).unwrap(), 1);
    assert!(fds[0].revents().contains(event::PollFlags::IN));

    let mut value = [0_u8; 8];
    assert_eq!(io::read(&counter, &mut value).unwrap(), 8);
    assert_eq!(u64::from_ne_bytes(value), 1);
    println!("m3-event ok");
}
