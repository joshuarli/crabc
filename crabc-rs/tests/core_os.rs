use core::mem::MaybeUninit;

use crabc_rs::{event, io, mm, net, pipe, rand, time};

#[test]
fn pipe_random_and_monotonic_clock_use_direct_kernel_contracts() {
    let (reader, writer) = pipe::pipe_with(pipe::PipeFlags::CLOEXEC)
        .expect("create a close-on-exec pipe through the direct kernel seam");
    assert_eq!(io::write(&writer, b"os").expect("write pipe payload"), 2);
    let mut received = [MaybeUninit::uninit(); 4];
    let (received, remainder) = io::read(&reader, &mut received).expect("read pipe payload");
    assert_eq!(received, b"os");
    assert_eq!(remainder.len(), 2);

    let mut random = [MaybeUninit::uninit(); 32];
    let (random, remainder) = rand::getrandom(&mut random, rand::GetRandomFlags::empty())
        .expect("obtain direct kernel random bytes");
    assert_eq!(random.len() + remainder.len(), 32);
    assert!(!random.is_empty());

    let resolution = time::clock_getres(time::ClockId::Monotonic);
    assert!(resolution.tv_sec >= 0);
    assert!((0..1_000_000_000).contains(&resolution.tv_nsec));
    let before = time::clock_gettime(time::ClockId::Monotonic);
    let after = time::clock_gettime(time::ClockId::Monotonic);
    assert!(
        (after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec),
        "monotonic clock must not move backwards",
    );
}

#[test]
fn eventfd_and_poll_report_direct_kernel_readiness() {
    let counter = event::eventfd(0, event::EventfdFlags::CLOEXEC)
        .expect("create an event counter through the direct kernel seam");
    assert_eq!(
        io::write(&counter, &1_u64.to_ne_bytes()).expect("increment counter"),
        8
    );

    let mut fds = [event::PollFd::new(&counter, event::PollFlags::IN)];
    assert_eq!(
        event::poll(&mut fds, Some(&time::Timespec::default())).expect("poll counter"),
        1
    );
    assert!(fds[0].revents().contains(event::PollFlags::IN));

    let mut value = [0_u8; 8];
    assert_eq!(io::read(&counter, &mut value).expect("read counter"), 8);
    assert_eq!(u64::from_ne_bytes(value), 1);
}

#[test]
fn socketpair_and_mapping_use_direct_kernel_contracts() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create a close-on-exec Unix socket pair through the direct kernel seam");
    assert_eq!(
        net::send(&sender, b"os", net::SendFlags::empty()).expect("send payload"),
        2
    );
    let mut received = [MaybeUninit::uninit(); 4];
    let ((received, remainder), received_length) =
        net::recv(&receiver, &mut received, net::RecvFlags::empty()).expect("receive payload");
    assert_eq!(received_length, 2);
    assert_eq!(received, b"os");
    assert_eq!(remainder.len(), 2);

    let length = 4096;
    let mapping = unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            length,
            mm::ProtFlags::READ | mm::ProtFlags::WRITE,
            mm::MapFlags::PRIVATE,
        )
    }
    .expect("map an anonymous page through the direct kernel seam");
    let byte = mapping.cast::<u8>();
    unsafe { byte.write(0x5a) };
    unsafe { mm::mprotect(mapping, length, mm::MprotectFlags::READ) }
        .expect("make mapped page read-only");
    assert_eq!(unsafe { byte.read() }, 0x5a);
    unsafe {
        mm::mprotect(
            mapping,
            length,
            mm::MprotectFlags::READ | mm::MprotectFlags::WRITE,
        )
    }
    .expect("restore mapped page write permission");
    unsafe { mm::munmap(mapping, length) }.expect("unmap anonymous page");
}
