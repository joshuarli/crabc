use crabc_rs::event;
use crabc_rs::Errno;

#[test]
fn eventfd_helpers_accumulate_and_consume_the_typed_counter_record() {
    let counter = event::eventfd(
        0,
        event::EventfdFlags::CLOEXEC | event::EventfdFlags::NONBLOCK,
    )
    .expect("create a nonblocking eventfd counter");

    assert_eq!(event::eventfd_read(&counter), Err(Errno::AGAIN));
    event::eventfd_write(&counter, 5).expect("write first eventfd increment");
    event::eventfd_write(&counter, 7).expect("write second eventfd increment");
    assert_eq!(
        event::eventfd_read(&counter).expect("read accumulated eventfd counter"),
        12,
    );
    assert_eq!(
        event::eventfd_read(&counter),
        Err(Errno::AGAIN),
        "a non-semaphore read consumes the counter and leaves it empty",
    );
}

#[test]
fn eventfd_write_preserves_linux_invalid_u64_record_error() {
    let counter = event::eventfd(0, event::EventfdFlags::NONBLOCK)
        .expect("create a nonblocking eventfd counter");

    assert_eq!(
        event::eventfd_write(&counter, u64::MAX),
        Err(Errno::INVAL),
        "Linux reserves the all-ones eventfd record",
    );
}
