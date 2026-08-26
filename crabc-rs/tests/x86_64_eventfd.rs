#![cfg(target_arch = "x86_64")]

use crabc_rs::event::{self, EventfdFlags};
use crabc_rs::io::{self, FdFlags};
use crabc_rs::Errno;

#[test]
fn x86_64_eventfd_nonblock_cloexec_accumulates_resets_and_reports_eagain() {
    let counter = event::eventfd(
        0,
        EventfdFlags::NONBLOCK | EventfdFlags::CLOEXEC,
    )
    .expect("create a nonblocking close-on-exec eventfd counter");

    // `fcntl_getfd` uses the direct kernel seam, so this observes the
    // descriptor flag installed by `EFD_CLOEXEC` without relying on a C ABI.
    assert!(
        io::fcntl_getfd(&counter)
            .expect("read eventfd descriptor flags")
            .contains(FdFlags::CLOEXEC),
        "EFD_CLOEXEC must install FD_CLOEXEC",
    );
    assert_eq!(event::eventfd_read(&counter), Err(Errno::AGAIN));

    event::eventfd_write(&counter, 5).expect("write first eventfd increment");
    event::eventfd_write(&counter, 7).expect("write second eventfd increment");
    assert_eq!(event::eventfd_read(&counter), Ok(12));
    assert_eq!(
        event::eventfd_read(&counter),
        Err(Errno::AGAIN),
        "a non-semaphore read resets the counter to zero",
    );
}

#[test]
fn x86_64_eventfd_semaphore_reads_one_and_decrements() {
    let counter = event::eventfd(0, EventfdFlags::NONBLOCK | EventfdFlags::SEMAPHORE)
        .expect("create a nonblocking semaphore eventfd");

    event::eventfd_write(&counter, 3).expect("seed semaphore counter");
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert_eq!(event::eventfd_read(&counter), Ok(1));
    assert_eq!(event::eventfd_read(&counter), Err(Errno::AGAIN));
}

#[test]
fn x86_64_eventfd_rejects_the_all_ones_counter_record() {
    let counter = event::eventfd(0, EventfdFlags::NONBLOCK)
        .expect("create a nonblocking eventfd counter");

    assert_eq!(
        event::eventfd_write(&counter, u64::MAX),
        Err(Errno::INVAL),
        "Linux reserves the all-ones eventfd record",
    );
}
