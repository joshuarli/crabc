//! Linux/x86-64 evidence for the private PTY ownership and naming seam.

#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;

use crabc_rs::{io, pty, Errno};

fn flags() -> pty::OpenptFlags {
    pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC
}

#[test]
fn x86_64_pair_requires_read_write_before_touching_devpts() {
    assert!(matches!(
        pty::PtyPair::open(pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC),
        Err(Errno::INVAL)
    ));
}

#[test]
fn x86_64_pair_owns_both_descriptors_and_resolves_slave_name() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");

    let mut storage = [MaybeUninit::uninit(); 32];
    let borrowed = pty::ptsname_into(pair.master(), &mut storage)
        .expect("resolve PTY name into caller storage");
    assert!(borrowed.to_bytes().starts_with(b"/dev/pts/"));

    #[cfg(feature = "alloc")]
    {
        let owned =
            pty::ptsname(pair.master(), b"stale-name".to_vec()).expect("resolve owned PTY name");
        assert_eq!(borrowed.to_bytes(), owned.as_bytes());
    }

    let (master, slave) = pair.into_parts();
    assert!(master.as_raw_fd() >= 0);
    assert!(slave.as_raw_fd() >= 0);
}

#[test]
fn x86_64_ptsname_into_rejects_short_caller_storage() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");
    let mut storage = [MaybeUninit::uninit(); 4];

    assert_eq!(
        pty::ptsname_into(pair.master(), &mut storage),
        Err(Errno::RANGE)
    );
}

#[test]
fn x86_64_slave_output_reaches_its_owned_master() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");

    assert_eq!(
        io::write(pair.slave(), b"x").expect("write one byte through PTY slave"),
        1
    );
    let mut received = [0_u8; 1];
    assert_eq!(
        io::read(pair.master(), &mut received).expect("read one byte from PTY master"),
        1
    );
    assert_eq!(received, *b"x");
}
