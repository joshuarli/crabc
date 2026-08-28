#![cfg(target_arch = "x86_64")]

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crabc_rs::io::{self, FdFlags};
use crabc_rs::system::inotify::{CreateFlags, EventMask, Inotify};
use crabc_rs::Errno;

fn temporary_directory(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("crabc-x86-inotify-{}-{label}-{nonce}", std::process::id()))
}

fn read_until<F>(inotify: &Inotify, buffer: &mut [u8], mut matches: F)
where
    F: FnMut(&crabc_rs::system::inotify::Event<'_>) -> bool,
{
    for _ in 0..100 {
        match inotify.read_events(buffer) {
            Ok(events) => {
                for event in events {
                    let event = event.expect("kernel inotify record");
                    if matches(&event) {
                        return;
                    }
                }
            }
            Err(Errno::AGAIN) => thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("read inotify events: {error:?}"),
        }
    }
    panic!("timed out waiting for inotify event");
}

#[test]
fn x86_64_inotify_owns_nonblocking_cloexec_watches_and_byte_events() {
    let directory = temporary_directory("events");
    std::fs::create_dir(&directory).expect("create isolated directory");

    let inotify = Inotify::new(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)
        .expect("create inotify descriptor");
    assert!(io::fcntl_getfd(inotify.as_fd())
        .expect("inotify descriptor flags")
        .contains(FdFlags::CLOEXEC));
    let mut bytes = [0_u8; 512];
    assert!(matches!(inotify.read_events(&mut bytes), Err(Errno::AGAIN)));

    let watch = inotify
        .add_watch(
            directory.as_os_str().as_bytes(),
            EventMask::CREATE | EventMask::DELETE,
        )
        .expect("watch isolated directory");
    let name = OsString::from_vec(b"created-\xff".to_vec());
    let created = directory.join(&name);
    std::fs::write(&created, b"event payload").expect("create watched byte name");

    read_until(&inotify, &mut bytes, |event| {
        event.watch() == Some(watch)
            && event.mask().contains(EventMask::CREATE)
            && event.name() == Some(b"created-\xff".as_slice())
    });

    std::fs::remove_file(&created).expect("remove watched byte name");
    inotify.remove_watch(watch).expect("remove live watch");
    read_until(&inotify, &mut bytes, |event| {
        event.watch() == Some(watch) && event.mask().contains(EventMask::IGNORED)
    });
    assert!(matches!(inotify.remove_watch(watch), Err(Errno::INVAL)));

    std::fs::remove_dir(&directory).expect("remove isolated directory");
}

#[test]
fn x86_64_inotify_preserves_direct_validation_and_noalloc_path_boundaries() {
    assert!(matches!(
        Inotify::new(CreateFlags::from_bits_retain(0x0000_0001)),
        Err(Errno::INVAL)
    ));

    let inotify = Inotify::new(CreateFlags::NONBLOCK).expect("create inotify descriptor");
    let missing = format!("/crabc-x86-inotify-missing-{}", std::process::id());
    assert!(matches!(
        inotify.add_watch(missing.as_str(), EventMask::CREATE),
        Err(Errno::NOENT)
    ));
    assert!(matches!(
        inotify.add_watch(&b"/inotify\0name"[..], EventMask::CREATE),
        Err(Errno::INVAL)
    ));

    #[cfg(not(feature = "alloc"))]
    {
        let overlong = [b'x'; crabc_rs::fs::SMALL_PATH_BUFFER_SIZE];
        assert!(matches!(
            inotify.add_watch(&overlong, EventMask::CREATE),
            Err(Errno::NAMETOOLONG)
        ));
    }
}
