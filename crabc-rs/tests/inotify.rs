use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crabc_rs::io::{self as native_io, FdFlags};
use crabc_rs::system::inotify::{CreateFlags, EventMask, Inotify};
use crabc_rs::{AsFd, Errno};

fn temporary_directory() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("monotonic wall clock")
        .as_nanos();
    std::env::temp_dir().join(format!("crabc-rs-inotify-{}-{nonce}", std::process::id()))
}

#[test]
fn owned_inotify_reports_byte_preserving_create_events() {
    let directory = temporary_directory();
    std::fs::create_dir(&directory).expect("create isolated inotify directory");

    let inotify = Inotify::new(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)
        .expect("create nonblocking inotify descriptor");
    assert!(native_io::fcntl_getfd(inotify.as_fd())
        .expect("read inotify descriptor flags")
        .contains(FdFlags::CLOEXEC));

    let watch = inotify
        .add_watch(&directory, EventMask::CREATE | EventMask::DELETE)
        .expect("watch isolated directory");
    let created = directory.join("created-by-crabc-rs");
    std::fs::write(&created, b"event payload").expect("create watched file");

    let mut bytes = [0u8; 512];
    let mut observed = false;
    for _ in 0..100 {
        match inotify.read_events(&mut bytes) {
            Ok(events) => {
                for event in events {
                    let event = event.expect("kernel inotify event record");
                    if event.watch() == Some(watch)
                        && event.mask().contains(EventMask::CREATE)
                        && event.name() == Some(b"created-by-crabc-rs".as_slice())
                    {
                        observed = true;
                    }
                }
                if observed {
                    break;
                }
            }
            Err(Errno::AGAIN) => thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("read inotify events: {error:?}"),
        }
    }

    let _ = std::fs::remove_file(&created);
    let _ = std::fs::remove_dir(&directory);
    assert!(observed, "did not observe the watched create event");
}
