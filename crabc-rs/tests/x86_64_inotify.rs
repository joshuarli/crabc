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

#[test]
fn x86_64_inotify_duplicate_retains_watch_and_batch_after_owner_drop() {
    use core::mem::MaybeUninit;
    use crabc_rs::event::epoll;
    use crabc_rs::time::Timespec;

    let directory = temporary_directory("duplicate-owner");
    std::fs::create_dir(&directory).unwrap();
    let inotify = Inotify::new(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).unwrap();
    let watch = inotify.add_watch(directory.as_os_str().as_bytes(), EventMask::CREATE).unwrap();
    let duplicate = io::dup(inotify.as_fd()).unwrap();
    let poller = epoll::create(epoll::CreateFlags::CLOEXEC).unwrap();
    epoll::add(&poller, inotify.as_fd(), epoll::EventData::new_u64(81), epoll::EventFlags::IN).unwrap();
    let first_name = OsString::from_vec(b"first-\xff".to_vec());
    std::fs::write(directory.join(&first_name), b"first").unwrap();
    let mut first_buffer = [0_u8; 512];
    let mut first_batch = inotify.read_events(&mut first_buffer).unwrap();
    let first_event = first_batch.next().unwrap().unwrap();
    assert_eq!(first_event.watch(), Some(watch));
    assert_eq!(first_event.mask(), EventMask::CREATE);
    assert_eq!(first_event.name(), Some(b"first-\xff".as_slice()));
    assert!(first_batch.next().is_none());
    drop(inotify);

    std::fs::write(directory.join("second"), b"second").unwrap();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut readiness = [MaybeUninit::uninit(); 1];
    let (ready, _) = epoll::wait(&poller, &mut readiness, Some(&zero)).unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].flags(), epoll::EventFlags::IN);
    assert_eq!(ready[0].data().u64(), 81);
    let mut second_buffer = [0_u8; 512];
    // Removing the watch does not flush records already queued for it.
    crabc_core::inotify::rm_watch(duplicate.as_raw_fd(), watch.as_raw()).unwrap();
    let count = io::read(&duplicate, &mut second_buffer).unwrap();
    assert!(count >= 39);
    assert_eq!(i32::from_ne_bytes(second_buffer[0..4].try_into().unwrap()), watch.as_raw());
    assert_eq!(u32::from_ne_bytes(second_buffer[4..8].try_into().unwrap()), EventMask::CREATE.bits());
    assert_eq!(&second_buffer[16..23], b"second\0");
    let first_length = 16 + u32::from_ne_bytes(second_buffer[12..16].try_into().unwrap()) as usize;
    assert_eq!(count, first_length + 16);
    assert_eq!(i32::from_ne_bytes(second_buffer[first_length..first_length + 4].try_into().unwrap()),
        watch.as_raw());
    assert_eq!(u32::from_ne_bytes(second_buffer[first_length + 4..first_length + 8].try_into().unwrap()),
        EventMask::IGNORED.bits());
    std::fs::write(directory.join("third"), b"third").unwrap();
    assert_eq!(io::read(&duplicate, &mut second_buffer), Err(Errno::AGAIN));
    drop(duplicate);
    let (ready, _) = epoll::wait(&poller, &mut readiness, Some(&zero)).unwrap();
    assert!(ready.is_empty());

    // Read-batch records borrow only caller storage, independently of the
    // descriptor or watch lifetime. A separate read cannot overwrite that storage.
    assert_eq!(first_event.watch(), Some(watch));
    assert_eq!(first_event.name(), Some(b"first-\xff".as_slice()));
    std::fs::remove_dir_all(directory).unwrap();
}
