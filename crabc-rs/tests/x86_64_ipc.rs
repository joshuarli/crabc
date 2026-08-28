#![cfg(target_arch = "x86_64")]

use crabc_rs::fs::Mode;
use crabc_rs::io::FdFlags;
use crabc_rs::ipc::{
    self, CreateFlags, MessagePriority, OpenFlags, QueueAttributes, QueueFlags, Timespec,
};
use crabc_rs::{AsFd, Errno};

/// Owns the POSIX namespace spelling independently from queue descriptor
/// lifetime. A stale fixture is unlinked before creation, and Drop removes the
/// name even when an assertion below fails; the queue descriptors themselves
/// retain Linux's unlink-after-open lifetime.
struct QueueName(String);

impl QueueName {
    fn new(suffix: &str) -> Self {
        let name = format!("/crabc-x86-mq-{}-{suffix}", std::process::id());
        let _ = ipc::unlink(name.as_str());
        Self(name)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for QueueName {
    fn drop(&mut self) {
        let _ = ipc::unlink(self.0.as_str());
    }
}

fn create_queue(
    name: &QueueName,
    flags: OpenFlags,
    max_messages: u64,
    message_size: usize,
) -> ipc::MessageQueue {
    ipc::create(
        name.as_str(),
        flags,
        CreateFlags::EXCLUSIVE,
        Mode::RUSR | Mode::WUSR,
        QueueAttributes::new(max_messages, message_size).expect("valid queue attributes"),
    )
    .expect("create POSIX message queue")
}

#[test]
fn x86_64_ipc_owns_attributes_priorities_nonblocking_and_unlink_lifetime() {
    let name = QueueName::new("basic");
    let queue = create_queue(
        &name,
        OpenFlags::RDWR | OpenFlags::NONBLOCK | OpenFlags::CLOEXEC,
        2,
        64,
    );
    assert!(crabc_rs::io::fcntl_getfd(queue.as_fd())
        .expect("queue descriptor flags")
        .contains(FdFlags::CLOEXEC));

    let attributes = queue.attributes().expect("queue attributes");
    assert_eq!(attributes.max_messages(), 2);
    assert_eq!(attributes.message_size(), 64);
    assert_eq!(attributes.current_messages(), 0);
    assert!(attributes.flags().contains(QueueFlags::NONBLOCK));

    queue
        .send(b"low", MessagePriority::new(1).expect("valid low priority"))
        .expect("send low-priority message");
    queue
        .send(b"high", MessagePriority::new(9).expect("valid high priority"))
        .expect("send high-priority message");
    assert_eq!(
        queue.attributes().expect("queue occupancy").current_messages(),
        2
    );

    let mut buffer = [0_u8; 64];
    let (length, priority) = queue.receive(&mut buffer).expect("receive high priority");
    assert_eq!(&buffer[..length], b"high");
    assert_eq!(priority.value(), 9);
    let (length, priority) = queue.receive(&mut buffer).expect("receive low priority");
    assert_eq!(&buffer[..length], b"low");
    assert_eq!(priority.value(), 1);
    assert_eq!(queue.receive(&mut buffer), Err(Errno::AGAIN));

    let previous = queue.set_nonblocking(false).expect("disable nonblocking");
    assert!(previous.flags().contains(QueueFlags::NONBLOCK));
    let previous = queue.set_nonblocking(true).expect("enable nonblocking");
    assert!(!previous.flags().contains(QueueFlags::NONBLOCK));

    let opened = ipc::open(name.as_str(), OpenFlags::RDWR | OpenFlags::NONBLOCK)
        .expect("open existing queue");
    ipc::unlink(name.as_str()).expect("unlink queue while descriptors remain open");
    assert!(matches!(
        ipc::open(name.as_str(), OpenFlags::RDWR),
        Err(Errno::NOENT)
    ));
    opened.close().expect("close unlinked duplicate queue descriptor");
    queue.close().expect("close unlinked original queue descriptor");
}

#[test]
fn x86_64_ipc_reports_full_empty_and_typed_priority_range() {
    let name = QueueName::new("full");
    let queue = create_queue(&name, OpenFlags::RDWR | OpenFlags::NONBLOCK, 1, 8);
    assert!(MessagePriority::new(32_767).is_some());
    assert!(MessagePriority::new(32_768).is_none());

    queue
        .send(b"one", MessagePriority::new(32_767).expect("maximum valid priority"))
        .expect("fill one-message queue");
    assert_eq!(
        queue.send(b"two", MessagePriority::new(0).expect("minimum valid priority")),
        Err(Errno::AGAIN)
    );
    let mut buffer = [0_u8; 8];
    queue.receive(&mut buffer).expect("drain full queue");
    assert_eq!(queue.receive(&mut buffer), Err(Errno::AGAIN));
}

#[test]
fn x86_64_ipc_uses_absolute_realtime_deadlines_and_validates_inputs() {
    let name = QueueName::new("deadline");
    let queue = create_queue(&name, OpenFlags::RDWR, 1, 8);
    let expired = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut buffer = [0_u8; 8];
    assert_eq!(
        queue.receive_until(&mut buffer, expired),
        Err(Errno::TIMEDOUT)
    );

    queue
        .send(b"one", MessagePriority::new(3).expect("valid priority"))
        .expect("fill blocking queue");
    assert_eq!(
        queue.send_until(
            b"two",
            MessagePriority::new(4).expect("valid priority"),
            expired,
        ),
        Err(Errno::TIMEDOUT)
    );
    assert_eq!(
        queue.receive_until(
            &mut buffer,
            Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
        ),
        Err(Errno::INVAL)
    );
}

#[test]
fn x86_64_ipc_rejects_invalid_names_attributes_and_noalloc_paths() {
    assert_eq!(QueueAttributes::new(0, 8), Err(Errno::INVAL));
    assert_eq!(QueueAttributes::new(1, 0), Err(Errno::INVAL));
    assert!(matches!(
        ipc::open("missing-leading-slash", OpenFlags::RDWR),
        Err(Errno::INVAL)
    ));
    assert!(matches!(
        ipc::open("/contains/slash", OpenFlags::RDWR),
        Err(Errno::INVAL)
    ));
    assert!(matches!(
        ipc::open(&b"/queue\0name"[..], OpenFlags::RDWR),
        Err(Errno::INVAL)
    ));

    #[cfg(not(feature = "alloc"))]
    {
        let mut overlong = [b'x'; crabc_rs::fs::SMALL_PATH_BUFFER_SIZE];
        overlong[0] = b'/';
        assert!(matches!(
            ipc::open(&overlong, OpenFlags::RDWR),
            Err(Errno::NAMETOOLONG)
        ));
    }
}
