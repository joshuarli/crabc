use crabc_rs::fs::Mode;
use crabc_rs::ipc::{
    self, CreateFlags, MessagePriority, OpenFlags, QueueAttributes, QueueFlags, Timespec,
};
use crabc_rs::io::FdFlags;
use crabc_rs::{AsFd, Errno};

struct QueueName(String);

impl QueueName {
    fn new(suffix: &str) -> Self {
        let name = format!("/crabc-rs-mq-{}-{suffix}", std::process::id());
        let _ = ipc::unlink(&name);
        Self(name)
    }

    fn as_str(&self) -> &str { &self.0 }
}

impl Drop for QueueName {
    fn drop(&mut self) {
        let _ = ipc::unlink(&self.0);
    }
}

fn create_queue(name: &QueueName, flags: OpenFlags, max_messages: u64, message_size: usize) -> ipc::MessageQueue {
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
fn owned_queue_attributes_priorities_nonblocking_and_unlink_lifetime() {
    let name = QueueName::new("basic");
    let queue = create_queue(
        &name,
        OpenFlags::RDWR | OpenFlags::NONBLOCK | OpenFlags::CLOEXEC,
        2,
        64,
    );
    assert!(crabc_rs::io::fcntl_getfd(queue.as_fd()).expect("queue fd flags").contains(FdFlags::CLOEXEC));

    let attributes = queue.attributes().expect("queue attributes");
    assert_eq!(attributes.max_messages(), 2);
    assert_eq!(attributes.message_size(), 64);
    assert_eq!(attributes.current_messages(), 0);
    assert!(attributes.flags().contains(QueueFlags::NONBLOCK));

    queue
        .send(b"low", MessagePriority::new(1).unwrap())
        .expect("send low-priority message");
    queue
        .send(b"high", MessagePriority::new(9).unwrap())
        .expect("send high-priority message");
    assert_eq!(queue.attributes().unwrap().current_messages(), 2);

    let mut buffer = [0_u8; 64];
    let (length, priority) = queue.receive(&mut buffer).expect("receive high-priority message");
    assert_eq!(&buffer[..length], b"high");
    assert_eq!(priority.value(), 9);
    let (length, priority) = queue.receive(&mut buffer).expect("receive low-priority message");
    assert_eq!(&buffer[..length], b"low");
    assert_eq!(priority.value(), 1);
    assert_eq!(queue.receive(&mut buffer), Err(Errno::AGAIN));

    let previous = queue.set_nonblocking(false).expect("disable nonblocking");
    assert!(previous.flags().contains(QueueFlags::NONBLOCK));
    let previous = queue.set_nonblocking(true).expect("enable nonblocking");
    assert!(!previous.flags().contains(QueueFlags::NONBLOCK));

    let opened = ipc::open(name.as_str(), OpenFlags::RDWR | OpenFlags::NONBLOCK)
        .expect("open an existing queue");
    ipc::unlink(name.as_str()).expect("unlink queue while descriptors remain open");
    assert!(matches!(
        ipc::open(name.as_str(), OpenFlags::RDWR),
        Err(Errno::NOENT)
    ));
    drop(opened);
    drop(queue);
}

#[test]
fn nonblocking_send_reports_full_queue_and_priority_range_is_typed() {
    let name = QueueName::new("full");
    let queue = create_queue(&name, OpenFlags::RDWR | OpenFlags::NONBLOCK, 1, 8);
    assert!(MessagePriority::new(32_767).is_some());
    assert!(MessagePriority::new(32_768).is_none());

    queue
        .send(b"one", MessagePriority::new(32_767).unwrap())
        .expect("fill one-message queue");
    assert_eq!(queue.send(b"two", MessagePriority::new(0).unwrap()), Err(Errno::AGAIN));
}

#[test]
fn absolute_realtime_deadlines_and_input_validation_are_explicit() {
    let name = QueueName::new("deadline");
    let queue = create_queue(&name, OpenFlags::RDWR, 1, 8);
    let expired = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut buffer = [0_u8; 8];
    assert_eq!(queue.receive_until(&mut buffer, expired), Err(Errno::TIMEDOUT));

    queue
        .send(b"one", MessagePriority::new(3).unwrap())
        .expect("fill blocking queue");
    assert_eq!(
        queue.send_until(b"two", MessagePriority::new(4).unwrap(), expired),
        Err(Errno::TIMEDOUT)
    );
    assert_eq!(
        queue.receive_until(&mut buffer, Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 }),
        Err(Errno::INVAL)
    );
}

#[test]
fn queue_names_and_creation_attributes_reject_invalid_inputs() {
    assert!(QueueAttributes::new(0, 8).is_err());
    assert!(QueueAttributes::new(1, 0).is_err());
    assert!(matches!(
        ipc::open("missing-leading-slash", OpenFlags::RDWR),
        Err(Errno::INVAL)
    ));
    assert!(matches!(
        ipc::open("/contains/slash", OpenFlags::RDWR),
        Err(Errno::INVAL)
    ));
}
