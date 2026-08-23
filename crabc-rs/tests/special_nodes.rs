use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{self, AtFlags, FileType, Mode, OFlags, CWD, FIFO_DEVICE};
use crabc_rs::Errno;

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct FifoFixture {
    root: String,
}

impl FifoFixture {
    fn new() -> Self {
        Self {
            root: format!(
                "/tmp/crabc-rs-native-special-nodes-{}-{}",
                std::process::id(),
                SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            ),
        }
    }

    fn path(&self, name: &str) -> String {
        format!("{}/{}", self.root, name)
    }

    fn prepare(&self) {
        // Remove only this fixture's known paths. The guard below repeats the
        // cleanup after every test outcome, including panics.
        for name in ["mknodat", "mkfifo", "mkfifoat"] {
            let _ = fs::unlink(self.path(name));
        }
        let _ = fs::rmdir(&self.root);
        fs::mkdir(&self.root, Mode::RWXU).expect("create FIFO fixture directory");
    }
}

impl Drop for FifoFixture {
    fn drop(&mut self) {
        for name in ["mknodat", "mkfifo", "mkfifoat"] {
            let _ = fs::unlink(self.path(name));
        }
        let _ = fs::rmdir(&self.root);
    }
}

fn assert_fifo(path: &str, requested_mode: Mode) {
    let metadata = fs::stat(path).expect("stat FIFO");
    assert_eq!(FileType::from_raw_mode(metadata.st_mode), FileType::Fifo);
    let observed_mode = Mode::from_raw_mode(metadata.st_mode);
    // The process umask may clear requested permission bits, but it must not
    // add permissions outside the creation mode supplied to the syscall.
    assert_eq!(observed_mode.bits() & !requested_mode.bits(), 0);

    // A nonblocking open proves that the node is a usable FIFO without
    // waiting for a peer to open the other end.
    let descriptor = fs::open(path, OFlags::RDONLY | OFlags::NONBLOCK, Mode::empty())
        .expect("open FIFO without blocking");
    drop(descriptor);
}

#[test]
fn mknodat_and_mkfifo_variants_create_typed_fifos() {
    let fixture = FifoFixture::new();
    fixture.prepare();
    let mode = Mode::RUSR | Mode::WUSR;

    fs::mknodat(
        CWD,
        fixture.path("mknodat"),
        FileType::Fifo,
        mode,
        FIFO_DEVICE,
    )
    .expect("mknodat FIFO");
    assert_fifo(&fixture.path("mknodat"), mode);

    fs::mkfifo(fixture.path("mkfifo"), mode).expect("mkfifo FIFO");
    assert_fifo(&fixture.path("mkfifo"), mode);

    let directory = fs::open(
        &fixture.root,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .expect("open fixture directory");
    fs::mkfifoat(&directory, "mkfifoat", mode).expect("mkfifoat FIFO");
    let metadata = fs::statat(&directory, "mkfifoat", AtFlags::empty()).expect("statat FIFO");
    assert_eq!(FileType::from_raw_mode(metadata.st_mode), FileType::Fifo);
    drop(directory);
}

#[test]
fn mknodat_rejects_metadata_only_file_types_and_type_bits_in_mode() {
    let fixture = FifoFixture::new();
    fixture.prepare();

    assert_eq!(
        fs::mknodat(
            CWD,
            fixture.path("mknodat"),
            FileType::Unknown,
            Mode::empty(),
            FIFO_DEVICE,
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::mknodat(
            CWD,
            fixture.path("mknodat"),
            FileType::Fifo,
            Mode::from_bits_retain(0o100000),
            FIFO_DEVICE,
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(fs::stat(fixture.path("mknodat")).unwrap_err(), Errno::NOENT);
}
