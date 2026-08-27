#![cfg(target_arch = "x86_64")]

use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, IntoRawFd};

use crabc_rs::io::{self, SyncFileRangeFlags};
use crabc_rs::{BorrowedFd, Errno};

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn regular_file_fixture() -> (std::fs::File, RemoveFileOnDrop) {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    path.push(format!(
        "crabc-x86-sync-file-range-{}-{nonce}",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique sync_file_range fixture");
    file.write_all(&[0x5a; 8192])
        .expect("seed sync_file_range fixture");
    (file, RemoveFileOnDrop(path))
}

fn borrow_file(file: &std::fs::File) -> BorrowedFd<'_> {
    // SAFETY: `file` retains sole ownership of its open descriptor for every
    // immediate direct-facade call using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

fn current_position(file: &std::fs::File) -> u64 {
    let position = crabc_core::fs::lseek(file.as_raw_fd(), 0, crabc_core::fs::SEEK_CUR)
        .expect("query regular-file position");
    u64::try_from(position).expect("successful Linux file position is nonnegative")
}

#[test]
fn x86_64_sync_file_range_requests_zero_length_to_eof_without_moving_position_when_supported() {
    let (mut file, _cleanup) = regular_file_fixture();
    file.seek(SeekFrom::Start(777))
        .expect("position sync_file_range fixture");
    let before = current_position(&file);

    let result = io::sync_file_range(
        borrow_file(&file),
        0,
        0,
        SyncFileRangeFlags::WAIT_BEFORE
            | SyncFileRangeFlags::WRITE
            | SyncFileRangeFlags::WAIT_AFTER,
    );
    let after = current_position(&file);

    match result {
        Ok(()) => {}
        // `sync_file_range` is intentionally unsupported by some otherwise
        // valid regular-file backing stores (notably tmpfs-like fixtures).
        // Keep the native status boundary explicit without turning a host
        // filesystem choice into a facade failure.
        Err(Errno::NOTSUP) => {
            assert_eq!(
                after, before,
                "an unsupported sync_file_range request must not move the file position",
            );
            return;
        }
        Err(error) => panic!("request zero-length regular-file range through EOF: {error}"),
    }

    assert_eq!(
        after, before,
        "sync_file_range must not move the regular file's current position",
    );
}

#[test]
fn x86_64_sync_file_range_rejects_invalid_flags_and_ranges_at_the_typed_boundary() {
    let (mut file, _cleanup) = regular_file_fixture();
    file.seek(SeekFrom::Start(317))
        .expect("position validation fixture");
    let before = current_position(&file);

    assert_eq!(SyncFileRangeFlags::WAIT_BEFORE.bits(), 0x01);
    assert_eq!(SyncFileRangeFlags::WRITE.bits(), 0x02);
    assert_eq!(SyncFileRangeFlags::WAIT_AFTER.bits(), 0x04);

    let unknown_flags = SyncFileRangeFlags::from_bits_retain(0x08);
    assert!(
        SyncFileRangeFlags::from_bits(unknown_flags.bits()).is_none(),
        "reserved sync_file_range flag bits must remain outside the safe set",
    );
    assert_eq!(
        io::sync_file_range(borrow_file(&file), 0, 0, unknown_flags),
        Err(Errno::INVAL),
        "unknown flags must be rejected by the typed boundary",
    );
    // The public facade rejects unknown bits before the syscall. Exercise the
    // raw shared seam separately with a live regular descriptor so the x86
    // syscall-fourth-argument (`r10`) delivery is directly observable.
    assert_eq!(
        crabc_core::io::sync_file_range(file.as_raw_fd(), 0, 0, 0x08),
        Err(Errno::INVAL),
        "the x86 raw sync_file_range seam must deliver invalid flags to Linux",
    );
    assert_eq!(
        io::sync_file_range(
            borrow_file(&file),
            i64::MAX as u64 + 1,
            0,
            SyncFileRangeFlags::empty(),
        ),
        Err(Errno::INVAL),
        "an offset beyond signed Linux loff_t must be rejected by the typed boundary",
    );
    assert_eq!(
        io::sync_file_range(
            borrow_file(&file),
            i64::MAX as u64,
            1,
            SyncFileRangeFlags::empty(),
        ),
        Err(Errno::INVAL),
        "an offset plus length beyond signed Linux loff_t must be rejected by the typed boundary",
    );
    assert_eq!(
        io::sync_file_range(
            borrow_file(&file),
            0,
            i64::MAX as u64 + 1,
            SyncFileRangeFlags::empty(),
        ),
        Err(Errno::INVAL),
        "a length beyond signed Linux loff_t must be rejected by the typed boundary",
    );
    assert_eq!(
        current_position(&file),
        before,
        "locally rejected sync_file_range inputs must not move the file position",
    );
}

#[test]
fn x86_64_sync_file_range_closed_descriptor_reports_ebadf() {
    let (file, _cleanup) = regular_file_fixture();
    let raw = file.into_raw_fd();
    crabc_core::io::close(raw).expect("close sync_file_range EBADF fixture");

    // A safe BorrowedFd cannot outlive an open descriptor. Exercise the same
    // raw syscall seam after close instead of constructing an invalid borrow.
    assert_eq!(
        crabc_core::io::sync_file_range(
            raw,
            0,
            0,
            (SyncFileRangeFlags::WAIT_BEFORE
                | SyncFileRangeFlags::WRITE
                | SyncFileRangeFlags::WAIT_AFTER)
                .bits(),
        ),
        Err(Errno::BADF),
    );
}
