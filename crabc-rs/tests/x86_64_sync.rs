#![cfg(target_arch = "x86_64")]

use std::io::Write;

use crabc_rs::fs;

struct RemoveFileOnDrop(std::path::PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn dirty_regular_file_fixture() -> (std::fs::File, RemoveFileOnDrop) {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    path.push(format!("crabc-x86-sync-{}-{nonce}", std::process::id()));

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique sync fixture");
    file.write_all(b"sync")
        .expect("dirty disposable sync fixture");
    (file, RemoveFileOnDrop(path))
}

#[test]
fn x86_64_sync_issues_a_unit_global_writeback_request() {
    let (_file, _cleanup) = dirty_regular_file_fixture();

    // Linux `sync` has global writeback scope and a unit success contract.
    // This regression deliberately makes no timing, per-file, crash, or
    // storage-media durability assertion.
    let (): () = fs::sync();
}
