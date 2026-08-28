#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;
use std::fs::{self as std_fs};
use std::path::PathBuf;

use crabc_rs::fs::Dir;

const FIRST_NAME: &[u8] = b"first";
const SECOND_NAME: &[u8] = b"second";

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (RemoveDirectoryOnDrop, String) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!(
        "crabc-x86-directory-position-{}-{nonce}",
        std::process::id()
    ));
    std_fs::create_dir(&root).expect("create directory-position fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());
    for name in [FIRST_NAME, SECOND_NAME] {
        std_fs::write(root.join(std::str::from_utf8(name).expect("ASCII fixture name")), name)
            .expect("create directory-position fixture entry");
    }
    let root = root
        .into_os_string()
        .into_string()
        .expect("generated fixture pathname is UTF-8");
    (cleanup, root)
}

#[test]
fn x86_64_dir_rewind_and_seek_discard_buffered_records() {
    let (_cleanup, root) = fixture();
    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut stream = Dir::open(root.as_str(), &mut storage).expect("open directory stream");

    let mut first_observed = None;
    let mut second_observed = None;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("read directory-position entry");
        if entry.name_bytes() != FIRST_NAME && entry.name_bytes() != SECOND_NAME {
            continue;
        }
        if first_observed.is_none() {
            first_observed = Some((entry.name_bytes().to_vec(), entry.next_entry_cookie() as i64));
        } else if second_observed.is_none() {
            second_observed = Some(entry.name_bytes().to_vec());
        }
    }
    let (first_name, first_cookie) = first_observed.expect("first fixture entry must be observed");
    let second_name = second_observed.expect("second fixture entry must be observed");

    stream.rewind();
    let mut rewound_first = false;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("read rewound directory stream");
        if entry.name_bytes() == first_name {
            rewound_first = true;
            break;
        }
    }
    assert!(
        rewound_first,
        "rewind must discard EOF state and restart iteration"
    );

    stream
        .seek(first_cookie)
        .expect("seek to first entry cookie");
    let mut sought_second = false;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("read sought directory stream");
        if entry.name_bytes() == second_name {
            sought_second = true;
            break;
        }
    }
    assert!(
        sought_second,
        "seek cookie must resume after the first entry"
    );
}
