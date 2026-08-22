use core::mem::MaybeUninit;

use crabc_rs::fs::{self, Dir, Mode, OFlags, CWD};

const ROOT_PATH: &[u8] = b"/tmp/crabc-rs-m10-directory-position";
const FIRST_NAME: &[u8] = b"first";
const SECOND_NAME: &[u8] = b"second";

#[test]
fn dir_rewind_and_seek_discard_buffered_records() {
    let _ = fs::rmdir(ROOT_PATH);
    fs::mkdir(ROOT_PATH, Mode::RWXU).expect("create directory-position fixture");
    let directory = fs::openat(
        CWD,
        ROOT_PATH,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open directory-position fixture");
    for name in [FIRST_NAME, SECOND_NAME] {
        let file = fs::openat(
            &directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("create directory-position entry");
        drop(file);
    }
    drop(directory);

    let mut storage = [MaybeUninit::uninit(); 4096];
    let mut stream = Dir::open(ROOT_PATH, &mut storage).expect("open directory stream");
    let mut first_observed = None;
    let mut second_observed = None;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("read directory-position entry");
        let fixture_name = if entry.name_bytes() == FIRST_NAME {
            Some(FIRST_NAME)
        } else if entry.name_bytes() == SECOND_NAME {
            Some(SECOND_NAME)
        } else {
            None
        };
        if let Some(fixture_name) = fixture_name {
            if first_observed.is_none() {
                first_observed = Some((fixture_name, entry.next_entry_cookie() as i64));
            } else if second_observed.is_none() {
                second_observed = Some(fixture_name);
            }
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
    assert!(rewound_first, "rewind must discard EOF state and restart iteration");

    stream.seek(first_cookie).expect("seek to first entry cookie");
    let mut sought_second = false;
    while let Some(entry) = stream.next() {
        let entry = entry.expect("read sought directory stream");
        if entry.name_bytes() == second_name {
            sought_second = true;
            break;
        }
    }
    assert!(sought_second, "seek cookie must resume after the first entry");

    drop(stream);
    let directory = fs::openat(
        CWD,
        ROOT_PATH,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("reopen directory-position fixture for cleanup");
    fs::unlinkat(&directory, FIRST_NAME, fs::AtFlags::empty())
        .expect("remove first directory-position entry");
    fs::unlinkat(&directory, SECOND_NAME, fs::AtFlags::empty())
        .expect("remove second directory-position entry");
    drop(directory);
    fs::rmdir(ROOT_PATH).expect("remove directory-position fixture");
}
