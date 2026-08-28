#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;
use std::os::fd::AsRawFd;

use crabc_rs::fs::{
    self, AtFlags, FileType, LinkAtFlags, Mode, OFlags, RenameFlags, UnlinkAtFlags,
};
use crabc_rs::BorrowedFd;

fn mode(bits: u32) -> Mode {
    Mode::from_bits(bits).expect("valid mode bits")
}

fn borrow(file: &std::fs::File) -> BorrowedFd<'_> {
    // SAFETY: `file` remains alive for each immediate descriptor-relative call.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

#[test]
fn x86_64_namespace_lifecycle_is_descriptor_relative() {
    let root = format!(
        "/tmp/crabc-x86-namespace-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall-clock fixture suffix")
            .as_nanos(),
    );
    let original_path = format!("{root}/original");
    let plain_hard_path = format!("{root}/plain-hard");
    let renamed_path = format!("{root}/renamed");
    let replaced_path = format!("{root}/replaced");
    let noreplace_path = format!("{root}/noreplace");
    std::fs::create_dir(root.as_str()).expect("fixture root");
    let directory = std::fs::File::open(root.as_str()).expect("fixture descriptor");

    let original = fs::openat(
        borrow(&directory),
        "original",
        OFlags::CREATE | OFlags::RDWR,
        mode(0o600),
    )
    .expect("create original");
    std::fs::write(original_path.as_str(), b"source").expect("write original contents");
    fs::linkat(
        borrow(&directory),
        "original",
        borrow(&directory),
        "hard",
        LinkAtFlags::empty(),
    )
    .expect("descriptor-relative hard link");
    assert_eq!(
        fs::statat(borrow(&directory), "original", AtFlags::empty())
            .expect("original metadata")
            .st_ino,
        fs::statat(borrow(&directory), "hard", AtFlags::empty())
            .expect("hard-link metadata")
            .st_ino,
    );
    fs::link(original_path.as_str(), plain_hard_path.as_str()).expect("cwd hard link");

    fs::symlinkat("original-target", borrow(&directory), "symbolic")
        .expect("descriptor-relative symbolic link");
    let mut full = [MaybeUninit::new(0xa5_u8); 64];
    let (target, untouched) = fs::readlinkat_raw(borrow(&directory), "symbolic", &mut full)
        .expect("full symbolic-link target");
    assert_eq!(target, b"original-target");
    assert!(!target.contains(&0), "readlinkat must not append a NUL");
    assert!(untouched
        .iter()
        .all(|byte| unsafe { byte.assume_init() } == 0xa5));
    let mut short = [MaybeUninit::new(0xa5_u8); 4];
    let (target, untouched) = fs::readlinkat_raw(borrow(&directory), "symbolic", &mut short)
        .expect("truncated symbolic-link target");
    assert_eq!(target, b"orig");
    assert!(untouched.is_empty());

    fs::renameat(
        borrow(&directory),
        "original",
        borrow(&directory),
        "renamed",
    )
    .expect("descriptor-relative rename");
    fs::rename(renamed_path.as_str(), replaced_path.as_str()).expect("cwd rename");
    fs::openat(
        borrow(&directory),
        "noreplace",
        OFlags::CREATE | OFlags::RDWR,
        mode(0o600),
    )
    .expect("create rename destination");
    std::fs::write(noreplace_path.as_str(), b"destination")
        .expect("write rename destination contents");
    assert_eq!(
        fs::renameat_with(
            borrow(&directory),
            "replaced",
            borrow(&directory),
            "noreplace",
            RenameFlags::NOREPLACE,
        )
        .unwrap_err(),
        crabc_rs::Errno::EXIST,
    );
    fs::renameat_with(
        borrow(&directory),
        "replaced",
        borrow(&directory),
        "noreplace",
        RenameFlags::EXCHANGE,
    )
    .expect("exchange names");
    assert_eq!(
        fs::statat(borrow(&directory), "replaced", AtFlags::empty())
            .expect("replacement metadata")
            .file_type(),
        FileType::RegularFile,
    );
    assert_eq!(
        std::fs::read(replaced_path.as_str()).expect("read exchanged replacement"),
        b"destination",
    );
    assert_eq!(
        std::fs::read(noreplace_path.as_str()).expect("read exchanged destination"),
        b"source",
    );
    assert_eq!(
        fs::renameat_with(
            borrow(&directory),
            "replaced",
            borrow(&directory),
            "noreplace",
            RenameFlags::NOREPLACE | RenameFlags::EXCHANGE,
        )
        .unwrap_err(),
        crabc_rs::Errno::INVAL,
    );
    assert_eq!(
        fs::renameat_with(
            borrow(&directory),
            "replaced",
            borrow(&directory),
            "noreplace",
            RenameFlags::from_bits_retain(0x4),
        )
        .unwrap_err(),
        crabc_rs::Errno::INVAL,
    );
    assert_eq!(
        fs::renameat(
            borrow(&directory),
            "missing",
            borrow(&directory),
            "x",
        )
        .unwrap_err(),
        crabc_rs::Errno::NOENT,
    );

    drop(original);
    fs::unlink(plain_hard_path.as_str()).expect("remove cwd hard link");
    fs::unlinkat(borrow(&directory), "hard", UnlinkAtFlags::empty()).expect("remove hard link");
    fs::unlinkat(borrow(&directory), "symbolic", UnlinkAtFlags::empty())
        .expect("remove symbolic link");
    fs::unlinkat(borrow(&directory), "replaced", UnlinkAtFlags::empty())
        .expect("remove replacement");
    fs::unlinkat(borrow(&directory), "noreplace", UnlinkAtFlags::empty())
        .expect("remove exchanged entry");
    fs::rmdir(root.as_str()).expect("remove fixture root");
}
