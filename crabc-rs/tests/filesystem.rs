use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs::{
    self, AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir, RenameFlags, ResolveFlags,
    Timespec, Timestamps, XattrFlags, ABS, CWD,
};
use crabc_rs::{Errno, Result};

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn with_scratch_directory<T>(run: impl FnOnce(&str) -> Result<T>) -> T {
    let root = format!(
        "/tmp/crabc-rs-fs-{}-{}",
        std::process::id(),
        SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    );
    match fs::rmdir(&root) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => panic!("remove stale directory: {error}"),
    }
    fs::mkdir(&root, Mode::RWXU).expect("create directory through the direct kernel seam");
    let result = run(&root).expect("filesystem operation");
    fs::rmdir(&root).expect("remove empty directory through the direct kernel seam");
    result
}

fn xattr_list_contains(list: &[u8], name: &[u8]) -> bool {
    list.split(|byte| *byte == 0).any(|entry| entry == name)
}

#[test]
fn statat_fstat_and_unlinkat_share_direct_metadata_contract() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        let file = fs::openat(
            &directory,
            "record",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("create regular file relative to directory descriptor");
        crabc_rs::io::write(&file, b"fs").expect("write test metadata payload");

        let by_fd = fs::fstat(&file).expect("fstat direct descriptor");
        assert_eq!(by_fd.st_size, 2);
        assert_eq!(FileType::from_raw_mode(by_fd.st_mode), FileType::RegularFile);
        assert!(Mode::from_raw_mode(by_fd.st_mode).contains(Mode::RUSR | Mode::WUSR));

        let by_path = fs::statat(&directory, "record", AtFlags::empty())
            .expect("statat direct relative path");
        assert_eq!(by_path.st_ino, by_fd.st_ino);
        assert_eq!(by_path.st_size, by_fd.st_size);

        let absolute = format!("{root}/record");
        assert_eq!(fs::stat(&absolute).unwrap().st_ino, by_fd.st_ino);
        let by_absolute = fs::statat(ABS, &absolute, AtFlags::empty())
            .expect("ABS accepts an absolute metadata path");
        assert_eq!(by_absolute.st_ino, by_fd.st_ino);
        assert_eq!(
            fs::statat(ABS, "record", AtFlags::empty()).unwrap_err(),
            Errno::BADF,
        );

        drop(file);
        fs::unlinkat(&directory, "record", AtFlags::empty())
            .expect("unlink regular file relative to descriptor");
        assert_eq!(
            fs::statat(&directory, "record", AtFlags::empty()).unwrap_err(),
            Errno::NOENT,
        );
        drop(directory);
        Ok(())
    });
}

#[test]
fn unlinkat_removedir_only_removes_directories() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        fs::mkdirat(&directory, "child", Mode::RWXU)
            .expect("directory creation will be added before this test is enabled");
        fs::unlinkat(&directory, "child", AtFlags::empty())
            .expect_err("unlinkat without REMOVEDIR cannot remove a directory");
        fs::unlinkat(&directory, "child", AtFlags::REMOVEDIR)
            .expect("unlinkat REMOVEDIR removes an empty directory");
        drop(directory);
        Ok(())
    });
}

#[test]
fn links_renames_and_bounded_readlink_use_the_direct_path_seam() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        let file = fs::openat(
            &directory,
            "record",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("create record");
        let record = fs::fstat(&file).expect("stat record");

        fs::linkat(&directory, "record", &directory, "hard", AtFlags::empty())
            .expect("create hard link");
        assert_eq!(fs::statat(&directory, "hard", AtFlags::empty()).unwrap().st_ino, record.st_ino);

        fs::symlinkat("record", &directory, "symbolic").expect("create symbolic link");
        assert_eq!(
            FileType::from_raw_mode(
                fs::statat(&directory, "symbolic", AtFlags::SYMLINK_NOFOLLOW)
                    .unwrap()
                    .st_mode,
            ),
            FileType::Symlink,
        );
        assert_eq!(
            FileType::from_raw_mode(fs::lstat(format!("{root}/symbolic")).unwrap().st_mode),
            FileType::Symlink,
        );
        let mut raw = [MaybeUninit::uninit(); 16];
        let (target, _) = fs::readlinkat_raw(&directory, "symbolic", &mut raw)
            .expect("read symbolic target without allocation");
        assert_eq!(target, b"record");
        assert_eq!(
            fs::readlinkat(&directory, "symbolic", Vec::new())
                .expect("read symbolic target with reusable allocation")
                .as_bytes(),
            b"record",
        );

        fs::renameat(&directory, "hard", &directory, "renamed").expect("rename hard link");
        assert_eq!(
            fs::renameat_with(
                &directory,
                "renamed",
                &directory,
                "record",
                RenameFlags::NOREPLACE,
            )
            .unwrap_err(),
            Errno::EXIST,
        );

        drop(file);
        for name in ["record", "renamed", "symbolic"] {
            fs::unlinkat(&directory, name, AtFlags::empty()).expect("remove link fixture");
        }
        drop(directory);
        Ok(())
    });
}

#[test]
fn permissions_and_timestamps_match_linux_rustix_contracts() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        let file = fs::openat(
            &directory,
            "record",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RWXU,
        )
        .expect("create record");
        fs::chmodat(&directory, "record", Mode::empty(), AtFlags::empty())
            .expect("chmodat regular file");
        assert_eq!(fs::statat(&directory, "record", AtFlags::empty()).unwrap().st_mode & 0o700, 0);
        fs::fchmod(&file, Mode::RWXU).expect("restore permissions through fchmod");
        let absolute = format!("{root}/record");
        fs::chmod(&absolute, Mode::RUSR).expect("chmod absolute file");
        assert_eq!(fs::stat(&absolute).unwrap().st_mode & 0o700, 0o400);
        fs::fchmod(&file, Mode::RWXU).expect("restore permissions after chmod");

        fs::symlinkat("record", &directory, "symbolic").expect("create symbolic link");
        assert_eq!(
            fs::chmodat(
                &directory,
                "symbolic",
                Mode::empty(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap_err(),
            Errno::OPNOTSUPP,
        );
        assert_eq!(
            fs::chmodat(&directory, "record", Mode::empty(), AtFlags::EACCESS).unwrap_err(),
            Errno::INVAL,
        );

        let times = Timestamps {
            last_access: Timespec { tv_sec: 44_000, tv_nsec: 45_000 },
            last_modification: Timespec { tv_sec: 46_000, tv_nsec: 47_000 },
        };
        fs::utimensat(&directory, "record", &times, AtFlags::empty())
            .expect("set timestamps through pathname");
        let by_path = fs::statat(&directory, "record", AtFlags::empty()).unwrap();
        assert_eq!((by_path.st_mtime, by_path.st_mtime_nsec), (46_000, 47_000));

        let by_fd_times = Timestamps {
            last_access: Timespec { tv_sec: 48_000, tv_nsec: 49_000 },
            last_modification: Timespec { tv_sec: 50_000, tv_nsec: 51_000 },
        };
        fs::futimens(&file, &by_fd_times).expect("set timestamps through descriptor");
        let by_fd = fs::fstat(&file).unwrap();
        assert_eq!((by_fd.st_mtime, by_fd.st_mtime_nsec), (50_000, 51_000));

        drop(file);
        for name in ["record", "symbolic"] {
            fs::unlinkat(&directory, name, AtFlags::empty()).expect("remove permission fixture");
        }
        drop(directory);
        Ok(())
    });
}

#[test]
fn raw_dir_preserves_record_lifetimes_alignment_and_long_names() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        let long_name = "n".repeat(255);
        for name in ["short", long_name.as_str()] {
            drop(
                fs::openat(
                    &directory,
                    name,
                    OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                    Mode::RUSR | Mode::WUSR,
                )
                .expect("create RawDir fixture entry"),
            );
        }
        assert_eq!(
            FileType::from_raw_mode(fs::statat(&directory, "short", AtFlags::empty()).unwrap().st_mode),
            FileType::RegularFile,
        );
        assert_eq!(
            FileType::from_raw_mode(
                fs::statat(&directory, long_name.as_str(), AtFlags::empty())
                    .unwrap()
                    .st_mode,
            ),
            FileType::RegularFile,
        );

        let iteration_directory = fs::openat(
            CWD,
            root,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("open directory descriptor for RawDir");
        let mut unaligned = [MaybeUninit::uninit(); 4097];
        let mut entries = RawDir::new(&iteration_directory, &mut unaligned[1..]);
        let mut names = Vec::new();
        while let Some(entry) = entries.next() {
            let entry = entry.expect("kernel directory records are validated");
            names.push(entry.file_name().to_bytes().to_vec());
        }
        assert!(entries.is_buffer_empty());
        assert!(names.iter().any(|name| name == b"short"), "entries: {names:?}");
        assert!(
            names.iter().any(|name| name == long_name.as_bytes()),
            "entries: {names:?}",
        );
        drop(entries);
        drop(iteration_directory);

        let small_directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open second directory descriptor");
        let mut too_small = [MaybeUninit::uninit(); 1];
        let mut too_small_iter = RawDir::new(&small_directory, &mut too_small);
        assert_eq!(
            too_small_iter
                .next()
                .expect("undersized buffer must return an error")
                .unwrap_err(),
            Errno::INVAL,
        );
        drop(too_small_iter);
        drop(small_directory);

        for name in ["short", long_name.as_str()] {
            fs::unlinkat(&directory, name, AtFlags::empty()).expect("remove RawDir fixture entry");
        }
        drop(directory);
        Ok(())
    });
}

#[test]
fn advisory_locks_use_direct_flock_and_fcntl_contracts() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        let file = fs::openat(
            &directory,
            "record",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("create lock fixture");

        fs::flock(&file, FlockOperation::LockExclusive).expect("acquire flock lock");
        fs::flock(&file, FlockOperation::Unlock).expect("release flock lock");
        fs::fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive)
            .expect("acquire process-associated fcntl lock");
        fs::fcntl_lock(&file, FlockOperation::NonBlockingUnlock)
            .expect("release process-associated fcntl lock");

        drop(file);
        fs::unlinkat(&directory, "record", AtFlags::empty()).expect("remove lock fixture");
        drop(directory);
        Ok(())
    });
}

#[test]
fn openat2_and_nofollow_preserve_linux_aarch64_path_resolution_rules() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        drop(
            fs::openat(
                &directory,
                "record",
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )
            .expect("create openat2 fixture"),
        );
        fs::symlinkat("record", &directory, "symbolic").expect("create fixture symlink");

        fs::openat(&directory, "symbolic", OFlags::RDONLY | OFlags::NOFOLLOW, Mode::empty())
            .expect_err("O_NOFOLLOW must reject a final symlink on Linux/AArch64");
        assert_eq!(
            fs::openat(
                &directory,
                "symbolic",
                OFlags::RDONLY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .unwrap_err(),
            Errno::LOOP,
        );
        let descriptor = fs::openat2(
            &directory,
            "record",
            OFlags::RDONLY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .expect("open regular file with constrained path resolution");
        drop(descriptor);
        assert_eq!(
            fs::openat2(
                &directory,
                "symbolic",
                OFlags::RDONLY,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
            .unwrap_err(),
            Errno::LOOP,
        );

        for name in ["record", "symbolic"] {
            fs::unlinkat(&directory, name, AtFlags::empty()).expect("remove openat2 fixture");
        }
        drop(directory);
        Ok(())
    });
}

#[test]
fn extended_attributes_preserve_path_link_fd_and_buffer_contracts() {
    with_scratch_directory(|root| {
        let directory = fs::openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("open directory");
        let file = fs::openat(
            &directory,
            "record",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("create xattr fixture");
        let path = format!("{root}/record");
        drop(fs::open(&path, OFlags::RDONLY, Mode::empty()).expect("open absolute fixture path"));

        match fs::setxattr(&path, "user.crabc-rs", b"path", XattrFlags::CREATE) {
            Ok(()) => {}
            Err(Errno::OPNOTSUPP | Errno::NOSYS) => {
                drop(file);
                fs::unlinkat(&directory, "record", AtFlags::empty())
                    .expect("remove unavailable xattr fixture");
                drop(directory);
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        assert_eq!(
            fs::getxattr(&path, "user.crabc-rs", &mut [0_u8; 0]).unwrap(),
            4,
        );
        let mut get = [0_u8; 32];
        let get_length = fs::getxattr(&path, "user.crabc-rs", &mut get).unwrap();
        assert_eq!(&get[..get_length], b"path");
        let mut lget = [0_u8; 32];
        let lget_length = fs::lgetxattr(&path, "user.crabc-rs", &mut lget).unwrap();
        assert_eq!(&lget[..lget_length], b"path");
        let mut fget = [0_u8; 32];
        let fget_length = fs::fgetxattr(&file, "user.crabc-rs", &mut fget).unwrap();
        assert_eq!(&fget[..fget_length], b"path");

        fs::lsetxattr(&path, "user.crabc-rs-link", b"link", XattrFlags::CREATE)
            .expect("set no-follow xattr");
        fs::fsetxattr(&file, "user.crabc-rs-fd", b"fd", XattrFlags::CREATE)
            .expect("set descriptor xattr");
        let mut listed = [0_u8; 128];
        for list_length in [
            fs::listxattr(&path, &mut listed).unwrap(),
            fs::llistxattr(&path, &mut listed).unwrap(),
            fs::flistxattr(&file, &mut listed).unwrap(),
        ] {
            assert!(xattr_list_contains(&listed[..list_length], b"user.crabc-rs"));
        }

        fs::removexattr(&path, "user.crabc-rs").expect("remove path xattr");
        fs::lremovexattr(&path, "user.crabc-rs-link").expect("remove no-follow xattr");
        fs::fremovexattr(&file, "user.crabc-rs-fd").expect("remove descriptor xattr");
        assert_eq!(
            fs::getxattr(&path, "user.crabc-rs", &mut [0_u8; 0]).unwrap_err(),
            Errno::NODATA,
        );

        drop(file);
        fs::unlinkat(&directory, "record", AtFlags::empty()).expect("remove xattr fixture");
        drop(directory);
        Ok(())
    });
}
