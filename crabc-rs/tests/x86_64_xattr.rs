#![cfg(target_arch = "x86_64")]

use std::fs::{self as std_fs, File};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use crabc_rs::{fs, BorrowedFd, Errno};

const UNTOUCHED: u8 = 0xa5;
const PATH_ATTRIBUTE: &str = "user.crabc-x86-path";
const NOFOLLOW_ATTRIBUTE: &str = "user.crabc-x86-nofollow";
const FD_ATTRIBUTE: &str = "user.crabc-x86-fd";
const REPLACED_VALUE: &[u8] = b"repl\0aced";

struct RemoveDirectoryOnDrop(PathBuf);

impl Drop for RemoveDirectoryOnDrop {
    fn drop(&mut self) {
        let _ = std_fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (RemoveDirectoryOnDrop, File, String) {
    let mut root = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    root.push(format!("crabc-x86-xattr-{}-{nonce}", std::process::id()));
    std_fs::create_dir(&root).expect("create xattr fixture directory");
    let cleanup = RemoveDirectoryOnDrop(root.clone());
    let path = root.join("record");
    let file = File::create(&path).expect("create xattr fixture file");
    let path = path
        .into_os_string()
        .into_string()
        .expect("generated xattr fixture pathname is UTF-8");
    (cleanup, file, path)
}

fn borrowed(file: &File) -> BorrowedFd<'_> {
    // SAFETY: The fixture retains its descriptor owner through each immediate
    // descriptor xattr operation using this borrow.
    unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) }
}

fn unavailable(error: Errno) -> bool {
    matches!(error, Errno::OPNOTSUPP | Errno::NOSYS)
}

fn list_contains(list: &[u8], name: &[u8]) -> bool {
    list.split(|byte| *byte == 0).any(|entry| entry == name)
}

#[test]
fn x86_64_xattr_preserves_path_nofollow_fd_and_caller_buffer_contracts() {
    let (_cleanup, file, path) = fixture();
    let value = b"path\0bytes";

    match fs::setxattr(path.as_str(), PATH_ATTRIBUTE, value, fs::XattrFlags::CREATE) {
        Ok(()) => {}
        Err(error) if unavailable(error) => return,
        Err(error) => panic!("set path xattr: {error}"),
    }
    assert_eq!(
        fs::setxattr(path.as_str(), PATH_ATTRIBUTE, value, fs::XattrFlags::CREATE).unwrap_err(),
        Errno::EXIST,
    );
    fs::setxattr(
        path.as_str(),
        PATH_ATTRIBUTE,
        REPLACED_VALUE,
        fs::XattrFlags::REPLACE,
    )
    .expect("replace an existing xattr");

    assert_eq!(
        fs::getxattr(path.as_str(), PATH_ATTRIBUTE, &mut [0_u8; 0])
            .expect("zero-size getxattr queries the value length"),
        REPLACED_VALUE.len(),
    );
    let mut get = [UNTOUCHED; 16];
    let returned = fs::getxattr(path.as_str(), PATH_ATTRIBUTE, &mut get)
        .expect("read path xattr into caller storage");
    assert_eq!(returned, REPLACED_VALUE.len());
    assert_eq!(&get[..returned], REPLACED_VALUE);
    assert!(get[REPLACED_VALUE.len()..]
        .iter()
        .all(|byte| *byte == UNTOUCHED));
    assert_eq!(
        fs::getxattr(path.as_str(), PATH_ATTRIBUTE, &mut [0_u8; 2]).unwrap_err(),
        Errno::RANGE,
    );

    let mut lget = [0_u8; 16];
    assert_eq!(
            fs::lgetxattr(path.as_str(), PATH_ATTRIBUTE, &mut lget)
                .expect("read no-follow xattr"),
        REPLACED_VALUE.len(),
    );
    assert_eq!(&lget[..REPLACED_VALUE.len()], REPLACED_VALUE);
    let mut fget = [0_u8; 16];
    assert_eq!(
            fs::fgetxattr(borrowed(&file), PATH_ATTRIBUTE, &mut fget)
                .expect("read descriptor xattr"),
        REPLACED_VALUE.len(),
    );
    assert_eq!(&fget[..REPLACED_VALUE.len()], REPLACED_VALUE);

    fs::lsetxattr(
        path.as_str(),
        NOFOLLOW_ATTRIBUTE,
        b"no-follow",
        fs::XattrFlags::CREATE,
    )
        .expect("set no-follow xattr");
    fs::fsetxattr(borrowed(&file), FD_ATTRIBUTE, b"fd", fs::XattrFlags::CREATE)
        .expect("set descriptor xattr");
    let mut list = [0_u8; 256];
    let path_list_size = fs::listxattr(path.as_str(), &mut [0_u8; 0])
        .expect("zero-size path list queries the required length");
    let listed = fs::listxattr(path.as_str(), &mut list).expect("list path xattrs");
    assert_eq!(listed, path_list_size);
    assert!(list_contains(&list[..listed], PATH_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], NOFOLLOW_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], FD_ATTRIBUTE.as_bytes()));
    let nofollow_list_size = fs::llistxattr(path.as_str(), &mut [0_u8; 0])
        .expect("zero-size no-follow list queries the required length");
    let listed = fs::llistxattr(path.as_str(), &mut list).expect("list no-follow xattrs");
    assert_eq!(listed, nofollow_list_size);
    assert!(list_contains(&list[..listed], PATH_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], NOFOLLOW_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], FD_ATTRIBUTE.as_bytes()));
    let fd_list_size = fs::flistxattr(borrowed(&file), &mut [0_u8; 0])
        .expect("zero-size descriptor list queries the required length");
    let listed = fs::flistxattr(borrowed(&file), &mut list).expect("list descriptor xattrs");
    assert_eq!(listed, fd_list_size);
    assert!(list_contains(&list[..listed], PATH_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], NOFOLLOW_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], FD_ATTRIBUTE.as_bytes()));
    assert_eq!(
        fs::listxattr(path.as_str(), &mut [0_u8; 1]).unwrap_err(),
        Errno::RANGE,
    );

    assert_eq!(
        fs::setxattr(
            path.as_str(),
            PATH_ATTRIBUTE,
            b"invalid",
            fs::XattrFlags::from_bits_retain(0x8000_0000),
        )
        .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::setxattr(
            path.as_str(),
            "user.crabc-x86-missing",
            b"missing",
            fs::XattrFlags::REPLACE,
        )
        .unwrap_err(),
        Errno::NODATA,
    );
    assert_eq!(
        fs::setxattr(&b"broken\0path"[..], PATH_ATTRIBUTE, b"x", fs::XattrFlags::empty())
            .unwrap_err(),
        Errno::INVAL,
    );
    assert_eq!(
        fs::setxattr(path.as_str(), &b"user.broken\0name"[..], b"x", fs::XattrFlags::empty())
            .unwrap_err(),
        Errno::INVAL,
    );

    fs::removexattr(path.as_str(), PATH_ATTRIBUTE).expect("remove path xattr");
    fs::lremovexattr(path.as_str(), NOFOLLOW_ATTRIBUTE).expect("remove no-follow xattr");
    fs::fremovexattr(borrowed(&file), FD_ATTRIBUTE).expect("remove descriptor xattr");
    assert_eq!(
        fs::getxattr(path.as_str(), PATH_ATTRIBUTE, &mut [0_u8; 0]).unwrap_err(),
        Errno::NODATA,
    );
    assert_eq!(
        fs::removexattr(path.as_str(), PATH_ATTRIBUTE).unwrap_err(),
        Errno::NODATA,
    );
}
