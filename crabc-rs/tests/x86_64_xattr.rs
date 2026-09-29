#![cfg(target_arch = "x86_64")]

use std::fs::{self as std_fs, File};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

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
fn x86_64_xattr_empty_fills_never_expose_query_sizes_as_initialized_storage() {
    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_xattr_empty_fill_child_checks_all_path_and_descriptor_forms",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .expect("run isolated extended-attribute child");
    assert!(
        output.status.success(),
        "isolated extended-attribute child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[ignore = "the parent regression invokes this test only in a subprocess"]
fn x86_64_xattr_empty_fill_child_checks_all_path_and_descriptor_forms() {
    let (_cleanup, file, path) = fixture();
    fs::setxattr(path.as_str(), PATH_ATTRIBUTE, b"value", fs::XattrFlags::CREATE)
        .expect("the native xattr regression fixture must support user attributes");

    macro_rules! check_short_fill {
        ($expected:expr; $operation:ident, $($argument:expr),+) => {{
            let mut empty: [MaybeUninit<u8>; 0] = [];
            assert!(matches!(
                fs::$operation($($argument,)+ &mut empty),
                Err(Errno::RANGE),
            ));
            let mut empty = [0u8; 0];
            assert_eq!(fs::$operation($($argument,)+ &mut empty), Err(Errno::RANGE));
            let mut short = [UNTOUCHED; 1];
            assert_eq!(fs::$operation($($argument,)+ &mut short), Err(Errno::RANGE));
            assert_eq!(short, [UNTOUCHED]);
            let mut short = [MaybeUninit::new(UNTOUCHED); 1];
            assert!(matches!(
                fs::$operation($($argument,)+ &mut short),
                Err(Errno::RANGE),
            ));
            // SAFETY: the sentinel was initialized before the failed fill.
            assert_eq!(unsafe { short[0].assume_init() }, UNTOUCHED);

            let expected: &[u8] = $expected;
            let mut storage = [MaybeUninit::new(UNTOUCHED); 128];
            let (filled, untouched) = fs::$operation($($argument,)+ &mut storage)
                .expect("fill only the initialized value or name-list prefix");
            assert_eq!(filled, expected);
            // SAFETY: each trailing sentinel was initialized before the fill.
            assert!(untouched.iter().all(|byte| unsafe { byte.assume_init() } == UNTOUCHED));

            #[cfg(feature = "alloc")]
            for capacity in [0, 1] {
                let mut bytes = Vec::<u8>::with_capacity(capacity);
                assert_eq!(
                    fs::$operation($($argument,)+ crabc_rs::buffer::spare_capacity(&mut bytes)),
                    Err(Errno::RANGE),
                );
                assert!(bytes.is_empty());
                assert_eq!(bytes.capacity(), capacity);
            }
            #[cfg(feature = "alloc")]
            {
                let mut bytes = Vec::<u8>::with_capacity(128);
                bytes.push(UNTOUCHED);
                assert_eq!(
                    fs::$operation($($argument,)+ crabc_rs::buffer::spare_capacity(&mut bytes)),
                    Ok(expected.len()),
                );
                assert_eq!(bytes[0], UNTOUCHED);
                assert_eq!(&bytes[1..], expected);
                assert_eq!(bytes.capacity(), 128);
            }
        }};
    }

    let mut names = PATH_ATTRIBUTE.as_bytes().to_vec();
    names.push(0);
    check_short_fill!(b"value"; getxattr, path.as_str(), PATH_ATTRIBUTE);
    check_short_fill!(b"value"; lgetxattr, path.as_str(), PATH_ATTRIBUTE);
    check_short_fill!(b"value"; fgetxattr, borrowed(&file), PATH_ATTRIBUTE);
    check_short_fill!(&names; listxattr, path.as_str());
    check_short_fill!(&names; llistxattr, path.as_str());
    check_short_fill!(&names; flistxattr, borrowed(&file));

    macro_rules! check_empty_fill {
        ($operation:ident, $($argument:expr),+) => {{
            let mut empty: [MaybeUninit<u8>; 0] = [];
            let (filled, untouched) = fs::$operation($($argument,)+ &mut empty)
                .expect("an empty value or list initializes an empty prefix");
            assert!(filled.is_empty());
            assert!(untouched.is_empty());
            let mut empty = [0u8; 0];
            assert_eq!(fs::$operation($($argument,)+ &mut empty), Ok(0));
            #[cfg(feature = "alloc")]
            {
                let mut bytes = Vec::<u8>::new();
                assert_eq!(
                    fs::$operation($($argument,)+ crabc_rs::buffer::spare_capacity(&mut bytes)),
                    Ok(0),
                );
                assert!(bytes.is_empty());
                assert_eq!(bytes.capacity(), 0);
            }
        }};
    }

    fs::setxattr(path.as_str(), PATH_ATTRIBUTE, b"", fs::XattrFlags::REPLACE)
        .expect("replace with an empty attribute value");
    assert_eq!(fs::getxattr_size(path.as_str(), PATH_ATTRIBUTE), Ok(0));
    assert_eq!(fs::lgetxattr_size(path.as_str(), PATH_ATTRIBUTE), Ok(0));
    assert_eq!(fs::fgetxattr_size(borrowed(&file), PATH_ATTRIBUTE), Ok(0));
    check_empty_fill!(getxattr, path.as_str(), PATH_ATTRIBUTE);
    check_empty_fill!(lgetxattr, path.as_str(), PATH_ATTRIBUTE);
    check_empty_fill!(fgetxattr, borrowed(&file), PATH_ATTRIBUTE);

    fs::removexattr(path.as_str(), PATH_ATTRIBUTE).expect("remove the last attribute name");
    assert_eq!(fs::listxattr_size(path.as_str()), Ok(0));
    assert_eq!(fs::llistxattr_size(path.as_str()), Ok(0));
    assert_eq!(fs::flistxattr_size(borrowed(&file)), Ok(0));
    check_empty_fill!(listxattr, path.as_str());
    check_empty_fill!(llistxattr, path.as_str());
    check_empty_fill!(flistxattr, borrowed(&file));
}

#[test]
fn x86_64_xattr_size_queries_preserve_target_selection_and_growth_errors() {
    let (cleanup, file, path) = fixture();
    fs::setxattr(path.as_str(), PATH_ATTRIBUTE, b"value", fs::XattrFlags::CREATE)
        .expect("the native xattr regression fixture must support user attributes");
    let link = cleanup.0.join("link");
    std::os::unix::fs::symlink(&path, &link).expect("create the query target symlink");
    let link = link.to_str().expect("generated symlink path is UTF-8");
    assert_eq!(fs::getxattr_size(link, PATH_ATTRIBUTE), Ok(5));
    assert_eq!(fs::lgetxattr_size(link, PATH_ATTRIBUTE), Err(Errno::NODATA));
    assert_eq!(fs::llistxattr_size(link), Ok(0));
    assert_eq!(fs::lgetxattr_size(path.as_str(), PATH_ATTRIBUTE), Ok(5));
    assert_eq!(fs::fgetxattr_size(borrowed(&file), PATH_ATTRIBUTE), Ok(5));
    let name_size = fs::listxattr_size(path.as_str()).expect("query the initial name-list size");
    assert_eq!(fs::listxattr_size(link), Ok(name_size));
    assert_eq!(fs::flistxattr_size(borrowed(&file)), Ok(name_size));

    let value_size = fs::getxattr_size(path.as_str(), PATH_ATTRIBUTE).unwrap();
    fs::fsetxattr(borrowed(&file), PATH_ATTRIBUTE, b"a larger value", fs::XattrFlags::REPLACE)
        .expect("grow the value after the size query");
    let mut old_value = vec![UNTOUCHED; value_size];
    assert_eq!(
        fs::getxattr(path.as_str(), PATH_ATTRIBUTE, &mut old_value[..]),
        Err(Errno::RANGE),
    );
    assert!(old_value.iter().all(|byte| *byte == UNTOUCHED));
    assert_eq!(fs::getxattr_size(path.as_str(), PATH_ATTRIBUTE), Ok(14));

    fs::setxattr(path.as_str(), FD_ATTRIBUTE, b"added", fs::XattrFlags::CREATE)
        .expect("grow the name list after the size query");
    let mut old_names = vec![UNTOUCHED; name_size];
    assert_eq!(fs::listxattr(path.as_str(), &mut old_names[..]), Err(Errno::RANGE));
    assert!(old_names.iter().all(|byte| *byte == UNTOUCHED));
    assert!(fs::listxattr_size(path.as_str()).unwrap() > name_size);

    std_fs::remove_file(&path).expect("unlink the descriptor's object");
    assert_eq!(fs::getxattr_size(path.as_str(), PATH_ATTRIBUTE), Err(Errno::NOENT));
    assert_eq!(fs::fgetxattr_size(borrowed(&file), PATH_ATTRIBUTE), Ok(14));
    assert!(fs::flistxattr_size(borrowed(&file)).unwrap() > name_size);
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
        fs::getxattr_size(path.as_str(), PATH_ATTRIBUTE)
            .expect("query the value byte length"),
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
    let path_list_size = fs::listxattr_size(path.as_str())
        .expect("query the path name-list byte length");
    let listed = fs::listxattr(path.as_str(), &mut list).expect("list path xattrs");
    assert_eq!(listed, path_list_size);
    assert!(list_contains(&list[..listed], PATH_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], NOFOLLOW_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], FD_ATTRIBUTE.as_bytes()));
    let nofollow_list_size = fs::llistxattr_size(path.as_str())
        .expect("query the no-follow name-list byte length");
    let listed = fs::llistxattr(path.as_str(), &mut list).expect("list no-follow xattrs");
    assert_eq!(listed, nofollow_list_size);
    assert!(list_contains(&list[..listed], PATH_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], NOFOLLOW_ATTRIBUTE.as_bytes()));
    assert!(list_contains(&list[..listed], FD_ATTRIBUTE.as_bytes()));
    let fd_list_size = fs::flistxattr_size(borrowed(&file))
        .expect("query the descriptor name-list byte length");
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
