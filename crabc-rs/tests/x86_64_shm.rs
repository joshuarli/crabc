#![cfg(target_arch = "x86_64")]

use core::ffi::CStr;

use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::io::{self, FdFlags};
use crabc_rs::{Errno, AsFd};

struct ShmName(String);

impl ShmName {
    fn new(suffix: &str) -> Self {
        let name = format!("/crabc-x86-shm-{}-{suffix}", std::process::id());
        let _ = crabc_rs::shm::unlink(name.as_str());
        Self(name)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ShmName {
    fn drop(&mut self) {
        let _ = crabc_rs::shm::unlink(self.0.as_str());
    }
}

#[test]
fn x86_64_shm_owns_cloexec_descriptors_and_unlink_after_open_lifetime() {
    let name = ShmName::new("lifetime");
    let descriptor = crabc_rs::shm::open(
        name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create private shared-memory object");

    assert!(io::fcntl_getfd(descriptor.as_fd())
        .expect("read shared-memory descriptor flags")
        .contains(FdFlags::CLOEXEC));
    assert!(
        !fs::fcntl_getfl(descriptor.as_fd())
            .expect("read shared-memory status flags")
            .contains(OFlags::NONBLOCK),
        "the direct Rust facade must preserve its caller-supplied status flags"
    );
    assert_eq!(
        fs::fstat(descriptor.as_fd())
            .expect("stat newly created shared-memory object")
            .st_size,
        0
    );

    let double_slash = format!("//{}", &name.as_str()[1..]);
    let same_object = crabc_rs::shm::open(double_slash.as_str(), OFlags::RDWR, Mode::empty())
        .expect("leading slashes normalize to the same POSIX shared-memory name");
    same_object.close().expect("close normalized-name descriptor");

    crabc_rs::shm::unlink(name.as_str()).expect("unlink object while descriptor remains open");
    assert!(matches!(
        crabc_rs::shm::open(name.as_str(), OFlags::RDWR, Mode::empty()),
        Err(Errno::NOENT)
    ));
    assert_eq!(
        fs::fstat(descriptor.as_fd())
            .expect("unlinked descriptor remains usable")
            .st_size,
        0
    );
    descriptor.close().expect("close unlinked descriptor");

    let recreated = crabc_rs::shm::open(
        name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("recreate name after unlink");
    assert!(fs::fcntl_getfl(recreated.as_fd())
        .expect("read requested nonblocking status flag")
        .contains(OFlags::NONBLOCK));
    recreated.close().expect("close recreated descriptor");
    crabc_rs::shm::unlink(name.as_str()).expect("unlink recreated object");
}

#[test]
fn x86_64_shm_normalizes_before_the_no_alloc_input_boundary() {
    let mut name = [b'x'; 255];
    let suffix = std::process::id().to_string();
    name[255 - suffix.len()..].copy_from_slice(suffix.as_bytes());
    let mut slash_prefixed = [0_u8; 256];
    slash_prefixed[0] = b'/';
    slash_prefixed[1..].copy_from_slice(&name);
    let mut c_name = [0_u8; 256];
    c_name[..255].copy_from_slice(&name);
    let mut double_slash_prefixed = [0_u8; 257];
    double_slash_prefixed[..2].copy_from_slice(b"//");
    double_slash_prefixed[2..].copy_from_slice(&name);

    let _ = crabc_rs::shm::unlink(&slash_prefixed);
    let descriptor = crabc_rs::shm::open(
        &slash_prefixed,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("a slash plus every valid NAME_MAX byte must fit before normalization");
    // SAFETY: the final byte is the sole terminator after exactly NAME_MAX
    // non-NUL bytes, so this also proves the borrowed-C-string input form.
    let c_name = unsafe { CStr::from_bytes_with_nul_unchecked(&c_name) };
    let same_object = crabc_rs::shm::open(c_name, OFlags::RDWR, Mode::empty())
        .expect("exact NAME_MAX C string opens the normalized object");

    crabc_rs::shm::unlink(&double_slash_prefixed)
        .expect("unlink normalizes leading slashes before its no-alloc boundary");
    assert!(matches!(
        crabc_rs::shm::open(c_name, OFlags::RDWR, Mode::empty()),
        Err(Errno::NOENT)
    ));
    same_object.close().expect("close exact-limit descriptor");
    descriptor.close().expect("close exact-limit descriptor");
}

#[test]
fn x86_64_shm_preserves_the_direct_no_follow_policy() {
    let target = ShmName::new("nofollow-target");
    let link = ShmName::new("nofollow-link");
    let target_descriptor = crabc_rs::shm::open(
        target.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create target shared-memory object");
    let target_path = format!("/dev/shm/{}", &target.as_str()[1..]);
    let link_path = format!("/dev/shm/{}", &link.as_str()[1..]);
    fs::symlink(target_path.as_str(), link_path.as_str())
        .expect("create a final symlink in the shared-memory mount");

    let followed = crabc_rs::shm::open(link.as_str(), OFlags::RDWR, Mode::empty())
        .expect("the direct Rust policy deliberately follows a final symlink");
    assert_eq!(
        fs::fstat(followed.as_fd()).expect("stat followed descriptor").st_ino,
        fs::fstat(target_descriptor.as_fd())
            .expect("stat target descriptor")
            .st_ino,
    );
    assert!(matches!(
        crabc_rs::shm::open(link.as_str(), OFlags::RDWR | OFlags::NOFOLLOW, Mode::empty()),
        Err(Errno::LOOP)
    ), "caller-selected O_NOFOLLOW remains visible instead of inheriting musl's implicit flag");

    followed.close().expect("close followed descriptor");
    crabc_rs::shm::unlink(link.as_str()).expect("unlink final symlink");
    target_descriptor.close().expect("close target descriptor");
    crabc_rs::shm::unlink(target.as_str()).expect("unlink target object");
}

#[test]
fn x86_64_shm_validates_posix_names_before_the_direct_syscall() {
    for name in ["", "/", "///", ".", "..", "/.", "/..", "/contains/slash"] {
        assert!(
            matches!(
                crabc_rs::shm::open(name, OFlags::RDWR, Mode::empty()),
                Err(Errno::INVAL)
            ),
            "invalid POSIX shared-memory name {name:?}"
        );
    }
    assert!(matches!(
        crabc_rs::shm::open(&b"/embedded\0name"[..], OFlags::RDWR, Mode::empty()),
        Err(Errno::INVAL)
    ));

    let mut overlong = [b'x'; 257];
    overlong[256] = 0;
    // SAFETY: the final byte is the one NUL terminator, and all preceding
    // bytes are non-NUL. A C string bypasses the generic fixed path buffer so
    // this directly proves the POSIX `NAME_MAX` check.
    let overlong = unsafe { CStr::from_bytes_with_nul_unchecked(&overlong) };
    assert!(matches!(
        crabc_rs::shm::open(overlong, OFlags::RDWR, Mode::empty()),
        Err(Errno::NAMETOOLONG)
    ));

    #[cfg(not(feature = "alloc"))]
    {
        let overlong_input = [b'x'; fs::SMALL_PATH_BUFFER_SIZE];
        assert!(matches!(
            crabc_rs::shm::open(&overlong_input, OFlags::RDWR, Mode::empty()),
            Err(Errno::NAMETOOLONG)
        ));
    }
}
