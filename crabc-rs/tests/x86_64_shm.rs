use core::ffi::CStr;

use crabc_rs::fs::{self, Mode, OFlags};
#[cfg(target_os = "macos")]
use crabc_rs::mm;
use crabc_rs::io::{self, FdFlags};
use crabc_rs::{Errno, AsFd};

struct ShmName(String);

impl ShmName {
    fn new(suffix: &str) -> Self {
        #[cfg(target_os = "linux")]
        let name = format!("/crabc-x86-shm-{}-{suffix}", std::process::id());
        // Darwin limits a shared-memory name to 31 bytes.
        #[cfg(target_os = "macos")]
        let name = format!("/crabc-shm-{}-{suffix}", std::process::id());
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

    // XNU's shm_open accepts no status flags beyond the access mode.
    #[cfg(target_os = "macos")]
    {
        assert!(matches!(
            crabc_rs::shm::open(
                name.as_str(),
                OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            ),
            Err(Errno::INVAL)
        ));
        let recreated = crabc_rs::shm::open(
            name.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
            Mode::RUSR | Mode::WUSR,
        )
        .expect("recreate name after unlink");
        recreated.close().expect("close recreated descriptor");
        crabc_rs::shm::unlink(name.as_str()).expect("unlink recreated object");
    }

    #[cfg(target_os = "linux")]
    let recreated = crabc_rs::shm::open(
        name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("recreate name after unlink");
    #[cfg(target_os = "linux")]
    {
        assert!(fs::fcntl_getfl(recreated.as_fd())
            .expect("read requested nonblocking status flag")
            .contains(OFlags::NONBLOCK));
        recreated.close().expect("close recreated descriptor");
        crabc_rs::shm::unlink(name.as_str()).expect("unlink recreated object");
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
#[test]
fn darwin_shm_normalizes_before_the_thirty_one_byte_name_limit() {
    let suffix = std::process::id().to_string();
    let mut name = [b'x'; 30];
    name[30 - suffix.len()..].copy_from_slice(suffix.as_bytes());
    let mut slash_prefixed = [0_u8; 31];
    slash_prefixed[0] = b'/';
    slash_prefixed[1..].copy_from_slice(&name);
    let mut double_slash_prefixed = [0_u8; 32];
    double_slash_prefixed[..2].copy_from_slice(b"//");
    double_slash_prefixed[2..].copy_from_slice(&name);
    let mut c_name = [0_u8; 31];
    c_name[..30].copy_from_slice(&name);

    let _ = crabc_rs::shm::unlink(&slash_prefixed);
    let descriptor = crabc_rs::shm::open(
        &double_slash_prefixed,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("a slash plus 30 bytes is the longest Darwin name");
    // SAFETY: the final byte is the sole terminator after 30 non-NUL bytes.
    let c_name = unsafe { CStr::from_bytes_with_nul_unchecked(&c_name) };
    let same_object = crabc_rs::shm::open(c_name, OFlags::RDWR, Mode::empty())
        .expect("the unslashed spelling opens the normalized object");
    assert_eq!(
        fs::fstat(same_object.as_fd()).expect("stat second descriptor").st_ino,
        fs::fstat(descriptor.as_fd()).expect("stat first descriptor").st_ino,
    );

    let mut too_long = [b'y'; 32];
    too_long[0] = b'/';
    assert!(matches!(
        crabc_rs::shm::open(&too_long, OFlags::CREATE | OFlags::RDWR, Mode::RUSR),
        Err(Errno::NAMETOOLONG)
    ));

    crabc_rs::shm::unlink(&slash_prefixed).expect("unlink the longest name");
    same_object.close().expect("close second descriptor");
    descriptor.close().expect("close first descriptor");
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_shm_objects_are_sized_once_and_shared_through_mappings() {
    const LENGTH: usize = 16384;
    let name = ShmName::new("map");
    let creator = crabc_rs::shm::open(
        name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
        Mode::RUSR | Mode::WUSR,
    )
    .expect("create shared-memory object");
    fs::ftruncate(&creator, LENGTH as u64).expect("size the new object");
    assert_eq!(fs::fstat(&creator).expect("stat sized object").st_size, LENGTH as i64);
    assert_eq!(fs::ftruncate(&creator, 2 * LENGTH as u64), Err(Errno::INVAL));

    let mut byte = [0_u8; 1];
    assert_eq!(io::read(&creator, &mut byte), Err(Errno::NXIO));
    assert_eq!(io::write(&creator, b"x"), Err(Errno::NXIO));

    let opener = crabc_rs::shm::open(name.as_str(), OFlags::RDWR, Mode::empty())
        .expect("open the object by name");
    let map = |fd: &crabc_rs::OwnedFd| {
        // SAFETY: the object is exactly LENGTH bytes and cannot shrink, and
        // each mapping is unmapped below after its last access.
        unsafe {
            mm::mmap(
                core::ptr::null_mut(),
                LENGTH,
                mm::ProtFlags::READ | mm::ProtFlags::WRITE,
                mm::MapFlags::SHARED,
                fd,
                0,
            )
        }
        .expect("map the shared object")
        .cast::<u8>()
    };
    let writer = map(&creator);
    let reader = map(&opener);
    // SAFETY: both mappings cover LENGTH writable bytes of one object, and
    // the accesses are volatile bytes with no Rust references.
    unsafe {
        writer.add(LENGTH - 1).write_volatile(0x5a);
        assert_eq!(reader.add(LENGTH - 1).read_volatile(), 0x5a);
    }

    crabc_rs::shm::unlink(name.as_str()).expect("unlink the mapped object");
    creator.close().expect("close the creator");
    opener.close().expect("close the opener");
    // SAFETY: the mappings keep the unlinked object alive after its last
    // descriptor closes; accesses stay inside both mappings.
    unsafe {
        reader.write_volatile(0xa5);
        assert_eq!(writer.read_volatile(), 0xa5);
    }
    // SAFETY: no pointer into either mapping is used after these unmaps.
    unsafe { mm::munmap(writer.cast(), LENGTH) }.expect("unmap the writer");
    // SAFETY: as above.
    unsafe { mm::munmap(reader.cast(), LENGTH) }.expect("unmap the reader");
    assert!(matches!(
        crabc_rs::shm::open(name.as_str(), OFlags::RDWR, Mode::empty()),
        Err(Errno::NOENT)
    ));
}
