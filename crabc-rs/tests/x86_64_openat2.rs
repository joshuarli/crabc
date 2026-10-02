#![cfg(target_arch = "x86_64")]

use crabc_rs::{fs, io, BorrowedFd, Errno};

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .expect("fixture clock").as_nanos();
        let path = std::env::temp_dir().join(format!("crabc-openat2-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).expect("fixture root");
        let fixture = Self(path);
        std::fs::create_dir(fixture.0.join("anchor")).expect("fixture directory");
        std::fs::write(fixture.0.join("anchor/inside"), b"owned").expect("fixture file");
        std::fs::write(fixture.0.join("outside"), b"outside").expect("sibling fixture file");
        std::os::unix::fs::symlink("inside", fixture.0.join("anchor/link"))
            .expect("fixture symbolic link");
        fixture
    }

    fn directory(&self) -> std::fs::File {
        std::fs::File::open(self.0.join("anchor")).expect("open fixture directory")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn borrow(file: &std::fs::File) -> BorrowedFd<'_> {
    // SAFETY: The standard owner retains the descriptor for the returned borrow.
    unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(file)) }
}

#[test]
fn x86_64_openat2_transfers_an_owned_descriptor_and_preserves_the_directory() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let file = fs::openat2(borrow(&directory), "inside", fs::OFlags::RDONLY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(), fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS)
        .expect("open constrained relative path");
    let mut bytes = [0; 5];
    assert_eq!(io::read(&file, &mut bytes), Ok(5));
    assert_eq!(&bytes, b"owned");
    assert!(io::fcntl_getfd(&file).expect("descriptor flags").contains(io::FdFlags::CLOEXEC));
    file.close().expect("close new owner");
    assert!(fs::fstat(borrow(&directory)).is_ok());
}

#[test]
fn x86_64_openat2_applies_symlink_beneath_and_explicit_root_resolution() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let fd = borrow(&directory);
    assert_eq!(fs::openat2(fd, "link", fs::OFlags::RDONLY, fs::Mode::empty(),
        fs::ResolveFlags::NO_SYMLINKS).err(), Some(Errno::LOOP));
    assert_eq!(fs::openat2(fd, "../outside", fs::OFlags::RDONLY, fs::Mode::empty(),
        fs::ResolveFlags::BENEATH).err(), Some(Errno::XDEV));
    let rooted = fs::openat2(fd, "/inside", fs::OFlags::RDONLY, fs::Mode::empty(),
        fs::ResolveFlags::IN_ROOT).expect("absolute path relative to explicit root");
    let mut bytes = [0; 5];
    assert_eq!(io::read(&rooted, &mut bytes), Ok(5));
    assert_eq!(&bytes, b"owned");
}

#[test]
fn x86_64_openat2_retains_kernel_validation_instead_of_an_openat_fallback() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let fd = borrow(&directory);
    assert_eq!(fs::openat2(fd, "inside", fs::OFlags::RDONLY,
        fs::Mode::from_bits_retain(0o600), fs::ResolveFlags::empty()).err(), Some(Errno::INVAL));
    assert_eq!(fs::openat2(fd, "inside", fs::OFlags::RDONLY, fs::Mode::empty(),
        fs::ResolveFlags::from_bits_retain(1 << 63)).err(), Some(Errno::INVAL));
    assert!(fs::openat2(fd, "inside", fs::OFlags::RDONLY, fs::Mode::empty(),
        fs::ResolveFlags::empty()).is_ok());
}
