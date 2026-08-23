use api::{fs, fs::Mode};

fn main() {
    // Rustix 1.1.4 has no mkdtemp wrapper. This common fixture exercises the
    // direct mkdirat/unlinkat primitive that underlies the crabc-rs native
    // temporary-directory operation, using an isolated source-compare CWD.
    let name = "native-rustix-tempdir-source";
    let parent = fs::open(
        ".",
        fs::OFlags::PATH | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open isolated fixture directory");
    let _ = fs::unlinkat(&parent, name, fs::AtFlags::REMOVEDIR);
    fs::mkdirat(&parent, name, Mode::RWXU).expect("mkdirat temporary fixture");
    let created = fs::openat(
        &parent,
        name,
        fs::OFlags::PATH | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("open created fixture directory");
    drop(created);
    fs::unlinkat(&parent, name, fs::AtFlags::REMOVEDIR).expect("remove fixture directory");
    println!("native-fs-tempdir source ok");
}
