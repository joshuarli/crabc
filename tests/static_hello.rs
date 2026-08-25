#[path = "common/mod.rs"]
mod test_support;

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn static_hello_links_through_owned_sysroot() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let sysroot = manifest_dir.join("target/crabc-sysroot");
    let compiler = sysroot.join("bin/crabc-cc");
    assert!(compiler.is_file(), "crabc-cc not found at {}", compiler.display());
    assert!(
        compiler.metadata().expect("crabc-cc metadata failed").permissions().mode() & 0o111 != 0,
        "crabc-cc is not executable: {}",
        compiler.display()
    );

    let hello_src = fixtures.join("hello.c");
    let hello_bin = test_support::TempArtifact::new("hello_static");

    let status = Command::new(&compiler)
        .args([
            "-static",
            "-no-pie",
            "-fno-stack-protector",
            hello_src.to_str().unwrap(),
            "-o",
            hello_bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run owned crabc-cc");
    assert!(status.success(), "static link through owned sysroot failed");

    let file_out = Command::new("file")
        .arg(&hello_bin)
        .output()
        .expect("file command failed");
    let file_info = String::from_utf8_lossy(&file_out.stdout);
    assert!(
        file_info.contains("statically linked"),
        "binary is not a static executable: {}",
        file_info
    );

    let output = Command::new(&hello_bin)
        .output()
        .expect("failed to run hello_static");
    assert!(
        output.status.success(),
        "hello_static exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello\n");
}
