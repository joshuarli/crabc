//! Conventional static `libc.a` pthread/TLS lifecycle evidence.
//!
//! The fixture is compiled and linked by the installed crabc driver. It is
//! deliberately separate from the dynamic-loader pthread/TLS tests: a static
//! link has no `libldso.so` boundary and must provide the complete
//! pthread/TLS lifecycle itself.
#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn static_pthread_tls_lifecycle_links_through_owned_sysroot() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let sysroot = manifest_dir.join("target/crabc-sysroot");
    let compiler = sysroot.join("bin/crabc-cc");
    assert!(compiler.is_file(), "crabc-cc not found at {}", compiler.display());
    let source = fixtures.join("static_pthread_tls_test.c");
    let binary = test_support::TempArtifact::new("static_pthread_tls_test");

    let status = Command::new(&compiler)
        .args([
            "-static",
            "-no-pie",
            "-fno-stack-protector",
            source.to_str().unwrap(),
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run owned crabc-cc for static pthread/TLS fixture");
    assert!(status.success(), "owned static pthread/TLS link failed");

    let file_out = Command::new("file")
        .arg(&binary)
        .output()
        .expect("file command failed");
    assert!(
        String::from_utf8_lossy(&file_out.stdout).contains("statically linked"),
        "static pthread/TLS fixture is not a static executable: {}",
        String::from_utf8_lossy(&file_out.stdout)
    );

    let output = Command::new(&binary)
        .output()
        .expect("failed to run static pthread/TLS fixture");
    assert!(
        output.status.success(),
        "static pthread/TLS fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "static pthread tls ok\n"
    );
}
