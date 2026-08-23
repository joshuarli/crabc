//! Conventional static `libc.a` pthread/TLS lifecycle evidence.
//!
//! The fixture is compiled by the pinned musl toolchain but linked only with
//! crabc's archive and musl's CRT objects.  It is deliberately separate from
//! the dynamic-loader pthread/TLS tests: a static link has no `libldso.so`
//! boundary and must provide the complete pthread/TLS lifecycle itself.
#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn static_pthread_tls_lifecycle_links_against_libc_a() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let libc_a = manifest_dir.join("target/debug/libc.a");
    assert!(libc_a.exists(), "libc.a not found at {}", libc_a.display());

    let arch = "aarch64";
    let musl_lib = std::env::var("MUSL_REFERENCE_LIBDIR")
        .unwrap_or_else(|_| format!("/usr/lib/{}-linux-musl", arch));
    let source = fixtures.join("static_pthread_tls_test.c");
    let binary = test_support::TempArtifact::new("static_pthread_tls_test");

    let status = Command::new("musl-gcc")
        .args([
            "-static",
            "-no-pie",
            "-nostdlib",
            "-fno-stack-protector",
            &format!("{}/crt1.o", musl_lib),
            &format!("{}/crti.o", musl_lib),
            source.to_str().unwrap(),
            libc_a.to_str().unwrap(),
            &format!("{}/crtn.o", musl_lib),
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for static pthread/TLS fixture");
    assert!(status.success(), "static pthread/TLS link failed");

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
