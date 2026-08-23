#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn static_hello_links_against_libc_a() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");

    // A static C program has no unwinder. The project therefore supports the
    // aborting release archive, the same archive exercised by the dedicated
    // pthread/TLS static-link gate.
    let libc_a = manifest_dir.join("target/release/libc.a");
    assert!(libc_a.exists(), "libc.a not found at {}", libc_a.display());

    let hello_src = fixtures.join("hello.c");
    let hello_bin = test_support::TempArtifact::new("hello_static");

    let arch = "aarch64";
    // Docker development deliberately keeps the pinned musl oracle outside
    // Alpine's system libc. Direct-host CI retains the conventional fallback.
    let musl_lib = std::env::var("MUSL_REFERENCE_LIBDIR")
        .unwrap_or_else(|_| format!("/usr/lib/{}-linux-musl", arch));

    let status = Command::new("musl-gcc")
        .args([
            "-static",
            // Alpine GCC defaults to PIE. This fixture exercises crabc's
            // conventional static libc.a startup path, not static-PIE.
            "-no-pie",
            "-nostdlib",
            "-fno-stack-protector",
            &format!("{}/crt1.o", musl_lib),
            &format!("{}/crti.o", musl_lib),
            hello_src.to_str().unwrap(),
            libc_a.to_str().unwrap(),
            &format!("{}/crtn.o", musl_lib),
            "-o",
            hello_bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc");
    assert!(status.success(), "static link with libc.a failed");

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
