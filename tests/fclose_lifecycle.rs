#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn freopen_replaces_memory_streams_and_preserves_standard_stream_storage() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/fclose_lifecycle_test.c");
    let binary = test_support::TempArtifact::new("crabc-compat-fclose-lifecycle");

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            root.join("include").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile the fclose lifetime fixture");
    assert!(status.success(), "fclose lifetime fixture did not compile");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run the fclose lifetime fixture");
    assert!(
        output.status.success(),
        "fclose lifetime fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
