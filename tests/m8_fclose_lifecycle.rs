#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn freopen_replaces_memory_streams_and_preserves_standard_stream_storage() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/m8_fclose_lifecycle_test.c");
    let binary = test_support::TempArtifact::new("crabc-m8-fclose-lifecycle");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile the M8 fclose lifetime fixture");
    assert!(status.success(), "M8 fclose lifetime fixture did not compile");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run the M8 fclose lifetime fixture");
    assert!(
        output.status.success(),
        "M8 fclose lifetime fixture exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
