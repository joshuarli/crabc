#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_dlsym_error_names_the_missing_symbol() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir.join("tests/fixtures/ldso_dlsym_error_test.c");
    let target = manifest_dir.join("target/debug");
    let binary = test_support::TempArtifact::new("ldso_dlsym_error_test");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-I",
            manifest_dir.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            fixture.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-ldl",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for dlsym error fixture");
    assert!(status.success(), "dlsym error fixture compilation failed");

    let output = Command::new(&*binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run dlsym error fixture");
    assert!(
        output.status.success(),
        "dlsym error fixture exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "dlsym error name ok\n");
}
