#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn quick_exit_handlers_under_libc_so() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/quick_exit_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-quick-exit");
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE", "-pie", "-fno-builtin", "-I",
            root.join("include").to_str().unwrap(), "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(), "-L",
            target.to_str().unwrap(), source.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined", "-lc", "-o", binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run musl-gcc for quick_exit_exports_test");
    assert!(status.success(), "quick_exit_exports_test compilation failed");
    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run quick_exit_exports_test");
    let _ = std::fs::remove_file(&binary);
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "second\nfirst\n");
    assert!(output.stderr.is_empty());
}
