#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ctype_assert_exports_under_libc_so() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let target = root.join("target/debug");
    let source = root.join("tests/fixtures/ctype_assert_exports_test.c");
    let binary = test_support::TempArtifact::new("crabc-c-abi-ctype-assert");

    let args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-fno-builtin".to_string(),
        "-D_GNU_SOURCE".to_string(),
        "-I".to_string(),
        root.join("include").to_str().unwrap().to_string(),
        "-L".to_string(),
        target.to_str().unwrap().to_string(),
        source.to_str().unwrap().to_string(),
        "-Wl,--allow-shlib-undefined".to_string(),
        "-lc".to_string(),
        "-o".to_string(),
        binary.to_str().unwrap().to_string(),
    ];
    let status = Command::new(test_support::crabc_cc())
        .args(&args)
        .status()
        .expect("failed to compile ctype_assert_exports_test");
    assert!(
        status.success(),
        "ctype_assert_exports_test compilation failed"
    );

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run ctype_assert_exports_test");
    let _ = std::fs::remove_file(&binary);
    assert!(
        output.status.success(),
        "ctype_assert_exports_test exited with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi ctype assert exports ok\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Assertion failed: value != 0 (ctype_assert_exports_test.c: main: 77)\n"
    );
}
