#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn existing_math_exports_have_musl_abi() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("existing_exports_test.c");
    let bin = test_support::TempArtifact::new("existing_exports_test");
    let mut args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-fno-builtin".to_string(),
    ];
    args.extend_from_slice(&[
        "-I".to_string(),
        include.to_str().unwrap().to_string(),
        "-L".to_string(),
        target.to_str().unwrap().to_string(),
        src.to_str().unwrap().to_string(),
        "-Wl,--allow-shlib-undefined".to_string(),
        "-lc".to_string(),
        "-o".to_string(),
        bin.to_str().unwrap().to_string(),
    ]);
    let status = Command::new(test_support::crabc_cc())
        .args(&args)
        .status()
        .expect("failed to run crabc-cc for existing_exports_test");
    assert!(
        status.success(),
        "crabc-cc existing_exports_test compilation failed"
    );

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run existing_exports_test");
    assert!(
        output.status.success(),
        "existing_exports_test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "c-abi existing exports ok\n"
    );
}
