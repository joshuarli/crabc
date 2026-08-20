#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn existing_math_exports_have_musl_abi() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures");
    let include = manifest_dir.join("include");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");

    let src = fixtures.join("m4_existing_exports_test.c");
    let bin = test_support::TempArtifact::new("m4_existing_exports_test");
    let mut args = vec![
        "-fPIE".to_string(),
        "-pie".to_string(),
        "-fno-builtin".to_string(),
    ];
    // crabc uses the 64-bit long-double ABI on x86_64; other targets use
    // their native binary128 long-double ABI.
    if cfg!(target_arch = "x86_64") {
        args.push("-mlong-double-64".to_string());
    }
    args.extend_from_slice(&[
        "-I".to_string(),
        include.to_str().unwrap().to_string(),
        "-Wl,--dynamic-linker".to_string(),
        ldso_path.to_str().unwrap().to_string(),
        "-L".to_string(),
        target.to_str().unwrap().to_string(),
        src.to_str().unwrap().to_string(),
        "-Wl,--allow-shlib-undefined".to_string(),
        "-lc".to_string(),
        "-o".to_string(),
        bin.to_str().unwrap().to_string(),
    ]);
    let status = Command::new("musl-gcc")
        .args(&args)
        .status()
        .expect("failed to run musl-gcc for m4_existing_exports_test");
    assert!(status.success(), "musl-gcc m4_existing_exports_test compilation failed");

    let output = Command::new(&bin)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run m4_existing_exports_test");
    assert!(
        output.status.success(),
        "m4_existing_exports_test exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "m4 existing exports ok\n"
    );
}
