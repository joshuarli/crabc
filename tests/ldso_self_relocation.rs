#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_self_relocates_at_the_auxv_interpreter_base() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = root.join("tests/fixtures/ldso_self_relocation_test.c");
    let binary = test_support::TempArtifact::new("crabc-ldso-self-relocation");
    let target = root.join("target/debug");
    let ldso = target.join("libldso.so");

    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-I",
            root.join("include").to_str().unwrap(),
            source.to_str().unwrap(),
            "-Wl,--dynamic-linker",
            ldso.to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            binary.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile ldso self-relocation fixture");
    assert!(status.success(), "fixture compilation failed");

    let output = Command::new(&binary)
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run ldso self-relocation fixture");
    assert!(
        output.status.success(),
        "fixture exited with {:?}; stdout: {}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"ldso self relocation ok\n");
}
