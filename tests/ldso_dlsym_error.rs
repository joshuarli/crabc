#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir.join("tests/fixtures/ldso_dlsym_error_test.c");
    let target = manifest_dir.join("target/debug");
    let mut command = Command::new("musl-gcc");

    command.args(["-fPIE", "-pie"]);
    if candidate {
        command.args([
            "-I",
            manifest_dir.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    let status = command
        .arg(&fixture)
        .args(["-ldl", "-lc", "-o"])
        .arg(binary)
        .status()
        .expect("failed to compile dlsym error fixture");
    assert!(status.success(), "dlsym error fixture compilation failed");
}

fn run(binary: &std::path::Path, candidate: bool) -> Output {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(binary);
    if candidate {
        command.env("LD_LIBRARY_PATH", manifest_dir.join("target/debug"));
    }
    command.output().expect("failed to run dlsym error fixture")
}

#[test]
fn ldso_dlsym_error_names_the_missing_symbol() {
    let reference = test_support::TempArtifact::new("ldso-dlsym-error-reference");
    let candidate = test_support::TempArtifact::new("ldso-dlsym-error-candidate");
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, false);
    let candidate_output = run(&candidate, true);
    assert!(
        reference_output.status.success(),
        "pinned musl dlsym error fixture exited with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr)
    );
    assert_eq!(reference_output.stdout, b"dlsym error name ok\n");
    assert_eq!(
        candidate_output.status,
        reference_output.status,
        "crabc exit status differs; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
