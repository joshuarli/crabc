#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("tests/fixtures/ldso_main_self_dlopen_test.c");
    let target = root.join("target/debug");
    let mut command = Command::new("musl-gcc");

    command.args(["-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
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
        .expect("failed to compile main self-dlopen fixture");
    assert!(status.success(), "main self-dlopen fixture compilation failed");
}

fn run(binary: &std::path::Path, candidate: bool) -> Output {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(binary);
    if candidate {
        command.env("LD_LIBRARY_PATH", root.join("target/debug"));
    }
    command
        .output()
        .expect("failed to run main self-dlopen fixture")
}

#[test]
fn ldso_matches_musl_for_explicit_main_executable_dlopen() {
    let reference = test_support::TempArtifact::new("ldso-main-self-dlopen-reference");
    let candidate = test_support::TempArtifact::new("ldso-main-self-dlopen-candidate");
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, false);
    let candidate_output = run(&candidate, true);
    assert!(
        reference_output.status.success(),
        "pinned musl self-dlopen fixture exited with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(reference_output.stdout, b"main-self-dlopen=ok\n");
    assert_eq!(
        candidate_output.status,
        reference_output.status,
        "crabc exit status differs; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
