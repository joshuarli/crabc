#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let fixture = root.join("tests/fixtures/memmem_regression_test.c");
    let mut command = Command::new("musl-gcc");
    command.args(["-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
        ]);
    }
    command
        .arg(&fixture)
        .args(["-Wl,--allow-shlib-undefined", "-lc", "-o"])
        .arg(binary);
    let status = command
        .status()
        .expect("failed to compile the memmem regression fixture");
    assert!(status.success(), "memmem regression fixture compilation failed");
}

fn run(binary: &std::path::Path, candidate: bool) -> Output {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(binary);
    if candidate {
        command.env("LD_LIBRARY_PATH", root.join("target/debug"));
    }
    command.output().expect("failed to run the memmem regression fixture")
}

#[test]
fn memmem_matches_pinned_musl_for_binary_overlap_and_page_edges() {
    let reference = test_support::TempArtifact::new("memmem-reference");
    let candidate = test_support::TempArtifact::new("memmem-candidate");
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, false);
    let candidate_output = run(&candidate, true);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(reference_output.stdout, b"memmem oracle ok\n");
    assert_eq!(
        candidate_output.status, reference_output.status,
        "crabc exit status differs; stderr: {}",
        String::from_utf8_lossy(&candidate_output.stderr),
    );
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
