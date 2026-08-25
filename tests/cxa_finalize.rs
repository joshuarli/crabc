#[path = "common/mod.rs"]
mod test_support;

use std::path::Path;
use std::process::Command;

fn compile_fixture(root: &Path, source: &Path, output: &Path, candidate: bool) {
    let mut command = if candidate {
        Command::new(test_support::crabc_cc())
    } else {
        Command::new("musl-gcc")
    };
    command.args(["-fPIE", "-pie", "-fno-builtin", "-I"]);
    command.arg(root.join("include"));
    if candidate {
        command.arg("-L");
        command.arg(root.join("target/debug"));
    }
    command.arg(source);
    if candidate {
        command.args(["-Wl,--allow-shlib-undefined", "-lc"]);
    }
    let status = command
        .arg("-o")
        .arg(output)
        .status()
        .expect("failed to compile __cxa_finalize fixture");
    assert!(status.success(), "__cxa_finalize fixture compilation failed");
}

#[test]
fn cxa_finalize_matches_musl_noop_and_process_exit_order() {
    let root = Path::new(test_support::REPOSITORY_ROOT);
    let source = root.join("tests/fixtures/cxa_finalize_test.c");
    let reference = test_support::TempArtifact::new("musl-cxa-finalize");
    let candidate = test_support::TempArtifact::new("crabc-cxa-finalize");
    let reference_marker = test_support::TempArtifact::new("musl-cxa-finalize-marker");
    let candidate_marker = test_support::TempArtifact::new("crabc-cxa-finalize-marker");

    compile_fixture(root, &source, &reference, false);
    compile_fixture(root, &source, &candidate, true);

    let reference_output = Command::new(&reference)
        .arg(reference_marker.as_os_str())
        .output()
        .expect("failed to run pinned-musl __cxa_finalize fixture");
    assert!(
        reference_output.status.success(),
        "pinned-musl __cxa_finalize fixture exited with {:?}, stdout: {}, stderr: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stdout),
        String::from_utf8_lossy(&reference_output.stderr)
    );

    let candidate_output = Command::new(&candidate)
        .arg(candidate_marker.as_os_str())
        .env("LD_LIBRARY_PATH", root.join("target/debug"))
        .output()
        .expect("failed to run __cxa_finalize fixture");
    assert!(
        candidate_output.status.success(),
        "__cxa_finalize fixture exited with {:?}, stdout: {}, stderr: {}",
        candidate_output.status.code(),
        String::from_utf8_lossy(&candidate_output.stdout),
        String::from_utf8_lossy(&candidate_output.stderr)
    );
    let reference_trace = std::fs::read_to_string(&*reference_marker)
        .expect("failed to read pinned-musl __cxa_finalize marker");
    assert_eq!(reference_trace, "first-new\nsecond\nfirst-old\n");
    assert_eq!(
        std::fs::read_to_string(&*candidate_marker)
            .expect("failed to read crabc __cxa_finalize marker"),
        reference_trace
    );
}
