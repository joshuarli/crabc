#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_reuses_the_kernel_mapped_main_pie() {
    let root = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixture = root.join("tests/fixtures/ldso_kernel_main_mapping_test.c");
    let target = root.join("target/debug");
    let reference = test_support::TempArtifact::new("ldso-kernel-main-reference");
    let candidate = test_support::TempArtifact::new("ldso-kernel-main-candidate");

    // This is the separately retained musl oracle executable. The crabc
    // candidate below links through the sealed owned driver.
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            fixture.to_str().unwrap(),
            "-o",
        ])
        .arg(reference.to_str().unwrap())
        .status()
        .expect("failed to compile pinned-musl main-image fixture");
    assert!(
        status.success(),
        "pinned-musl main-image fixture compilation failed"
    );

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-fno-builtin",
            "-L",
            target.to_str().unwrap(),
            fixture.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
        ])
        .arg(candidate.to_str().unwrap())
        .status()
        .expect("failed to compile crabc main-image fixture");
    assert!(
        status.success(),
        "crabc main-image fixture compilation failed"
    );

    let reference_output = Command::new(reference.to_str().unwrap())
        .output()
        .expect("failed to run pinned-musl main-image fixture");
    assert!(
        reference_output.status.success(),
        "pinned musl failed: {reference_output:?}"
    );
    assert_eq!(reference_output.stdout, b"kernel-main-image=ok\n");
    assert!(reference_output.stderr.is_empty());

    let candidate_output = Command::new(candidate.to_str().unwrap())
        .env("LD_LIBRARY_PATH", &target)
        .output()
        .expect("failed to run crabc main-image fixture");
    assert_eq!(candidate_output.status, reference_output.status);
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
