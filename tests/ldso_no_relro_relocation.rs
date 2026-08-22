#[path = "common/mod.rs"]
mod test_support;

use std::process::{Command, Output};

fn compile_shared(source: &std::path::Path, output: &std::path::Path) {
    let status = Command::new("musl-gcc")
        .args([
            "-O3",
            "-shared",
            "-fPIC",
            "-fno-builtin",
            "-Wl,-z,norelro",
            "-Wl,-z,pack-relative-relocs",
        ])
        .arg(source)
        .args(["-o"])
        .arg(output)
        .status()
        .expect("failed to compile no-RELRO DSO");
    assert!(status.success(), "no-RELRO DSO compilation failed");
}

fn compile_fixture(binary: &std::path::Path, candidate: bool) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let target = root.join("target/debug");
    let fixture = root.join("tests/fixtures/ldso_no_relro_relocation_test.c");
    let mut command = Command::new("musl-gcc");
    command.args(["-O3", "-fPIE", "-pie", "-fno-builtin"]);
    if candidate {
        command.args([
            "-I",
            root.join("include").to_str().unwrap(),
            "-Wl,--dynamic-linker",
            target.join("libldso.so").to_str().unwrap(),
            "-L",
            target.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
        ]);
    }
    command
        .arg(fixture)
        .args(["-ldl", "-lc", "-o"])
        .arg(binary);
    let status = command
        .status()
        .expect("failed to compile no-RELRO relocation fixture");
    assert!(status.success(), "no-RELRO relocation fixture compilation failed");
}

fn run(binary: &std::path::Path, first: &std::path::Path, second: &std::path::Path, candidate: bool) -> Output {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(binary);
    command.args([first, second]).env("LD_LIBRARY_PATH", first.parent().unwrap());
    if candidate {
        command.env(
            "LD_LIBRARY_PATH",
            format!(
                "{}:{}",
                first.parent().unwrap().display(),
                root.join("target/debug").display()
            ),
        );
    }
    command
        .output()
        .expect("failed to run no-RELRO relocation fixture")
}

#[test]
fn late_load_does_not_repeat_no_relro_relocations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("tests/fixtures");
    let reference = test_support::TempArtifact::new("no-relro-relocation-reference");
    let candidate = test_support::TempArtifact::new("no-relro-relocation-candidate");
    let first = test_support::TempArtifact::new("libno_relro_first.so");
    let second = test_support::TempArtifact::new("libno_relro_second.so");

    compile_shared(&fixtures.join("ldso_no_relro_value_dso.c"), &first);
    compile_shared(&fixtures.join("ldso_no_relro_second_dso.c"), &second);
    let program_headers = Command::new("readelf")
        .arg("-Wl")
        .arg(&first)
        .output()
        .expect("failed to inspect no-RELRO DSO program headers");
    assert!(program_headers.status.success(), "readelf failed for no-RELRO DSO");
    assert!(
        !String::from_utf8_lossy(&program_headers.stdout).contains("GNU_RELRO"),
        "fixture unexpectedly has a GNU_RELRO segment"
    );
    let relocations = Command::new("readelf")
        .args(["-Wr"])
        .arg(&first)
        .output()
        .expect("failed to inspect no-RELRO DSO relocations");
    assert!(relocations.status.success(), "readelf failed for no-RELRO DSO relocations");
    assert!(
        String::from_utf8_lossy(&relocations.stdout).contains(".relr.dyn"),
        "fixture lacks the packed base-relative relocation this regression needs"
    );
    compile_fixture(&reference, false);
    compile_fixture(&candidate, true);

    let reference_output = run(&reference, &first, &second, false);
    let candidate_output = run(&candidate, &first, &second, true);
    assert!(
        reference_output.status.success(),
        "pinned musl fixture failed with {:?}: {}",
        reference_output.status.code(),
        String::from_utf8_lossy(&reference_output.stderr),
    );
    assert_eq!(reference_output.stdout, b"no-relro relocation ok\n");
    assert_eq!(candidate_output.status, reference_output.status);
    assert_eq!(candidate_output.stdout, reference_output.stdout);
    assert_eq!(candidate_output.stderr, reference_output.stderr);
}
