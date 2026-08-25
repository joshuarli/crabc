#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn ldso_deduplicates_needed_symlink_aliases() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);
    let fixtures = manifest_dir.join("tests/fixtures");
    let target = manifest_dir.join("target/debug");
    let ldso_path = target.join("libldso.so");
    let libc_path = target.join("libc.so");
    let bin = test_support::TempArtifact::new("ldso_alias_dedup_test");
    let fake_libs = bin.parent().join("fake-libs");

    assert!(ldso_path.exists(), "libldso.so not found");
    assert!(libc_path.exists(), "libc.so not found");
    std::fs::create_dir(&fake_libs).expect("failed to create isolated fake-library directory");
    for library in [
        "libc",
        "libpthread",
        "libm",
        "librt",
        "libcrypt",
        "libdl",
        "libresolv",
        "libutil",
    ] {
        std::os::unix::fs::symlink(&libc_path, fake_libs.join(format!("{library}.so")))
            .expect("failed to create isolated libc alias");
    }

    let status = Command::new(test_support::crabc_cc())
        .args([
            "-fPIE",
            "-pie",
            "-I",
            manifest_dir.join("include").to_str().unwrap(),
            "-L",
            fake_libs.to_str().unwrap(),
            "-Wl,--no-as-needed",
            "-lpthread",
            "-lm",
            "-lrt",
            "-lcrypt",
            "-ldl",
            "-lresolv",
            "-lutil",
            "-Wl,--as-needed",
            fixtures.join("ldso_alias_dedup_test.c").to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("failed to compile alias dedup fixture");
    assert!(status.success(), "alias dedup fixture compilation failed");

    let dynamic = Command::new("readelf")
        .args(["-d", bin.to_str().unwrap()])
        .output()
        .expect("failed to inspect alias fixture dynamic section");
    assert!(
        dynamic.status.success(),
        "readelf alias fixture inspection failed"
    );
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    for alias in [
        "libpthread.so",
        "libm.so",
        "librt.so",
        "libcrypt.so",
        "libdl.so",
        "libresolv.so",
        "libutil.so",
    ] {
        assert!(
            dynamic.contains(alias),
            "fixture does not retain DT_NEEDED alias {alias}: {dynamic}",
        );
    }

    let output = Command::new(&bin)
        .env(
            "LD_LIBRARY_PATH",
            format!("{}:{}", fake_libs.display(), target.display()),
        )
        .output()
        .expect("failed to run alias dedup fixture");
    assert!(
        output.status.success(),
        "alias DT_NEEDED entries mapped duplicate libc objects: stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}
