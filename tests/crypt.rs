#[path = "common/mod.rs"]
mod test_support;

use std::process::Command;

#[test]
fn crypt_under_libc_so() {
    let manifest_dir = std::path::Path::new(test_support::REPOSITORY_ROOT);

    let libc_path = manifest_dir.join("target/debug/libc.so");
    assert!(libc_path.exists(), "libc.so not found");

    // Create test C source
    let test_src = r#"
#include <crypt.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
static char *p;

extern char *__crypt_blowfish(const char *, const char *, char *);
extern char *__crypt_md5(const char *, const char *, char *);

#define CHECK(expected, salt, key) \
    p = crypt(key, salt); \
    if (!p) p = "*"; \
    if (strcmp(p, expected) != 0) { \
        write(2, "FAIL\n", 5); \
        failures++; \
    }

#define CHECK_R(expected, salt, key) \
    do { \
        struct crypt_data data = { 0x13579bdf, { 0 } }; \
        int initialized = data.initialized; \
        p = crypt_r(key, salt, &data); \
        if (!p || p != data.__buf || data.initialized != initialized || strcmp(p, expected) != 0) { \
            write(2, "FAIL-R\\n", 7); \
            failures++; \
        } \
    } while (0)

int main() {
    /* MD5-crypt is ABI-visible but deliberately unsupported in crabc. */
    CHECK("*", "$1$abcd0123$", "Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !")
    CHECK("*", "$1$$", "")
    CHECK("*", "$1$salt$", "")
    if (__crypt_md5(NULL, NULL, NULL) != NULL ||
        __crypt_blowfish(NULL, NULL, NULL) != NULL ||
        crypt_r("x", "$1$salt$", NULL) != NULL) {
        write(2, "FAIL-NULL\n", 10);
        failures++;
    }

    /* SHA-256: canonical Base64ShaCrypt salts use dependency-owned MCF. */
    CHECK("$5$rounds=5000$9aEeVXnCiCNHUjO/$FrVBcjyJukRaE6inMYazyQv1DBnwaKfom.71ebgQR/0", "$5$9aEeVXnCiCNHUjO/", "foobar")
    CHECK("$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D", "$5$rounds=100000$9aEeVXnCiCNHUjO/", "foobar")

    /* SHA-512 */
    CHECK("$6$rounds=5000$bbe605c2cce4c642$BiBOywFAm9kdv6ZPpj2GaKVqeh/.c21pf1uFBaq.e59KEE2Ej74iJleXaLXURYV6uh5LF4K7dDc4vtRtPiiKB/", "$6$bbe605c2cce4c642", "foobar")
    CHECK("$6$rounds=100000$bbe605c2cce4c642$bCGLqF35/fKkEVLwsr19YOM6.EcwMQ1svcz3iFHIfJZZ3etWnNZIMpAlO3EC3OHZJpNqNlC0sMLh3K/ctWdmF1", "$6$rounds=100000$bbe605c2cce4c642", "foobar")
    CHECK("*", "$5$", "foobar")
    CHECK("*", "$5$x", "foobar")
    CHECK("*", "$6$xx", "foobar")
    CHECK("*", "$5$9aEeVXnCiCNHUjO/$extra", "foobar")
    CHECK_R("$5$rounds=5000$9aEeVXnCiCNHUjO/$FrVBcjyJukRaE6inMYazyQv1DBnwaKfom.71ebgQR/0", "$5$9aEeVXnCiCNHUjO/", "foobar");
    CHECK_R("$6$rounds=100000$bbe605c2cce4c642$bCGLqF35/fKkEVLwsr19YOM6.EcwMQ1svcz3iFHIfJZZ3etWnNZIMpAlO3EC3OHZJpNqNlC0sMLh3K/ctWdmF1", "$6$rounds=100000$bbe605c2cce4c642", "foobar");

    /* Blowfish/bcrypt is ABI-visible but deliberately unsupported in crabc. */
    CHECK("*", "$2a$04$0123456789012345678901", "")
    CHECK("*", "$2a$04$abcdefghijklmnopqrstuv", "Aa@\xaa 0123456789")
    CHECK("*", "$2y$04$abcdefghijklmnopqrstuv", "\xff\xff\xff\xa3\x33\x01\x40")

    /* Blowfish invalid salts return "*" */
    p = crypt("", "$2a$00$0123456789012345678901");
    if (!p || strcmp(p, "*") != 0) { write(2, "FAIL\n", 5); failures++; }
    p = crypt("", "$2a$08$01234567890123456789");
    if (!p || strcmp(p, "*") != 0) { write(2, "FAIL\n", 5); failures++; }

    if (failures == 0) write(1, "crypt ok\n", 9);
    return failures;
}
"#;

    let src_path = test_support::TempArtifact::new("crypt_test.c");
    std::fs::write(&src_path, test_src).expect("failed to write crypt test source");

    let bin_path = test_support::TempArtifact::new("crypt_test");
    let dynamic_linker = format!(
        "-Wl,--dynamic-linker={}",
        manifest_dir.join("target/debug/libldso.so").display()
    );
    let status = Command::new("musl-gcc")
        .args([
            "-fPIE",
            "-pie",
            "-D_GNU_SOURCE",
            "-I",
            manifest_dir.join("include").to_str().unwrap(),
            "-L",
            manifest_dir.join("target/debug").to_str().unwrap(),
            src_path.to_str().unwrap(),
            "-Wl,--allow-shlib-undefined",
            "-lc",
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .arg(dynamic_linker)
        .status()
        .expect("failed to compile crypt test");
    assert!(status.success(), "crypt test compilation failed");

    let output = Command::new(&bin_path)
        .env(
            "LD_LIBRARY_PATH",
            manifest_dir.join("target/debug").to_str().unwrap(),
        )
        .output()
        .expect("failed to run crypt test");

    assert!(
        output.status.success(),
        "crypt test failed (exit {}), stderr: {}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "crypt ok\n");
}
