fn main() {
    // Rust's cdylib linker otherwise adds the platform crt startup objects.
    // Their linker-generated global `_init`/`_fini` symbols override the
    // musl ABI's weak exports.  libc has no crt entry point of its own, so
    // omit only those startup files; Rust's init/fini arrays remain in the
    // shared object and are handled by the dynamic linker.
    println!("cargo:rustc-cdylib-link-arg=-nostartfiles");
}
