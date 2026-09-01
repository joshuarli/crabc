fn main() {
    // The installed static product compiles its dlfcn bridge with a local
    // unavailable-record trampoline, rather than carrying a dynamic-loader
    // weak import into a closed ET_EXEC image.
    println!("cargo::rustc-check-cfg=cfg(crabc_owned_static_sysroot)");
    // Rust's cdylib linker otherwise adds the platform crt startup objects.
    // Their linker-generated global `_init`/`_fini` symbols override the
    // musl ABI's weak exports.  libc has no crt entry point of its own, so
    // omit only those startup files; Rust's init/fini arrays remain in the
    // shared object and are handled by the dynamic linker.
    println!("cargo:rustc-cdylib-link-arg=-nostartfiles");
    // Keep the workspace-wide `link-dead-code` instrumentation, but let this
    // final panic-abort cdylib discard unreachable target-std unwind cleanup
    // retained by RustCrypto's alloc-enabled MCF serializer. This affects
    // neither the static archive nor any other workspace artifact.
    println!("cargo:rustc-cdylib-link-arg=-Wl,--gc-sections");
}
