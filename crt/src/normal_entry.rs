//! Conventional dynamically relocated and static ET_EXEC AArch64 entry.

/// Kernel entry shim for `crt1.o` and `Scrt1.o`.
///
/// This is naked because compiler-generated frame setup would overwrite the
/// kernel entry-state contract. `x9` preserves the original stack pointer
/// while `sp` is explicitly realigned before normal Rust code runs. The
/// dynamic linker supplies its process-finalizer callback in `x0`; an
/// ordinary static ELF entry has no such register contract, so `crt1.o`
/// explicitly passes null instead.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    #[cfg(crabc_dynamic_startup)]
    core::arch::naked_asm!(
        "mov x9, sp",
        "mov x10, x0",
        "mov x29, xzr",
        "mov x30, xzr",
        "and sp, x9, #0xfffffffffffffff0",
        "mov x0, x9",
        "mov x1, x10",
        "b {startup}",
        startup = sym crate::__crabc_start,
    );
    #[cfg(not(crabc_dynamic_startup))]
    core::arch::naked_asm!(
        "mov x9, sp",
        "mov x29, xzr",
        "mov x30, xzr",
        "and sp, x9, #0xfffffffffffffff0",
        "mov x0, x9",
        "mov x1, xzr",
        "b {startup}",
        startup = sym crate::__crabc_start,
    );
}
