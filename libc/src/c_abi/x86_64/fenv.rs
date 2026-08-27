//! Linux/x86-64 source-only C floating-point-environment leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The source map is
//! deliberately local and exact:
//!
//! - `arch/x86_64/bits/fenv.h` is the public 32-byte `fenv_t` contract already
//!   staged in [`include/fenv.h`](../../../../include/fenv.h).
//! - `src/fenv/x86_64/fenv.s` supplies the instruction sequences below for
//!   `feclearexcept`, `feraiseexcept`, `__fesetround`, `fegetround`,
//!   `fegetenv`, `fesetenv`, and `fetestexcept`.
//! - `src/fenv/{fegetexceptflag,feholdexcept,fesetexceptflag,fesetround,
//!   feupdateenv,__flt_rounds}.c` maps to the Rust C-ABI wrappers below.
//!
//! The intentional implementation difference is lexical only: the fixed
//! assembly is carried by Rust's `global_asm!` and the tiny generic wrappers
//! live in this one `no_std` source file. This remains a source-only evidence
//! leaf until the wider x86 `crabc-libc` composition is selected; it must not
//! be mistaken for a complete C runtime or public x86 support claim.

use core::ffi::c_int;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 C fenv leaf requires little-endian Linux/x86-64");

const FE_ALL_EXCEPT: c_int = 63;
const FE_TONEAREST: c_int = 0;
const FE_DOWNWARD: c_int = 0x400;
const FE_UPWARD: c_int = 0x800;
const FE_TOWARDZERO: c_int = 0xc00;

/// The x86 C header's unsigned-short exception-flag storage.
pub type Fexcept = u16;

/// Exact musl x86-64 public `fenv_t` storage.
///
/// The C header's two adjacent bit-fields occupy the one `u16` at offset 18;
/// all operations below preserve its raw bits through the x87 `FNSTENV` and
/// `FLDENV` instructions. This is deliberately a private C-layout record,
/// not `crabc-core::fenv::Environment`, whose smaller typed snapshot does not
/// carry tag/instruction metadata.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct Fenv {
    control_word: u16,
    unused1: u16,
    status_word: u16,
    unused2: u16,
    tags: u16,
    unused3: u16,
    instruction_pointer: u32,
    code_selector: u16,
    opcode_and_reserved: u16,
    data_offset: u32,
    data_selector: u16,
    unused5: u16,
    mxcsr: u32,
}

const _: [(); 32] = [(); core::mem::size_of::<Fenv>()];
const _: [(); 4] = [(); core::mem::align_of::<Fenv>()];
const _: [(); 4] = [(); core::mem::offset_of!(Fenv, status_word)];
const _: [(); 28] = [(); core::mem::offset_of!(Fenv, mxcsr)];

// These are the fixed musl `src/fenv/x86_64/fenv.s` instruction sequences in
// Intel syntax. Preserve their intentionally asymmetric behavior: x87 status
// is observed/cleared where musl does so, while `feraiseexcept` records the
// raised flags in MXCSR. Replacing this with the narrower Rust fenv vocabulary
// would lose the public x86 denormal-operand bit and alter C behavior.
core::arch::global_asm!(
    r#"
    .text
    .global feclearexcept
    .type feclearexcept,@function
feclearexcept:
    mov ecx, edi
    and ecx, 0x3f
    fnstsw ax
    test eax, ecx
    jz 1f
    fnclex
1:
    stmxcsr dword ptr [rsp - 8]
    and eax, 0x3f
    or dword ptr [rsp - 8], eax
    test dword ptr [rsp - 8], ecx
    jz 2f
    not ecx
    and dword ptr [rsp - 8], ecx
    ldmxcsr dword ptr [rsp - 8]
2:
    xor eax, eax
    ret
    .size feclearexcept, .-feclearexcept

    .global feraiseexcept
    .type feraiseexcept,@function
feraiseexcept:
    and edi, 0x3f
    stmxcsr dword ptr [rsp - 8]
    or dword ptr [rsp - 8], edi
    ldmxcsr dword ptr [rsp - 8]
    xor eax, eax
    ret
    .size feraiseexcept, .-feraiseexcept

    .global __fesetround
    .hidden __fesetround
    .type __fesetround,@function
__fesetround:
    push rax
    xor eax, eax
    mov ecx, edi
    fnstcw word ptr [rsp]
    and byte ptr [rsp + 1], 0xf3
    or byte ptr [rsp + 1], ch
    fldcw word ptr [rsp]
    stmxcsr dword ptr [rsp]
    shl ch, 3
    and byte ptr [rsp + 1], 0x9f
    or byte ptr [rsp + 1], ch
    ldmxcsr dword ptr [rsp]
    pop rcx
    ret
    .size __fesetround, .-__fesetround

    .global fegetround
    .type fegetround,@function
fegetround:
    push rax
    stmxcsr dword ptr [rsp]
    pop rax
    shr eax, 3
    and eax, 0xc00
    ret
    .size fegetround, .-fegetround

    .global fegetenv
    .type fegetenv,@function
fegetenv:
    xor eax, eax
    fnstenv [rdi]
    stmxcsr dword ptr [rdi + 28]
    ret
    .size fegetenv, .-fegetenv

    .global fesetenv
    .type fesetenv,@function
fesetenv:
    xor eax, eax
    inc rdi
    jz 3f
    fldenv [rdi - 1]
    ldmxcsr dword ptr [rdi + 27]
    ret
3:
    push rax
    push rax
    push 0xffff
    push 0x37f
    fldenv [rsp]
    push 0x1f80
    ldmxcsr dword ptr [rsp]
    add rsp, 40
    ret
    .size fesetenv, .-fesetenv

    .global fetestexcept
    .type fetestexcept,@function
fetestexcept:
    and edi, 0x3f
    push rax
    stmxcsr dword ptr [rsp]
    pop rsi
    fnstsw ax
    or eax, esi
    and eax, edi
    ret
    .size fetestexcept, .-fetestexcept

    .section .note.GNU-stack, "", @progbits
"#,
);

unsafe extern "C" {
    fn feclearexcept(mask: c_int) -> c_int;
    fn feraiseexcept(mask: c_int) -> c_int;
    fn __fesetround(rounding: c_int) -> c_int;
    fn fegetround() -> c_int;
    fn fegetenv(environment: *mut Fenv) -> c_int;
    fn fesetenv(environment: *const Fenv) -> c_int;
    fn fetestexcept(mask: c_int) -> c_int;
}

/// Stores the selected current exception flags in C's `fexcept_t` record.
#[no_mangle]
pub unsafe extern "C" fn fegetexceptflag(flags: *mut Fexcept, mask: c_int) -> c_int {
    // SAFETY: C's API requires writable `fexcept_t` storage. The direct
    // assembly helper owns no pointer and returns only scalar flag bits.
    unsafe {
        *flags = fetestexcept(mask) as Fexcept;
    }
    0
}

/// Saves the complete x86 C environment and clears its pending exceptions.
#[no_mangle]
pub unsafe extern "C" fn feholdexcept(environment: *mut Fenv) -> c_int {
    // SAFETY: C's API requires writable `fenv_t` storage. These fixed musl
    // helpers use that same exact x87/MXCSR layout.
    unsafe {
        fegetenv(environment);
        feclearexcept(FE_ALL_EXCEPT);
    }
    0
}

/// Replaces selected exception flags without changing unselected flags.
#[no_mangle]
pub unsafe extern "C" fn fesetexceptflag(flags: *const Fexcept, mask: c_int) -> c_int {
    // SAFETY: C's API requires readable `fexcept_t` storage. The two helpers
    // preserve the fixed musl clear-then-raise ordering.
    unsafe {
        let selected = *flags as c_int;
        feclearexcept(!selected & mask);
        feraiseexcept(selected & mask);
    }
    0
}

/// Validates and installs one of the four C rounding modes.
#[no_mangle]
pub unsafe extern "C" fn fesetround(rounding: c_int) -> c_int {
    match rounding {
        FE_TONEAREST | FE_DOWNWARD | FE_UPWARD | FE_TOWARDZERO => {
            // SAFETY: The match admits exactly the fixed x86 rounding
            // encodings consumed by the hidden assembly helper.
            unsafe { __fesetround(rounding) }
        }
        _ => -1,
    }
}

/// Restores an environment and re-raises flags that were pending beforehand.
#[no_mangle]
pub unsafe extern "C" fn feupdateenv(environment: *const Fenv) -> c_int {
    // SAFETY: C's API requires readable `fenv_t` storage. The scalar flags are
    // captured before the restore exactly as in musl's generic wrapper.
    unsafe {
        let exceptions = fetestexcept(FE_ALL_EXCEPT);
        fesetenv(environment);
        feraiseexcept(exceptions);
    }
    0
}

/// Returns C99's `FLT_ROUNDS` classification for the current x86 environment.
#[no_mangle]
pub extern "C" fn __flt_rounds() -> c_int {
    // SAFETY: The fixed no-argument assembly helper observes only the calling
    // thread's MXCSR rounding field.
    match unsafe { fegetround() } {
        FE_TOWARDZERO => 0,
        FE_TONEAREST => 1,
        FE_UPWARD => 2,
        FE_DOWNWARD => 3,
        _ => -1,
    }
}
