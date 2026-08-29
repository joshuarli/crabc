#![no_std]

//! Checked Linux/x86-64 self-relocating static-PIE entry object.
//!
//! This target-specific foundation applies only `R_X86_64_RELATIVE` RELA and
//! RELR records before any Rust code runs, validates every table and target
//! against the executable load map, seals GNU RELRO, then enters the bounded
//! static-PIE lifecycle in `x86_64_startup`.

mod x86_64_array_boundaries;
mod x86_64_startup;
mod x86_64_static_tls;

pub use x86_64_startup::__crabc_x86_64_static_pie_start;

core::arch::global_asm!(
    r#"
    .intel_syntax noprefix
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    // Keep the kernel stack and establish the x86-64 SysV call alignment.
    // The bootstrap uses a small unrelocated local area only; it never reads
    // GOT, TLS, or Rust state before relocating the image.
    mov r15, rsp
    xor ebp, ebp
    and rsp, -16
    sub rsp, 80

    // Walk argc, argv, envp, then auxv for AT_PHDR/AT_PHENT/AT_PHNUM.
    mov rax, QWORD PTR [r15]
    cmp rax, 0x100000
    ja .Lstatic_pie_fail
    lea r8, [r15 + rax * 8 + 16]
    mov ecx, 0x100000
.Lstatic_pie_env:
    test rcx, rcx
    jz .Lstatic_pie_fail
    mov rdx, QWORD PTR [r8]
    add r8, 8
    dec rcx
    test rdx, rdx
    jnz .Lstatic_pie_env

    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    mov ecx, 4096
.Lstatic_pie_auxv:
    test rcx, rcx
    jz .Lstatic_pie_fail
    mov rax, QWORD PTR [r8]
    mov rdx, QWORD PTR [r8 + 8]
    add r8, 16
    dec rcx
    test rax, rax
    jz .Lstatic_pie_auxv_done
    cmp rax, 3
    jne .Lstatic_pie_not_phdr
    mov r12, rdx
    jmp .Lstatic_pie_auxv
.Lstatic_pie_not_phdr:
    cmp rax, 4
    jne .Lstatic_pie_not_phent
    mov r14, rdx
    jmp .Lstatic_pie_auxv
.Lstatic_pie_not_phent:
    cmp rax, 5
    jne .Lstatic_pie_auxv
    mov r13, rdx
    jmp .Lstatic_pie_auxv
.Lstatic_pie_auxv_done:
    test r12, r12
    jz .Lstatic_pie_fail
    cmp r14, 56
    jne .Lstatic_pie_fail
    test r13, r13
    jz .Lstatic_pie_fail
    cmp r13, 128
    ja .Lstatic_pie_fail

    // Find the single PT_PHDR and PT_DYNAMIC records in the bounded table.
    mov r8, r12
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor eax, eax
    mov QWORD PTR [rsp + 40], rax
    mov QWORD PTR [rsp + 48], rax
.Lstatic_pie_program_headers:
    cmp r9, r13
    jae .Lstatic_pie_program_headers_done
    mov eax, DWORD PTR [r8]
    cmp eax, 6
    jne .Lstatic_pie_not_program_header
    test r10, r10
    jnz .Lstatic_pie_fail
    mov r14, QWORD PTR [r8 + 16]
    mov r10d, 1
    jmp .Lstatic_pie_next_program_header
.Lstatic_pie_not_program_header:
    cmp eax, 2
    jne .Lstatic_pie_next_program_header
    test r11, r11
    jnz .Lstatic_pie_fail
    mov rax, QWORD PTR [r8 + 16]
    mov QWORD PTR [rsp + 40], rax
    mov rax, QWORD PTR [r8 + 40]
    mov QWORD PTR [rsp + 48], rax
    mov r11d, 1
.Lstatic_pie_next_program_header:
    add r8, 56
    inc r9
    jmp .Lstatic_pie_program_headers
.Lstatic_pie_program_headers_done:
    test r10, r10
    jz .Lstatic_pie_fail
    test r11, r11
    jz .Lstatic_pie_fail
    cmp QWORD PTR [rsp + 48], 0
    je .Lstatic_pie_fail
    mov rbx, r12
    sub rbx, r14

    // PT_DYNAMIC must itself be completely mapped before tag traversal.
    mov rdi, QWORD PTR [rsp + 40]
    add rdi, rbx
    jc .Lstatic_pie_fail
    mov rsi, QWORD PTR [rsp + 48]
    xor edx, edx
    lea r11, [rip + .Lstatic_pie_after_dynamic_range]
    jmp .Lstatic_pie_require_load_range
.Lstatic_pie_after_dynamic_range:
    mov r8, QWORD PTR [rsp + 40]
    add r8, rbx
    jc .Lstatic_pie_fail
    mov r9, r8
    add r9, QWORD PTR [rsp + 48]
    jc .Lstatic_pie_fail

    // Keep dynamic relocation values in the unrelocated local area:
    // RELA address/size, RELR address/size/entry-size.
    xor eax, eax
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp + 8], rax
    mov QWORD PTR [rsp + 16], rax
    mov QWORD PTR [rsp + 24], rax
    mov QWORD PTR [rsp + 32], rax
.Lstatic_pie_dynamic:
    lea rax, [r8 + 16]
    cmp rax, r9
    ja .Lstatic_pie_fail
    mov rax, QWORD PTR [r8]
    mov rcx, QWORD PTR [r8 + 8]
    add r8, 16
    test rax, rax
    jz .Lstatic_pie_dynamic_done
    cmp rax, 7
    jne .Lstatic_pie_not_rela
    mov QWORD PTR [rsp], rcx
    jmp .Lstatic_pie_dynamic
.Lstatic_pie_not_rela:
    cmp rax, 8
    jne .Lstatic_pie_not_relasz
    mov QWORD PTR [rsp + 8], rcx
    jmp .Lstatic_pie_dynamic
.Lstatic_pie_not_relasz:
    cmp rax, 36
    jne .Lstatic_pie_not_relr
    mov QWORD PTR [rsp + 16], rcx
    jmp .Lstatic_pie_dynamic
.Lstatic_pie_not_relr:
    cmp rax, 35
    jne .Lstatic_pie_not_relrsz
    mov QWORD PTR [rsp + 24], rcx
    jmp .Lstatic_pie_dynamic
.Lstatic_pie_not_relrsz:
    cmp rax, 37
    jne .Lstatic_pie_dynamic
    mov QWORD PTR [rsp + 32], rcx
    jmp .Lstatic_pie_dynamic
.Lstatic_pie_dynamic_done:

    // Only symbol-free R_X86_64_RELATIVE RELA records are valid here.
    mov rsi, QWORD PTR [rsp + 8]
    test rsi, rsi
    jz .Lstatic_pie_rela_done
    mov rdi, QWORD PTR [rsp]
    test rdi, rdi
    jz .Lstatic_pie_fail
    mov rax, rsi
    xor edx, edx
    mov ecx, 24
    div rcx
    test rdx, rdx
    jnz .Lstatic_pie_fail
    mov rdi, QWORD PTR [rsp]
    add rdi, rbx
    jc .Lstatic_pie_fail
    mov rsi, QWORD PTR [rsp + 8]
    xor edx, edx
    lea r11, [rip + .Lstatic_pie_after_rela_table_range]
    jmp .Lstatic_pie_require_load_range
.Lstatic_pie_after_rela_table_range:
    mov r8, QWORD PTR [rsp]
    add r8, rbx
    jc .Lstatic_pie_fail
    mov r9, r8
    add r9, QWORD PTR [rsp + 8]
    jc .Lstatic_pie_fail
.Lstatic_pie_rela:
    cmp r8, r9
    jae .Lstatic_pie_rela_done
    mov rax, QWORD PTR [r8]
    mov rcx, QWORD PTR [r8 + 8]
    mov r14, QWORD PTR [r8 + 16]
    mov rdx, rcx
    shr rdx, 32
    test rdx, rdx
    jnz .Lstatic_pie_fail
    test ecx, ecx
    jz .Lstatic_pie_next_rela
    cmp ecx, 8
    jne .Lstatic_pie_fail
    test al, 7
    jnz .Lstatic_pie_fail
    mov rdi, rbx
    add rdi, rax
    jc .Lstatic_pie_fail
    mov r10, r8
    mov rbp, r9
    mov esi, 8
    mov edx, 1
    lea r11, [rip + .Lstatic_pie_after_rela_target_range]
    jmp .Lstatic_pie_require_load_range
.Lstatic_pie_after_rela_target_range:
    add r14, rbx
    jc .Lstatic_pie_fail
    mov QWORD PTR [rdi], r14
    lea r8, [r10 + 24]
    mov r9, rbp
    jmp .Lstatic_pie_rela
.Lstatic_pie_next_rela:
    add r8, 24
    jmp .Lstatic_pie_rela
.Lstatic_pie_rela_done:

    // RELR is accepted only with its ELF64 entry size and writable targets.
    mov rsi, QWORD PTR [rsp + 24]
    test rsi, rsi
    jz .Lstatic_pie_relr_done
    mov rdi, QWORD PTR [rsp + 16]
    test rdi, rdi
    jz .Lstatic_pie_fail
    cmp QWORD PTR [rsp + 32], 8
    jne .Lstatic_pie_fail
    test rsi, 7
    jnz .Lstatic_pie_fail
    add rdi, rbx
    jc .Lstatic_pie_fail
    xor edx, edx
    lea r11, [rip + .Lstatic_pie_after_relr_table_range]
    jmp .Lstatic_pie_require_load_range
.Lstatic_pie_after_relr_table_range:
    mov r8, QWORD PTR [rsp + 16]
    add r8, rbx
    jc .Lstatic_pie_fail
    mov r9, r8
    add r9, QWORD PTR [rsp + 24]
    jc .Lstatic_pie_fail
    xor ebp, ebp
    xor r14d, r14d
.Lstatic_pie_relr:
    cmp r8, r9
    jae .Lstatic_pie_relr_done
    mov rax, QWORD PTR [r8]
    add r8, 8
    test al, 1
    jnz .Lstatic_pie_relr_bitmap
    test rax, 7
    jnz .Lstatic_pie_fail
    mov r14, rbx
    add r14, rax
    jc .Lstatic_pie_fail
    mov r10, r8
    mov rdi, r14
    mov esi, 8
    mov edx, 1
    lea r11, [rip + .Lstatic_pie_after_relr_target_range]
    jmp .Lstatic_pie_require_load_range
.Lstatic_pie_after_relr_target_range:
    mov rax, QWORD PTR [rdi]
    add rax, rbx
    jc .Lstatic_pie_fail
    mov QWORD PTR [rdi], rax
    add r14, 8
    jc .Lstatic_pie_fail
    mov ebp, 1
    mov r8, r10
    mov r9, QWORD PTR [rsp + 16]
    add r9, rbx
    jc .Lstatic_pie_fail
    add r9, QWORD PTR [rsp + 24]
    jc .Lstatic_pie_fail
    jmp .Lstatic_pie_relr
.Lstatic_pie_relr_bitmap:
    test rbp, rbp
    jz .Lstatic_pie_fail
    shr rax, 1
    mov QWORD PTR [rsp + 56], rax
    xor eax, eax
    mov QWORD PTR [rsp + 64], rax
.Lstatic_pie_relr_bits:
    mov rax, QWORD PTR [rsp + 64]
    cmp rax, 63
    jae .Lstatic_pie_relr_bits_done
    mov rcx, QWORD PTR [rsp + 56]
    mov rdx, rcx
    and edx, 1
    shr rcx, 1
    mov QWORD PTR [rsp + 56], rcx
    test edx, edx
    jz .Lstatic_pie_relr_next_bit
    shl rax, 3
    mov rdi, r14
    add rdi, rax
    jc .Lstatic_pie_fail
    mov r10, r8
    mov esi, 8
    mov edx, 1
    lea r11, [rip + .Lstatic_pie_after_relr_bitmap_target_range]
    jmp .Lstatic_pie_require_load_range
.Lstatic_pie_after_relr_bitmap_target_range:
    mov rax, QWORD PTR [rdi]
    add rax, rbx
    jc .Lstatic_pie_fail
    mov QWORD PTR [rdi], rax
    mov r8, r10
    mov r9, QWORD PTR [rsp + 16]
    add r9, rbx
    jc .Lstatic_pie_fail
    add r9, QWORD PTR [rsp + 24]
    jc .Lstatic_pie_fail
.Lstatic_pie_relr_next_bit:
    add QWORD PTR [rsp + 64], 1
    jmp .Lstatic_pie_relr_bits
.Lstatic_pie_relr_bits_done:
    add r14, 504
    jc .Lstatic_pie_fail
    jmp .Lstatic_pie_relr
.Lstatic_pie_relr_done:
    // GNU RELRO becomes read-only only after all relocation writes complete.
    mov r8, r12
    xor r9d, r9d
.Lstatic_pie_relro:
    cmp r9, r13
    jae .Lstatic_pie_enter_rust
    cmp DWORD PTR [r8], 0x6474e552
    jne .Lstatic_pie_next_relro
    mov rdi, QWORD PTR [r8 + 16]
    add rdi, rbx
    jc .Lstatic_pie_fail
    and rdi, -4096
    mov rsi, QWORD PTR [r8 + 16]
    add rsi, rbx
    jc .Lstatic_pie_fail
    add rsi, QWORD PTR [r8 + 40]
    jc .Lstatic_pie_fail
    add rsi, 4095
    jc .Lstatic_pie_fail
    and rsi, -4096
    sub rsi, rdi
    jz .Lstatic_pie_next_relro
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    js .Lstatic_pie_fail
.Lstatic_pie_next_relro:
    add r8, 56
    inc r9
    jmp .Lstatic_pie_relro

.Lstatic_pie_enter_rust:
    xor ebp, ebp
    mov rdi, r15
    xor esi, esi
    call {startup}
    ud2

.Lstatic_pie_fail:
    mov edi, 127
    mov eax, 60
    syscall
    ud2
    .size _start, .-_start

    // Inputs: rdi = runtime start address, rsi = nonzero byte length, edx =
    // nonzero when the target must be writable. This is intentionally an
    // internal jump helper so it cannot use a call stack, GOT, or TLS.
.Lstatic_pie_require_load_range:
    test rsi, rsi
    jz .Lstatic_pie_fail
    add rsi, rdi
    jc .Lstatic_pie_fail
    mov r8, r12
    xor r9d, r9d
.Lstatic_pie_require_load_range_next:
    cmp r9, r13
    jae .Lstatic_pie_fail
    cmp DWORD PTR [r8], 1
    jne .Lstatic_pie_require_load_range_advance
    test edx, edx
    jz .Lstatic_pie_require_load_range_bounds
    mov eax, DWORD PTR [r8 + 4]
    test eax, 2
    jz .Lstatic_pie_require_load_range_advance
.Lstatic_pie_require_load_range_bounds:
    mov rax, QWORD PTR [r8 + 16]
    add rax, rbx
    jc .Lstatic_pie_fail
    mov rcx, QWORD PTR [r8 + 40]
    add rcx, rax
    jc .Lstatic_pie_fail
    cmp rdi, rax
    jb .Lstatic_pie_require_load_range_advance
    cmp rsi, rcx
    ja .Lstatic_pie_require_load_range_advance
    jmp r11
.Lstatic_pie_require_load_range_advance:
    add r8, 56
    inc r9
    jmp .Lstatic_pie_require_load_range_next

    .att_syntax prefix
    .section .note.GNU-stack,"",@progbits
"#,
    startup = sym __crabc_x86_64_static_pie_start,
);
