/*
 * Small native harness that traces only ARCH_SET_FS in an expected-failing
 * candidate launch. It lets ELF negative fixtures prove their rejection
 * occurs before a general initial TLS transaction can install a new FS base.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#if !defined(__aarch64__)
#include <sys/user.h>
#else
#include <stdint.h>
#include <sys/uio.h>
#endif
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
struct arm64_registers { uint64_t x[31], sp, pc, pstate; };
struct syscall_info {
    uint8_t op, pad[3]; uint32_t arch; uint64_t ip, sp;
    union { struct { uint64_t nr, args[6]; } entry; struct { int64_t result; uint8_t error; } exit; } data;
};

static long peek(pid_t child, uint64_t address) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, child, (void *)(uintptr_t)address, 0);
    if (word == -1 && errno) { perror("ptrace read"); exit(75); }
    return word;
}

static void watch_range(pid_t child, uint64_t start, uint64_t length) {
    if (start + length < start || length > 0x40000000UL) exit(75);
    uint64_t end = start + length;
    start &= ~(uint64_t)7;
    for (uint64_t address = start; address < end; address += 8) {
        uint64_t word = (uint64_t)peek(child, address), replacement = word;
        for (unsigned offset = 0; offset != 64; offset += 32) {
            uint32_t instruction = word >> offset;
            if ((instruction & 0xffffffe0U) == 0xd51bd040U) {
                replacement = (replacement & ~((uint64_t)0xffffffffU << offset)) |
                    ((uint64_t)0xd4200000U << offset);
            }
        }
        if (replacement != word && ptrace(PTRACE_POKETEXT, child, (void *)(uintptr_t)address,
                                          (void *)(uintptr_t)replacement) != 0) {
            perror("ptrace breakpoint"); exit(75);
        }
    }
}

static void watch_image(pid_t child, uint64_t header) {
    if (!header) return;
    uint64_t ident = (uint64_t)peek(child, header);
    if ((ident & 0xffffffffffffUL) != 0x0102464c457fUL) exit(75);
    uint64_t phoff = (uint64_t)peek(child, header + 32);
    uint64_t shape = (uint64_t)peek(child, header + 48);
    unsigned phentsize = (shape >> 48) & 0xffff;
    unsigned phnum = (uint64_t)peek(child, header + 56) & 0xffff;
    if (phentsize != 56 || !phnum || phnum > 128 || phoff > 65536) exit(75);
    uint64_t bias = 0;
    int found = 0;
    for (unsigned i = 0; i < phnum; ++i) {
        uint64_t ph = header + phoff + (uint64_t)i * phentsize;
        uint64_t type_flags = (uint64_t)peek(child, ph);
        uint64_t offset = (uint64_t)peek(child, ph + 8);
        uint64_t vaddr = (uint64_t)peek(child, ph + 16);
        if ((uint32_t)type_flags == 1 && offset == 0) {
            if (header < vaddr) exit(75);
            bias = header - vaddr; found = 1; break;
        }
    }
    if (!found) exit(75);
    for (unsigned i = 0; i < phnum; ++i) {
        uint64_t ph = header + phoff + (uint64_t)i * phentsize;
        uint64_t type_flags = (uint64_t)peek(child, ph);
        if ((uint32_t)type_flags == 1 && (type_flags >> 32 & 1)) {
            uint64_t vaddr = (uint64_t)peek(child, ph + 16);
            uint64_t size = (uint64_t)peek(child, ph + 32);
            if (bias + vaddr < bias) exit(75);
            watch_range(child, bias + vaddr, size);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    pid_t child = fork();
    if (child < 0) return 65;
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(66);
        raise(SIGSTOP); execv(argv[1], &argv[1]); _exit(67);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 68;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD) != 0 ||
        ptrace(PTRACE_CONT, child, 0, 0) != 0 || waitpid(child, &status, 0) != child ||
        !WIFSTOPPED(status) || (unsigned)status >> 16 != PTRACE_EVENT_EXEC) return 69;
    struct arm64_registers regs;
    struct iovec buffer = { &regs, sizeof regs };
    if (ptrace(PTRACE_GETREGSET, child, (void *)1, &buffer) != 0 || buffer.iov_len != sizeof regs) return 75;
    uint64_t cursor = regs.sp, count = (uint64_t)peek(child, cursor);
    if (count > 65536) return 75;
    cursor += 8 * (count + 2);
    while (peek(child, cursor)) cursor += 8;
    cursor += 8;
    uint64_t phdr = 0, base = 0, vdso = 0;
    for (unsigned i = 0; i != 4096; ++i, cursor += 16) {
        uint64_t tag = (uint64_t)peek(child, cursor), value = (uint64_t)peek(child, cursor + 8);
        if (!tag) break;
        if (tag == 3) phdr = value;
        if (tag == 7) base = value;
        if (tag == 33) vdso = value;
        if (i == 4095) return 75;
    }
    if (!phdr) return 75;
    uint64_t header = phdr & ~(uint64_t)4095;
    int found = 0;
    for (unsigned i = 0; i != 16 && header; ++i, header -= 4096) {
        uint64_t magic = (uint64_t)peek(child, header);
        if ((magic & 0xffffffffffffUL) == 0x0102464c457fUL &&
            header + (uint64_t)peek(child, header + 32) == phdr) { found = 1; break; }
    }
    if (!found) return 75;
    watch_image(child, header); watch_image(child, base); watch_image(child, vdso);
    uint64_t syscall = 0, args[6] = {0};
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0 || waitpid(child, &status, 0) != child) return 76;
        if (WIFEXITED(status)) return WEXITSTATUS(status) == 127 ? 0 : 71;
        if (!WIFSTOPPED(status)) return 73;
        if (WSTOPSIG(status) == SIGTRAP) {
            kill(child, SIGKILL); waitpid(child, &status, 0);
            fputs("candidate wrote TPIDR_EL0 before rejection\n", stderr); return 72;
        }
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            kill(child, SIGKILL); waitpid(child, &status, 0); return 73;
        }
        struct syscall_info info = {0};
        if (ptrace(0x420e, child, sizeof info, &info) < 0 || info.arch != 0xc00000b7U) return 75;
        if (info.op == 1) {
            syscall = info.data.entry.nr;
            for (unsigned i = 0; i != 6; ++i) args[i] = info.data.entry.args[i];
        } else if (info.op == 2 && !info.data.exit.error) {
            if (syscall == 222 && (args[2] & 4)) watch_range(child, info.data.exit.result, args[1]);
            if ((syscall == 226 || syscall == 288) && (args[2] & 4)) watch_range(child, args[0], args[1]);
            if (syscall == 196 && (args[2] & 0x8000)) return 75;
        }
    }
}

#else
enum {
    SYS_ARCH_PRCTL_X86_64 = 158,
    ARCH_SET_FS_X86_64 = 0x1002,
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fputs("usage: ldso_general_initial_tls_trace PROGRAM [ARG...]\n", stderr);
        return 64;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 65;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(66);
        raise(SIGSTOP);
        execv(argv[1], &argv[1]);
        _exit(67);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
        fputs("trace child did not stop\n", stderr);
        return 68;
    }
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) != 0
        || ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
        perror("ptrace setup");
        return 69;
    }

    int entering_syscall = 1;
    int saw_arch_set_fs = 0;
    for (;;) {
        if (waitpid(child, &status, 0) != child) {
            perror("waitpid");
            return 70;
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != 127) {
                fprintf(stderr, "candidate exit was %d, expected 127\n", WEXITSTATUS(status));
                return 71;
            }
            if (saw_arch_set_fs) {
                fputs("candidate executed ARCH_SET_FS before rejection\n", stderr);
                return 72;
            }
            return 0;
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "candidate died from signal %d\n", WTERMSIG(status));
            return 73;
        }
        if (!WIFSTOPPED(status)) {
            fputs("unexpected trace status\n", stderr);
            return 74;
        }

        int signal_number = WSTOPSIG(status);
        if (signal_number == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) {
                perror("ptrace registers");
                return 75;
            }
            if (entering_syscall
                && regs.orig_rax == SYS_ARCH_PRCTL_X86_64
                && regs.rdi == ARCH_SET_FS_X86_64) {
                saw_arch_set_fs = 1;
            }
            entering_syscall = !entering_syscall;
            if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
                perror("ptrace syscall");
                return 76;
            }
            continue;
        }

        if (signal_number != SIGTRAP) {
            // Suppressing SIGSEGV/SIGILL would re-execute the faulting
            // instruction forever. Kill and reap this exact owned child.
            fprintf(stderr, "candidate stopped by signal %d\n", signal_number);
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            return 73;
        }
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
            perror("ptrace signal");
            return 77;
        }
    }
}

#endif
