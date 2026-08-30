#ifndef _CRABC_BITS_PTRACE_H
#define _CRABC_BITS_PTRACE_H

/* Linux/x86-64 ptrace extensions from musl 1.2.6
 * `arch/x86_64/bits/ptrace.h`.  Other active crabc targets intentionally
 * receive no x86-only commands from this internal header. */
#if defined(__x86_64__)
#define PTRACE_GET_THREAD_AREA 25
#define PTRACE_SET_THREAD_AREA 26
#define PTRACE_ARCH_PRCTL 30
#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32
#define PTRACE_SINGLEBLOCK 33

#define PT_GET_THREAD_AREA PTRACE_GET_THREAD_AREA
#define PT_SET_THREAD_AREA PTRACE_SET_THREAD_AREA
#define PT_ARCH_PRCTL PTRACE_ARCH_PRCTL
#define PT_SYSEMU PTRACE_SYSEMU
#define PT_SYSEMU_SINGLESTEP PTRACE_SYSEMU_SINGLESTEP
#define PT_STEPBLOCK PTRACE_SINGLEBLOCK
#endif

#endif
