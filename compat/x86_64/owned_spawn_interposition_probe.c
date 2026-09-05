#define _GNU_SOURCE
#include <spawn.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
/* Default mode injects callbacks with --wrap=memcpy/memset. The installed
 * shared-product mode defines ordinary ELF overrides instead. Spawn's child
 * and its lock-held stack setup must not enter these application callbacks. */
static volatile int active;
static long parent_pid;
static long raw_pid(void) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(39L) : "rcx","r11","memory");
    return result;
}
static void reject(int status) {
    __asm__ volatile("syscall" : : "a"(231L),"D"((long)status) : "rcx","r11","memory");
    __builtin_unreachable();
}
#ifdef CRABC_SPAWN_ELF_INTERPOSITION
#define __wrap_memcpy memcpy
#define __wrap_memset memset
/* Volatile accesses keep these application implementations independent of
 * libc and prevent compiler recognition from making them recursive. */
static void *__real_memcpy(void *destination, const void *source, size_t length) {
    volatile unsigned char *out=destination;
    const volatile unsigned char *in=source;
    for (size_t index=0; index<length; ++index) out[index]=in[index];
    return destination;
}
static void *__real_memset(void *destination, int value, size_t length) {
    volatile unsigned char *out=destination;
    for (size_t index=0; index<length; ++index) out[index]=(unsigned char)value;
    return destination;
}
#else
void *__real_memcpy(void *, const void *, size_t);
void *__real_memset(void *, int, size_t);
#endif
void *__wrap_memcpy(void *destination, const void *source, size_t length) {
    if (active && raw_pid()!=parent_pid) reject(92);
    return __real_memcpy(destination,source,length);
}
void *__wrap_memset(void *destination, int value, size_t length) {
    if (active && raw_pid()!=parent_pid) reject(93);
#ifndef ALLOW_PARENT_STACK_ZERO
    if (active && length==5120) reject(94);
#endif
    return __real_memset(destination,value,length);
}
int main(int argc, char **argv) {
#ifdef CRABC_SPAWN_ELF_INTERPOSITION
    /* The private execution root installs this same owned executable as
     * /bin/true. A successful exec gets fresh globals and this child mode. */
    if (argc==2) return 0;
#else
    (void)argc; (void)argv;
#endif
    alarm(10); parent_pid=raw_pid();
    if (setenv("PATH","/no-such-spawn-component:/bin",1)) return 1;
    char *arguments[]={"true",
#ifdef CRABC_SPAWN_ELF_INTERPOSITION
        "--spawn-child",
#endif
        NULL}, *environment[]={NULL};
    pid_t pid=-1; int status=0;
    active=1;
    int error=posix_spawnp(&pid,"true",NULL,NULL,arguments,environment);
    active=0;
    if (error || waitpid(pid,&status,0)!=pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 2;
    return 0;
}
