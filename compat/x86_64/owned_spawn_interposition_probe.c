#define _GNU_SOURCE
#include <spawn.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
/* Link this focused fault-injection consumer with --wrap=memcpy/memset.
 * Ordinary public interposition remains enabled. Spawn's child and its
 * lock-held stack setup must not enter these application callbacks. */
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
void *__real_memcpy(void *, const void *, size_t);
void *__real_memset(void *, int, size_t);
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
int main(void) {
    alarm(10); parent_pid=raw_pid();
    if (setenv("PATH","/no-such-spawn-component:/bin",1)) return 1;
    char *arguments[]={"true",NULL}, *environment[]={NULL};
    pid_t pid=-1; int status=0;
    active=1;
    int error=posix_spawnp(&pid,"true",NULL,NULL,arguments,environment);
    active=0;
    if (error || waitpid(pid,&status,0)!=pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 2;
    return 0;
}
