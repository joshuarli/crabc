#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/klog.h>
#include <sys/module.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/reboot.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* Musl exports this historical spelling without a public prototype. */
extern int pivot_root(const char *, const char *);
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"linux-control:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)

static long raw6(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10")=d;
    register long r8 __asm__("r8")=e;
    register long r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c),
        "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}

/* Only invalid or nonexistent targets reach these privileged operations.
 * The raw comparison adapts to the container's kernel authority without
 * assuming that a denied operation is implemented as ENOSYS. */
#define ERROR_MATCH(call,n,a,b,c,d,e,f) do { \
    errno=E2BIG; long raw=raw6(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f)); \
    CHECK(raw<0 && raw>=-4095 && errno==E2BIG); \
    errno=ERANGE; CHECK((call)==-1 && errno==-raw); \
} while (0)

static int kernel_errors(void) {
    const char *missing="/crabc-control-path-never-created";
    ERROR_MATCH(acct(missing),SYS_acct,missing,0,0,0,0,0);
    ERROR_MATCH(capset(NULL,NULL),SYS_capset,0,0,0,0,0,0);
    ERROR_MATCH(delete_module("",O_NONBLOCK),SYS_delete_module,"",O_NONBLOCK,0,0,0,0);
    ERROR_MATCH(init_module(NULL,0,""),SYS_init_module,0,0,"",0,0,0);
    ERROR_MATCH(fanotify_init(UINT_MAX,UINT_MAX),SYS_fanotify_init,UINT_MAX,UINT_MAX,0,0,0,0);
    ERROR_MATCH(fanotify_mark(-1,0,0,-1,NULL),SYS_fanotify_mark,-1,0,0,-1,0,0);
    ERROR_MATCH(klogctl(-1,NULL,0),SYS_syslog,-1,0,0,0,0,0);
    ERROR_MATCH(pivot_root(missing,missing),SYS_pivot_root,missing,missing,0,0,0,0);
    ERROR_MATCH(quotactl(-1,missing,-1,NULL),SYS_quotactl,-1,missing,-1,0,0,0);
    ERROR_MATCH(reboot(-1),SYS_reboot,0xfee1deadL,672274793,-1,0,0,0);
    ERROR_MATCH(setns(-1,0),SYS_setns,-1,0,0,0,0,0);
    ERROR_MATCH(swapon(missing,0),SYS_swapon,missing,0,0,0,0,0);
    ERROR_MATCH(swapoff(missing),SYS_swapoff,missing,0,0,0,0,0);
    ERROR_MATCH(unshare(-1),SYS_unshare,-1,0,0,0,0,0);
    ERROR_MATCH(process_vm_readv(-1,NULL,1,NULL,1,0),SYS_process_vm_readv,-1,0,1,0,1,0);
    ERROR_MATCH(process_vm_writev(-1,NULL,1,NULL,1,0),SYS_process_vm_writev,-1,0,1,0,1,0);
    ERROR_MATCH(ptrace(-1,(pid_t)-1,(void *)0,(void *)0),SYS_ptrace,-1,-1,0,0,0,0);
    return 0;
}

static int capabilities(void) {
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct observed[2], raw[2];
    memset(observed,0xa5,sizeof observed); memset(raw,0xa5,sizeof raw);
    errno=E2BIG;
    CHECK(raw6(SYS_capget,(long)&header,(long)raw,0,0,0,0)==0 && errno==E2BIG);
    CHECK(capget(&header,observed)==0 && errno==E2BIG);
    CHECK(!memcmp(raw,observed,sizeof raw));
    header.version=0;
    errno=E2BIG;
    CHECK(capget(&header,NULL)==0 && errno==E2BIG && header.version==_LINUX_CAPABILITY_VERSION_3);
    header.version=0;
    CHECK(capget(&header,observed)==-1 && errno==EINVAL && header.version==_LINUX_CAPABILITY_VERSION_3);
    return 0;
}

static int process_memory(void) {
    char source[]="owned process memory", destination[sizeof source];
    memset(destination,0,sizeof destination);
    struct iovec local={destination,sizeof destination}, remote={source,sizeof source};
    errno=E2BIG;
    CHECK(process_vm_readv(getpid(),&local,1,&remote,1,0)==sizeof source && errno==E2BIG);
    CHECK(!memcmp(source,destination,sizeof source));
    char replacement[]="owned process update";
    local.iov_base=replacement; local.iov_len=sizeof replacement;
    remote.iov_base=destination; remote.iov_len=sizeof destination;
    CHECK(sizeof replacement==sizeof destination);
    CHECK(process_vm_writev(getpid(),&local,1,&remote,1,0)==sizeof replacement && errno==E2BIG);
    CHECK(!memcmp(replacement,destination,sizeof replacement));
    ERROR_MATCH(process_vm_readv(getpid(),&local,1,&remote,1,1),SYS_process_vm_readv,getpid(),&local,1,&remote,1,1);
    return 0;
}

static volatile long traced_word=-1;
static int trace_child(void) {
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        if (ptrace(PTRACE_TRACEME,(pid_t)0,(void *)0,(void *)0)) _exit(77);
        raise(SIGSTOP);
        _exit(traced_word==42 ? 0 : 78);
    }
    int status;
    CHECK(waitpid(child,&status,0)==child && WIFSTOPPED(status) && WSTOPSIG(status)==SIGSTOP);
    /* A successfully read word of -1 is data, not the raw Linux errno range.
     * Musl keeps successful calls' incoming errno; the caller may clear it. */
    errno=E2BIG;
    CHECK(ptrace(PTRACE_PEEKDATA,child,(void *)&traced_word,(void *)0)==-1 && errno==E2BIG);
    errno=0;
    CHECK(ptrace(PTRACE_PEEKTEXT,child,(void *)&traced_word,(void *)0)==-1 && errno==0);
    CHECK(ptrace(PTRACE_POKEDATA,child,(void *)&traced_word,(void *)42)==0 && errno==0);
    CHECK(ptrace(PTRACE_PEEKDATA,child,(void *)&traced_word,(void *)0)==42 && errno==0);
    CHECK(ptrace(PTRACE_CONT,child,(void *)0,(void *)0)==0);
    CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(traced_word==-1);
    return 0;
}

int main(void) {
    alarm(20);
    CHECK(!kernel_errors());
    CHECK(!capabilities());
    CHECK(!process_memory());
    CHECK(!trace_child());
    puts("owned-linux-control-ok");
    return 0;
}
