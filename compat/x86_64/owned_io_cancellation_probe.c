#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <stddef.h>
#include <ucontext.h>

_Static_assert(offsetof(ucontext_t,uc_mcontext.gregs[REG_RIP])==168,
    "owned SIGCANCEL PC window requires the pinned x86 ucontext RIP slot");
_Static_assert(offsetof(ucontext_t,uc_sigmask)==296,
    "owned SIGCANCEL restores the kernel signal-mask prefix");

/* Pinned musl pthread_cancel.c + x86_64/syscall_cp.s: cancellation must
 * interrupt a task actually blocked in the kernel, not merely observe a flag
 * at function entry. /proc reports the exact target syscall before delivery.
 * Ordinary stdio backends are intentionally NOT cancellation points in musl.
 * The probe creates only pipes and reads /proc; no shared scratch pathname. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"io-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum operation { READ_BYTE, READ_VECTOR, WRITE_BYTE, WRITE_VECTOR, READ_DISABLED, READ_MASKED, READ_FILE, READ_FILE_LOCKED, READ_PENDING, ASYNC_LOOP };
struct operation_state {
    enum operation operation;
    int fd;
    FILE *file;
    _Atomic int tid, completed, cleanup_order, observed_error, release;
};
static void cleanup_outer(void *opaque) {
    struct operation_state *s=opaque;
    atomic_store(&s->cleanup_order,10*atomic_load(&s->cleanup_order)+1);
}
static void cleanup_inner(void *opaque) {
    struct operation_state *s=opaque;
    atomic_store(&s->cleanup_order,10*atomic_load(&s->cleanup_order)+2);
    if (s->operation==READ_FILE_LOCKED) funlockfile(s->file);
}
static void *run_operation(void *opaque) {
    struct operation_state *s=opaque;
    char byte='K'; struct iovec vector={&byte,1};
    if (s->operation==READ_DISABLED && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL)) return (void *)1;
    if (s->operation==READ_MASKED && pthread_setcancelstate(2,NULL)) return (void *)2;
    if (s->operation==READ_FILE_LOCKED) flockfile(s->file);
    pthread_cleanup_push(cleanup_outer,s);
    pthread_cleanup_push(cleanup_inner,s);
    if (s->operation==ASYNC_LOOP && pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL)) _exit(86);
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    if (s->operation==READ_PENDING) while (!atomic_load(&s->release)) {}
    if (s->operation==ASYNC_LOOP) for (;;) { atomic_signal_fence(memory_order_seq_cst); }
    ssize_t result;
    switch (s->operation) {
    case READ_VECTOR: result=readv(s->fd,&vector,1); break;
    case WRITE_BYTE: result=write(s->fd,&byte,1); break;
    case WRITE_VECTOR: result=writev(s->fd,&vector,1); break;
    case READ_FILE: result=fgetc(s->file); break;
    default: result=read(s->fd,&byte,1); break;
    }
    atomic_store(&s->observed_error,errno);
    if (s->operation==READ_MASKED) {
        if (result!=-1 || errno!=ECANCELED) _exit(81);
        int previous=-1;
        if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous) || previous!=PTHREAD_CANCEL_DISABLE) _exit(82);
    } else if (s->operation==READ_DISABLED) {
        if (result!=1 || byte!='K' || pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL)) _exit(83);
    } else if (s->operation==READ_FILE) {
        if (result!='K') _exit(84);
    } else _exit(85); /* real cancellation cannot return from the syscall */
    atomic_store(&s->completed,1);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    return (void *)3;
}
static int wait_in_syscall(struct operation_state *s, long expected) {
    const struct timespec pause={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(&s->tid);
        if (tid) {
            char path[96], line[256];
            snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=open(path,O_RDONLY|O_CLOEXEC);
            if (fd>=0) {
                ssize_t count=read(fd,line,sizeof line-1); close(fd);
                if (count>0) {
                    line[count]=0; long actual=-1;
                    if (sscanf(line,"%ld",&actual)==1 && actual==expected) return 1;
                }
            }
        }
        nanosleep(&pause,NULL);
    }
    return 0;
}
static int exercise(enum operation operation) {
    int descriptors[2]; CHECK(!pipe(descriptors));
    int output=operation==WRITE_BYTE || operation==WRITE_VECTOR;
    if (output) {
        int flags=fcntl(descriptors[1],F_GETFL); CHECK(flags>=0);
        CHECK(!fcntl(descriptors[1],F_SETFL,flags|O_NONBLOCK));
        char fill[4096]; memset(fill,'F',sizeof fill);
        while(write(descriptors[1],fill,sizeof fill)>0) {}
        CHECK(errno==EAGAIN && !fcntl(descriptors[1],F_SETFL,flags));
    }
    struct operation_state state={.operation=operation,.fd=descriptors[output]};
    if (operation==READ_FILE || operation==READ_FILE_LOCKED) {
        state.file=fdopen(dup(descriptors[0]),"r"); CHECK(state.file);
    }
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,run_operation,&state));
    long number=operation==READ_VECTOR ? SYS_readv : operation==WRITE_VECTOR ? SYS_writev : output ? SYS_write : SYS_read;
    if (operation==READ_PENDING || operation==ASYNC_LOOP) {
        while (!atomic_load(&state.tid)) {}
    } else CHECK(wait_in_syscall(&state,number));
    CHECK(!pthread_cancel(thread));
    if (operation==READ_PENDING) atomic_store(&state.release,1);
    if (operation==READ_DISABLED || operation==READ_FILE) {
        CHECK(wait_in_syscall(&state,number) && !atomic_load(&state.completed));
        CHECK(write(descriptors[1],"K",1)==1);
    }
    void *result=NULL; CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED);
    CHECK(atomic_load(&state.cleanup_order)==21);
    CHECK(atomic_load(&state.completed)==(operation==READ_DISABLED || operation==READ_MASKED || operation==READ_FILE));
    if (state.file) {
        CHECK(!ftrylockfile(state.file)); funlockfile(state.file);
        CHECK(!fclose(state.file));
    }
    CHECK(!close(descriptors[0]) && !close(descriptors[1]));
    printf("blocked-operation %d canceled cleanup=21\n",operation);
    return 0;
}

static pthread_t initial_thread;
static struct operation_state initial_state;
static void initial_cleanup(void *unused) {
    (void)unused;
    atomic_store(&initial_state.completed,1);
}
static void *cancel_initial(void *unused) {
    (void)unused;
    if (!wait_in_syscall(&initial_state,SYS_read)) _exit(91);
    if (pthread_cancel(initial_thread)) _exit(92);
    while (!atomic_load(&initial_state.completed)) {}
    _exit(0);
}
static int exercise_initial(void) {
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        int descriptors[2]; if (pipe(descriptors)) _exit(93);
        initial_thread=pthread_self();
        atomic_store(&initial_state.tid,(int)syscall(SYS_gettid));
        pthread_t helper;
        pthread_cleanup_push(initial_cleanup,NULL);
        if (pthread_create(&helper,NULL,cancel_initial,NULL)) _exit(94);
        char byte; read(descriptors[0],&byte,1);
        pthread_cleanup_pop(0);
        _exit(95);
    }
    int status; CHECK(waitpid(child,&status,0)==child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
    puts("initial-thread blocked read canceled cleanup=1");
    return 0;
}
/* Fork retains the calling task's pending bit, state, type, and cleanup
 * chain, including a worker adopted as the child's initial task. */
static void inherited_cleanup(void *unused) { (void)unused; _exit(42); }
static void *fork_cancel_state(void *unused) {
    (void)unused;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL) ||
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL)) _exit(101);
    pthread_cleanup_push(inherited_cleanup,NULL);
    if (pthread_cancel(pthread_self())) _exit(102);
    pid_t child=fork(); if (child<0) _exit(103);
    if (!child) {
        int previous=-1;
        if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,&previous) ||
            previous!=PTHREAD_CANCEL_ASYNCHRONOUS) _exit(104);
        if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous) ||
            previous!=PTHREAD_CANCEL_DISABLE) _exit(105);
        pthread_testcancel();
        _exit(106);
    }
    int status;
    if (waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=42) _exit(107);
    pthread_cleanup_pop(0);
    return NULL;
}
static int exercise_fork_state(void) {
    pid_t child=fork(); CHECK(child>=0);
    if (!child) { fork_cancel_state(NULL); _exit(0); }
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    pthread_t worker; void *result=(void *)1;
    CHECK(!pthread_create(&worker,NULL,fork_cancel_state,NULL));
    CHECK(!pthread_join(worker,&result) && !result);
    puts("fork retains initial/worker pending state type cleanup");
    return 0;
}

/* Abandoned explicit locks remain unavailable after task retirement, just
 * like musl's orphan sentinel. Each negative case exits its own process via
 * _exit because ordinary exit must not flush a deliberately locked FILE. */
static void *orphan_file_lock(void *opaque) {
    FILE *file=opaque;
    flockfile(file); flockfile(file);
    return NULL;
}
static int exercise_orphan_lock(void) {
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        int descriptors[2]; if (pipe(descriptors)) _exit(111);
        FILE *file=fdopen(descriptors[0],"r"); if (!file) _exit(112);
        pthread_t worker;
        if (pthread_create(&worker,NULL,orphan_file_lock,file) || pthread_join(worker,NULL)) _exit(113);
        if (!ftrylockfile(file)) _exit(114);
        _exit(0);
    }
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    puts("retired task explicit FILE lock remains orphaned");
    return 0;
}
int main(void) {
    alarm(20);
    for (int operation=READ_BYTE;operation<=ASYNC_LOOP;operation++) CHECK(!exercise(operation));
    CHECK(!exercise_initial());
    CHECK(!exercise_fork_state());
    CHECK(!exercise_orphan_lock());
    puts("owned-io-cancellation-ok");
    return 0;
}
