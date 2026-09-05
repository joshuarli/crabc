#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include "owned_cancellation_proc_witness.h"

/* Pinned musl 1.2.6 src/fcntl/{open,openat,creat,fcntl}.c and
 * src/mman/msync.c: F_SETLKW alone cancels among the selected fcntl commands.
 * The runner supplies a private repository-local directory. FIFO opens and a
 * child-held POSIX record lock provide observable blocked syscall boundaries.
 * Mapping checks cover cancellation and kernel validation, not durability. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"open-lock-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum operation { OPEN_PATH, OPEN_RELATIVE, CREATE_PATH, LOCK_WAIT, LOCK_TRY,
    LOCK_QUERY, GET_FLAGS, SET_FLAGS, GET_STATUS, SET_STATUS, SYNC_MAPPING, SYNC_INVALID };
struct state {
    enum operation operation;
    int fd, directory, opened, cancel_state, pending, fifo;
    const char *path;
    void *mapping;
    _Atomic int tid, returned, result, error, state_after, cleanup;
};
static struct flock whole_lock(short type) {
    struct flock lock={.l_type=type,.l_whence=SEEK_SET,.l_start=0,.l_len=0};
    return lock;
}
static void cleanup_worker(void *opaque) {
    struct state *s=opaque;
    if (s->opened>=0 && close(s->opened)) _exit(81);
    if (s->operation==LOCK_WAIT || s->operation==LOCK_TRY) {
        struct flock lock=whole_lock(F_UNLCK);
        if (fcntl(s->fd,F_SETLK,&lock)) _exit(82);
    }
    atomic_store(&s->cleanup,1);
}
static void *worker(void *opaque) {
    struct state *s=opaque;
    struct flock lock=whole_lock(F_WRLCK);
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(83);
    pthread_cleanup_push(cleanup_worker,s);
    if (s->pending && pthread_cancel(pthread_self())) _exit(84);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result;
    int flags=s->fifo ? O_RDONLY|O_CLOEXEC : O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC;
    switch(s->operation) {
    case OPEN_PATH: result=open(s->path,flags,0600); break;
    case OPEN_RELATIVE: result=openat(s->directory,"file",flags,0600); break;
    case CREATE_PATH: result=creat(s->path,0600); break;
    case LOCK_WAIT: result=fcntl(s->fd,F_SETLKW,&lock); break;
    case LOCK_TRY: result=fcntl(s->fd,F_SETLK,&lock); break;
    case LOCK_QUERY: result=fcntl(s->fd,F_GETLK,&lock); break;
    case GET_FLAGS: result=fcntl(s->fd,F_GETFD); break;
    case SET_FLAGS: result=fcntl(s->fd,F_SETFD,FD_CLOEXEC); break;
    case GET_STATUS: result=fcntl(s->fd,F_GETFL); break;
    case SET_STATUS: result=fcntl(s->fd,F_SETFL,O_NONBLOCK); break;
    case SYNC_MAPPING: result=msync(s->mapping,4096,MS_SYNC); break;
    case SYNC_INVALID: result=msync(s->mapping,4096,MS_SYNC|MS_ASYNC); break;
    default: _exit(85);
    }
    atomic_store(&s->result,result); atomic_store(&s->error,errno);
    if (s->operation<=CREATE_PATH && result>=0) {
        s->opened=result;
        if (fcntl(result,F_GETFD)!=(s->operation==CREATE_PATH ? 0 : FD_CLOEXEC)) _exit(86);
    }
    atomic_store(&s->returned,1);
    int previous=-1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(87);
    atomic_store(&s->state_after,previous);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static int wait_in_syscall(struct state *s, long expected) {
    const struct timespec delay={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(&s->tid);
        if (tid) {
            char path[96], line[256];
            snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if (fd>=0) {
                ssize_t count=read(fd,line,sizeof line-1); close(fd);
                if (count>0) {
                    line[count]=0; long actual=-1;
                    if (sscanf(line,"%ld",&actual)==1 && actual==expected) return 1;
                }
            }
        }
        nanosleep(&delay,NULL);
    }
    return 0;
}
static int is_cancellation_point(enum operation op) {
    return op<=LOCK_WAIT || op>=SYNC_MAPPING;
}
static int join_canceled(pthread_t thread, struct state *s) {
    void *result=NULL;
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED && atomic_load(&s->cleanup));
    int returned=s->cancel_state!=PTHREAD_CANCEL_ENABLE || !is_cancellation_point(s->operation);
    CHECK(atomic_load(&s->returned)==returned);
    if (returned) {
        int masked=s->cancel_state==2 && is_cancellation_point(s->operation);
        CHECK(atomic_load(&s->state_after)==(masked ? PTHREAD_CANCEL_DISABLE : s->cancel_state));
        int expected_error=masked ? ECANCELED : s->operation==SYNC_INVALID ? EINVAL : 90;
        CHECK(atomic_load(&s->error)==expected_error);
        CHECK((atomic_load(&s->result)<0)==(expected_error!=90));
    }
    return 0;
}
static int exercise_pending(enum operation op, int cancel_state, const char *path, int directory, int existing) {
    struct state s={.operation=op,.fd=-1,.directory=directory,.opened=-1,.cancel_state=cancel_state,
        .pending=1,.path=path,.state_after=-1};
    if (op<=CREATE_PATH) {
        if (existing) {
            int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600); CHECK(fd>=0);
            CHECK(write(fd,"I",1)==1 && !close(fd));
        }
    } else {
        s.fd=memfd_create("open-lock-cancellation",MFD_CLOEXEC); CHECK(s.fd>=0);
        CHECK(!ftruncate(s.fd,4096));
        if (op>=SYNC_MAPPING) {
            s.mapping=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,s.fd,0); CHECK(s.mapping!=MAP_FAILED);
            *(char *)s.mapping='K';
        }
    }
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,worker,&s));
    CHECK(!join_canceled(thread,&s));
    if (op<=CREATE_PATH) {
        int changed=cancel_state==PTHREAD_CANCEL_DISABLE;
        struct stat status;
        if (existing || changed) {
            CHECK(!stat(path,&status) && status.st_size==(changed ? 0 : 1));
            if (!changed) {
                int fd=open(path,O_RDONLY|O_CLOEXEC); char byte=0; CHECK(fd>=0);
                CHECK(read(fd,&byte,1)==1 && byte=='I' && !close(fd));
            }
            CHECK(!unlink(path));
        } else CHECK(stat(path,&status)==-1 && errno==ENOENT);
    } else {
        if (op>=SYNC_MAPPING) CHECK(!munmap(s.mapping,4096));
        CHECK(!close(s.fd));
    }
    printf("pending operation=%d state=%d existing=%d\n",op,cancel_state,existing);
    return 0;
}
static _Atomic int signal_observed;
static void interrupt_handler(int number) { (void)number; atomic_store(&signal_observed,1); }
static int interrupt_worker(struct state *s, long number, int restart) {
    CHECK(wait_in_syscall(s,number));
    atomic_store(&signal_observed,0);
    CHECK(!syscall(SYS_tgkill,getpid(),atomic_load(&s->tid),SIGUSR1));
    while (!atomic_load(&signal_observed)) {}
    if (restart) CHECK(wait_in_syscall(s,number));
    return 0;
}
static int join_interrupted(pthread_t thread, struct state *s, int restart) {
    void *result=(void *)1;
    CHECK(!pthread_join(thread,&result) && result==NULL && atomic_load(&s->cleanup));
    CHECK(atomic_load(&s->returned));
    CHECK(atomic_load(&s->error)==(restart ? 90 : EINTR));
    CHECK((atomic_load(&s->result)>=0)==restart);
    return 0;
}
static int exercise_fifo(enum operation op, const char *path, int directory, int signal_mode) {
    CHECK(!mkfifo(path,0600));
    struct state s={.operation=op,.fd=-1,.directory=directory,.opened=-1,.path=path,.fifo=1,.state_after=-1};
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,worker,&s));
    long number=op==OPEN_RELATIVE ? SYS_openat : SYS_open;
    CHECK(wait_in_syscall(&s,number));
    int peer=-1;
    if (!signal_mode) {
        CHECK(!pthread_cancel(thread)); CHECK(!join_canceled(thread,&s));
    } else {
        CHECK(!interrupt_worker(&s,number,signal_mode==2));
        if (signal_mode==2) { peer=open(path,O_RDWR|O_NONBLOCK|O_CLOEXEC); CHECK(peer>=0); }
        CHECK(!join_interrupted(thread,&s,signal_mode==2));
    }
    if (peer>=0) CHECK(!close(peer));
    CHECK(!unlink(path));
    printf("fifo operation=%d signal-mode=%d\n",op,signal_mode);
    return 0;
}
struct lock_child { pid_t pid; int release; };
static int hold_child_lock(int fd, struct lock_child *child) {
    int ready[2], release[2]; CHECK(!pipe(ready) && !pipe(release));
    child->pid=fork(); CHECK(child->pid>=0);
    if (!child->pid) {
        close(ready[0]); close(release[1]);
        struct flock lock=whole_lock(F_WRLCK);
        if (fcntl(fd,F_SETLK,&lock) || write(ready[1],"K",1)!=1) _exit(88);
        char byte;
        if (read(release[0],&byte,1)!=1) _exit(89);
        _exit(23);
    }
    CHECK(!close(ready[1]) && !close(release[0]));
    char byte; CHECK(read(ready[0],&byte,1)==1 && !close(ready[0]));
    child->release=release[1];
    return 0;
}
static int release_child(struct lock_child *child) {
    CHECK(write(child->release,"K",1)==1 && !close(child->release));
    int status; CHECK(waitpid(child->pid,&status,0)==child->pid && WIFEXITED(status) && WEXITSTATUS(status)==23);
    return 0;
}
static int exercise_blocked_lock(int cancel_state, int signal_mode) {
    struct state s={.operation=LOCK_WAIT,.fd=memfd_create("blocked-record-lock",MFD_CLOEXEC),
        .opened=-1,.cancel_state=cancel_state,.state_after=-1}; CHECK(s.fd>=0);
    struct lock_child child; CHECK(!hold_child_lock(s.fd,&child));
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,worker,&s));
    CHECK(wait_in_syscall(&s,SYS_fcntl));
    int released=0;
    if (!signal_mode) {
        CHECK(!pthread_cancel(thread));
        if (cancel_state==PTHREAD_CANCEL_DISABLE) {
            CHECK(wait_in_syscall(&s,SYS_fcntl));
            CHECK(!release_child(&child)); released=1;
        }
        CHECK(!join_canceled(thread,&s));
    } else {
        CHECK(!interrupt_worker(&s,SYS_fcntl,signal_mode==2));
        if (signal_mode==2) { CHECK(!release_child(&child)); released=1; }
        CHECK(!join_interrupted(thread,&s,signal_mode==2));
    }
    if (!released) {
        struct flock lock=whole_lock(F_WRLCK); CHECK(!fcntl(s.fd,F_GETLK,&lock));
        CHECK(lock.l_type==F_WRLCK && lock.l_pid==child.pid);
        CHECK(!release_child(&child));
    }
    CHECK(!close(s.fd));
    printf("blocked record-lock state=%d signal-mode=%d\n",cancel_state,signal_mode);
    return 0;
}
int main(int argc, char **argv) {
    alarm(30);
    CHECK(argc==2 && !mkdir(argv[1],0700));
    char path[4096]; CHECK(snprintf(path,sizeof path,"%s/file",argv[1])<(int)sizeof path);
    int directory=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC); CHECK(directory>=0);
    for (int op=OPEN_PATH;op<=SYNC_INVALID;op++)
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) {
            CHECK(!exercise_pending(op,state,path,directory,0));
            if (op<=CREATE_PATH) CHECK(!exercise_pending(op,state,path,directory,1));
        }
    for (int op=OPEN_PATH;op<=CREATE_PATH;op++) CHECK(!exercise_fifo(op,path,directory,0));
    for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) CHECK(!exercise_blocked_lock(state,0));
    for (int mode=1;mode<=2;mode++) {
        struct sigaction action={.sa_handler=interrupt_handler,.sa_flags=mode==2 ? SA_RESTART : 0}, previous;
        sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGUSR1,&action,&previous));
        for (int op=OPEN_PATH;op<=CREATE_PATH;op++) CHECK(!exercise_fifo(op,path,directory,mode));
        CHECK(!exercise_blocked_lock(PTHREAD_CANCEL_ENABLE,mode));
        CHECK(!sigaction(SIGUSR1,&previous,NULL));
    }
    CHECK(!close(directory) && !rmdir(argv[1]));
    puts("owned-open-lock-cancellation-ok");
    return 0;
}
