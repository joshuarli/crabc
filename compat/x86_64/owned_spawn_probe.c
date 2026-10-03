#define _GNU_SOURCE
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pthread.h>

/* Installed chroots use an explicit owned executable; the static host
 * fixture retains Linux's self-executable path. Both oracle and candidate
 * compile the same pathname and exercise the same spawn transitions. */
#ifndef CRABC_SPAWN_EXECUTABLE
#define CRABC_SPAWN_EXECUTABLE "/proc/self/exe"
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"spawn:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
static void returning_handler(int signal) { (void)signal; }
static int reap(pid_t pid, int expected) {
    int status=0;
    CHECK(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==expected);
    return 0;
}
/* Isolated Linux/x86 syscall denial; no kernel-header/runtime dependency. */
struct filter_instruction { unsigned short code; unsigned char yes, no; unsigned value; };
struct filter_program { unsigned short count; struct filter_instruction *instructions; };
static long raw_prctl(long operation, long value, long pointer) {
    register long fourth __asm__("r10")=0;
    register long fifth __asm__("r8")=0;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(157L), "D"(operation),
        "S"(value), "d"(pointer), "r"(fourth), "r"(fifth) : "rcx", "r11", "memory");
    return result;
}
static int denied_spawn(const char *mode) {
    unsigned syscall_number=!strcmp(mode,"deny-clone") ? 56 : !strcmp(mode,"deny-exec") ? 59 : 293;
    int expected=syscall_number==56 ? EAGAIN : syscall_number==59 ? EACCES : EMFILE;
    struct filter_instruction instructions[]={
        {0x20,0,0,0}, {0x15,0,1,syscall_number},
        {0x06,0,0,0x50000|(unsigned)expected}, {0x06,0,0,0x7fff0000}
    };
    struct filter_program program={4,instructions};
    sigset_t before, after, blocked;
    sigemptyset(&blocked); sigaddset(&blocked,SIGUSR2);
    CHECK(!sigprocmask(SIG_BLOCK,&blocked,NULL));
    CHECK(!sigprocmask(SIG_SETMASK,NULL,&before));
    CHECK(!raw_prctl(38,1,0) && !raw_prctl(22,2,(long)&program));
    char *arguments[]={"spawn-child","child","basic",NULL};
    char *environment[]={"SPAWN_TOKEN=child-environment",NULL};
    for (int attempt=0;attempt<3;attempt++) {
        pid_t pid=-123; errno=ENOSPC;
        CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,environment)==expected && pid==-123);
        CHECK(errno==(syscall_number==56 ? ENOSPC : expected));
        CHECK(!sigprocmask(SIG_SETMASK,NULL,&after));
        for (int signal=1;signal<65;signal++)
            CHECK(sigismember(&before,signal)==sigismember(&after,signal));
        struct sigaction action;
        CHECK(!sigaction(SIGABRT,NULL,&action)); /* shared lock was released */
        int fd=dup(0); CHECK(fd==3 && !close(fd));
        CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    }
    return 23;
}
static int child(int argc, char **argv) {
    CHECK(argc>=3 && getenv("SPAWN_TOKEN") && !strcmp(getenv("SPAWN_TOKEN"),"child-environment"));
    if (!strncmp(argv[2],"deny-",5)) return denied_spawn(argv[2]);
    if (!strcmp(argv[2],"worker-actions")) {
        sigset_t mask;
        CHECK(!sigprocmask(SIG_SETMASK,NULL,&mask) && !sigismember(&mask,SIGUSR2));
        CHECK(!(fcntl(7,F_GETFD)&FD_CLOEXEC) && !(fcntl(9,F_GETFD)&FD_CLOEXEC));
        for (int fd=3;fd<=6;fd++) CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
        char bytes[16]={0};
        CHECK(read(7,bytes,sizeof bytes)==12 && !memcmp(bytes,"worker-input",12));
        CHECK(write(9,"worker-output",13)==13);
        return 23;
    }
    if (!strncmp(argv[2],"abort-",6)) {
        if (!strcmp(argv[2],"abort-ignore")) signal(SIGABRT,SIG_IGN);
        if (!strcmp(argv[2],"abort-handler")) signal(SIGABRT,returning_handler);
        if (!strcmp(argv[2],"abort-block")) {
            sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked,SIGABRT);
            CHECK(!sigprocmask(SIG_BLOCK,&blocked,NULL));
        }
        abort();
    }
    if (!strcmp(argv[2],"attributes")) {
        struct sigaction action; sigset_t mask;
        CHECK(!sigaction(SIGUSR1,NULL,&action) && action.sa_handler==SIG_DFL);
        CHECK(!sigprocmask(SIG_SETMASK,NULL,&mask) && sigismember(&mask,SIGUSR2));
        CHECK(getpgrp()==getpid());
    } else if (!strcmp(argv[2],"inherited-mask") || !strcmp(argv[2],"cleared-mask")) {
        sigset_t mask;
        CHECK(!sigprocmask(SIG_SETMASK,NULL,&mask));
        CHECK(sigismember(&mask,SIGUSR2)==(!strcmp(argv[2],"inherited-mask")));
    } else if (!strcmp(argv[2],"session")) {
        CHECK(getsid(0)==getpid());
    } else if (!strcmp(argv[2],"descriptor") || !strcmp(argv[2],"collision") ||
               !strcmp(argv[2],"ordered-directory") || !strcmp(argv[2],"copied-paths")) {
        int flags=fcntl(9,F_GETFD);
        CHECK(flags>=0 && !(flags&FD_CLOEXEC));
        if (!strcmp(argv[2],"descriptor")) {
            flags=fcntl(3,F_GETFD); CHECK(flags>=0 && !(flags&FD_CLOEXEC));
        } else CHECK(fcntl(3,F_GETFD)==-1 && errno==EBADF);
        if (!strcmp(argv[2],"ordered-directory") || !strcmp(argv[2],"copied-paths")) {
            CHECK(access("spawn-marker",F_OK)==0);
        }
        if (!strcmp(argv[2],"ordered-directory")) {
            sigset_t mask;
            CHECK(getpgrp()==getpid());
            CHECK(!sigprocmask(SIG_SETMASK,NULL,&mask) && sigismember(&mask,SIGUSR2));
        }
        CHECK(write(9,"ordered-actions",15)==15);
    } else if (!strcmp(argv[2],"directory")) {
        CHECK(access("spawn-marker",F_OK)==0);
    }
    return 23;
}
static char *child_environment[] = {"SPAWN_TOKEN=child-environment","PATH=/not-the-search-path",NULL};
static void *worker(void *unused) {
    (void)unused; pid_t pid;
    char *arguments[]={"spawn-child","child","basic",NULL};
    if (posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment) || reap(pid,23)) return (void *)1;
    return NULL;
}
struct worker_actions {
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    const char *directory;
    int directory_fd;
    unsigned char *retained;
};
static int check_worker_spawn(struct worker_actions *owner, int expected)
{
    sigset_t before, after;
    CHECK(!sigprocmask(SIG_SETMASK,NULL,&before));
    pid_t pid=-123;
    char *arguments[]={"spawn-child","child","worker-actions",NULL};
    errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&owner->actions,&owner->attributes,
        arguments,child_environment)==expected && errno==ENOSPC);
    if (expected) {
        CHECK(pid==-123 && waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    } else CHECK(!reap(pid,23));
    CHECK(!sigprocmask(SIG_SETMASK,NULL,&after));
    for (int signal=1;signal<65;signal++)
        CHECK(sigismember(&before,signal)==sigismember(&after,signal));
    int old_state=-1;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old_state) &&
        old_state==PTHREAD_CANCEL_ENABLE && !pthread_setcancelstate(old_state,NULL));
    /* The error pipe must be gone in the parent, while its original directory
     * descriptor and offset remain available for the next action generation. */
    int copy=dup(owner->directory_fd);
    CHECK(copy==4 && !close(copy) && fcntl(owner->directory_fd,F_GETFD)==FD_CLOEXEC);
    return 0;
}
static void *worker_actions_body(void *pointer)
{
    struct worker_actions *owner=pointer;
    char output_copy[]="ordered-output", input_copy[]="ready-input";
    owner->retained=malloc(8193);
    if (!owner->retained) return (void *)1;
    for (int i=0;i<8193;i++) owner->retained[i]=(unsigned char)(i*17+3);
    if (posix_spawn_file_actions_init(&owner->actions) ||
        posix_spawn_file_actions_addfchdir_np(&owner->actions,owner->directory_fd) ||
        posix_spawn_file_actions_addopen(&owner->actions,5,output_copy,O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC,0600) ||
        posix_spawn_file_actions_addclose(&owner->actions,4) ||
        posix_spawn_file_actions_adddup2(&owner->actions,5,9) ||
        posix_spawn_file_actions_addclose(&owner->actions,5) ||
        posix_spawn_file_actions_addopen(&owner->actions,7,input_copy,O_RDONLY|O_CLOEXEC,0) ||
        posix_spawn_file_actions_adddup2(&owner->actions,7,7) ||
        posix_spawn_file_actions_addclose(&owner->actions,owner->directory_fd)) return (void *)2;
    output_copy[0]='X'; input_copy[0]='X';
    /* With fd 3 retained by the parent, OPEN 5 and CLOSE 4 each relocate the
     * child error writer. A later missing file must still report and be reaped. */
    for (int attempt=0;attempt<3;attempt++)
        if (check_worker_spawn(owner,ENOENT)) return (void *)3;
    char path[4096];
    snprintf(path,sizeof path,"%s/ready-input",owner->directory);
    int fd=open(path,O_CREAT|O_WRONLY,0600);
    if (fd<0 || write(fd,"worker-input",12)!=12 || close(fd) ||
        check_worker_spawn(owner,0)) return (void *)4;
    return NULL;
}
static int ordinary_worker_actions(const char *directory)
{
    CHECK(!mkdir(directory,0700));
    struct worker_actions owner={.directory=directory};
    owner.directory_fd=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    CHECK(owner.directory_fd==3 && !posix_spawnattr_init(&owner.attributes));
    sigset_t empty, blocked, saved;
    sigemptyset(&empty); sigemptyset(&blocked); sigaddset(&blocked,SIGUSR2);
    CHECK(!posix_spawnattr_setsigmask(&owner.attributes,&empty) &&
        !posix_spawnattr_setflags(&owner.attributes,POSIX_SPAWN_SETSIGMASK));
    CHECK(!sigprocmask(SIG_BLOCK,&blocked,&saved));
    char before[4096], after[4096];
    CHECK(getcwd(before,sizeof before));
    pthread_t thread; void *result=(void *)1;
    CHECK(!pthread_create(&thread,NULL,worker_actions_body,&owner) &&
        !pthread_join(thread,&result) && !result);
    /* Join transfers the allocated action records and retained allocation to
     * this task. They remain usable after the constructing worker has exited. */
    CHECK(!check_worker_spawn(&owner,0));
    for (int i=0;i<8193;i++) CHECK(owner.retained[i]==(unsigned char)(i*17+3));
    free(owner.retained);
    CHECK(!posix_spawn_file_actions_destroy(&owner.actions) &&
        !posix_spawnattr_destroy(&owner.attributes) && !close(owner.directory_fd));
    CHECK(getcwd(after,sizeof after) && !strcmp(before,after));
    CHECK(!sigprocmask(SIG_SETMASK,&saved,NULL));
    char path[4096], bytes[16]={0};
    snprintf(path,sizeof path,"%s/ordered-output",directory);
    int fd=open(path,O_RDONLY);
    CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==13 && !memcmp(bytes,"worker-output",13) &&
        !close(fd) && !unlink(path));
    snprintf(path,sizeof path,"%s/ready-input",directory);
    CHECK(!unlink(path) && !rmdir(directory));
    puts("owned-spawn-worker-actions-ok");
    return 0;
}
static int action_failure_cases(const char *missing, char **arguments) {
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int old_errno;
    CHECK(!posix_spawn_file_actions_init(&actions));
    errno=ENOSPC;
    CHECK(posix_spawn_file_actions_addclose(&actions,-1)==EBADF && errno==ENOSPC);
    CHECK(posix_spawn_file_actions_adddup2(&actions,-1,9)==EBADF && errno==ENOSPC);
    CHECK(posix_spawn_file_actions_adddup2(&actions,3,-1)==EBADF && errno==ENOSPC);
    CHECK(posix_spawn_file_actions_addopen(&actions,-1,missing,O_RDONLY,0)==EBADF && errno==ENOSPC);
    CHECK(posix_spawn_file_actions_addfchdir_np(&actions,-1)==EBADF && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_addchdir_np(&actions,missing));
    pid=-123; errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment)==ENOENT && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addfchdir_np(&actions,123));
    pid=-123; errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment)==EBADF && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,9,missing,O_RDONLY,0));
    pid=-123; errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment)==ENOENT && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    old_errno=errno;
    CHECK(!posix_spawn_file_actions_init(&actions));
    pid=-123;
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && errno==old_errno && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(waitpid(pid,NULL,WNOHANG)==-1 && errno==ECHILD);
    return 0;
}
int main(int argc, char **argv) {
    if (argc>=2 && !strcmp(argv[1],"child")) return child(argc,argv);
    if (argc==3 && !strcmp(argv[1],"ordinary-worker-actions"))
        return ordinary_worker_actions(argv[2]);
    CHECK(argc==2); alarm(30);
    struct rlimit no_core={0,0}; CHECK(!setrlimit(RLIMIT_CORE,&no_core));
    CHECK(!mkdir(argv[1],0700));
    char executable[4096], marker[4096], output[4096], missing[4096], text_file[4096];
    snprintf(executable,sizeof executable,"%s/spawn-image",argv[1]);
    snprintf(marker,sizeof marker,"%s/spawn-marker",argv[1]);
    snprintf(output,sizeof output,"%s/spawn-output",argv[1]);
    snprintf(missing,sizeof missing,"%s/missing",argv[1]);
    snprintf(text_file,sizeof text_file,"%s/spawn-text",argv[1]);
    CHECK(!symlink(CRABC_SPAWN_EXECUTABLE,executable));
    int fd=open(marker,O_CREAT|O_RDWR,0600); CHECK(fd>=0 && !close(fd));
    char *arguments[]={"spawn-child","child","basic",NULL};
    pid_t pid=-123;
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment) && !reap(pid,23));
    const char *abort_modes[]={"abort-default","abort-ignore","abort-handler","abort-block"};
    for (int i=0;i<4;i++) {
        arguments[2]=(char *)abort_modes[i];
        CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment));
        int status; CHECK(waitpid(pid,&status,0)==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT);
    }
    arguments[2]="basic";
    const char *denied_modes[]={"deny-clone","deny-exec","deny-pipe"};
    for (int i=0;i<3;i++) {
        arguments[2]=(char *)denied_modes[i];
        CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment) && !reap(pid,23));
    }
    arguments[2]="basic";
    CHECK(!setenv("PATH",argv[1],1));
    CHECK(!posix_spawnp(&pid,"spawn-image",NULL,NULL,arguments,child_environment) && !reap(pid,23));
    pid=-123;
    errno=ENOSPC;
    CHECK(posix_spawn(&pid,missing,NULL,NULL,arguments,child_environment)==ENOENT && pid==-123 && errno==ENOENT);
    CHECK(posix_spawnp(&pid,"",NULL,NULL,arguments,child_environment)==ENOENT && pid==-123);
    CHECK(posix_spawnp(&pid,"spawn-marker",NULL,NULL,arguments,child_environment)==EACCES && pid==-123);
    char search[8192]; snprintf(search,sizeof search,"%s:%s:%s",argv[1],missing,marker);
    CHECK(!setenv("PATH",search,1));
    CHECK(posix_spawnp(&pid,"spawn-marker",NULL,NULL,arguments,child_environment)==EACCES && pid==-123 && errno==EACCES);
    errno=ENOSPC;
    CHECK(!posix_spawnp(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment) && errno==ENOENT && !reap(pid,23));
    CHECK(!setenv("PATH",argv[1],1));
    char long_name[257]; memset(long_name,'x',sizeof long_name-1); long_name[sizeof long_name-1]=0;
    pid=-123;
    CHECK(posix_spawnp(&pid,long_name,NULL,NULL,arguments,child_environment)==ENAMETOOLONG && pid==-123);
    fd=open(text_file,O_CREAT|O_WRONLY,0700); CHECK(fd>=0 && write(fd,"exit 0\n",7)==7 && !close(fd));
    CHECK(posix_spawnp(&pid,"spawn-text",NULL,NULL,arguments,child_environment)==ENOEXEC && pid==-123);
    posix_spawnattr_t attributes;
    CHECK(!posix_spawnattr_init(&attributes));
    sigset_t defaults, blocked; sigemptyset(&defaults); sigemptyset(&blocked);
    sigaddset(&defaults,SIGUSR1); sigaddset(&blocked,SIGUSR2);
    struct sigaction ignore={0}, old; ignore.sa_handler=SIG_IGN;
    CHECK(!sigaction(SIGUSR1,&ignore,&old));
    CHECK(!posix_spawnattr_setsigdefault(&attributes,&defaults));
    CHECK(!posix_spawnattr_setsigmask(&attributes,&blocked));
    CHECK(!posix_spawnattr_setpgroup(&attributes,0));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_RESETIDS));
    arguments[2]="attributes";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,&attributes,arguments,child_environment) && !reap(pid,23));
    sigset_t parent_mask; CHECK(!sigprocmask(SIG_SETMASK,NULL,&parent_mask) && !sigismember(&parent_mask,SIGUSR2));
    CHECK(!sigaction(SIGUSR1,&old,NULL));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSID)); arguments[2]="session";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,&attributes,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSID|POSIX_SPAWN_SETPGROUP));
    pid=-123; errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,&attributes,arguments,child_environment)==EPERM && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawnattr_destroy(&attributes));
    sigset_t saved_mask, empty_mask;
    CHECK(!sigprocmask(SIG_BLOCK,&blocked,&saved_mask));
    arguments[2]="inherited-mask";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawnattr_init(&attributes));
    sigemptyset(&empty_mask);
    CHECK(!posix_spawnattr_setsigmask(&attributes,&empty_mask));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSIGMASK));
    arguments[2]="cleared-mask";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,&attributes,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawnattr_destroy(&attributes));
    CHECK(!sigprocmask(SIG_SETMASK,NULL,&parent_mask) && sigismember(&parent_mask,SIGUSR2));
    CHECK(!sigprocmask(SIG_SETMASK,&saved_mask,NULL));
    posix_spawn_file_actions_t actions;
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,3,output,O_CREAT|O_WRONLY|O_CLOEXEC,0600));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,3,3));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,3,9));
    CHECK(!posix_spawn_file_actions_addclose(&actions,10));
    arguments[2]="descriptor";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(output,O_RDONLY); char bytes[32]={0};
    CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==15 && !strcmp(bytes,"ordered-actions") && !close(fd));
    /* The first open takes the error pipe's write descriptor. A later close
     * takes its relocated descriptor, so both moves must preserve reporting. */
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,4,output,O_TRUNC|O_WRONLY,0600));
    CHECK(!posix_spawn_file_actions_addclose(&actions,5));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,4,9));
    arguments[2]="collision";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(output,O_RDONLY); memset(bytes,0,sizeof bytes);
    CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==15 && !strcmp(bytes,"ordered-actions") && !close(fd));
    char directory_copy[4096], open_copy[64], copied_output[4096];
    snprintf(directory_copy,sizeof directory_copy,"%s",argv[1]);
    snprintf(open_copy,sizeof open_copy,"spawn-copied-output");
    snprintf(copied_output,sizeof copied_output,"%s/%s",argv[1],open_copy);
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addchdir_np(&actions,directory_copy));
    CHECK(!posix_spawn_file_actions_addopen(&actions,9,open_copy,O_CREAT|O_WRONLY,0600));
    directory_copy[0]='X'; open_copy[0]='X';
    arguments[2]="copied-paths";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(copied_output,O_RDONLY); memset(bytes,0,sizeof bytes);
    CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==15 && !strcmp(bytes,"ordered-actions") && !close(fd));
    CHECK(!unlink(copied_output));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,4,output,O_TRUNC|O_WRONLY,0600));
    CHECK(!posix_spawn_file_actions_addclose(&actions,5));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,123,9));
    pid=-123; errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment)==EBADF && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addchdir_np(&actions,argv[1]));
    CHECK(!posix_spawn_file_actions_addopen(&actions,4,"spawn-output",O_TRUNC|O_WRONLY,0600));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,4,9));
    CHECK(!posix_spawn_file_actions_addclose(&actions,4));
    CHECK(!posix_spawnattr_init(&attributes));
    CHECK(!posix_spawnattr_setpgroup(&attributes,0));
    CHECK(!posix_spawnattr_setsigmask(&attributes,&blocked));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_SETSIGMASK));
    arguments[2]="ordered-directory";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,&attributes,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawnattr_destroy(&attributes));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(output,O_RDONLY); memset(bytes,0,sizeof bytes);
    CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==15 && !strcmp(bytes,"ordered-actions") && !close(fd));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,4,output,O_TRUNC|O_WRONLY|O_CLOEXEC,0600));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,4,4));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,4,9));
    arguments[2]="collision";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addchdir_np(&actions,argv[1])); arguments[2]="directory";
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!setenv("PATH",":",1));
    CHECK(!posix_spawnp(&pid,"spawn-image",&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(argv[1],O_RDONLY|O_DIRECTORY); CHECK(fd>=0);
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addfchdir_np(&actions,fd));
    CHECK(!posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions) && !close(fd));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,123,9)); pid=-123;
    errno=ENOSPC;
    CHECK(posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,&actions,NULL,arguments,child_environment)==EBADF && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    arguments[2]="basic";
    CHECK(!action_failure_cases(missing,arguments));
    pthread_t thread; void *result;
    CHECK(!pthread_create(&thread,NULL,worker,NULL) && !pthread_join(thread,&result) && !result);
    struct rlimit limit, low; CHECK(!getrlimit(RLIMIT_NOFILE,&limit)); low=limit; low.rlim_cur=3;
    CHECK(!setrlimit(RLIMIT_NOFILE,&low)); pid=-123;
    int error=posix_spawn(&pid,CRABC_SPAWN_EXECUTABLE,NULL,NULL,arguments,child_environment);
    CHECK(!setrlimit(RLIMIT_NOFILE,&limit) && error==EMFILE && pid==-123);
    fd=dup(0); CHECK(fd==3 && !close(fd));
    CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    CHECK(!unlink(executable) && !unlink(marker) && !unlink(output) && !unlink(text_file) && !rmdir(argv[1]));
    puts("owned-spawn-ok"); return 0;
}
