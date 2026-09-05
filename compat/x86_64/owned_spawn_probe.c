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

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"spawn:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
static void returning_handler(int signal) { (void)signal; }
static int reap(pid_t pid, int expected) {
    int status=0;
    CHECK(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==expected);
    return 0;
}
static int child(int argc, char **argv) {
    CHECK(argc>=3 && getenv("SPAWN_TOKEN") && !strcmp(getenv("SPAWN_TOKEN"),"child-environment"));
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
    } else if (!strcmp(argv[2],"session")) {
        CHECK(getsid(0)==getpid());
    } else if (!strcmp(argv[2],"descriptor") || !strcmp(argv[2],"collision")) {
        int flags=fcntl(9,F_GETFD);
        CHECK(flags>=0 && !(flags&FD_CLOEXEC));
        if (!strcmp(argv[2],"descriptor")) {
            flags=fcntl(3,F_GETFD); CHECK(flags>=0 && !(flags&FD_CLOEXEC));
        } else CHECK(fcntl(3,F_GETFD)==-1 && errno==EBADF);
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
    if (posix_spawn(&pid,"/proc/self/exe",NULL,NULL,arguments,child_environment) || reap(pid,23)) return (void *)1;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc>=2 && !strcmp(argv[1],"child")) return child(argc,argv);
    CHECK(argc==2); alarm(30);
    struct rlimit no_core={0,0}; CHECK(!setrlimit(RLIMIT_CORE,&no_core));
    CHECK(!mkdir(argv[1],0700));
    char executable[4096], marker[4096], output[4096], missing[4096], text_file[4096];
    snprintf(executable,sizeof executable,"%s/spawn-image",argv[1]);
    snprintf(marker,sizeof marker,"%s/spawn-marker",argv[1]);
    snprintf(output,sizeof output,"%s/spawn-output",argv[1]);
    snprintf(missing,sizeof missing,"%s/missing",argv[1]);
    snprintf(text_file,sizeof text_file,"%s/spawn-text",argv[1]);
    CHECK(!symlink("/proc/self/exe",executable));
    int fd=open(marker,O_CREAT|O_RDWR,0600); CHECK(fd>=0 && !close(fd));
    char *arguments[]={"spawn-child","child","basic",NULL};
    pid_t pid=-123;
    CHECK(!posix_spawn(&pid,"/proc/self/exe",NULL,NULL,arguments,child_environment) && !reap(pid,23));
    const char *abort_modes[]={"abort-default","abort-ignore","abort-handler","abort-block"};
    for (int i=0;i<4;i++) {
        arguments[2]=(char *)abort_modes[i];
        CHECK(!posix_spawn(&pid,"/proc/self/exe",NULL,NULL,arguments,child_environment));
        int status; CHECK(waitpid(pid,&status,0)==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT);
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
    CHECK(!posix_spawnp(&pid,"/proc/self/exe",NULL,NULL,arguments,child_environment) && errno==ENOENT && !reap(pid,23));
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
    CHECK(!posix_spawn(&pid,"/proc/self/exe",NULL,&attributes,arguments,child_environment) && !reap(pid,23));
    sigset_t parent_mask; CHECK(!sigprocmask(SIG_SETMASK,NULL,&parent_mask) && !sigismember(&parent_mask,SIGUSR2));
    CHECK(!sigaction(SIGUSR1,&old,NULL));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSID)); arguments[2]="session";
    CHECK(!posix_spawn(&pid,"/proc/self/exe",NULL,&attributes,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSID|POSIX_SPAWN_SETPGROUP));
    pid=-123; errno=ENOSPC;
    CHECK(posix_spawn(&pid,"/proc/self/exe",NULL,&attributes,arguments,child_environment)==EPERM && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawnattr_destroy(&attributes));
    posix_spawn_file_actions_t actions;
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,3,output,O_CREAT|O_WRONLY|O_CLOEXEC,0600));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,3,3));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,3,9));
    CHECK(!posix_spawn_file_actions_addclose(&actions,10));
    arguments[2]="descriptor";
    CHECK(!posix_spawn(&pid,"/proc/self/exe",&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(output,O_RDONLY); char bytes[32]={0};
    CHECK(fd>=0 && read(fd,bytes,sizeof bytes)==15 && !strcmp(bytes,"ordered-actions") && !close(fd));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addopen(&actions,4,output,O_TRUNC|O_WRONLY|O_CLOEXEC,0600));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,4,4));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,4,9));
    arguments[2]="collision";
    CHECK(!posix_spawn(&pid,"/proc/self/exe",&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addchdir_np(&actions,argv[1])); arguments[2]="directory";
    CHECK(!posix_spawn(&pid,"/proc/self/exe",&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!setenv("PATH",":",1));
    CHECK(!posix_spawnp(&pid,"spawn-image",&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    fd=open(argv[1],O_RDONLY|O_DIRECTORY); CHECK(fd>=0);
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_addfchdir_np(&actions,fd));
    CHECK(!posix_spawn(&pid,"/proc/self/exe",&actions,NULL,arguments,child_environment) && !reap(pid,23));
    CHECK(!posix_spawn_file_actions_destroy(&actions) && !close(fd));
    CHECK(!posix_spawn_file_actions_init(&actions));
    CHECK(!posix_spawn_file_actions_adddup2(&actions,123,9)); pid=-123;
    errno=ENOSPC;
    CHECK(posix_spawn(&pid,"/proc/self/exe",&actions,NULL,arguments,child_environment)==EBADF && pid==-123 && errno==ENOSPC);
    CHECK(!posix_spawn_file_actions_destroy(&actions));
    pthread_t thread; void *result;
    CHECK(!pthread_create(&thread,NULL,worker,NULL) && !pthread_join(thread,&result) && !result);
    struct rlimit limit, low; CHECK(!getrlimit(RLIMIT_NOFILE,&limit)); low=limit; low.rlim_cur=3;
    CHECK(!setrlimit(RLIMIT_NOFILE,&low)); pid=-123;
    int error=posix_spawn(&pid,"/proc/self/exe",NULL,NULL,arguments,child_environment);
    CHECK(!setrlimit(RLIMIT_NOFILE,&limit) && error==EMFILE && pid==-123);
    fd=dup(0); CHECK(fd==3 && !close(fd));
    CHECK(waitpid(-1,NULL,WNOHANG)==-1 && errno==ECHILD);
    CHECK(!unlink(executable) && !unlink(marker) && !unlink(output) && !unlink(text_file) && !rmdir(argv[1]));
    puts("owned-spawn-ok"); return 0;
}
