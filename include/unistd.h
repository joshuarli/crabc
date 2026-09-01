#ifndef _UNISTD_H
#define _UNISTD_H

#include <features.h>
#include <sys/types.h>
#include <stdint.h>

#ifndef __DEFINED_size_t
#define __DEFINED_size_t
typedef __SIZE_TYPE__ size_t;
#endif

/* POSIX option and selector values from the pinned musl AArch64 ABI. */
#define _POSIX_VERSION 200809L
#define _POSIX2_VERSION _POSIX_VERSION
#define _XOPEN_VERSION 700
#define _XOPEN_ENH_I18N 1
#define _XOPEN_UNIX 1
#define _POSIX_ASYNCHRONOUS_IO _POSIX_VERSION
#define _POSIX_BARRIERS _POSIX_VERSION
#define _POSIX_CHOWN_RESTRICTED 1
#define _POSIX_CLOCK_SELECTION _POSIX_VERSION
#define _POSIX_JOB_CONTROL 1
#define _POSIX_MAPPED_FILES _POSIX_VERSION
#define _POSIX_MEMORY_PROTECTION _POSIX_VERSION
#define _POSIX_NO_TRUNC 1
#define _POSIX_READER_WRITER_LOCKS _POSIX_VERSION
#define _POSIX_REALTIME_SIGNALS _POSIX_VERSION
#define _POSIX_REGEXP 1
#define _POSIX_SAVED_IDS 1
#define _POSIX_SEMAPHORES _POSIX_VERSION
#define _POSIX_SHELL 1
#define _POSIX_SPIN_LOCKS _POSIX_VERSION
#define _POSIX_THREAD_SAFE_FUNCTIONS _POSIX_VERSION
#define _POSIX_THREADS _POSIX_VERSION
#define _POSIX_TIMEOUTS _POSIX_VERSION
#define _POSIX_TIMERS _POSIX_VERSION
#define _POSIX2_C_BIND _POSIX_VERSION
#define _POSIX_ADVISORY_INFO _POSIX_VERSION
#define _POSIX_CPUTIME _POSIX_VERSION
#define _POSIX_FSYNC _POSIX_VERSION
#define _POSIX_IPV6 _POSIX_VERSION
#define _POSIX_MEMLOCK _POSIX_VERSION
#define _POSIX_MEMLOCK_RANGE _POSIX_VERSION
#define _POSIX_MESSAGE_PASSING _POSIX_VERSION
#define _POSIX_MONOTONIC_CLOCK _POSIX_VERSION
#define _POSIX_RAW_SOCKETS _POSIX_VERSION
#define _POSIX_SHARED_MEMORY_OBJECTS _POSIX_VERSION
#define _POSIX_SPAWN _POSIX_VERSION
#define _POSIX_THREAD_ATTR_STACKADDR _POSIX_VERSION
#define _POSIX_THREAD_ATTR_STACKSIZE _POSIX_VERSION
#define _POSIX_THREAD_CPUTIME _POSIX_VERSION
#define _POSIX_THREAD_PRIORITY_SCHEDULING _POSIX_VERSION
#define _POSIX_THREAD_PROCESS_SHARED _POSIX_VERSION
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1

#ifndef NULL
#if defined(__x86_64__) && defined(__LP64__) && defined(__cplusplus)
#if __cplusplus >= 201103L
#define NULL nullptr
#else
#define NULL 0L
#endif
#else
#define NULL ((void *)0)
#endif
#endif

#define _CS_PATH 0
#define _CS_POSIX_V7_ILP32_OFF32_CFLAGS 1132
#define _CS_POSIX_V7_ILP32_OFF32_LDFLAGS 1133
#define _CS_POSIX_V7_ILP32_OFF32_LIBS 1134
#define _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS 1136
#define _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS 1137
#define _CS_POSIX_V7_ILP32_OFFBIG_LIBS 1138
#define _CS_POSIX_V7_LP64_OFF64_CFLAGS 1140
#define _CS_POSIX_V7_LP64_OFF64_LDFLAGS 1141
#define _CS_POSIX_V7_LP64_OFF64_LIBS 1142
#define _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS 1144
#define _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS 1145
#define _CS_POSIX_V7_LPBIG_OFFBIG_LIBS 1146
#define _CS_POSIX_V7_THREADS_CFLAGS 1150
#define _CS_POSIX_V7_THREADS_LDFLAGS 1151
#define _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS 5
#define _CS_V7_ENV 1149

#if defined(__x86_64__) && defined(__LP64__)
/* The x86-64 LP64 namespace includes the historical V5/V6 confstr
 * selectors that musl exposes in addition to the common V7 subset above. */
#define _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS 1
#define _CS_GNU_LIBC_VERSION 2
#define _CS_GNU_LIBPTHREAD_VERSION 3
#define _CS_POSIX_V5_WIDTH_RESTRICTED_ENVS 4
#define _CS_POSIX_V6_ILP32_OFF32_CFLAGS 1116
#define _CS_POSIX_V6_ILP32_OFF32_LDFLAGS 1117
#define _CS_POSIX_V6_ILP32_OFF32_LIBS 1118
#define _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS 1119
#define _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS 1120
#define _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS 1121
#define _CS_POSIX_V6_ILP32_OFFBIG_LIBS 1122
#define _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS 1123
#define _CS_POSIX_V6_LP64_OFF64_CFLAGS 1124
#define _CS_POSIX_V6_LP64_OFF64_LDFLAGS 1125
#define _CS_POSIX_V6_LP64_OFF64_LIBS 1126
#define _CS_POSIX_V6_LP64_OFF64_LINTFLAGS 1127
#define _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS 1128
#define _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS 1129
#define _CS_POSIX_V6_LPBIG_OFFBIG_LIBS 1130
#define _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS 1131
#define _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS 1135
#define _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS 1139
#define _CS_POSIX_V7_LP64_OFF64_LINTFLAGS 1143
#define _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS 1147
#define _CS_V6_ENV 1148
#endif
#define F_LOCK 1
#define F_TEST 3
#define F_TLOCK 2
#define F_ULOCK 0
#define _PC_2_SYMLINKS 20
#define _PC_ALLOC_SIZE_MIN 18
#define _PC_ASYNC_IO 10
#define _PC_CHOWN_RESTRICTED 6
#define _PC_FILESIZEBITS 13
#define _PC_LINK_MAX 0
#define _PC_MAX_CANON 1
#define _PC_MAX_INPUT 2
#define _PC_NAME_MAX 3
#define _PC_NO_TRUNC 7
#define _PC_PATH_MAX 4
#define _PC_PIPE_BUF 5
#define _PC_PRIO_IO 11
#define _PC_SOCK_MAXBUF 12
#define _PC_REC_INCR_XFER_SIZE 14
#define _PC_REC_MAX_XFER_SIZE 15
#define _PC_REC_MIN_XFER_SIZE 16
#define _PC_REC_XFER_ALIGN 17
#define _PC_SYMLINK_MAX 19
#define _PC_SYNC_IO 9
#define _PC_VDISABLE 8
#define _SC_2_C_BIND 47
#define _SC_2_C_DEV 48
#define _SC_2_CHAR_TERM 95
#define _SC_2_FORT_DEV 49
#define _SC_2_FORT_RUN 50
#define _SC_2_LOCALEDEF 52
#define _SC_2_PBS 168
#define _SC_2_PBS_ACCOUNTING 169
#define _SC_2_PBS_CHECKPOINT 175
#define _SC_2_PBS_LOCATE 170
#define _SC_2_PBS_MESSAGE 171
#define _SC_2_PBS_TRACK 172
#define _SC_2_SW_DEV 51
#define _SC_2_UPE 97
#define _SC_2_VERSION 46
#define _SC_ADVISORY_INFO 132
#define _SC_AIO_LISTIO_MAX 23
#define _SC_AIO_MAX 24
#define _SC_AIO_PRIO_DELTA_MAX 25
#define _SC_ARG_MAX 0
#define _SC_ASYNCHRONOUS_IO 12
#define _SC_ATEXIT_MAX 87
#define _SC_BARRIERS 133
#define _SC_BC_BASE_MAX 36
#define _SC_BC_DIM_MAX 37
#define _SC_BC_SCALE_MAX 38
#define _SC_BC_STRING_MAX 39
#define _SC_CHILD_MAX 1
#define _SC_CLK_TCK 2
#define _SC_CLOCK_SELECTION 137
#define _SC_COLL_WEIGHTS_MAX 40
#define _SC_CPUTIME 138
#define _SC_DELAYTIMER_MAX 26
#define _SC_EXPR_NEST_MAX 42
#define _SC_FSYNC 15
#define _SC_GETGR_R_SIZE_MAX 69
#define _SC_GETPW_R_SIZE_MAX 70
#define _SC_HOST_NAME_MAX 180
#define _SC_IOV_MAX 60
#define _SC_IPV6 235
#define _SC_JOB_CONTROL 7
#define _SC_LINE_MAX 43
#define _SC_LOGIN_NAME_MAX 71
#define _SC_MAPPED_FILES 16
#define _SC_MEMLOCK 17
#define _SC_MEMLOCK_RANGE 18
#define _SC_MEMORY_PROTECTION 19
#define _SC_MESSAGE_PASSING 20
#define _SC_MONOTONIC_CLOCK 149
#define _SC_MQ_OPEN_MAX 27
#define _SC_MQ_PRIO_MAX 28
#define _SC_NGROUPS_MAX 3
#define _SC_NPROCESSORS_CONF 83
#define _SC_NPROCESSORS_ONLN 84
#define _SC_OPEN_MAX 4
#define _SC_PAGE_SIZE 30
#define _SC_PAGESIZE 30
#define _SC_PRIORITIZED_IO 13
#define _SC_PRIORITY_SCHEDULING 10
#define _SC_RAW_SOCKETS 236
#define _SC_RE_DUP_MAX 44
#define _SC_READER_WRITER_LOCKS 153
#define _SC_REALTIME_SIGNALS 9
#define _SC_REGEXP 155
#define _SC_RTSIG_MAX 31
#define _SC_SAVED_IDS 8
#define _SC_SEM_NSEMS_MAX 32
#define _SC_SEM_VALUE_MAX 33
#define _SC_SEMAPHORES 21
#define _SC_SHARED_MEMORY_OBJECTS 22
#define _SC_SHELL 157
#define _SC_SIGQUEUE_MAX 34
#define _SC_SPAWN 159
#define _SC_SPIN_LOCKS 154
#define _SC_SPORADIC_SERVER 160
#define _SC_SS_REPL_MAX 241
#define _SC_STREAM_MAX 5
#define _SC_SYMLOOP_MAX 173
#define _SC_SYNCHRONIZED_IO 14
#define _SC_THREAD_ATTR_STACKADDR 77
#define _SC_THREAD_ATTR_STACKSIZE 78
#define _SC_THREAD_CPUTIME 139
#define _SC_THREAD_DESTRUCTOR_ITERATIONS 73
#define _SC_THREAD_KEYS_MAX 74
#define _SC_THREAD_PRIO_INHERIT 80
#define _SC_THREAD_PRIO_PROTECT 81
#define _SC_THREAD_PRIORITY_SCHEDULING 79
#define _SC_THREAD_PROCESS_SHARED 82
#define _SC_THREAD_ROBUST_PRIO_INHERIT 247
#define _SC_THREAD_ROBUST_PRIO_PROTECT 248
#define _SC_THREAD_SAFE_FUNCTIONS 68
#define _SC_THREAD_SPORADIC_SERVER 161
#define _SC_THREAD_STACK_MIN 75
#define _SC_THREAD_THREADS_MAX 76
#define _SC_THREADS 67
#define _SC_TIMEOUTS 164
#define _SC_TIMER_MAX 35
#define _SC_TIMERS 11
#define _SC_TRACE 181
#define _SC_TRACE_EVENT_FILTER 182
#define _SC_TRACE_EVENT_NAME_MAX 242
#define _SC_TRACE_INHERIT 183
#define _SC_TRACE_LOG 184
#define _SC_TRACE_NAME_MAX 243
#define _SC_TRACE_SYS_MAX 244
#define _SC_TRACE_USER_EVENT_MAX 245
#define _SC_TTY_NAME_MAX 72
#define _SC_TYPED_MEMORY_OBJECTS 165
#define _SC_TZNAME_MAX 6
#define _SC_V7_ILP32_OFF32 237
#define _SC_V7_ILP32_OFFBIG 238
#define _SC_V7_LP64_OFF64 239
#define _SC_V7_LPBIG_OFFBIG 240
#define _SC_VERSION 29
#define _SC_XOPEN_CRYPT 92
#define _SC_XOPEN_ENH_I18N 93
#define _SC_XOPEN_REALTIME 130
#define _SC_XOPEN_REALTIME_THREADS 131
#define _SC_XOPEN_SHM 94
#define _SC_XOPEN_STREAMS 246
#define _SC_XOPEN_UNIX 91
#define _SC_XOPEN_VERSION 89

#if defined(__x86_64__) && defined(__LP64__)
#define _SC_UIO_MAXIOV 60
#define _SC_PHYS_PAGES 85
#define _SC_AVPHYS_PAGES 86
#define _SC_PASS_MAX 88
#define _SC_NZERO 109
#define _SC_XOPEN_XCU_VERSION 90
#define _SC_XOPEN_XPG2 98
#define _SC_XOPEN_XPG3 99
#define _SC_XOPEN_XPG4 100
#define _SC_XBS5_ILP32_OFF32 125
#define _SC_XBS5_ILP32_OFFBIG 126
#define _SC_XBS5_LP64_OFF64 127
#define _SC_XBS5_LPBIG_OFFBIG 128
#define _SC_XOPEN_LEGACY 129
#define _SC_STREAMS 174
#define _SC_V6_ILP32_OFF32 176
#define _SC_V6_ILP32_OFFBIG 177
#define _SC_V6_LP64_OFF64 178
#define _SC_V6_LPBIG_OFFBIG 179
#define _SC_MINSIGSTKSZ 249
#define _SC_SIGSTKSZ 250
#endif
#define STDERR_FILENO 2
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define _POSIX_VDISABLE 0
#define _POSIX_V7_LP64_OFF64 1
#if defined(__x86_64__) && defined(__LP64__)
#define _POSIX_V6_LP64_OFF64 1
#endif
#define POSIX_CLOSE_RESTART 0
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_DATA 3
#define SEEK_HOLE 4

#ifdef __cplusplus
extern "C" {
#endif

typedef long ssize_t;
#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
typedef int pid_t;
#endif
typedef unsigned int uid_t;
typedef unsigned int gid_t;

int fork(void);
pid_t _Fork(void);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
pid_t vfork(void);
#endif
int execve(const char *, char *const [], char *const []);
int execl(const char *, const char *, ...);
int execle(const char *, const char *, ...);
int execlp(const char *, const char *, ...);
int execv(const char *, char *const []);
int execvp(const char *, char *const []);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int execvpe(const char *, char *const [], char *const []);
#endif
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
gid_t getgid(void);
uid_t geteuid(void);
gid_t getegid(void);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getentropy(void *, size_t);
#endif
#ifdef _GNU_SOURCE
int setresuid(uid_t, uid_t, uid_t);
int setresgid(gid_t, gid_t, gid_t);
int getresuid(uid_t *, uid_t *, uid_t *);
int getresgid(gid_t *, gid_t *, gid_t *);
#endif

int close(int);
int posix_close(int, int);
ssize_t read(int, void *, size_t);
ssize_t write(int, const void *, size_t);
ssize_t pread(int, void *, size_t, off_t);
ssize_t pwrite(int, const void *, size_t, off_t);
void _exit(int) __attribute__((noreturn));

unsigned int sleep(unsigned int);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE) \
 || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE+0 < 700)
int usleep(unsigned int);
#endif

int pipe(int *);
int pipe2(int *, int);
int dup(int);
int dup2(int, int);
int dup3(int, int, int);
int fcntl(int, int, ...);
int access(const char *, int);
int unlink(const char *);
int rmdir(const char *);
int chdir(const char *);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int chroot(const char *);
int acct(const char *);
int vhangup(void);
#endif
char *getcwd(char *, size_t);
int gethostname(char *, size_t);
char *ctermid(char *);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getpagesize(void);
#endif
int truncate(const char *, off_t);
int ftruncate(int, off_t);
off_t lseek(int, off_t, int);

struct timespec;

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
long syscall(long, ...);
#endif

int nanosleep(const struct timespec *, struct timespec *);
unsigned int alarm(unsigned int);
int pause(void);
int fsync(int);
int fdatasync(int);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void sync(void);
#endif

int symlink(const char *, const char *);
ssize_t readlink(const char *, char *, size_t);
int link(const char *, const char *);
int chmod(const char *, unsigned int);
int fchmod(int, unsigned int);
unsigned int umask(unsigned int);
int isatty(int);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int issetugid(void);
#endif
char *ttyname(int);
char *getlogin(void);
int getgroups(int, unsigned int *);
int setuid(unsigned int);
int setgid(unsigned int);
int seteuid(unsigned int);
int setegid(unsigned int);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int setreuid(unsigned int, unsigned int);
int setregid(unsigned int, unsigned int);
#endif
pid_t setsid(void);
int setpgid(pid_t, pid_t);
pid_t getpgid(pid_t);
pid_t getsid(pid_t);
pid_t getpgrp(void);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
pid_t setpgrp(void);
#endif
int mkdir(const char *, unsigned int);

#ifdef _GNU_SOURCE
extern char **environ;
#endif
extern char *optarg;
extern int opterr;
extern int optind;
extern int optopt;

int chown(const char *, uid_t, gid_t);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int brk(void *);
void *sbrk(intptr_t);
#endif
size_t confstr(int, char *, size_t);
int faccessat(int, const char *, int, int);
int fchdir(int);
int fchown(int, uid_t, gid_t);
int fchownat(int, const char *, uid_t, gid_t, int);
int fexecve(int, char *const [], char *const []);
#ifdef _GNU_SOURCE
int eaccess(const char *, int);
int euidaccess(const char *, int);
#endif
long fpathconf(int, int);
int getlogin_r(char *, size_t);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *getusershell(void);
void setusershell(void);
void endusershell(void);
#endif
int getopt(int, char *const [], const char *);
int lchown(const char *, uid_t, gid_t);
int linkat(int, const char *, int, const char *, int);
long pathconf(const char *, int);
ssize_t readlinkat(int, const char *__restrict, char *__restrict, size_t);
int symlinkat(const char *, int, const char *);
long sysconf(int);
pid_t tcgetpgrp(int);
int tcsetpgrp(int, pid_t);
int ttyname_r(int, char *, size_t);
int unlinkat(int, const char *, int);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *crypt(const char *, const char *);
void encrypt(char [], int);
#endif
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
long gethostid(void);
int lockf(int, int, off_t);
int nice(int);
void swab(const void *__restrict, void *__restrict, ssize_t);
#endif

/* Linux/x86-64's staged header follows the pinned musl extension surface.
 * Keep these declarations target-local so the established AArch64 header
 * remains unchanged while the source-only x86 ABI ratchet grows. */
#if defined(__x86_64__) && defined(__LP64__) && (defined(_GNU_SOURCE) || defined(_BSD_SOURCE))
#define L_SET 0
#define L_INCR 1
#define L_XTND 2
int getdtablesize(void);
int sethostname(const char *, size_t);
int getdomainname(char *, size_t);
int setdomainname(const char *, size_t);
int setgroups(size_t, const gid_t *);
char *getpass(const char *);
int daemon(int, int);
extern int optreset;
#endif

#if defined(__x86_64__) && defined(__LP64__) && defined(_GNU_SOURCE)
char *get_current_dir_name(void);
int syncfs(int);
ssize_t copy_file_range(int, off_t *, int, off_t *, size_t, unsigned);
pid_t gettid(void);
#endif

#if defined(__x86_64__) && defined(__LP64__) && defined(_LARGEFILE64_SOURCE)
#define lseek64 lseek
#define pread64 pread
#define pwrite64 pwrite
#define truncate64 truncate
#define ftruncate64 ftruncate
#define lockf64 lockf
typedef off_t off64_t;
#endif

#ifdef __cplusplus
}
#endif

#endif
