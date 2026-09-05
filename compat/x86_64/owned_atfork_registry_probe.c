#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { dprintf(2, "atfork registry line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)

/* Distinct functions make order observable across the former 32-slot limit. */
#define CALLBACK_IDS(X) \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) \
    X(10) X(11) X(12) X(13) X(14) X(15) X(16) X(17) X(18) X(19) \
    X(20) X(21) X(22) X(23) X(24) X(25) X(26) X(27) X(28) X(29) \
    X(30) X(31) X(32) X(33) X(34) X(35) X(36) X(37) X(38) X(39) \
    X(40) X(41) X(42) X(43) X(44) X(45) X(46) X(47) X(48) X(49) \
    X(50) X(51) X(52) X(53) X(54) X(55) X(56) X(57) X(58) X(59) \
    X(60) X(61) X(62) X(63) X(64) X(65) X(66) X(67) X(68) X(69)

static int registered, next_prepare, next_post, parents, children;
static void prepare_record(int id) { CHECK(next_prepare-- == id); }
static void parent_record(int id) { CHECK(next_post++ == id); parents++; }
static void child_record(int id) { CHECK(next_post++ == id); children++; }
#define DEFINE_CALLBACKS(id) \
    static void prepare_##id(void) { prepare_record(id); } \
    static void parent_##id(void) { parent_record(id); } \
    static void child_##id(void) { child_record(id); }
CALLBACK_IDS(DEFINE_CALLBACKS)
struct callbacks { void (*prepare)(void), (*parent)(void), (*child)(void); };
#define CALLBACK_ENTRY(id) {prepare_##id, parent_##id, child_##id},
static const struct callbacks callbacks[] = { CALLBACK_IDS(CALLBACK_ENTRY) };

static void register_next(void) {
    CHECK(registered < (int)(sizeof callbacks / sizeof *callbacks));
    const struct callbacks *entry = &callbacks[registered];
    int result = pthread_atfork(entry->prepare, entry->parent, entry->child);
    if (result) dprintf(2, "registration %d returned %d\n", registered, result);
    CHECK(result == 0);
    registered++;
}
static void reset_round(void) {
    next_prepare = registered - 1;
    next_post = parents = children = 0;
}
static void check_completion(int child) {
    CHECK(next_prepare == -1 && next_post == registered);
    CHECK(parents == (child ? 0 : registered));
    CHECK(children == (child ? registered : 0));
}
static void wait_child(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void ordinary_round(void) {
    reset_round();
    pid_t child = fork();
    CHECK(child >= 0);
    check_completion(child == 0);
    if (child == 0) _exit(0);
    wait_child(child);
}
static void *register_from_worker(void *unused) {
    (void)unused;
    register_next();
    return 0;
}
static void deny_fork(void) {
    /* Linux 5.10 sock_filter/sock_fprog layouts, scoped to this process. */
    struct instruction { unsigned short code; unsigned char yes, no; unsigned value; };
    struct program { unsigned short count; struct instruction *instructions; };
    struct instruction instructions[] = {
        {0x20, 0, 0, 0},
        {0x15, 0, 1, SYS_fork},
        {0x06, 0, 0, 0x00050000 | EAGAIN},
        {0x06, 0, 0, 0x7fff0000},
    };
    struct program program = {sizeof instructions / sizeof *instructions, instructions};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &program) == 0);
}
static void failed_round(void) {
    reset_round();
    errno = 0;
    CHECK(fork() == -1 && errno == EAGAIN);
    check_completion(0);
}
int main(void) {
    ordinary_round(); /* Empty-registry prepare/completion must stay paired. */
    /* This is deliberately the application's first allocation client. */
    for (int i = 0; i < 67; i++) register_next();
    CHECK(pthread_atfork(0, 0, 0) == 0);
    reset_round();
    pid_t child = fork();
    CHECK(child >= 0);
    check_completion(child == 0);
    if (child == 0) {
        /* The copied registry must return to its newest-first orientation
         * and release its copied lock before subsequent child registration. */
        register_next();
        ordinary_round();
        _exit(0);
    }
    wait_child(child);
    pthread_t worker;
    CHECK(pthread_create(&worker, 0, register_from_worker, 0) == 0);
    CHECK(pthread_join(worker, 0) == 0);
    register_next();
    ordinary_round();
    ordinary_round();
    deny_fork();
    failed_round();
    register_next();
    failed_round();
    puts("owned-atfork-registry-ok");
    return 0;
}
