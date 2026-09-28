#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

struct worker_case {
    int (*run)(int);
    int malformed;
    int result;
};

static void *worker(void *argument) {
    struct worker_case *test = argument;
    test->result = test->run(test->malformed);
    return 0;
}

static int child_case(const char *label, int malformed) {
    void *library = dlopen("libcrabc_guarded_dso_cfi.so", RTLD_NOW);
    if (!library) return 1;
    int (*run)(int) = dlsym(library, "crabc_guarded_dso_cfi");
    if (!run) return 2;
    struct worker_case test = {run, malformed, -1};
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &test) != 0) return 3;
    if (pthread_join(thread, 0) != 0) return 4;
    printf("%s unwind=%d\n", label, test.result);
    fflush(stdout);
    if (dlclose(library) != 0) return 5;
    return test.result == (malformed ? 3 : 5) ? 0 : 6;
}

static int parent_case(const char *label, int malformed) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) _exit(child_case(label, malformed));
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 2;
    int observed = WIFEXITED(status) ? WEXITSTATUS(status) :
                   WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255;
    printf("%s wait=%d\n", label, observed);
    fflush(stdout);
    return observed;
}

int main(void) {
    setbuf(stdout, 0);
    if (parent_case("mapped", 0) != 0) return 1;
    if (parent_case("unreadable", 1) != 0) return 2;
    return 0;
}
