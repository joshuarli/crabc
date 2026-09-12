/*
 * Test-only fork interposer for x86_64_timing_launcher.c.
 *
 * Including the production source with a renamed main and fork call keeps the
 * measured launcher bytes free of test modes.  This wrapper burns supervisor
 * CPU immediately before the real fork; a parent wait4 of the supervisor must
 * see that burn while the launcher's child-only result must not.
 */

#define main crabc_timing_launcher_production_main
#define fork crabc_timing_launcher_test_interposed_fork
#include "../x86_64_timing_launcher.c"
#undef fork
#undef main

/* The renamed include rewrote unistd.h's normal fork declaration too. */
extern pid_t fork(void);


static void burn_supervisor_cpu_before_real_fork(void) {
    struct timespec started;
    struct timespec current;
    uint64_t started_ns;
    uint64_t iterations = 0;
    volatile uint64_t state = UINT64_C(0x6a09e667f3bcc909);

    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &started) != 0 || started.tv_sec < 0 || started.tv_nsec < 0) {
        return;
    }
    started_ns = (uint64_t)started.tv_sec * UINT64_C(1000000000) + (uint64_t)started.tv_nsec;
    for (;;) {
        state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
        ++iterations;
        if ((iterations & UINT64_C(1023)) != 0) {
            continue;
        }
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &current) != 0 || current.tv_sec < 0 || current.tv_nsec < 0 ||
            (uint64_t)current.tv_sec * UINT64_C(1000000000) + (uint64_t)current.tv_nsec - started_ns >=
                UINT64_C(150000000)) {
            break;
        }
    }
    (void)state;
}


pid_t crabc_timing_launcher_test_interposed_fork(void) {
    burn_supervisor_cpu_before_real_fork();
    return fork();
}


int main(int argc, char **argv) {
    return crabc_timing_launcher_production_main(argc, argv);
}
