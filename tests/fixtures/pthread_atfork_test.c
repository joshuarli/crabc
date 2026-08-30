#include "unistd.h"
#include "sys/wait.h"
#include "pthread_atfork.h"
#include "stdlib.h"

static int prepare_seq[10], parent_seq[10], child_seq[10];
static int pi, pai, chi;

static void prep_a(void) { prepare_seq[pi++] = 'A'; }
static void prep_b(void) { prepare_seq[pi++] = 'B'; }
static void prep_c(void) { prepare_seq[pi++] = 'C'; }
static void par_a(void) { parent_seq[pai++] = 'A'; }
static void par_b(void) { parent_seq[pai++] = 'B'; }
static void par_c(void) { parent_seq[pai++] = 'C'; }
static void ch_a(void) { child_seq[chi++] = 'A'; }
static void ch_b(void) { child_seq[chi++] = 'B'; }
static void ch_c(void) { child_seq[chi++] = 'C'; }

static void dump(int *seq, int n) {
    for (int i = 0; i < n; i++) {
        char c = seq[i];
        write(1, &c, 1);
    }
    write(1, "\n", 1);
}

/*
 * This stays outside the public atfork callbacks.  The selected native
 * allocator must have completed its private child transition before the
 * callbacks run, but neither musl's handler ordering nor the bounded
 * allocator fork contract permits allocation from a hook.
 */
static int exercise_quiescent_allocator(unsigned char tag)
{
    unsigned char *block;
    unsigned char *grown;

    block = malloc(73);
    if (block == NULL)
        return 1;
    block[0] = tag;
    block[72] = (unsigned char)(tag + 1);

    grown = realloc(block, 149);
    if (grown == NULL)
        return 2;
    if (grown[0] != tag || grown[72] != (unsigned char)(tag + 1)) {
        free(grown);
        return 3;
    }
    grown[148] = (unsigned char)(tag + 2);
    if (grown[148] != (unsigned char)(tag + 2)) {
        free(grown);
        return 4;
    }
    free(grown);
    return 0;
}

int main(void) {
    pthread_atfork(prep_a, par_a, ch_a);
    pthread_atfork(prep_b, par_b, ch_b);
    pthread_atfork(prep_c, par_c, ch_c);

    /*
     * Make the initial native owner real, then return it to its fully
     * dormant source image before the fork.  No allocation remains live and
     * no later worker exists, so this is deliberately not a general
     * post-fork pointer or lock-repair test.
     */
    if (exercise_quiescent_allocator(0x31) != 0)
        return 1;

    pid_t pid = fork();
    if (pid < 0) return 1;

    if (pid == 0) {
        if (exercise_quiescent_allocator(0x51) != 0)
            _exit(2);
        dump(prepare_seq, pi);
        dump(child_seq, chi);
        _exit(0);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid || status != 0)
        return 2;
    if (exercise_quiescent_allocator(0x71) != 0)
        return 3;
    dump(prepare_seq, pi);
    dump(parent_seq, pai);
    return 0;
}
