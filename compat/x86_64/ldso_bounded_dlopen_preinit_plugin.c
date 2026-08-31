/*
 * GNU ld correctly rejects `.preinit_array` in a DSO. The bounded-runtime
 * runner links this ordinary init-array fixture, then changes only its two
 * dynamic-tag spellings to DT_PREINIT_ARRAY/DT_PREINIT_ARRAYSZ. That leaves a
 * real ELF64 array relocation and callback target while making the runtime
 * DSO preinit boundary observable without selecting a generic lifecycle.
 */
int bounded_preinit_array_runs;

static void bounded_preinit_array_entry(void) {
    ++bounded_preinit_array_runs;
}

typedef void (*bounded_preinit_hook)(void);

__attribute__((used, section(".init_array")))
static bounded_preinit_hook const bounded_preinit_array_slot =
    bounded_preinit_array_entry;

int bounded_preinit_value(void) {
    return 83;
}
