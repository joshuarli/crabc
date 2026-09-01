extern int shared_value(void);
extern int shared_mark_left(void);

#include "ldso_general_initial_graph_cycle_marker.h"

__attribute__((constructor(101))) static void left_initializer(void) {
#if defined(CRABC_GENERAL_CYCLE_CALLBACK_MARKER)
    general_initial_graph_cycle_callback_marker();
#endif
    if (shared_mark_left() != 0) __builtin_trap();
}

#if defined(CRABC_GENERAL_INIT_ARRAY_ZERO)
/* The loader must inspect every relocated entry before calling the valid
   priority-101 initializer above. This deliberately retains a literal null
   entry in the same dependency array. */
__attribute__((used, section(".init_array.00200")))
static void (*const general_init_array_zero)(void) = 0;
#endif

#if defined(CRABC_GENERAL_INIT_ARRAY_NONEXECUTABLE)
static volatile int general_init_array_nonexecutable_target;

/* A local data address produces an ordinary relative relocation. It becomes
   an in-load but non-executable entry only after relocation, exactly the
   target class the loader preflight must reject before dispatch. */
__attribute__((used, section(".init_array.00200")))
static void (*const general_init_array_nonexecutable)(void) =
    (void (*)(void))&general_init_array_nonexecutable_target;
#endif

#if defined(CRABC_GENERAL_FINI_ARRAY)
/* Dependency finalization is not selected by the initial startup owner. */
__attribute__((destructor)) static void left_finalizer(void) {
    __builtin_trap();
}
#endif

int left_value(void) {
    return shared_value() + 10;
}
