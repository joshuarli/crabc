extern int shared_value(void);
extern int shared_mark_right(void);

#include "ldso_general_initial_graph_cycle_marker.h"

__attribute__((constructor(101))) static void right_initializer(void) {
#if defined(CRABC_GENERAL_CYCLE_CALLBACK_MARKER)
    general_initial_graph_cycle_callback_marker();
#endif
    if (shared_mark_right() != 0) __builtin_trap();
}

int right_value(void) {
    return shared_value() + 12;
}
