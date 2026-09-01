static volatile int general_initial_order;

#include "ldso_general_initial_graph_cycle_marker.h"

__attribute__((constructor(101))) static void shared_initializer(void) {
#if defined(CRABC_GENERAL_CYCLE_CALLBACK_MARKER)
    general_initial_graph_cycle_callback_marker();
#endif
    general_initial_order = 1;
}

int shared_mark_left(void) {
    if ((general_initial_order & 1) == 0 || (general_initial_order & 2) != 0)
        return -1;
    general_initial_order |= 2;
    return 0;
}

int shared_mark_right(void) {
    if ((general_initial_order & 1) == 0 || (general_initial_order & 4) != 0)
        return -1;
    general_initial_order |= 4;
    return 0;
}

int shared_value(void) {
    return general_initial_order == 7 ? 10 : -100;
}
