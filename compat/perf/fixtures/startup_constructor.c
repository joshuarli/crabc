/* Constructor/destructor PIE contract for the dynamic-startup scorecard row. */
#include <stdlib.h>
#include <unistd.h>

#include "diagnostic_marker.h"

static volatile unsigned int constructor_state;
static volatile unsigned int main_state;

__attribute__((constructor))
static void verify_constructor_order(void)
{
    constructor_state = 0x63ab19e5U;
}

__attribute__((destructor))
static void verify_destructor_order(void)
{
    if (constructor_state != 0x63ab19e5U || main_state != 0x78d40f2bU)
        _Exit(3);
}

int main(void)
{
    int status = 0;
    const int marker_fd = diagnostic_marker_fd();

    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_BEGIN, sizeof(DIAGNOSTIC_MARKER_BEGIN) - 1);
    if (constructor_state != 0x63ab19e5U)
        status = 2;
    else {
        main_state = 0x78d40f2bU;
        if (write(STDOUT_FILENO, "ok\n", 3) != 3)
            status = 4;
    }
    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_END, sizeof(DIAGNOSTIC_MARKER_END) - 1);
    return status;
}
