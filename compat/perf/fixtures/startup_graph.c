/* Startup-linked DSO graph contract; the root must resolve both leaf branches. */
#include <stdio.h>

#include "diagnostic_marker.h"

extern int bench_graph_root_value(void);

int main(void)
{
    int status = 0;
    const int marker_fd = diagnostic_marker_fd();

    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_BEGIN, sizeof(DIAGNOSTIC_MARKER_BEGIN) - 1);
    if (bench_graph_root_value() != 31)
        status = 3;
    else if (puts("ok") == EOF)
        status = 4;
    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_END, sizeof(DIAGNOSTIC_MARKER_END) - 1);
    return status;
}
