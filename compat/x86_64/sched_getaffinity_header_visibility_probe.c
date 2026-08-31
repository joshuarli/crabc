/* This must fail outside the GNU profile because the API and mask are GNU. */

#include <sched.h>

static int (*sched_getaffinity_visibility_witness)(pid_t, size_t, cpu_set_t *) =
    sched_getaffinity;

int crabc_x86_64_sched_getaffinity_header_visibility_probe(void)
{
    return sched_getaffinity_visibility_witness != 0 ? 0 : 1;
}
