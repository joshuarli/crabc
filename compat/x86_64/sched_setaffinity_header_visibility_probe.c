/* This must fail outside the GNU profile because the API and mask are GNU. */

#include <sched.h>

static int (*sched_setaffinity_visibility_witness)(pid_t, size_t,
    const cpu_set_t *) = sched_setaffinity;

int crabc_x86_64_sched_setaffinity_header_visibility_probe(void)
{
    return sched_setaffinity_visibility_witness != 0 ? 0 : 1;
}
