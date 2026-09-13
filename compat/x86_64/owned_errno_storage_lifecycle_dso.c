/* Loaded-DSO public accessor witness for owned errno/h_errno storage.
 *
 * This has no private data spelling and does not retain any returned pointer.
 * Its caller controls the lifetime: it invokes this entry only while the main
 * task or selected worker is live, and closes the DSO after the worker joins.
 */

#ifndef _GNU_SOURCE
#error "this DSO witness requires the installed GNU profile"
#endif

#include <errno.h>
#include <netdb.h>

struct errno_storage_snapshot {
    int *errno_location;
    int errno_value;
    int *h_errno_location;
    int h_errno_value;
};

int errno_storage_lifecycle_snapshot(struct errno_storage_snapshot *out)
{
    int *errno_location;
    int *h_errno_location;

    if (!out)
        return 1;
    errno_location = __errno_location();
    h_errno_location = __h_errno_location();
    if (!errno_location || !h_errno_location)
        return 2;
    out->errno_location = errno_location;
    out->errno_value = *errno_location;
    out->h_errno_location = h_errno_location;
    out->h_errno_value = *h_errno_location;
    return 0;
}
