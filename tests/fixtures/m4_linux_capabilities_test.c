#define _GNU_SOURCE 1

#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct __user_cap_header_struct current_header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct before[_LINUX_CAPABILITY_U32S_3];
    struct __user_cap_data_struct after[_LINUX_CAPABILITY_U32S_3];
    struct __user_cap_header_struct invalid_header = {
        .version = 0xdeadbeefU,
        .pid = 0,
    };
    struct __user_cap_data_struct invalid_data[_LINUX_CAPABILITY_U32S_3];

    memset(before, 0, sizeof before);
    memset(after, 0, sizeof after);
    memset(invalid_data, 0, sizeof invalid_data);

    /* Version 3 is the 64-bit Linux ABI and returns the current sets. */
    if (capget(&current_header, before) != 0 ||
        current_header.version != _LINUX_CAPABILITY_VERSION_3)
        return 1;

    /* Exercise the public constants as part of the ABI compile/runtime check. */
    if (CAP_LAST_CAP != CAP_CHECKPOINT_RESTORE ||
        CAP_TO_INDEX(CAP_CHECKPOINT_RESTORE) != 1 ||
        CAP_TO_MASK(CAP_CHECKPOINT_RESTORE) != 0x100U)
        return 2;

    /* An unknown header version is rejected before any capability update. */
    errno = 0;
    if (capset(&invalid_header, invalid_data) != -1 || errno != EINVAL)
        return 3;

    /* The failed capset must not change the process's capability sets. */
    current_header.version = _LINUX_CAPABILITY_VERSION_3;
    if (capget(&current_header, after) != 0 ||
        memcmp(before, after, sizeof before) != 0)
        return 4;

    puts("m4 linux capabilities ok");
    return 0;
}
