/* SPDX-License-Identifier: MIT */
/* Exercise the selected allocator's automatic process finalizer from a real
 * main return. User atexit runs before the allocator's fini-array entry; an
 * application destructor follows it and reads only a process-static audit. */
#include <stdlib.h>
#include <unistd.h>

extern int __crabc_x86_native_mimalloc_process_done_fini_array_test_audit(void);

static volatile int user_atexit_seen;
static int expected_action;

int crabc_x86_64_native_mimalloc_shadow_prestart_rejection(void)
{
    return 0;
}

int crabc_x86_64_native_mimalloc_shadow_normal_main_user_atexit_observed(void)
{
    return __atomic_load_n(&user_atexit_seen, __ATOMIC_ACQUIRE);
}

void crabc_x86_64_native_mimalloc_shadow_normal_main_process_done_fini_observed(void)
{
    const char marker = 'M';
    if (write(STDERR_FILENO, &marker, 1) != 1)
        _Exit(91);
}

static void user_atexit(void)
{
    const char marker = 'A';
    void *client = malloc(353);
    if (client == 0)
        _Exit(92);
    ((volatile unsigned char *)client)[0] = 0x3d;
    free(client);
    __atomic_store_n(&user_atexit_seen, 1, __ATOMIC_RELEASE);
    if (write(STDERR_FILENO, &marker, 1) != 1)
        _Exit(93);
}

__attribute__((destructor))
static void application_fini(void)
{
    const char marker = 'D';
    if (__crabc_x86_native_mimalloc_process_done_fini_array_test_audit() != expected_action)
        _Exit(94);
    /* Automatic suppression leaves ordinary allocation available. Physical
     * destruction deliberately has no post-finalizer allocator operation. */
    if (expected_action == 3) {
        void *client = malloc(359);
        if (client == 0)
            _Exit(95);
        free(client);
    }
    if (write(STDERR_FILENO, &marker, 1) != 1)
        _Exit(96);
}

int main(void)
{
    const char *option = getenv("mimalloc_destroy_on_exit");
    if (option == 0 || (option[0] != '1' && option[0] != '2') || option[1] != 0)
        return 97;
    expected_action = option[0] == '1' ? 2 : 3;
    if (atexit(user_atexit) != 0)
        return 98;
    void *live = malloc(431);
    if (live == 0)
        return 99;
    ((volatile unsigned char *)live)[0] = 0x9a;
    return 0;
}
