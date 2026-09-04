/* GNU-only file-handle declarations must stay hidden outside _GNU_SOURCE. */

#if !defined(__linux__) || !defined(__x86_64__)
#error "this probe requires Linux/x86-64"
#endif

#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>

int crabc_x86_64_file_handles_header_hidden_probe(void)
{
    struct file_handle *handle = (struct file_handle *)0;
    return name_to_handle_at(-100, "hidden", handle, (int *)0, 0) +
           open_by_handle_at(-1, handle, 0);
}
