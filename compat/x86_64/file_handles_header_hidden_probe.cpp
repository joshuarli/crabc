/* C++17 GNU-only file-handle declarations must remain hidden. */

#if !defined(__linux__) || !defined(__x86_64__)
#error "this probe requires Linux/x86-64"
#endif

#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>

int crabc_x86_64_file_handles_header_hidden_probe_cpp()
{
    struct file_handle *handle = nullptr;
    return name_to_handle_at(-100, "hidden", handle, nullptr, 0) +
           open_by_handle_at(-1, handle, 0);
}
