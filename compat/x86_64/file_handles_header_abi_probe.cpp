/* C++17 companion for the GNU Linux/x86-64 file-handle ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#include <stddef.h>
#include <fcntl.h>
#include <sys/syscall.h>

using name_to_handle_signature = int (*)(int, const char *,
                                         struct file_handle *, int *, int);
using open_by_handle_signature = int (*)(int, struct file_handle *, int);

static_assert(sizeof(struct file_handle) == 8 &&
                  alignof(struct file_handle) == 4 &&
                  offsetof(struct file_handle, handle_bytes) == 0 &&
                  offsetof(struct file_handle, handle_type) == 4 &&
                  offsetof(struct file_handle, f_handle) == 8,
              "C++ x86 file_handle flexible-tail ABI");
static_assert(SYS_name_to_handle_at == 303 && SYS_open_by_handle_at == 304,
              "C++ Linux x86-64 file-handle syscall numbers");
static_assert(__is_same(decltype(&name_to_handle_at),
                        name_to_handle_signature),
              "C++ name_to_handle_at declaration");
static_assert(__is_same(decltype(&open_by_handle_at),
                        open_by_handle_signature),
              "C++ open_by_handle_at declaration");

__attribute__((used)) static name_to_handle_signature name_to_handle_pointer =
    name_to_handle_at;
__attribute__((used)) static open_by_handle_signature open_by_handle_pointer =
    open_by_handle_at;

int crabc_x86_64_file_handles_header_abi_probe_cpp()
{
    struct file_handle *handle = nullptr;
    return handle == nullptr;
}
