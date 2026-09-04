/* GNU Linux/x86-64 file-handle declaration, linkage, and tail-layout probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#include <stddef.h>
#include <fcntl.h>
#include <sys/syscall.h>

typedef int (*name_to_handle_signature)(int, const char *,
                                        struct file_handle *, int *, int);
typedef int (*open_by_handle_signature)(int, struct file_handle *, int);

_Static_assert(sizeof(unsigned int) == 4 && sizeof(int) == 4,
               "x86 file-handle scalar ABI");
_Static_assert(sizeof(struct file_handle) == 8 &&
                   _Alignof(struct file_handle) == 4 &&
                   offsetof(struct file_handle, handle_bytes) == 0 &&
                   offsetof(struct file_handle, handle_type) == 4 &&
                   offsetof(struct file_handle, f_handle) == 8,
               "x86 file_handle flexible-tail ABI");
_Static_assert(SYS_name_to_handle_at == 303 && SYS_open_by_handle_at == 304,
               "Linux x86-64 file-handle syscall numbers");

static name_to_handle_signature name_to_handle_pointer = name_to_handle_at;
static open_by_handle_signature open_by_handle_pointer = open_by_handle_at;

int crabc_x86_64_file_handles_header_abi_probe(void)
{
    struct {
        struct file_handle header;
        unsigned char bytes[16];
    } storage = { { 16, 0 }, { 0 } };

    (void)name_to_handle_pointer;
    (void)open_by_handle_pointer;
    return storage.header.handle_type;
}
