/* Selected Linux/x86-64 GNU sync_file_range C header ABI facts. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <sys/types.h>

#ifdef CRABC_EXPECT_SYNC_FILE_RANGE
typedef int (*crabc_sync_file_range_signature)(int, off_t, off_t, unsigned);

_Static_assert(sizeof(off_t) == 8 && _Alignof(off_t) == 8 &&
                   __builtin_types_compatible_p(off_t, long),
               "x86 sync_file_range off_t ABI");
_Static_assert(SYNC_FILE_RANGE_WAIT_BEFORE == 1 &&
                   SYNC_FILE_RANGE_WRITE == 2 &&
                   SYNC_FILE_RANGE_WAIT_AFTER == 4,
               "x86 sync_file_range flag ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sync_file_range),
                                             crabc_sync_file_range_signature),
               "sync_file_range declaration");
#endif

int crabc_x86_64_sync_file_range_header_abi_probe(void)
{
    return sync_file_range(-1, (off_t)0, (off_t)0,
                           SYNC_FILE_RANGE_WRITE);
}
