/* C++ companion for the native x86-64 GNU <fcntl.h> sync_file_range probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <fcntl.h>

extern "C" int sync_file_range(int, off_t, off_t, unsigned);

using sync_file_range_signature = int (*)(int, off_t, off_t, unsigned);

#if defined(CRABC_EXPECT_SYNC_FILE_RANGE)
static_assert(__is_same(decltype(&sync_file_range), sync_file_range_signature),
              "sync_file_range declaration");
#endif

int crabc_x86_64_sync_file_range_header_abi_probe_cpp()
{
    return 0;
}
