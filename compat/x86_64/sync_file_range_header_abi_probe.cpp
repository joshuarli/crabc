/* C++17 companion for selected Linux/x86-64 GNU sync_file_range headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <sys/types.h>

#ifdef CRABC_EXPECT_SYNC_FILE_RANGE
using sync_file_range_signature = int (*)(int, off_t, off_t, unsigned);

static_assert(sizeof(off_t) == 8 && alignof(off_t) == 8 &&
                  __is_same(off_t, long),
              "C++ x86 sync_file_range off_t ABI");
static_assert(SYNC_FILE_RANGE_WAIT_BEFORE == 1 &&
                  SYNC_FILE_RANGE_WRITE == 2 &&
                  SYNC_FILE_RANGE_WAIT_AFTER == 4,
              "C++ x86 sync_file_range flag ABI");
static_assert(__is_same(decltype(&sync_file_range), sync_file_range_signature),
              "C++ sync_file_range declaration");

__attribute__((used)) static sync_file_range_signature crabc_sync_file_range =
    sync_file_range;
#endif

int crabc_x86_64_sync_file_range_header_abi_probe_cpp()
{
    return sync_file_range(-1, (off_t)0, (off_t)0,
                           SYNC_FILE_RANGE_WRITE);
}
