/* Source-only Linux/x86-64 GNU <fcntl.h> sync_file_range declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <fcntl.h>

typedef int (*sync_file_range_signature)(int, off_t, off_t, unsigned);

#if defined(CRABC_EXPECT_SYNC_FILE_RANGE)
static sync_file_range_signature sync_file_range_signature_value = sync_file_range;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_SYNC_FILE_RANGE_HIDDEN)
static sync_file_range_signature required_sync_file_range_signature = sync_file_range;
#endif

int crabc_x86_64_sync_file_range_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_SYNC_FILE_RANGE)
    (void)sync_file_range_signature_value;
#endif
#if defined(CRABC_REQUIRE_SYNC_FILE_RANGE_HIDDEN)
    (void)required_sync_file_range_signature;
#endif
    return 0;
}
