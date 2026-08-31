/* C++17 companion for the Linux/x86-64 GNU copy_file_range declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <unistd.h>

extern "C" ssize_t copy_file_range(int, off_t *, int, off_t *, size_t,
    unsigned);

using copy_file_range_signature = ssize_t (*)(int, off_t *, int, off_t *,
    size_t, unsigned);

#if defined(CRABC_EXPECT_COPY_FILE_RANGE)
static_assert(__is_same(decltype(&copy_file_range), copy_file_range_signature),
    "copy_file_range declaration");
static copy_file_range_signature copy_file_range_function __attribute__((used)) =
    copy_file_range;
#endif

#if defined(CRABC_REQUIRE_COPY_FILE_RANGE_HIDDEN)
static copy_file_range_signature copy_file_range_must_be_hidden
    __attribute__((used)) = copy_file_range;
#endif

int crabc_x86_64_copy_file_range_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_COPY_FILE_RANGE)
    return copy_file_range_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}
