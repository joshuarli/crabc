/* Source-only Linux/x86-64 GNU <unistd.h> copy_file_range declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <unistd.h>

typedef ssize_t (*copy_file_range_signature)(int, off_t *, int, off_t *,
    size_t, unsigned);

#if defined(CRABC_EXPECT_COPY_FILE_RANGE)
_Static_assert(sizeof(off_t) == sizeof(long), "x86 LP64 off_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&copy_file_range),
    copy_file_range_signature), "copy_file_range declaration");
static copy_file_range_signature copy_file_range_function __attribute__((used)) =
    copy_file_range;
#endif

/* This branch is compiled only as an expected-failure selector check. */
#if defined(CRABC_REQUIRE_COPY_FILE_RANGE_HIDDEN)
static copy_file_range_signature copy_file_range_must_be_hidden
    __attribute__((used)) = copy_file_range;
#endif

int crabc_x86_64_copy_file_range_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_COPY_FILE_RANGE)
    return copy_file_range_function != (copy_file_range_signature)0 ? 0 : 1;
#else
    return 0;
#endif
}
