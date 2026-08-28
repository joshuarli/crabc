/* C++ companion for the native Linux/x86-64 random-source header probe. */

#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

using getrandom_type = ssize_t (*)(void *, size_t, unsigned);

static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
    "C++ x86 size types");
static_assert(__is_same(decltype(&getrandom), getrandom_type),
    "C++ getrandom declaration");
static_assert(GRND_NONBLOCK == 0x0001 && GRND_RANDOM == 0x0002 &&
    GRND_INSECURE == 0x0004, "C++ getrandom flags");

#if defined(CRABC_EXPECT_GETENTROPY)
using getentropy_type = int (*)(void *, size_t);
static_assert(__is_same(decltype(&getentropy), getentropy_type),
    "C++ getentropy declaration");
#endif

int crabc_random_entropy_header_abi_probe_cpp()
{
    return GRND_NONBLOCK + GRND_RANDOM + GRND_INSECURE;
}
