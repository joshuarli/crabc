/* Selected static x86 musl strsignal compatibility fixture. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <string.h>
#if defined(CRABC_STRSIGNAL_ERRNO_PROBE)
#include <errno.h>
#endif

static char digest_line[] = "strsignal-domain-fnv1a64=0000000000000000\n";

static int local_streq(const char *left, const char *right)
{
    size_t index = 0;
    do {
        if (left[index] != right[index]) return 0;
    } while (left[index++]);
    return 1;
}

static long raw_write(int descriptor, const void *buffer, size_t length)
{
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1L), "D"((long)descriptor), "S"((long)buffer), "d"((long)length)
        : "rcx", "r11", "memory");
    return result;
}

static int write_all(const char *buffer, size_t length)
{
    while (length) {
        long written = raw_write(1, buffer, length);
        if (written <= 0) return 0;
        buffer += (size_t)written;
        length -= (size_t)written;
    }
    return 1;
}

static uint64_t hash_byte(uint64_t hash, unsigned char byte)
{
    return (hash ^ byte) * UINT64_C(1099511628211);
}

static uint64_t hash_signal_domain(void)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    int signal_number;

    for (signal_number = -4; signal_number <= 68; signal_number++) {
        const unsigned char *description =
            (const unsigned char *)strsignal(signal_number);
        unsigned int word = (unsigned int)signal_number;
        int byte;
        for (byte = 0; byte < 4; byte++) {
            hash = hash_byte(hash, (unsigned char)word);
            word >>= 8;
        }
        do {
            hash = hash_byte(hash, *description);
        } while (*description++);
    }
    return hash;
}

static void write_digest_hex(uint64_t digest)
{
    static const char hex[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 16; index++) {
        unsigned int shift = (unsigned int)((15 - index) * 4);
        digest_line[sizeof digest_line - 18 + index] = hex[(digest >> shift) & 15];
    }
}

static int check_signal_descriptions(void)
{
    if (!local_streq(strsignal(-1), "Unknown signal")) return 1;
    if (!local_streq(strsignal(0), "Unknown signal")) return 2;
    if (!local_streq(strsignal(1), "Hangup")) return 3;
    if (!local_streq(strsignal(5), "Trace/breakpoint trap")) return 4;
    if (!local_streq(strsignal(6), "Aborted")) return 5;
    if (!local_streq(strsignal(16), "Stack fault")) return 6;
    if (!local_streq(strsignal(31), "Bad system call")) return 7;
    if (!local_streq(strsignal(32), "RT32")) return 8;
    if (!local_streq(strsignal(34), "RT34")) return 9;
    if (!local_streq(strsignal(35), "RT35")) return 10;
    if (!local_streq(strsignal(64), "RT64")) return 11;
    if (!local_streq(strsignal(65), "Unknown signal")) return 12;
    if (strsignal(-1) != strsignal(0) || strsignal(0) != strsignal(65)) return 13;
    return 0;
}

static int check_storage_and_extreme_inputs(void)
{
    const char *trap = strsignal(5);
    const char *realtime = strsignal(34);
    const char *unknown = strsignal(0);
    static const int intervening[] = {
        INT32_MIN, -1000000, -4, -1, 0, 1, 31, 32, 33, 34, 35,
        63, 64, 65, 68, 1000000, INT32_MAX
    };
    size_t index;

    if (!trap || !realtime || !unknown) return 14;
    for (index = 0; index < sizeof intervening / sizeof intervening[0]; index++) {
        const char *description = strsignal(intervening[index]);
        if (!description) return 15;
        if (strsignal(intervening[index]) != description) return 16;
        if (strsignal(5) != trap || strsignal(34) != realtime ||
            strsignal(0) != unknown) return 17;
        if (!local_streq(trap, "Trace/breakpoint trap") ||
            !local_streq(realtime, "RT34") ||
            !local_streq(unknown, "Unknown signal")) return 18;
    }
    if (strsignal(INT32_MIN) != unknown ||
        strsignal(-1000000) != unknown ||
        strsignal(1000000) != unknown ||
        strsignal(INT32_MAX) != unknown) return 19;
    if (!local_streq(strsignal(33), "RT33") ||
        !local_streq(strsignal(63), "RT63")) return 20;
    return 0;
}

#if defined(CRABC_STRSIGNAL_ERRNO_PROBE)
static int check_errno_preservation(void)
{
    static const int numbers[] = {INT32_MIN, -1, 0, 1, 31, 32, 34, 64, 65, INT32_MAX};
    size_t index;

    for (index = 0; index < sizeof numbers / sizeof numbers[0]; index++) {
        errno = EALREADY;
        if (!strsignal(numbers[index]) || errno != EALREADY) return 21;
        errno = ENOTTY;
        if (!strsignal(numbers[index]) || errno != ENOTTY) return 22;
    }
    return 0;
}
#endif

int crabc_x86_64_strsignal_probe(void)
{
    int result = check_signal_descriptions();
    if (result) return result;
    result = check_storage_and_extreme_inputs();
    if (result) return result;
#if defined(CRABC_STRSIGNAL_ERRNO_PROBE)
    result = check_errno_preservation();
    if (result) return result;
#endif

    write_digest_hex(hash_signal_domain());
    return write_all(digest_line, sizeof digest_line - 1) ? 0 : 31;
}

#if !defined(CRABC_STRSIGNAL_FREESTANDING)
int main(void)
{
    return crabc_x86_64_strsignal_probe();
}
#endif
