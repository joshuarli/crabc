/* Selected static x86 musl strsignal compatibility fixture. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <string.h>

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

int crabc_x86_64_strsignal_probe(void)
{
    int result = check_signal_descriptions();
    if (result) return result;

    write_digest_hex(hash_signal_domain());
    return write_all(digest_line, sizeof digest_line - 1) ? 0 : 31;
}

#if !defined(CRABC_STRSIGNAL_FREESTANDING)
int main(void)
{
    return crabc_x86_64_strsignal_probe();
}
#endif
