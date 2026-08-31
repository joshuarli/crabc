/* Static crabc-libc x86-64 musl error-string compatibility fixture. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>

extern int __xpg_strerror_r(int, char *, size_t);

static char digest_line[] = "strerror-domain-fnv1a64=0000000000000000\n";
static const char alias_line[] = "strerror-r-alias=weak-same-address\n";

static size_t local_strlen(const char *text)
{
    size_t length = 0;
    while (text[length]) length++;
    return length;
}

static int local_streq(const char *left, const char *right)
{
    size_t index = 0;
    do {
        if (left[index] != right[index]) return 0;
    } while (left[index++]);
    return 1;
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;
    for (index = 0; index < length; index++)
        if (left[index] != right[index]) return 0;
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

static uint64_t hash_error_domain(void)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    int error;
    for (error = 0; error <= 134; error++) {
        const unsigned char *message = (const unsigned char *)strerror(error);
        unsigned int word = (unsigned int)error;
        int byte;
        for (byte = 0; byte < 4; byte++) {
            hash = hash_byte(hash, (unsigned char)word);
            word >>= 8;
        }
        do {
            hash = hash_byte(hash, *message);
        } while (*message++);
    }
    return hash;
}

static void write_digest_hex(uint64_t digest)
{
    static const char hex[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 16; index++) {
        unsigned int shift = (unsigned int)((15 - index) * 4);
        digest_line[24 + index] = hex[(digest >> shift) & 15];
    }
}

static int check_strerror_messages(void)
{
    if (!local_streq(strerror(0), "No error information")) return 1;
    if (!local_streq(strerror(2), "No such file or directory")) return 2;
    if (!local_streq(strerror(12), "Out of memory")) return 3;
    if (!local_streq(strerror(25), "Not a tty")) return 4;
    if (!local_streq(strerror(29), "Invalid seek")) return 5;
    if (!local_streq(strerror(34), "Result not representable")) return 6;
    if (!local_streq(strerror(36), "Filename too long")) return 7;
    if (!local_streq(strerror(75), "Value too large for data type")) return 8;
    if (!local_streq(strerror(95), "Not supported")) return 9;
    if (!local_streq(strerror(119), "Resource not available")) return 10;
    if (!local_streq(strerror(41), "No error information")) return 11;
    if (!local_streq(strerror(109), "No error information")) return 12;
    if (!local_streq(strerror(133), "No error information")) return 13;
    if (!local_streq(strerror(134), "No error information")) return 14;
    if (strerror(0) != strerror(41) || strerror(0) != strerror(134)) return 15;
    return 0;
}

static int check_strerror_r(void)
{
    const char *message = "No such file or directory";
    const size_t length = local_strlen(message);
    char buffer[64];
    size_t index;

    if (strerror_r(ENOENT, (char *)0, 0) != ERANGE) return 21;

    for (index = 0; index < sizeof buffer; index++) buffer[index] = 'Z';
    if (strerror_r(ENOENT, buffer, 1) != ERANGE) return 22;
    if (buffer[0] != 0 || buffer[1] != 'Z') return 23;

    for (index = 0; index < sizeof buffer; index++) buffer[index] = 'Z';
    if (strerror_r(ENOENT, buffer, length) != ERANGE) return 24;
    if (!bytes_equal(buffer, message, length - 1)) return 25;
    if (buffer[length - 1] != 0 || buffer[length] != 'Z') return 26;

    for (index = 0; index < sizeof buffer; index++) buffer[index] = 'Z';
    if (strerror_r(ENOENT, buffer, length + 1) != 0) return 27;
    if (!local_streq(buffer, message) || buffer[length + 1] != 'Z') return 28;

    for (index = 0; index < sizeof buffer; index++) buffer[index] = 'Z';
    if (strerror_r(41, buffer, sizeof buffer) != 0) return 29;
    if (!local_streq(buffer, "No error information")) return 30;

    if (strerror_r != __xpg_strerror_r) return 31;
    for (index = 0; index < sizeof buffer; index++) buffer[index] = 'Z';
    if (__xpg_strerror_r(34, buffer, sizeof buffer) != 0) return 32;
    if (!local_streq(buffer, "Result not representable")) return 33;
    return 0;
}

int crabc_x86_64_error_strings_probe(void)
{
    int result = check_strerror_messages();
    if (result) return result;
    result = check_strerror_r();
    if (result) return result;

    write_digest_hex(hash_error_domain());
    if (!write_all(digest_line, sizeof digest_line - 1)) return 41;
    if (!write_all(alias_line, sizeof alias_line - 1)) return 42;
    return 0;
}

#if !defined(CRABC_ERROR_STRINGS_FREESTANDING)
int main(void)
{
    return crabc_x86_64_error_strings_probe();
}
#endif
