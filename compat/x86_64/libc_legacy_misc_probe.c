/* Static Linux/x86-64 frozen legacy.misc behavior fixture.
 *
 * The aggregate is deliberately narrow: its retained system-information and
 * `issetugid` observations are existing x86 prerequisites, while this slice
 * adds only fmtmsg/setkey/encrypt.  Pinned musl 1.2.6 remains the fmtmsg and
 * declaration oracle.  DES is the explicit exception: the candidate adopts
 * the established project inert-DES compatibility contract, so no local
 * cipher is implemented and candidate buffers remain byte-for-byte unchanged.
 *
 * The fixture redirects fd 2 to private pipes instead of relying on host
 * stderr.  It verifies MSGVERB selection, exact normal output, a closed-fd
 * MM_NOMSG/EBADF path, and a forced partial nonblocking write followed by
 * MM_NOMSG/EAGAIN.  The console route compares fmtmsg's failure errno with a
 * direct /dev/console open when the native container has no usable console.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <fmtmsg.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

typedef int (*fmtmsg_signature)(long, const char *, int, const char *,
    const char *, const char *);
typedef void (*encrypt_signature)(char *, int);
typedef void (*setkey_signature)(const char *);
typedef int (*get_nprocs_signature)(void);
typedef long (*get_pages_signature)(void);
typedef int (*issetugid_signature)(void);

_Static_assert(sizeof(long) == 8, "x86 LP64 long");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fmtmsg), fmtmsg_signature),
    "fmtmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&encrypt), encrypt_signature),
    "encrypt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setkey), setkey_signature),
    "setkey declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_nprocs_conf),
    get_nprocs_signature), "get_nprocs_conf declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_nprocs),
    get_nprocs_signature), "get_nprocs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_phys_pages),
    get_pages_signature), "get_phys_pages declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_avphys_pages),
    get_pages_signature), "get_avphys_pages declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&issetugid),
    issetugid_signature), "issetugid declaration");

static size_t c_length(const char *text)
{
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    return length;
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;
    for (index = 0; index < length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static int set_msgverb(const char *value)
{
    return setenv("MSGVERB", value, 1) == 0 ? 0 : 1;
}

static int capture_print(const char *verb, const char *expected)
{
    int descriptors[2];
    int saved_stderr;
    int result;
    int saved_errno;
    char output[128];
    ssize_t received;

    if (set_msgverb(verb) != 0)
        return 1;
    if (pipe(descriptors) != 0)
        return 2;
    saved_stderr = dup(2);
    if (saved_stderr < 0)
        return 3;
    if (dup2(descriptors[1], 2) != 2)
        return 4;
    if (close(descriptors[1]) != 0)
        return 5;

    errno = E2BIG;
    result = fmtmsg(MM_PRINT, "LBL", MM_ERROR, "TEXT", "FIX", "TAG");
    saved_errno = errno;
    if (dup2(saved_stderr, 2) != 2)
        return 6;
    if (close(saved_stderr) != 0)
        return 7;
    received = read(descriptors[0], output, sizeof output);
    if (close(descriptors[0]) != 0)
        return 8;
    if (result != MM_OK || saved_errno != E2BIG)
        return 9;
    if (received != (ssize_t)c_length(expected))
        return 10;
    if (!bytes_equal(output, expected, (size_t)received))
        return 11;
    return 0;
}

static int check_print_paths(void)
{
    static const char all_components[] =
        "LBL: ERROR: TEXT\nTO FIX: FIX TAG\n";
    static const char label_and_text[] = "LBL: TEXT\n";
    int result;

    errno = E2BIG;
    if (fmtmsg(MM_NULLMC, "ignored", MM_ERROR, "ignored", NULL, NULL) != MM_OK ||
        errno != E2BIG)
        return 1;
    result = capture_print("label:severity:text:action:tag", all_components);
    if (result != 0)
        return 10 + result;
    result = capture_print("label:text", label_and_text);
    if (result != 0)
        return 30 + result;
    /* Musl treats an unrecognized MSGVERB component as all components. */
    result = capture_print("not-a-component", all_components);
    if (result != 0)
        return 50 + result;
    result = capture_print("", all_components);
    if (result != 0)
        return 70 + result;
    return 0;
}

static int check_closed_stderr_error(void)
{
    int saved_stderr = dup(2);
    int result;
    int saved_errno;

    if (saved_stderr < 0)
        return 1;
    if (close(2) != 0)
        return 2;
    if (set_msgverb("text") != 0)
        return 3;
    errno = E2BIG;
    result = fmtmsg(MM_PRINT, NULL, MM_NOSEV, "closed", NULL, NULL);
    saved_errno = errno;
    if (dup2(saved_stderr, 2) != 2)
        return 4;
    if (close(saved_stderr) != 0)
        return 5;
    return result == MM_NOMSG && saved_errno == EBADF ? 0 : 6;
}

static int check_short_write_error(void)
{
    enum { pipe_atomic_bytes = 4096, message_bytes = pipe_atomic_bytes * 2 };
    int descriptors[2];
    int saved_stderr;
    int result;
    int saved_errno;
    char fill[pipe_atomic_bytes];
    char drained[pipe_atomic_bytes];
    static char text[message_bytes + 1];
    size_t index;
    ssize_t count;

    for (index = 0; index < sizeof fill; ++index)
        fill[index] = 'F';
    for (index = 0; index < message_bytes; ++index)
        text[index] = 'X';
    text[message_bytes] = '\0';
    if (set_msgverb("text") != 0)
        return 1;
    if (pipe2(descriptors, O_NONBLOCK) != 0)
        return 2;
    for (;;) {
        count = write(descriptors[1], fill, sizeof fill);
        if (count > 0)
            continue;
        if (count == -1 && errno == EAGAIN)
            break;
        return 3;
    }
    count = read(descriptors[0], drained, sizeof drained);
    if (count != (ssize_t)sizeof drained)
        return 4;
    saved_stderr = dup(2);
    if (saved_stderr < 0)
        return 5;
    if (dup2(descriptors[1], 2) != 2)
        return 6;
    if (close(descriptors[1]) != 0)
        return 7;
    errno = E2BIG;
    result = fmtmsg(MM_PRINT, NULL, MM_NOSEV, text, NULL, NULL);
    saved_errno = errno;
    if (dup2(saved_stderr, 2) != 2)
        return 8;
    if (close(saved_stderr) != 0)
        return 9;
    if (close(descriptors[0]) != 0)
        return 10;
    return result == MM_NOMSG && saved_errno == EAGAIN ? 0 : 11;
}

static int check_console_path(void)
{
    int direct_console = open("/dev/console", O_WRONLY);
    int direct_errno;
    int result;
    int saved_errno;

    if (direct_console >= 0) {
        if (close(direct_console) != 0)
            return 1;
        errno = E2BIG;
        result = fmtmsg(MM_CONSOLE, "LBL", MM_ERROR, "TEXT", "FIX", "TAG");
        saved_errno = errno;
        /* A usable device may still disappear or reject its write.  In that
         * case fmtmsg must report only the documented console bit and retain
         * the underlying failing syscall's errno. */
        if (result == MM_OK && saved_errno == E2BIG)
            return 0;
        return result == MM_NOCON && saved_errno != 0 ? 0 : 2;
    }

    direct_errno = errno;
    errno = E2BIG;
    result = fmtmsg(MM_CONSOLE, "LBL", MM_ERROR, "TEXT", "FIX", "TAG");
    saved_errno = errno;
    return result == MM_NOCON && saved_errno == direct_errno ? 0 : 3;
}

static void make_bits(const unsigned char bytes[8], char bits[64], unsigned char noise)
{
    int index;
    for (index = 0; index < 64; ++index)
        bits[index] = (char)(noise | ((bytes[index / 8] >> (7 - index % 8)) & 1));
}

static int check_des_boundary(void)
{
    static const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    static const unsigned char plain[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    char key_bits[64];
    char block_bits[64];
    char before[64];

    /* Use canonical zero/one bit cells for the musl reference branch. The
     * candidate's inert contract is stronger—it leaves even arbitrary bytes
     * untouched—but this aggregate does not make musl's DES bit-normalizing
     * details part of its intentional divergence. */
    make_bits(key, key_bits, 0);
    make_bits(plain, block_bits, 0);
    for (size_t index = 0; index < sizeof before; ++index)
        before[index] = block_bits[index];
    setkey(key_bits);
    encrypt(block_bits, 0);
#if defined(CRABC_LEGACY_MISC_CANDIDATE)
    /* Intentional project divergence: see legacy_des_exports.rs.  This is an
     * ABI-compatible inert boundary, not a DES implementation. */
    if (!bytes_equal(block_bits, before, sizeof before))
        return 1;
    encrypt(block_bits, 7);
    return bytes_equal(block_bits, before, sizeof before) ? 0 : 2;
#else
    /* The pinned-musl branch confirms that this fixture's bit-array input
     * reaches musl's real legacy DES path.  It deliberately does not make
     * that cipher an oracle for the candidate's documented inert contract. */
    if (bytes_equal(block_bits, before, sizeof before))
        return 1;
    encrypt(block_bits, 7);
    return bytes_equal(block_bits, before, sizeof before) ? 0 : 2;
#endif
}

static int check_retained_observations(void)
{
    const get_nprocs_signature configured = get_nprocs_conf;
    const get_nprocs_signature online = get_nprocs;
    const get_pages_signature physical = get_phys_pages;
    const get_pages_signature available = get_avphys_pages;
    const issetugid_signature secure = issetugid;
    int configured_count;
    int online_count;
    long physical_pages;
    long available_pages;

    if (!configured || !online || !physical || !available || !secure)
        return 1;
    configured_count = configured();
    online_count = online();
    physical_pages = physical();
    available_pages = available();
    if (configured_count <= 0 || online_count <= 0 || physical_pages <= 0 ||
        available_pages < 0)
        return 2;
    /* The ordinary execution path has no AT_SECURE or credential mismatch. */
    return secure() == 0 ? 0 : 3;
}

int crabc_x86_64_legacy_misc_probe(void)
{
    int result;

    result = check_retained_observations();
    if (result != 0)
        return 10 + result;
    result = check_print_paths();
    if (result != 0)
        return 30 + result;
    result = check_closed_stderr_error();
    if (result != 0)
        return 120 + result;
    result = check_short_write_error();
    if (result != 0)
        return 140 + result;
    result = check_console_path();
    if (result != 0)
        return 170 + result;
    result = check_des_boundary();
    return result == 0 ? 0 : 190 + result;
}

#ifndef CRABC_LEGACY_MISC_FREESTANDING
int main(void)
{
    return crabc_x86_64_legacy_misc_probe();
}
#endif
