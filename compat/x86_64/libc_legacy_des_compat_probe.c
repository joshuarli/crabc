/* Static Linux/x86-64 direct inert-DES compatibility fixture.
 *
 * `setkey` and `encrypt` are deliberate link-only compatibility names. This
 * candidate-only probe proves that the selected narrow owner accepts null and
 * unreadable pointers without touching them, leaves live storage unchanged,
 * and preserves a caller-selected errno. It intentionally does not compare
 * cipher behavior with musl: implementing that cipher is outside scope.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef CRABC_LEGACY_DES_COMPAT_FREESTANDING
#error "this probe must link only the freestanding inert-DES candidate"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static int bytes_equal(const char *left, const char *right, unsigned long length)
{
    unsigned long index;
    for (index = 0; index < length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

int crabc_x86_legacy_des_compat_probe(void)
{
    char key[64];
    char block[64];
    char before[64];
    unsigned long index;

    for (index = 0; index < sizeof key; ++index) {
        key[index] = (char)(index * 3u + 1u);
        block[index] = (char)(index * 5u + 2u);
        before[index] = block[index];
    }

    errno = ERANGE;
    setkey(NULL);
    if (errno != ERANGE)
        return 1;
    errno = EILSEQ;
    encrypt(NULL, -1);
    if (errno != EILSEQ)
        return 2;

    errno = ERANGE;
    setkey((const char *)(uintptr_t)1);
    if (errno != ERANGE)
        return 3;
    errno = EILSEQ;
    encrypt((char *)(uintptr_t)1, 1);
    if (errno != EILSEQ)
        return 4;

    errno = ERANGE;
    setkey(key);
    if (errno != ERANGE)
        return 5;
    errno = EILSEQ;
    encrypt(block, 0);
    if (errno != EILSEQ || !bytes_equal(block, before, sizeof block))
        return 6;
    errno = ERANGE;
    encrypt(block, 9);
    if (errno != ERANGE || !bytes_equal(block, before, sizeof block))
        return 7;
    return 0;
}
