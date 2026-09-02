/* Private x86 crypt/allocator provider-composition ABI fixture. */

#include <crypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef char *(*crypt_signature)(const char *, const char *);
typedef char *(*crypt_r_signature)(const char *, const char *, struct crypt_data *);

static crypt_signature public_crypt = crypt;
static crypt_r_signature public_crypt_r = crypt_r;
static int failures;

#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
typedef char *(*crypt_private_hash_signature)(const char *, const char *, char *);

extern char *__crypt_sha256(const char *, const char *, char *);

static crypt_private_hash_signature private_sha256 = __crypt_sha256;
#endif

struct guarded_crypt_data {
    struct crypt_data data;
    unsigned char guard;
};

static void check_heap_backed_crypt(void)
{
    static const char expected[] =
        "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D";
    static const char key_source[] = "foobar";
    static const char setting_source[] = "$5$rounds=100000$9aEeVXnCiCNHUjO/";
    char *key = malloc(sizeof(key_source));
    char *setting = malloc(sizeof(setting_source));
    struct guarded_crypt_data *storage = malloc(sizeof(*storage));
    char *result;

    if (key == 0 || setting == 0 || storage == 0) {
        failures++;
        goto cleanup;
    }
    memcpy(key, key_source, sizeof(key_source));
    memcpy(setting, setting_source, sizeof(setting_source));
    memset(&storage->data, 0, sizeof(storage->data));
    storage->data.initialized = 0x13579bdf;
    storage->guard = 0xa5;

    result = public_crypt(key, setting);
    if (result == 0 || strcmp(result, expected) != 0)
        failures++;

    result = public_crypt_r(key, setting, &storage->data);
#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
    if (result != storage->data.__buf ||
        storage->data.initialized != 0x13579bdf || storage->guard != 0xa5 ||
        strcmp(result, expected) != 0)
        failures++;
#else
    if (result == 0 || strcmp(result, expected) != 0)
        failures++;
#endif

#ifdef CRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE
    {
        /* 320 is a nonzero multiple of 64 and leaves a guard after __buf. */
        unsigned char *private_output = aligned_alloc(64, 320);

        if (private_output == 0 || ((uintptr_t)private_output & 63) != 0) {
            failures++;
        } else {
            private_output[256] = 0xa5;
            result = private_sha256(key, setting, (char *)private_output);
            if (result != (char *)private_output || private_output[256] != 0xa5 ||
                strcmp(result, expected) != 0)
                failures++;
        }
        free(private_output);
    }
#endif

cleanup:
    free(storage);
    free(setting);
    free(key);
}

int main(void)
{
    check_heap_backed_crypt();
    if (failures != 0)
        return failures;
    return write(1, "crypt allocator composition ok\n",
                 sizeof("crypt allocator composition ok\n") - 1) ==
                   (ssize_t)(sizeof("crypt allocator composition ok\n") - 1)
               ? 0
               : 1;
}
