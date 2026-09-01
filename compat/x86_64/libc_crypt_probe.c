/* Pinned-musl/public-and-private x86 crabc SHA-crypt ABI fixture. */

#include <crypt.h>
#include <string.h>
#include <unistd.h>

typedef char *(*crypt_signature)(const char *, const char *);
typedef char *(*crypt_r_signature)(const char *, const char *, struct crypt_data *);

/* These are musl's private C ABI entries, not installed header declarations. */
#ifdef CRABC_X86_CRYPT_CANDIDATE
typedef char *(*crypt_private_hash_signature)(const char *, const char *, char *);
typedef char *(*crypt_private_r_signature)(const char *, const char *, void *);

extern char *__crypt_blowfish(const char *, const char *, char *);
extern char *__crypt_md5(const char *, const char *, char *);
extern char *__crypt_r(const char *, const char *, void *);
extern char *__crypt_sha256(const char *, const char *, char *);
extern char *__crypt_sha512(const char *, const char *, char *);

static crypt_private_hash_signature private_blowfish = __crypt_blowfish;
static crypt_private_hash_signature private_md5 = __crypt_md5;
static crypt_private_r_signature private_r = __crypt_r;
static crypt_private_hash_signature private_sha256 = __crypt_sha256;
static crypt_private_hash_signature private_sha512 = __crypt_sha512;
#endif

static crypt_signature public_crypt = crypt;
static crypt_r_signature public_crypt_r = crypt_r;
static int failures;
static char *result;

struct crypt_output_storage {
    char bytes[sizeof(((struct crypt_data *)0)->__buf)];
    unsigned char guard;
};

struct crypt_r_storage {
    struct crypt_data data;
    unsigned char guard;
};

#ifdef CRABC_CRYPT_TRACE
static void trace_result(const char *value)
{
    if (value != 0) {
        write(2, value, strlen(value));
        write(2, "\n", 1);
    }
}
#else
static void trace_result(const char *value)
{
    (void)value;
}
#endif

#define CHECK_PUBLIC(expected, setting, key) do { \
    result = public_crypt((key), (setting)); \
    if (result == 0 || strcmp(result, (expected)) != 0) { trace_result(result); failures++; } \
} while (0)

#ifdef CRABC_X86_CRYPT_CANDIDATE
#define CHECK_REENTRANT(function, expected, setting, key) do { \
    struct crypt_r_storage storage = { { 0x13579bdf, { 0 } }, 0xa5 }; \
    int initialized = storage.data.initialized; \
    result = (function)((key), (setting), &storage.data); \
    if (result != storage.data.__buf || storage.data.initialized != initialized || \
        storage.guard != 0xa5 || strcmp(result, (expected)) != 0) { trace_result(result); failures++; } \
} while (0)
#define CHECK_PRIVATE_HASH(function, expected, setting, key) do { \
    struct crypt_output_storage storage = { { 0 }, 0xa5 }; \
    result = (function)((key), (setting), storage.bytes); \
    if (result != storage.bytes || storage.guard != 0xa5 || \
        strcmp(result, (expected)) != 0) { trace_result(result); failures++; } \
} while (0)
#else
#define CHECK_REENTRANT(function, expected, setting, key) do { \
    struct crypt_data data = { 0x13579bdf, { 0 } }; \
    result = (function)((key), (setting), &data); \
    if (result == 0 || strcmp(result, (expected)) != 0) { trace_result(result); failures++; } \
} while (0)
#endif

static void check_public_shared_result(void)
{
    char *first = public_crypt("foobar", "$5$rounds=100000$9aEeVXnCiCNHUjO/");
    char *second = public_crypt("foobar", "$6$rounds=100000$bbe605c2cce4c642");

    if (first == 0 || second == 0 || first != second ||
        strcmp(second, "$6$rounds=100000$bbe605c2cce4c642$bCGLqF35/fKkEVLwsr19YOM6.EcwMQ1svcz3iFHIfJZZ3etWnNZIMpAlO3EC3OHZJpNqNlC0sMLh3K/ctWdmF1") != 0) {
        trace_result(second);
        failures++;
    }
}

#ifdef CRABC_X86_CRYPT_CANDIDATE
static void check_bounded_inputs(void)
{
    char key[258];
    char overlong_setting[65];

    memset(key, 'k', sizeof(key));
    key[256] = 0;
    result = public_crypt(key, "$5$rounds=1000$9aEeVXnCiCNHUjO/");
    if (result == 0 || strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    key[256] = 'k';
    key[257] = 0;
    result = public_crypt(key, "$5$rounds=1000$9aEeVXnCiCNHUjO/");
    if (result == 0 || strcmp(result, "*") != 0) {
        trace_result(result);
        failures++;
    }

    overlong_setting[0] = '$';
    overlong_setting[1] = '5';
    overlong_setting[2] = '$';
    memset(overlong_setting + 3, 'a', sizeof(overlong_setting) - 4);
    overlong_setting[sizeof(overlong_setting) - 1] = 0;
    result = public_crypt("foobar", overlong_setting);
    if (result == 0 || strcmp(result, "*") != 0) {
        trace_result(result);
        failures++;
    }
}

static void check_null_arguments(void)
{
    struct crypt_output_storage storage = { { 'k', 0 }, 0xa5 };

    result = public_crypt(0, "$5$rounds=1000$9aEeVXnCiCNHUjO/");
    if (result == 0 || strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }
    result = public_crypt("foobar", 0);
    if (result == 0 || strcmp(result, "*") != 0) {
        trace_result(result);
        failures++;
    }
    result = private_sha256(0, "$5$rounds=1000$9aEeVXnCiCNHUjO/", storage.bytes);
    if (result != storage.bytes || storage.guard != 0xa5 || strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    storage.bytes[0] = 'k';
    storage.bytes[1] = 0;
    result = private_sha256("foobar", 0, storage.bytes);
    if (result != storage.bytes || storage.guard != 0xa5 ||
        storage.bytes[0] != 'k' || storage.bytes[1] != 0) {
        trace_result(result);
        failures++;
    }
}

static void check_overlapping_inputs(void)
{
    static const char setting[] = "$5$rounds=100000$9aEeVXnCiCNHUjO/";
    static const char expected[] = "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D";
    struct crypt_output_storage private_key = { { 0 }, 0xa5 };
    struct crypt_output_storage private_setting = { { 0 }, 0xa5 };
    struct crypt_r_storage reentrant = { { 0x13579bdf, { 0 } }, 0xa5 };
    char *shared;
    int initialized;

    memcpy(private_key.bytes, "foobar", sizeof("foobar"));
    result = private_sha256(private_key.bytes, setting, private_key.bytes);
    if (result != private_key.bytes || private_key.guard != 0xa5 ||
        strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    memcpy(private_setting.bytes, setting, sizeof(setting));
    result = private_sha256("foobar", private_setting.bytes, private_setting.bytes);
    if (result != private_setting.bytes || private_setting.guard != 0xa5 ||
        strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    shared = public_crypt("foobar", setting);
    result = public_crypt(shared, setting);
    if (shared == 0 || result != shared || strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    memcpy(reentrant.data.__buf, "foobar", sizeof("foobar"));
    initialized = reentrant.data.initialized;
    result = public_crypt_r(reentrant.data.__buf, setting, &reentrant.data);
    if (result != reentrant.data.__buf || reentrant.data.initialized != initialized ||
        reentrant.guard != 0xa5 || strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    memcpy(reentrant.data.__buf, "foobar", sizeof("foobar"));
    result = private_r(reentrant.data.__buf, setting, &reentrant.data);
    if (result != reentrant.data.__buf || reentrant.data.initialized != initialized ||
        reentrant.guard != 0xa5 || strcmp(result, "*") == 0) {
        trace_result(result);
        failures++;
    }

    /* The reentrant output buffer may also provide either accepted input. */
    memcpy(reentrant.data.__buf, setting, sizeof(setting));
    result = public_crypt_r("foobar", reentrant.data.__buf, &reentrant.data);
    if (result != reentrant.data.__buf || reentrant.data.initialized != initialized ||
        reentrant.guard != 0xa5 || strcmp(result, expected) != 0) {
        trace_result(result);
        failures++;
    }

    memcpy(reentrant.data.__buf, setting, sizeof(setting));
    result = private_r("foobar", reentrant.data.__buf, &reentrant.data);
    if (result != reentrant.data.__buf || reentrant.data.initialized != initialized ||
        reentrant.guard != 0xa5 || strcmp(result, expected) != 0) {
        trace_result(result);
        failures++;
    }
}
#endif

int main(void)
{
    /* Explicit rounds are shared musl/RustCrypto SHA-crypt observations. */
    CHECK_PUBLIC("$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D", "$5$rounds=100000$9aEeVXnCiCNHUjO/", "foobar");
    CHECK_PUBLIC("$6$rounds=100000$bbe605c2cce4c642$bCGLqF35/fKkEVLwsr19YOM6.EcwMQ1svcz3iFHIfJZZ3etWnNZIMpAlO3EC3OHZJpNqNlC0sMLh3K/ctWdmF1", "$6$rounds=100000$bbe605c2cce4c642", "foobar");
    CHECK_REENTRANT(public_crypt_r, "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D", "$5$rounds=100000$9aEeVXnCiCNHUjO/", "foobar");
    CHECK_REENTRANT(public_crypt_r, "$6$rounds=100000$bbe605c2cce4c642$bCGLqF35/fKkEVLwsr19YOM6.EcwMQ1svcz3iFHIfJZZ3etWnNZIMpAlO3EC3OHZJpNqNlC0sMLh3K/ctWdmF1", "$6$rounds=100000$bbe605c2cce4c642", "foobar");
    check_public_shared_result();

#ifdef CRABC_X86_CRYPT_CANDIDATE
    /* The dependency serializer spells default rounds explicitly. */
    CHECK_PUBLIC("$5$rounds=5000$9aEeVXnCiCNHUjO/$FrVBcjyJukRaE6inMYazyQv1DBnwaKfom.71ebgQR/0", "$5$9aEeVXnCiCNHUjO/", "foobar");
    CHECK_PUBLIC("$6$rounds=5000$bbe605c2cce4c642$BiBOywFAm9kdv6ZPpj2GaKVqeh/.c21pf1uFBaq.e59KEE2Ej74iJleXaLXURYV6uh5LF4K7dDc4vtRtPiiKB/", "$6$bbe605c2cce4c642", "foobar");
    check_bounded_inputs();
    check_null_arguments();
    check_overlapping_inputs();

    /* Every actual exported private entry executes through its C ABI. */
    CHECK_PRIVATE_HASH(private_sha256, "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D", "$5$rounds=100000$9aEeVXnCiCNHUjO/", "foobar");
    CHECK_PRIVATE_HASH(private_sha512, "$6$rounds=100000$bbe605c2cce4c642$bCGLqF35/fKkEVLwsr19YOM6.EcwMQ1svcz3iFHIfJZZ3etWnNZIMpAlO3EC3OHZJpNqNlC0sMLh3K/ctWdmF1", "$6$rounds=100000$bbe605c2cce4c642", "foobar");
    CHECK_REENTRANT(private_r, "$5$rounds=100000$9aEeVXnCiCNHUjO/$8sPrwM2muhX.m.Wk6nf/qjLv257uvFtFEdFt0Up616D", "$5$rounds=100000$9aEeVXnCiCNHUjO/", "foobar");

    /* Frozen profile boundaries: no local legacy password primitive. */
    CHECK_PUBLIC("*", "$1$salt$", "foobar");
    CHECK_PUBLIC("*", "$2a$04$abcdefghijklmnopqrstuv", "foobar");
    CHECK_PUBLIC("*", "$5$", "foobar");
    CHECK_PUBLIC("*", "$5$x", "foobar");
    CHECK_PUBLIC("*", "$5$9aEeVXnCiCNHUjO/$extra", "foobar");
    CHECK_PRIVATE_HASH(private_md5, "*", "$1$salt$", "foobar");
    CHECK_PRIVATE_HASH(private_blowfish, "*", "$2a$04$abcdefghijklmnopqrstuv", "foobar");
    CHECK_REENTRANT(private_r, "*", "$1$salt$", "foobar");
    CHECK_REENTRANT(public_crypt_r, "*", 0, "foobar");
    CHECK_REENTRANT(private_r, "*", 0, "foobar");
    if (public_crypt_r("x", "$5$salt$", 0) != 0 ||
        private_r("x", "$5$salt$", 0) != 0 ||
        private_md5(0, 0, 0) != 0 || private_blowfish(0, 0, 0) != 0)
        failures++;
#endif

    if (failures != 0)
        return failures;
    return write(1, "crypt ok\n", 9) == 9 ? 0 : 1;
}
