/* Native Linux/x86-64 static POSIX spawn-attribute signal-field C ABI evidence.
 *
 * The same project-header body first executes through pinned musl 1.2.6 and
 * then a true static candidate. It observes only flags validation and direct
 * complete sigset field copying: never spawn execution, file actions, or
 * signal delivery.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif
#include <spawn.h>
#ifndef CRABC_POSIX_SPAWNATTR_SIGNAL_FIELDS_FREESTANDING
#include <errno.h>
#endif

typedef int (*posix_spawnattr_setflags_signature)(posix_spawnattr_t *, short);
typedef int (*posix_spawnattr_setsigset_signature)(posix_spawnattr_t *, const sigset_t *);
typedef int (*posix_spawnattr_getsigset_signature)(const posix_spawnattr_t *, sigset_t *);
enum { CRABC_EINVAL = 22, CRABC_ALL_SPAWN_FLAGS = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 };
#ifndef CRABC_POSIX_SPAWNATTR_SIGNAL_FIELDS_FREESTANDING
_Static_assert(CRABC_EINVAL == EINVAL, "Linux EINVAL status value");
#endif
_Static_assert(sizeof(posix_spawnattr_t) == 336 && _Alignof(posix_spawnattr_t) == 8, "attribute ABI");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8, "sigset ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_setflags), posix_spawnattr_setflags_signature), "setflags declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_setsigmask), posix_spawnattr_setsigset_signature), "setsigmask declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getsigmask), posix_spawnattr_getsigset_signature), "getsigmask declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_setsigdefault), posix_spawnattr_setsigset_signature), "setsigdefault declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawnattr_getsigdefault), posix_spawnattr_getsigset_signature), "getsigdefault declaration");

struct guarded_attributes { unsigned char before[17]; posix_spawnattr_t attributes; unsigned char after[19]; };
struct guarded_sigset { unsigned char before[13]; sigset_t value; unsigned char after[23]; };
static void fill_bytes(unsigned char *p, unsigned long n, unsigned char v) { unsigned long i; for (i = 0; i != n; ++i) p[i] = v; }
static void copy_bytes(unsigned char *d, const unsigned char *s, unsigned long n) { unsigned long i; for (i = 0; i != n; ++i) d[i] = s[i]; }
static int bytes_match(const unsigned char *a, const unsigned char *b, unsigned long n) { unsigned long i; for (i = 0; i != n; ++i) if (a[i] != b[i]) return 0; return 1; }
static int bytes_value(const unsigned char *p, unsigned long n, unsigned char v) { unsigned long i; for (i = 0; i != n; ++i) if (p[i] != v) return 0; return 1; }
static void reset_attributes(struct guarded_attributes *g, unsigned char v) { fill_bytes(g->before, sizeof(g->before), 0x3c); fill_bytes((unsigned char *)&g->attributes, sizeof(g->attributes), v); fill_bytes(g->after, sizeof(g->after), 0x96); }
static void reset_sigset(struct guarded_sigset *g, unsigned char v) { fill_bytes(g->before, sizeof(g->before), 0x5a); fill_bytes((unsigned char *)&g->value, sizeof(g->value), v); fill_bytes(g->after, sizeof(g->after), 0xa5); }
static int attribute_guards(const struct guarded_attributes *g) { return bytes_value(g->before, sizeof(g->before), 0x3c) && bytes_value(g->after, sizeof(g->after), 0x96); }
static int sigset_guards(const struct guarded_sigset *g) { return bytes_value(g->before, sizeof(g->before), 0x5a) && bytes_value(g->after, sizeof(g->after), 0xa5); }

static int check_flags(posix_spawnattr_setflags_signature setflags) {
    struct guarded_attributes attributes;
    unsigned char expected[sizeof(attributes.attributes)];
    reset_attributes(&attributes, 0xa5);
    if (posix_spawnattr_setflags(&attributes.attributes, 0) != 0 || attributes.attributes.__flags != 0 || !attribute_guards(&attributes)) return 1;
    if (setflags(&attributes.attributes, (short)CRABC_ALL_SPAWN_FLAGS) != 0 || attributes.attributes.__flags != CRABC_ALL_SPAWN_FLAGS || !attribute_guards(&attributes)) return 2;
    copy_bytes(expected, (const unsigned char *)&attributes.attributes, sizeof(expected));
    if (setflags(&attributes.attributes, (short)-1) != CRABC_EINVAL || !bytes_match((const unsigned char *)&attributes.attributes, expected, sizeof(expected)) || !attribute_guards(&attributes)) return 3;
    if (posix_spawnattr_setflags(&attributes.attributes, (short)256) != CRABC_EINVAL || !bytes_match((const unsigned char *)&attributes.attributes, expected, sizeof(expected)) || !attribute_guards(&attributes)) return 4;
    if (setflags((posix_spawnattr_t *)0, (short)256) != CRABC_EINVAL) return 5;
    return 0;
}

static int check_signal_fields(posix_spawnattr_setsigset_signature setmask, posix_spawnattr_getsigset_signature getmask, posix_spawnattr_setsigset_signature setdefault, posix_spawnattr_getsigset_signature getdefault) {
    struct guarded_attributes attributes;
    struct guarded_sigset source, output;
    unsigned char expected[sizeof(attributes.attributes)];
    reset_attributes(&attributes, 0x69);
    reset_sigset(&source, 0xa5);
    reset_sigset(&output, 0x5a);
    copy_bytes(expected, (const unsigned char *)&attributes.attributes, sizeof(expected));
    copy_bytes(expected + __builtin_offsetof(posix_spawnattr_t, __mask), (const unsigned char *)&source.value, sizeof(source.value));
    if (posix_spawnattr_setsigmask(&attributes.attributes, &source.value) != 0 || !bytes_match((const unsigned char *)&attributes.attributes, expected, sizeof(expected)) || !attribute_guards(&attributes) || !sigset_guards(&source)) return 1;
    if (getmask(&attributes.attributes, &output.value) != 0 || !bytes_match((const unsigned char *)&output.value, (const unsigned char *)&source.value, sizeof(output.value)) || !sigset_guards(&output) || !attribute_guards(&attributes)) return 2;
    reset_sigset(&source, 0x3c);
    reset_sigset(&output, 0x96);
    copy_bytes(expected + __builtin_offsetof(posix_spawnattr_t, __def), (const unsigned char *)&source.value, sizeof(source.value));
    if (setdefault(&attributes.attributes, &source.value) != 0 || !bytes_match((const unsigned char *)&attributes.attributes, expected, sizeof(expected)) || !attribute_guards(&attributes) || !sigset_guards(&source)) return 3;
    if (posix_spawnattr_getsigdefault(&attributes.attributes, &output.value) != 0 || !bytes_match((const unsigned char *)&output.value, (const unsigned char *)&source.value, sizeof(output.value)) || !sigset_guards(&output) || !attribute_guards(&attributes)) return 4;
    return 0;
}

int crabc_x86_64_posix_spawnattr_signal_fields_probe(void) {
    int result;
#ifndef CRABC_POSIX_SPAWNATTR_SIGNAL_FIELDS_FREESTANDING
    errno = E2BIG;
#endif
    result = check_flags(posix_spawnattr_setflags);
    if (result) return result;
    result = check_signal_fields(posix_spawnattr_setsigmask, posix_spawnattr_getsigmask, posix_spawnattr_setsigdefault, posix_spawnattr_getsigdefault);
    if (result) return result + 16;
#ifndef CRABC_POSIX_SPAWNATTR_SIGNAL_FIELDS_FREESTANDING
    if (errno != E2BIG) return 48;
#endif
    return 0;
}
#ifndef CRABC_POSIX_SPAWNATTR_SIGNAL_FIELDS_FREESTANDING
int main(void) { return crabc_x86_64_posix_spawnattr_signal_fields_probe(); }
#endif
