// Direct C++ type and linkage surface for the eight reviewed project C-ABI
// extensions.  <stdatomic.h> is intentionally empty in C++17; the public C
// atomic macros below must therefore stay absent.  The static object addresses
// every other callable, while the dynamic object addresses only owned exports;
// both prove unmangled C linkage without invoking capability or module calls.
#include <daemon.h>
#include <dn_expand.h>
#include <linux/capability.h>
#include <lrand48.h>
#include <pthread_atfork.h>
#include <stdatomic.h>
#include <strverscmp.h>
#include <sys/module.h>

#if defined(ATOMIC_FLAG_INIT) || defined(ATOMIC_INT_LOCK_FREE) || \
    defined(atomic_flag_clear) || defined(atomic_thread_fence)
#error "C++17 stdatomic.h must not expose the C11 atomic vocabulary"
#endif

using daemon_type = int (*)(int, int);
using dn_expand_type = int (*)(const unsigned char *, const unsigned char *,
    const unsigned char *, char *, int);
using dn_skipname_type = int (*)(const unsigned char *, const unsigned char *);
using capability_type = int (*)(cap_user_header_t, cap_user_data_t);
using lrand48_type = long (*)(void);
using rand48_words_type = long (*)(unsigned short *);
using drand48_type = double (*)(void);
using erand48_type = double (*)(unsigned short *);
using lcong48_type = void (*)(unsigned short *);
using seed48_type = unsigned short *(*)(unsigned short *);
using srand48_type = void (*)(long);
using pthread_atfork_type = int (*)(void (*)(void), void (*)(void), void (*)(void));
using strverscmp_type = int (*)(const char *, const char *);
using init_module_type = int (*)(void *, unsigned long, const char *);
using delete_module_type = int (*)(const char *, unsigned int);

static_assert(__is_same(decltype(&daemon), daemon_type));
static_assert(__is_same(decltype(&dn_expand), dn_expand_type));
static_assert(__is_same(decltype(&dn_skipname), dn_skipname_type));
static_assert(__is_same(decltype(&capget), capability_type));
static_assert(__is_same(decltype(&capset), capability_type));
static_assert(__is_same(decltype(&lrand48), lrand48_type));
static_assert(__is_same(decltype(&mrand48), lrand48_type));
static_assert(__is_same(decltype(&nrand48), rand48_words_type));
static_assert(__is_same(decltype(&jrand48), rand48_words_type));
static_assert(__is_same(decltype(&drand48), drand48_type));
static_assert(__is_same(decltype(&erand48), erand48_type));
static_assert(__is_same(decltype(&lcong48), lcong48_type));
static_assert(__is_same(decltype(&seed48), seed48_type));
static_assert(__is_same(decltype(&srand48), srand48_type));
static_assert(__is_same(decltype(&pthread_atfork), pthread_atfork_type));
static_assert(__is_same(decltype(&strverscmp), strverscmp_type));
static_assert(__is_same(decltype(&init_module), init_module_type));
static_assert(__is_same(decltype(&delete_module), delete_module_type));

static_assert(sizeof(__u32) == 4);
static_assert(sizeof(__user_cap_header_struct) == 8);
static_assert(sizeof(__user_cap_data_struct) == 12);
static_assert(__builtin_offsetof(__user_cap_header_struct, version) == 0);
static_assert(__builtin_offsetof(__user_cap_header_struct, pid) == 4);
static_assert(__builtin_offsetof(__user_cap_data_struct, effective) == 0);
static_assert(__builtin_offsetof(__user_cap_data_struct, permitted) == 4);
static_assert(__builtin_offsetof(__user_cap_data_struct, inheritable) == 8);

#define CRABC_REFERENCE(type, name) static type const volatile name##_reference = &name
CRABC_REFERENCE(daemon_type, daemon);
CRABC_REFERENCE(capability_type, capget);
CRABC_REFERENCE(capability_type, capset);
CRABC_REFERENCE(init_module_type, init_module);
CRABC_REFERENCE(delete_module_type, delete_module);
#ifndef CRABC_PROJECT_HEADER_DYNAMIC
CRABC_REFERENCE(dn_expand_type, dn_expand);
CRABC_REFERENCE(dn_skipname_type, dn_skipname);
CRABC_REFERENCE(lrand48_type, lrand48);
CRABC_REFERENCE(lrand48_type, mrand48);
CRABC_REFERENCE(rand48_words_type, nrand48);
CRABC_REFERENCE(rand48_words_type, jrand48);
CRABC_REFERENCE(drand48_type, drand48);
CRABC_REFERENCE(erand48_type, erand48);
CRABC_REFERENCE(lcong48_type, lcong48);
CRABC_REFERENCE(seed48_type, seed48);
CRABC_REFERENCE(srand48_type, srand48);
CRABC_REFERENCE(pthread_atfork_type, pthread_atfork);
CRABC_REFERENCE(strverscmp_type, strverscmp);
#endif
#undef CRABC_REFERENCE

extern "C" int main(void) {
    return daemon_reference == 0 || capget_reference == 0 || capset_reference == 0 ||
        init_module_reference == 0 || delete_module_reference == 0
#ifndef CRABC_PROJECT_HEADER_DYNAMIC
        || dn_expand_reference == 0 || dn_skipname_reference == 0 || lrand48_reference == 0 ||
        mrand48_reference == 0 || nrand48_reference == 0 || jrand48_reference == 0 ||
        drand48_reference == 0 || erand48_reference == 0 || lcong48_reference == 0 ||
        seed48_reference == 0 || srand48_reference == 0 || pthread_atfork_reference == 0 ||
        strverscmp_reference == 0
#endif
        ;
}
