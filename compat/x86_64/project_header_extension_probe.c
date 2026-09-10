/* Direct C type surface for the eight reviewed project C-ABI extensions.
 *
 * The paths are intentionally included by their standalone spellings.  Their
 * feature-gated canonical paths remain governed by their own header matrices.
 */
#include <daemon.h>
#include <dn_expand.h>
#include <linux/capability.h>
#include <lrand48.h>
#include <pthread_atfork.h>
#include <stdatomic.h>
#include <strverscmp.h>
#include <sys/module.h>

typedef int (*daemon_type)(int, int);
typedef int (*dn_expand_type)(const unsigned char *, const unsigned char *,
    const unsigned char *, char *, int);
typedef int (*dn_skipname_type)(const unsigned char *, const unsigned char *);
typedef int (*capability_type)(cap_user_header_t, cap_user_data_t);
typedef long (*lrand48_type)(void);
typedef long (*rand48_words_type)(unsigned short [3]);
typedef double (*drand48_type)(void);
typedef double (*erand48_type)(unsigned short [3]);
typedef void (*lcong48_type)(unsigned short [7]);
typedef unsigned short *(*seed48_type)(unsigned short [3]);
typedef void (*srand48_type)(long);
typedef int (*pthread_atfork_type)(void (*)(void), void (*)(void), void (*)(void));
typedef int (*strverscmp_type)(const char *, const char *);
typedef int (*init_module_type)(void *, unsigned long, const char *);
typedef int (*delete_module_type)(const char *, unsigned int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&daemon), daemon_type), "daemon");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dn_expand), dn_expand_type), "dn_expand");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dn_skipname), dn_skipname_type), "dn_skipname");
_Static_assert(__builtin_types_compatible_p(__typeof__(&capget), capability_type), "capget");
_Static_assert(__builtin_types_compatible_p(__typeof__(&capset), capability_type), "capset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lrand48), lrand48_type), "lrand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mrand48), lrand48_type), "mrand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nrand48), rand48_words_type), "nrand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&jrand48), rand48_words_type), "jrand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&drand48), drand48_type), "drand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&erand48), erand48_type), "erand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lcong48), lcong48_type), "lcong48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&seed48), seed48_type), "seed48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&srand48), srand48_type), "srand48");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_atfork), pthread_atfork_type), "pthread_atfork");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strverscmp), strverscmp_type), "strverscmp");
_Static_assert(__builtin_types_compatible_p(__typeof__(&init_module), init_module_type), "init_module");
_Static_assert(__builtin_types_compatible_p(__typeof__(&delete_module), delete_module_type), "delete_module");

_Static_assert(sizeof(__u32) == 4, "Linux capability word width");
_Static_assert(sizeof(struct __user_cap_header_struct) == 8, "Linux capability header width");
_Static_assert(sizeof(struct __user_cap_data_struct) == 12, "Linux capability data width");
_Static_assert(__builtin_offsetof(struct __user_cap_header_struct, version) == 0, "capability version offset");
_Static_assert(__builtin_offsetof(struct __user_cap_header_struct, pid) == 4, "capability pid offset");
_Static_assert(__builtin_offsetof(struct __user_cap_data_struct, effective) == 0, "capability effective offset");
_Static_assert(__builtin_offsetof(struct __user_cap_data_struct, permitted) == 4, "capability permitted offset");
_Static_assert(__builtin_offsetof(struct __user_cap_data_struct, inheritable) == 8, "capability inheritable offset");
_Static_assert(sizeof(atomic_flag) == 1, "C11 atomic flag representation");

int crabc_project_header_extension_c_types(void) {
    return 0;
}
