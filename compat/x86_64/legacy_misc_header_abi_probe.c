/* Pinned-musl/project Linux/x86-64 legacy.misc declaration matrix.
 *
 * This probe keeps the frozen aggregate's eight C spellings together without
 * treating that aggregate as a public runtime family.  `fmtmsg` and the four
 * sysinfo observations are ordinary declarations; `encrypt`/`setkey` retain
 * their X/Open-or-extension visibility and `issetugid` retains GNU/BSD-only
 * visibility.  The companion runner checks the same matrix against pinned
 * musl 1.2.6 and the project header tree.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

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

#if defined(CRABC_LEGACY_MISC_EXPECT_BASE)
_Static_assert(MM_HARD == 1 && MM_SOFT == 2 && MM_FIRM == 4,
    "fmtmsg source class bits");
_Static_assert(MM_APPL == 8 && MM_UTIL == 16 && MM_OPSYS == 32,
    "fmtmsg origin class bits");
_Static_assert(MM_RECOVER == 64 && MM_NRECOV == 128 && MM_PRINT == 256 &&
    MM_CONSOLE == 512 && MM_NULLMC == 0L, "fmtmsg destination constants");
_Static_assert(MM_HALT == 1 && MM_ERROR == 2 && MM_WARNING == 3 && MM_INFO == 4 &&
    MM_NOSEV == 0, "fmtmsg severity constants");
_Static_assert(MM_OK == 0 && MM_NOTOK == -1 && MM_NOMSG == 1 && MM_NOCON == 4,
    "fmtmsg result constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fmtmsg), fmtmsg_signature),
    "fmtmsg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_nprocs_conf),
    get_nprocs_signature), "get_nprocs_conf declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_nprocs),
    get_nprocs_signature), "get_nprocs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_phys_pages),
    get_pages_signature), "get_phys_pages declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&get_avphys_pages),
    get_pages_signature), "get_avphys_pages declaration");

static fmtmsg_signature fmtmsg_function __attribute__((used)) = fmtmsg;
static get_nprocs_signature get_nprocs_conf_function __attribute__((used)) =
    get_nprocs_conf;
static get_nprocs_signature get_nprocs_function __attribute__((used)) = get_nprocs;
static get_pages_signature get_phys_pages_function __attribute__((used)) =
    get_phys_pages;
static get_pages_signature get_avphys_pages_function __attribute__((used)) =
    get_avphys_pages;
#endif

#if defined(CRABC_LEGACY_MISC_EXPECT_XOPEN)
_Static_assert(__builtin_types_compatible_p(__typeof__(&encrypt), encrypt_signature),
    "encrypt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setkey), setkey_signature),
    "setkey declaration");
static encrypt_signature encrypt_function __attribute__((used)) = encrypt;
static setkey_signature setkey_function __attribute__((used)) = setkey;
#endif

#if defined(CRABC_LEGACY_MISC_EXPECT_GNU_BSD)
_Static_assert(__builtin_types_compatible_p(__typeof__(&issetugid),
    issetugid_signature), "issetugid declaration");
static issetugid_signature issetugid_function __attribute__((used)) = issetugid;
#endif

/* These deliberate unresolved spellings make the profile-hidden tests fail. */
#if defined(CRABC_LEGACY_MISC_REQUIRE_XOPEN_HIDDEN)
static encrypt_signature encrypt_must_be_hidden __attribute__((used)) = encrypt;
static setkey_signature setkey_must_be_hidden __attribute__((used)) = setkey;
#endif

#if defined(CRABC_LEGACY_MISC_REQUIRE_ISSETUGID_HIDDEN)
static issetugid_signature issetugid_must_be_hidden __attribute__((used)) =
    issetugid;
#endif

int crabc_x86_64_legacy_misc_header_abi_probe(void)
{
#if defined(CRABC_LEGACY_MISC_EXPECT_BASE)
    return fmtmsg_function != (fmtmsg_signature)0 &&
        get_nprocs_conf_function != (get_nprocs_signature)0 &&
        get_nprocs_function != (get_nprocs_signature)0 &&
        get_phys_pages_function != (get_pages_signature)0 &&
        get_avphys_pages_function != (get_pages_signature)0
#if defined(CRABC_LEGACY_MISC_EXPECT_XOPEN)
        && encrypt_function != (encrypt_signature)0 &&
        setkey_function != (setkey_signature)0
#endif
#if defined(CRABC_LEGACY_MISC_EXPECT_GNU_BSD)
        && issetugid_function != (issetugid_signature)0
#endif
        ? 0 : 1;
#else
    return 0;
#endif
}
