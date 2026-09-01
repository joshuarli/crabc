/* C++17 companion for the Linux/x86-64 legacy.misc declaration matrix. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fmtmsg.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

using fmtmsg_signature = int (*)(long, const char *, int, const char *,
    const char *, const char *);
using encrypt_signature = void (*)(char *, int);
using setkey_signature = void (*)(const char *);
using get_nprocs_signature = int (*)(void);
using get_pages_signature = long (*)(void);
using issetugid_signature = int (*)(void);

#if defined(CRABC_LEGACY_MISC_EXPECT_BASE)
static_assert(MM_HARD == 1 && MM_SOFT == 2 && MM_FIRM == 4,
    "fmtmsg source class bits");
static_assert(MM_APPL == 8 && MM_UTIL == 16 && MM_OPSYS == 32,
    "fmtmsg origin class bits");
static_assert(MM_RECOVER == 64 && MM_NRECOV == 128 && MM_PRINT == 256 &&
    MM_CONSOLE == 512 && MM_NULLMC == 0L, "fmtmsg destination constants");
static_assert(MM_HALT == 1 && MM_ERROR == 2 && MM_WARNING == 3 && MM_INFO == 4 &&
    MM_NOSEV == 0, "fmtmsg severity constants");
static_assert(MM_OK == 0 && MM_NOTOK == -1 && MM_NOMSG == 1 && MM_NOCON == 4,
    "fmtmsg result constants");
static_assert(__is_same(decltype(&fmtmsg), fmtmsg_signature),
    "fmtmsg declaration");
static_assert(__is_same(decltype(&get_nprocs_conf), get_nprocs_signature),
    "get_nprocs_conf declaration");
static_assert(__is_same(decltype(&get_nprocs), get_nprocs_signature),
    "get_nprocs declaration");
static_assert(__is_same(decltype(&get_phys_pages), get_pages_signature),
    "get_phys_pages declaration");
static_assert(__is_same(decltype(&get_avphys_pages), get_pages_signature),
    "get_avphys_pages declaration");

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
static_assert(__is_same(decltype(&encrypt), encrypt_signature),
    "encrypt declaration");
static_assert(__is_same(decltype(&setkey), setkey_signature),
    "setkey declaration");
static encrypt_signature encrypt_function __attribute__((used)) = encrypt;
static setkey_signature setkey_function __attribute__((used)) = setkey;
#endif

#if defined(CRABC_LEGACY_MISC_EXPECT_GNU_BSD)
static_assert(__is_same(decltype(&issetugid), issetugid_signature),
    "issetugid declaration");
static issetugid_signature issetugid_function __attribute__((used)) = issetugid;
#endif

#if defined(CRABC_LEGACY_MISC_REQUIRE_XOPEN_HIDDEN)
static encrypt_signature encrypt_must_be_hidden __attribute__((used)) = encrypt;
static setkey_signature setkey_must_be_hidden __attribute__((used)) = setkey;
#endif

#if defined(CRABC_LEGACY_MISC_REQUIRE_ISSETUGID_HIDDEN)
static issetugid_signature issetugid_must_be_hidden __attribute__((used)) =
    issetugid;
#endif

int crabc_x86_64_legacy_misc_header_abi_probe_cpp()
{
#if defined(CRABC_LEGACY_MISC_EXPECT_BASE)
    return fmtmsg_function != nullptr &&
        get_nprocs_conf_function != nullptr && get_nprocs_function != nullptr &&
        get_phys_pages_function != nullptr && get_avphys_pages_function != nullptr
#if defined(CRABC_LEGACY_MISC_EXPECT_XOPEN)
        && encrypt_function != nullptr && setkey_function != nullptr
#endif
#if defined(CRABC_LEGACY_MISC_EXPECT_GNU_BSD)
        && issetugid_function != nullptr
#endif
        ? 0 : 1;
#else
    return 0;
#endif
}
