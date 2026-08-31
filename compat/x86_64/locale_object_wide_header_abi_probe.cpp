/* Native Linux/x86-64 C++17 locale-object/localized-wide C-linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <langinfo.h>
#include <locale.h>
#include <wchar.h>
#include <wctype.h>

static_assert(sizeof(locale_t) == sizeof(void *));
static_assert(sizeof(nl_item) == sizeof(int));
static_assert(LC_CTYPE_MASK == 1 && LC_ALL_MASK == 0x7fffffff);
static_assert(CODESET == 14 && ERA_T_FMT == 0x20031);

#define REFERENCE(name) auto *crabc_locale_object_wide_##name = &(name)
REFERENCE(newlocale);
REFERENCE(freelocale);
REFERENCE(uselocale);
REFERENCE(duplocale);
REFERENCE(nl_langinfo);
REFERENCE(nl_langinfo_l);
REFERENCE(iswalnum_l);
REFERENCE(iswalpha_l);
REFERENCE(iswblank_l);
REFERENCE(iswcntrl_l);
REFERENCE(iswdigit_l);
REFERENCE(iswgraph_l);
REFERENCE(iswlower_l);
REFERENCE(iswprint_l);
REFERENCE(iswpunct_l);
REFERENCE(iswspace_l);
REFERENCE(iswupper_l);
REFERENCE(iswxdigit_l);
REFERENCE(iswctype_l);
REFERENCE(wctype_l);
REFERENCE(towlower_l);
REFERENCE(towupper_l);
REFERENCE(towctrans_l);
REFERENCE(wctrans_l);
REFERENCE(wcscasecmp_l);
REFERENCE(wcsncasecmp_l);
REFERENCE(wcscoll_l);
REFERENCE(wcsxfrm_l);
