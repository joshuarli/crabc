/* Native Linux/x86-64 C++17 selected wide-character C-linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <wchar.h>
#include <wctype.h>

static_assert(sizeof(wchar_t) == 4 && alignof(wchar_t) == 4);
static_assert(sizeof(wint_t) == 4 && sizeof(wctype_t) == 8);
static_assert(sizeof(wctrans_t) == sizeof(void *));

#define REFERENCE(name) auto *crabc_wide_##name = &(name)
REFERENCE(wcslen);
REFERENCE(wcsnlen);
REFERENCE(wcscpy);
REFERENCE(wcsncpy);
REFERENCE(wcpcpy);
REFERENCE(wcpncpy);
REFERENCE(wcscat);
REFERENCE(wcsncat);
REFERENCE(wcscmp);
REFERENCE(wcsncmp);
REFERENCE(wcschr);
REFERENCE(wcsrchr);
REFERENCE(wcsstr);
REFERENCE(wcscspn);
REFERENCE(wcsspn);
REFERENCE(wcspbrk);
REFERENCE(wcsxfrm);
REFERENCE(wcscoll);
REFERENCE(wcstok);
REFERENCE(wcscasecmp);
REFERENCE(wcsncasecmp);
REFERENCE(wmemchr);
REFERENCE(wmemcmp);
REFERENCE(wmemcpy);
REFERENCE(wmemmove);
REFERENCE(wmemset);
REFERENCE(wcwidth);
REFERENCE(wcswidth);
REFERENCE(iswalnum);
REFERENCE(iswalpha);
REFERENCE(iswblank);
REFERENCE(iswcntrl);
REFERENCE(iswdigit);
REFERENCE(iswgraph);
REFERENCE(iswlower);
REFERENCE(iswprint);
REFERENCE(iswpunct);
REFERENCE(iswspace);
REFERENCE(iswupper);
REFERENCE(iswxdigit);
REFERENCE(iswctype);
REFERENCE(wctype);
REFERENCE(towlower);
REFERENCE(towupper);
REFERENCE(towctrans);
REFERENCE(wctrans);
