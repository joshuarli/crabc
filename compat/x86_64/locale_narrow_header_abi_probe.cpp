/* Native Linux/x86-64 C++17 fixed-locale narrow text C-linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <strings.h>

static_assert(sizeof(locale_t) == sizeof(void *));
static_assert(LC_CTYPE_MASK == 1 && LC_COLLATE_MASK == 8 &&
    LC_ALL_MASK == 0x7fffffff);

#define REFERENCE(name) auto *crabc_locale_narrow_##name = &(name)
REFERENCE(isalnum_l);
REFERENCE(isalpha_l);
REFERENCE(isblank_l);
REFERENCE(iscntrl_l);
REFERENCE(isdigit_l);
REFERENCE(isgraph_l);
REFERENCE(islower_l);
REFERENCE(isprint_l);
REFERENCE(ispunct_l);
REFERENCE(isspace_l);
REFERENCE(isupper_l);
REFERENCE(isxdigit_l);
REFERENCE(tolower_l);
REFERENCE(toupper_l);
REFERENCE(strcasecmp);
REFERENCE(strcasecmp_l);
REFERENCE(strncasecmp);
REFERENCE(strncasecmp_l);
REFERENCE(strcoll);
REFERENCE(strcoll_l);
REFERENCE(strxfrm);
REFERENCE(strxfrm_l);
