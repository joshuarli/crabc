/* Source-and-installed-header C ABI witness for account-file entries. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <shadow.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

typedef char *(*cuserid_signature)(char *);
typedef void (*usershell_void_signature)(void);
typedef char *(*getusershell_signature)(void);
typedef void (*spent_void_signature)(void);
typedef struct spwd *(*getspent_signature)(void);
typedef struct spwd *(*fgetspent_signature)(FILE *);
typedef struct spwd *(*getspnam_signature)(const char *);
typedef int (*getspnam_r_signature)(const char *, struct spwd *, char *, size_t,
    struct spwd **);
typedef int (*putspent_signature)(const struct spwd *, FILE *);
typedef int (*lock_signature)(void);

_Static_assert(sizeof(struct spwd) == 72, "spwd LP64 size");
_Static_assert(_Alignof(struct spwd) == _Alignof(void *), "spwd LP64 alignment");
_Static_assert(offsetof(struct spwd, sp_namp) == 0, "spwd name offset");
_Static_assert(offsetof(struct spwd, sp_pwdp) == 8, "spwd password offset");
_Static_assert(offsetof(struct spwd, sp_lstchg) == 16, "spwd date offset");
_Static_assert(offsetof(struct spwd, sp_flag) == 64, "spwd flag offset");
_Static_assert(L_cuserid == 20, "cuserid public limit");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cuserid), cuserid_signature),
    "cuserid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setusershell), usershell_void_signature),
    "setusershell declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&endusershell), usershell_void_signature),
    "endusershell declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getusershell), getusershell_signature),
    "getusershell declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setspent), spent_void_signature),
    "setspent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&endspent), spent_void_signature),
    "endspent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getspent), getspent_signature),
    "getspent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fgetspent), fgetspent_signature),
    "fgetspent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getspnam), getspnam_signature),
    "getspnam declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getspnam_r), getspnam_r_signature),
    "getspnam_r declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&putspent), putspent_signature),
    "putspent declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lckpwdf), lock_signature),
    "lckpwdf declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ulckpwdf), lock_signature),
    "ulckpwdf declaration");

cuserid_signature crabc_x86_64_account_files_cuserid_c(void) { return cuserid; }
usershell_void_signature crabc_x86_64_account_files_setusershell_c(void) { return setusershell; }
usershell_void_signature crabc_x86_64_account_files_endusershell_c(void) { return endusershell; }
getusershell_signature crabc_x86_64_account_files_getusershell_c(void) { return getusershell; }
spent_void_signature crabc_x86_64_account_files_setspent_c(void) { return setspent; }
spent_void_signature crabc_x86_64_account_files_endspent_c(void) { return endspent; }
getspent_signature crabc_x86_64_account_files_getspent_c(void) { return getspent; }
fgetspent_signature crabc_x86_64_account_files_fgetspent_c(void) { return fgetspent; }
getspnam_signature crabc_x86_64_account_files_getspnam_c(void) { return getspnam; }
getspnam_r_signature crabc_x86_64_account_files_getspnam_r_c(void) { return getspnam_r; }
putspent_signature crabc_x86_64_account_files_putspent_c(void) { return putspent; }
lock_signature crabc_x86_64_account_files_lckpwdf_c(void) { return lckpwdf; }
lock_signature crabc_x86_64_account_files_ulckpwdf_c(void) { return ulckpwdf; }
