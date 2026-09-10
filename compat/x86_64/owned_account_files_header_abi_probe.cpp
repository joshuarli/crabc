/* Source-and-installed-header C++17 ABI witness for account-file entries. */
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

using cuserid_signature = char *(*)(char *);
using usershell_void_signature = void (*)(void);
using getusershell_signature = char *(*)(void);
using spent_void_signature = void (*)(void);
using getspent_signature = spwd *(*)(void);
using fgetspent_signature = spwd *(*)(FILE *);
using getspnam_signature = spwd *(*)(const char *);
using getspnam_r_signature = int (*)(const char *, spwd *, char *, size_t, spwd **);
using putspent_signature = int (*)(const spwd *, FILE *);
using lock_signature = int (*)(void);

static_assert(sizeof(spwd) == 72, "spwd LP64 size");
static_assert(alignof(spwd) == alignof(void *), "spwd LP64 alignment");
static_assert(offsetof(spwd, sp_namp) == 0, "spwd name offset");
static_assert(offsetof(spwd, sp_pwdp) == 8, "spwd password offset");
static_assert(offsetof(spwd, sp_lstchg) == 16, "spwd date offset");
static_assert(offsetof(spwd, sp_flag) == 64, "spwd flag offset");
static_assert(L_cuserid == 20, "cuserid public limit");
static_assert(__is_same(decltype(&cuserid), cuserid_signature), "cuserid declaration");
static_assert(__is_same(decltype(&setusershell), usershell_void_signature), "setusershell declaration");
static_assert(__is_same(decltype(&endusershell), usershell_void_signature), "endusershell declaration");
static_assert(__is_same(decltype(&getusershell), getusershell_signature), "getusershell declaration");
static_assert(__is_same(decltype(&setspent), spent_void_signature), "setspent declaration");
static_assert(__is_same(decltype(&endspent), spent_void_signature), "endspent declaration");
static_assert(__is_same(decltype(&getspent), getspent_signature), "getspent declaration");
static_assert(__is_same(decltype(&fgetspent), fgetspent_signature), "fgetspent declaration");
static_assert(__is_same(decltype(&getspnam), getspnam_signature), "getspnam declaration");
static_assert(__is_same(decltype(&getspnam_r), getspnam_r_signature), "getspnam_r declaration");
static_assert(__is_same(decltype(&putspent), putspent_signature), "putspent declaration");
static_assert(__is_same(decltype(&lckpwdf), lock_signature), "lckpwdf declaration");
static_assert(__is_same(decltype(&ulckpwdf), lock_signature), "ulckpwdf declaration");

extern "C" cuserid_signature crabc_x86_64_account_files_cuserid_cxx() { return cuserid; }
extern "C" usershell_void_signature crabc_x86_64_account_files_setusershell_cxx() { return setusershell; }
extern "C" usershell_void_signature crabc_x86_64_account_files_endusershell_cxx() { return endusershell; }
extern "C" getusershell_signature crabc_x86_64_account_files_getusershell_cxx() { return getusershell; }
extern "C" spent_void_signature crabc_x86_64_account_files_setspent_cxx() { return setspent; }
extern "C" spent_void_signature crabc_x86_64_account_files_endspent_cxx() { return endspent; }
extern "C" getspent_signature crabc_x86_64_account_files_getspent_cxx() { return getspent; }
extern "C" fgetspent_signature crabc_x86_64_account_files_fgetspent_cxx() { return fgetspent; }
extern "C" getspnam_signature crabc_x86_64_account_files_getspnam_cxx() { return getspnam; }
extern "C" getspnam_r_signature crabc_x86_64_account_files_getspnam_r_cxx() { return getspnam_r; }
extern "C" putspent_signature crabc_x86_64_account_files_putspent_cxx() { return putspent; }
extern "C" lock_signature crabc_x86_64_account_files_lckpwdf_cxx() { return lckpwdf; }
extern "C" lock_signature crabc_x86_64_account_files_ulckpwdf_cxx() { return ulckpwdf; }
