/* Source-only Linux/x86-64 <unistd.h> credential-observation declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*getgroups_signature)(int, gid_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getgroups),
    getgroups_signature), "getgroups declaration");

static getgroups_signature getgroups_function = getgroups;

#if defined(CRABC_EXPECT_GNU_CREDENTIAL_OBSERVATION)
typedef int (*getresuid_signature)(uid_t *, uid_t *, uid_t *);
typedef int (*getresgid_signature)(gid_t *, gid_t *, gid_t *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getresuid),
    getresuid_signature), "getresuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getresgid),
    getresgid_signature), "getresgid declaration");

static getresuid_signature getresuid_function = getresuid;
static getresgid_signature getresgid_function = getresgid;
#endif

/* An opt-in reference that must fail without GNU feature selection. */
#if defined(CRABC_REQUIRE_GETRES_HIDDEN)
typedef int (*hidden_getresuid_signature)(uid_t *, uid_t *, uid_t *);
typedef int (*hidden_getresgid_signature)(gid_t *, gid_t *, gid_t *);
static hidden_getresuid_signature getresuid_must_be_hidden = getresuid;
static hidden_getresgid_signature getresgid_must_be_hidden = getresgid;
#endif

int crabc_x86_64_credential_observation_header_abi_probe(void)
{
    gid_t groups[1];

#if defined(CRABC_EXPECT_GNU_CREDENTIAL_OBSERVATION)
    uid_t user_ids[3];
    gid_t group_ids[3];

    return getgroups_function(0, groups) >= 0 &&
        getresuid_function(&user_ids[0], &user_ids[1], &user_ids[2]) == 0 &&
        getresgid_function(&group_ids[0], &group_ids[1], &group_ids[2]) == 0
        ? 0 : 1;
#else
    return getgroups_function(0, groups) >= 0 ? 0 : 1;
#endif
}
