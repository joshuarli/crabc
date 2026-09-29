/* Observe the bounded SHA-crypt C ABI with pinned musl and installed crabc. */
#include <crypt.h>
#include <stdio.h>
#include <string.h>

struct observation {
    const char *name;
    const char *setting;
};

static const struct observation cases[] = {
    {"sha256-default", "$5$9aEeVXnCiCNHUjO/"},
    {"sha256-min-clamp", "$5$rounds=0001$9aEeVXnCiCNHUjO/"},
    {"sha256-min", "$5$rounds=1000$9aEeVXnCiCNHUjO/"},
    {"sha256-leading-zero", "$5$rounds=00001000$9aEeVXnCiCNHUjO/"},
    {"sha512-default", "$6$bbe605c2cce4c642"},
    {"sha512-min-clamp", "$6$rounds=0$bbe605c2cce4c642"},
    {"sha512-min", "$6$rounds=1000$bbe605c2cce4c642"},
    {"empty-salt", "$5$"},
    {"noncanonical-salt", "$5$x"},
    {"extra-field", "$5$9aEeVXnCiCNHUjO/$extra"},
    {"overlong-salt", "$6$abcdefghijklmnopq"},
    {"missing-rounds", "$5$rounds=$9aEeVXnCiCNHUjO/"},
    {"signed-rounds", "$5$rounds=+1000$9aEeVXnCiCNHUjO/"},
#ifdef CRABC_X86_CRYPT_CANDIDATE
    /* Pinned musl clamps these to a billion rounds, so only exercise rejection. */
    {"overflow-rounds", "$5$rounds=4294967296$9aEeVXnCiCNHUjO/"},
    {"above-max-rounds", "$6$rounds=1000000000$bbe605c2cce4c642"},
#endif
    {"legacy-md5", "$1$salt$"},
    {"legacy-bcrypt", "$2a$04$abcdefghijklmnopqrstuv"},
};

static int print_result(const char *name, const char *kind, const char *value)
{
    if (printf("%s %s ", name, kind) < 0)
        return 1;
    if (value == 0) {
        if (puts("null") < 0) return 1;
        return 0;
    }
    for (size_t i = 0; i < 256 && value[i]; i++)
        if (printf("%02x", (unsigned char)value[i]) < 0) return 1;
    if (strlen(value) >= 256 || putchar('\n') == EOF) return 1;
    return 0;
}

int main(void)
{
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct crypt_data data = { 0 };
        const char *shared = crypt("foobar", cases[i].setting);
        if (print_result(cases[i].name, "crypt", shared)) return 1;
        const char *reentrant = crypt_r("foobar", cases[i].setting, &data);
        if (print_result(cases[i].name, "crypt_r", reentrant)) return 1;
    }
    return 0;
}
