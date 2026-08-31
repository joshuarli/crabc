/* Allocation-free wide-character fixture shared by musl and crabc-libc. */

#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(wchar_t) == 4 && (wchar_t)-1 < 0,
    "x86 signed 32-bit wchar_t");
_Static_assert(sizeof(wint_t) == 4 && sizeof(wctype_t) == 8,
    "x86 wide classification descriptors");

static int sign_of(int value)
{
    return (value > 0) - (value < 0);
}

static int wide_equal(const wchar_t *left, const wchar_t *right)
{
    while (*left == *right) {
        if (*left == 0)
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static int check_memory_and_strings(void)
{
    static const wchar_t alphabet[] = { 'a', 'b', 'c', 'd', 0 };
    static const wchar_t suffix[] = { 'c', 'd', 0 };
    static const wchar_t absent[] = { 'x', 'y', 0 };
    static const wchar_t periodic[] = {
        'a', 'b', 'a', 'b', 'a', 'b', 'a', 'c', 0
    };
    static const wchar_t needle[] = { 'a', 'b', 'a', 'c', 0 };
    wchar_t memory[12];
    wchar_t copy[16];
    wchar_t pad[8];
    wchar_t cat[16] = { 'a', 'b', 0 };
    wchar_t tokens[] = { ',', ',', 'a', ',', 'b', 'c', ',', 0 };
    const wchar_t separators[] = { ',', 0 };
    wchar_t *state = (wchar_t *)(uintptr_t)1;
    wchar_t *token;

    if (wmemset(memory, 0x1234, 12) != memory ||
        memory[0] != 0x1234 || memory[11] != 0x1234)
        return 1;
    if (wmemcpy(memory, alphabet, 5) != memory ||
        wmemcmp(memory, alphabet, 5) != 0 ||
        wmemchr(memory, 'c', 5) != memory + 2 ||
        wmemchr(memory, 'x', 5) != NULL)
        return 2;
    if (wmemmove(memory + 1, memory, 4) != memory + 1 ||
        memory[0] != 'a' || memory[1] != 'a' || memory[4] != 'd')
        return 3;
    if (wmemmove(memory, memory + 1, 4) != memory ||
        wmemcmp(memory, alphabet, 4) != 0)
        return 4;

    if (wcslen(alphabet) != 4 || wcsnlen(alphabet, 2) != 2 ||
        wcsnlen(alphabet, 8) != 4)
        return 5;
    if (wcscpy(copy, alphabet) != copy || !wide_equal(copy, alphabet) ||
        wcpcpy(copy, suffix) != copy + 2 || !wide_equal(copy, suffix))
        return 6;
    wmemset(pad, 0x7777, 8);
    if (wcsncpy(pad, suffix, 5) != pad || pad[2] != 0 || pad[4] != 0 ||
        pad[5] != 0x7777)
        return 7;
    wmemset(pad, 0x7777, 8);
    if (wcpncpy(pad, alphabet, 3) != pad + 3 ||
        pad[0] != 'a' || pad[2] != 'c' || pad[3] != 0x7777)
        return 8;
    if (wcscat(cat, suffix) != cat || !wide_equal(cat,
        (const wchar_t[]){ 'a', 'b', 'c', 'd', 0 }))
        return 9;
    if (wcsncat(cat, alphabet, 2) != cat || !wide_equal(cat,
        (const wchar_t[]){ 'a', 'b', 'c', 'd', 'a', 'b', 0 }))
        return 10;
    if (sign_of(wcscmp(alphabet, suffix)) != -1 ||
        sign_of(wcscmp(suffix, alphabet)) != 1 ||
        wcscmp(alphabet, alphabet) != 0 ||
        wcsncmp(alphabet, absent, 0) != 0 ||
        sign_of(wcsncmp(alphabet, suffix, 2)) != -1)
        return 11;
    if (wcschr(alphabet, 'c') != alphabet + 2 ||
        wcschr(alphabet, 0) != alphabet + 4 ||
        wcschr(alphabet, 'x') != NULL)
        return 12;
    {
        const wchar_t repeated[] = { 'a', 'b', 'a', 0 };
        if (wcsrchr(repeated, 'a') != repeated + 2 ||
            wcsrchr(repeated, 0) != repeated + 3 ||
            wcsrchr(repeated, 'x') != NULL)
            return 12;
    }
    if (wcsstr(periodic, needle) != periodic + 4 ||
        wcsstr(periodic, absent) != NULL ||
        wcsstr(periodic, (const wchar_t[]){ 0 }) != periodic)
        return 13;
    if (wcsspn((const wchar_t[]){ 'a', 'b', 'a', 'x', 0 }, alphabet) != 3 ||
        wcscspn(alphabet, suffix) != 2 || wcscspn(alphabet, absent) != 4 ||
        wcspbrk(alphabet, suffix) != alphabet + 2 ||
        wcspbrk(alphabet, absent) != NULL)
        return 14;

    token = wcstok(tokens, separators, &state);
    if (token != tokens + 2 || !wide_equal(token, (const wchar_t[]){ 'a', 0 }))
        return 15;
    token = wcstok(NULL, separators, &state);
    if (token != tokens + 4 ||
        !wide_equal(token, (const wchar_t[]){ 'b', 'c', 0 }))
        return 16;
    if (wcstok(NULL, separators, &state) != NULL || state != NULL)
        return 17;
    return 0;
}

static int check_collation_case_and_width(void)
{
    static const wchar_t source[] = { 'A', 0x00c4, 0x4e00, 0 };
    static const wchar_t lower[] = { 'a', 0x00e4, 0x4e00, 0 };
    static const wchar_t widths[] = { 'A', 0x0301, 0x4e00, 0 };
    wchar_t transformed[8];
    const char *locales[] = { "C", "POSIX", "C.UTF-8" };
    size_t index;

    for (index = 0; index < sizeof(locales) / sizeof(locales[0]); ++index) {
        if (setlocale(LC_ALL, locales[index]) == NULL)
            return 1;
        if (wcscoll(source, lower) >= 0 || wcsxfrm(transformed, source, 8) != 3 ||
            !wide_equal(transformed, source))
            return 2;
    }
    wmemset(transformed, 0x7777, 8);
    if (wcsxfrm(transformed, source, 2) != 3 || transformed[0] != 'A' ||
        transformed[1] != 0 || transformed[2] != 0x7777 ||
        wcsxfrm(NULL, source, 0) != 3)
        return 3;
    if (wcscasecmp(source, lower) != 0 || wcsncasecmp(source, lower, 1) != 0 ||
        sign_of(wcsncasecmp(source, (const wchar_t[]){ 'A', 0x00d6, 0 }, 2)) != -1)
        return 4;
    if (wcwidth(0) != 0 || wcwidth('A') != 1 || wcwidth('\n') != -1 ||
        wcwidth(0x0301) != 0 || wcwidth(0x4e00) != 2 ||
        wcwidth(0xd800) != 1 || wcwidth(0x110000) != 1)
        return 5;
    if (wcswidth(widths, 4) != 3 || wcswidth(widths, 2) != 1 ||
        wcswidth((const wchar_t[]){ 'A', '\n', 0 }, 3) != -1)
        return 6;
    return 0;
}

static uint64_t mix_u32(uint64_t hash, uint32_t value)
{
    unsigned shift;

    for (shift = 0; shift != 32; shift += 8) {
        hash ^= (value >> shift) & 0xffu;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int emit_unicode_oracle_fingerprint(void)
{
    static const char *class_names[] = {
        "alnum", "alpha", "blank", "cntrl", "digit", "graph",
        "lower", "print", "punct", "space", "upper", "xdigit"
    };
    wctype_t classes[12];
    wctrans_t upper;
    wctrans_t lower;
    uint64_t hash = UINT64_C(1469598103934665603);
    uint32_t scalar;
    size_t index;

    for (index = 0; index != 12; ++index) {
        classes[index] = wctype(class_names[index]);
        if (classes[index] == 0)
            return 1;
    }
    if (wctype("unknown") != 0 || wctype("") != 0)
        return 2;
    upper = wctrans("toupper");
    lower = wctrans("tolower");
    if (upper == 0 || lower == 0 || wctrans("unknown") != 0)
        return 3;

    for (scalar = 0; scalar <= 0x110000u; ++scalar) {
        wint_t value = (wint_t)scalar;
        uint32_t flags = 0;

        flags |= !!iswalnum(value) << 0;
        flags |= !!iswalpha(value) << 1;
        flags |= !!iswblank(value) << 2;
        flags |= !!iswcntrl(value) << 3;
        flags |= !!(iswdigit)(value) << 4;
        flags |= !!iswgraph(value) << 5;
        flags |= !!iswlower(value) << 6;
        flags |= !!iswprint(value) << 7;
        flags |= !!iswpunct(value) << 8;
        flags |= !!iswspace(value) << 9;
        flags |= !!iswupper(value) << 10;
        flags |= !!iswxdigit(value) << 11;
        for (index = 0; index != 12; ++index) {
            if (!!iswctype(value, classes[index]) != !!(flags & (1u << index)))
                return 4;
        }
        hash = mix_u32(hash, scalar);
        hash = mix_u32(hash, flags);
        hash = mix_u32(hash, towlower(value));
        hash = mix_u32(hash, towupper(value));
        hash = mix_u32(hash, towctrans(value, lower));
        hash = mix_u32(hash, towctrans(value, upper));
        hash = mix_u32(hash, (uint32_t)wcwidth((wchar_t)value));
    }
    hash = mix_u32(hash, towctrans(WEOF, (wctrans_t)0));
    if (write(STDOUT_FILENO, &hash, sizeof(hash)) != (ssize_t)sizeof(hash))
        return 5;
    return 0;
}

int crabc_x86_64_wide_character_probe(void)
{
    int result;

    result = check_memory_and_strings();
    if (result != 0)
        return 10 + result;
    result = check_collation_case_and_width();
    if (result != 0)
        return 50 + result;
    result = emit_unicode_oracle_fingerprint();
    if (result != 0)
        return 70 + result;
    return 0;
}

#if !defined(CRABC_WIDE_CHARACTER_FREESTANDING)
int main(void)
{
    return crabc_x86_64_wide_character_probe();
}
#endif
