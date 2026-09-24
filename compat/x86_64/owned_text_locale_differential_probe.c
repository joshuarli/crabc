/* Installed text, locale, multibyte, iconv, and numeric differential transcript.
 *
 * Unlike the older focused probes, this role carries no expected values. It
 * serializes exact observable results (return values, errno, pointer
 * progress, output bytes, mbstate_t initial-state predicates, and locale
 * handle relations) for the selected fixed C/POSIX/C.UTF-8 profile. The
 * component runner links this same object to pinned musl 1.2.6 and to every
 * supplied static/dynamic product and requires the transcripts to match
 * byte-for-byte, so any divergence is a parity failure rather than a
 * silently accepted candidate value.
 *
 * The transcript is deliberately closed to inputs whose musl behavior is an
 * intentional profile difference: musl synthesizes a UTF-8 locale map for any
 * other name (including slash or leading-dot names that it rewrites to
 * C.UTF-8) and iconv accepts BOM/UCS-2/legacy codepage spellings. The fixed
 * profile rejects those names; their candidate-only rejection is observed by
 * the source-specific supplement, never here. Calls whose musl behavior is
 * undefined (an `_l` query with LC_GLOBAL_LOCALE, negative nl_langinfo items,
 * or a zero-capacity mbsrtowcs resume that overruns in musl) are excluded.
 *
 * Output uses write(2) directly so the transcript does not depend on the
 * separately owned stdio engine.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <iconv.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>
#include <pthread.h>
#include <inttypes.h>

/* musl exports these internal spellings as the strong definitions behind
 * strerror_l and wcsftime_l; the frozen locale.core inventory selects them. */
char *__strerror_l(int, locale_t);
size_t __wcsftime_l(wchar_t *__restrict, size_t, const wchar_t *__restrict,
    const struct tm *__restrict, locale_t);

const unsigned short **__ctype_b_loc(void);
const int32_t **__ctype_tolower_loc(void);
const int32_t **__ctype_toupper_loc(void);

static char out_buffer[1 << 16];
static size_t out_used;

static void flush_out(void)
{
    size_t done = 0;
    while (done < out_used) {
        ssize_t n = write(1, out_buffer + done, out_used - done);
        if (n <= 0)
            _exit(99);
        done += (size_t)n;
    }
    out_used = 0;
}

static void put_bytes(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (out_used == sizeof out_buffer)
            flush_out();
        out_buffer[out_used++] = s[i];
    }
}

static void put_s(const char *s) { put_bytes(s, strlen(s)); }

static void put_u(unsigned long long v)
{
    char tmp[32];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n)
        put_bytes(&tmp[--n], 1);
}

static void put_i(long long v)
{
    if (v < 0) {
        put_s("-");
        put_u(0ULL - (unsigned long long)v);
    } else
        put_u((unsigned long long)v);
}

static void put_x(unsigned long long v)
{
    static const char digits[] = "0123456789abcdef";
    char tmp[32];
    int n = 0;
    do {
        tmp[n++] = digits[v & 15];
        v >>= 4;
    } while (v);
    put_s("0x");
    while (n)
        put_bytes(&tmp[--n], 1);
}

static void put_z(size_t v)
{
    if (v == (size_t)-1)
        put_s("-1");
    else if (v == (size_t)-2)
        put_s("-2");
    else if (v == (size_t)-3)
        put_s("-3");
    else
        put_u(v);
}

static void put_hexbytes(const void *p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    const unsigned char *b = p;
    put_s("[");
    for (size_t i = 0; i < n; i++) {
        char c[2] = { digits[b[i] >> 4], digits[b[i] & 15] };
        put_bytes(c, 2);
    }
    put_s("]");
}

static void put_cstr(const char *s)
{
    if (!s) {
        put_s("(null)");
        return;
    }
    put_s("\"");
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\')
            put_bytes((const char *)&c, 1);
        else {
            static const char digits[] = "0123456789abcdef";
            char e[4] = { '\\', 'x', digits[c >> 4], digits[c & 15] };
            put_bytes(e, 4);
        }
    }
    put_s("\"");
}

static void put_wstr(const wchar_t *s, size_t max)
{
    put_s("L[");
    for (size_t i = 0; i < max; i++) {
        if (i)
            put_s(",");
        put_x((unsigned)s[i]);
        if (!s[i])
            break;
    }
    put_s("]");
}

static void nl(void) { put_s("\n"); }

static void put_errno(int e) { put_s(" errno="); put_i(e); }

#define SENTINEL_ERRNO 1234

/* Corpus of multibyte sequences. */
static const struct {
    const char *bytes;
    size_t len;
} corpus[] = {
    { "", 1 },
    { "A", 1 },
    { "\x7f", 1 },
    { "\x80", 1 },
    { "\xbf", 1 },
    { "\xc0\x80", 2 },
    { "\xc1\xbf", 2 },
    { "\xc2\x80", 2 },
    { "\xc2\x7f", 2 },
    { "\xc2\xc0", 2 },
    { "\xdf\xbf", 2 },
    { "\xe0\x80\x80", 3 },
    { "\xe0\x9f\xbf", 3 },
    { "\xe0\xa0\x80", 3 },
    { "\xe2\x82\xac", 3 },
    { "\xed\x9f\xbf", 3 },
    { "\xed\xa0\x80", 3 },
    { "\xed\xbf\xbf", 3 },
    { "\xee\x80\x80", 3 },
    { "\xef\xbf\xbd", 3 },
    { "\xef\xbf\xbf", 3 },
    { "\xf0\x80\x80\x80", 4 },
    { "\xf0\x8f\xbf\xbf", 4 },
    { "\xf0\x90\x80\x80", 4 },
    { "\xf0\x9f\x98\x80", 4 },
    { "\xf4\x8f\xbf\xbf", 4 },
    { "\xf4\x90\x80\x80", 4 },
    { "\xf5\x80\x80\x80", 4 },
    { "\xf8\x88\x80\x80\x80", 5 },
    { "\xfe", 1 },
    { "\xff", 1 },
    { "\xe2\x82", 2 },
    { "\xe2\x28\xa1", 3 },
    { "\xf0\x9f\x98", 3 },
    { "\xf0\x9f\x98\x41", 4 },
    { "\xc3\xa9\x00\x41", 4 },
    { "A\xe2\x82\xac" "B", 5 },
};
#define CORPUS_COUNT (sizeof corpus / sizeof corpus[0])

static const wchar_t wide_values[] = {
    0, 1, 0x41, 0x7f, 0x80, 0xff, 0x100, 0x7ff, 0x800, 0xd7ff, 0xd800,
    0xdbff, 0xdc00, 0xdfff, 0xe000, 0xfffd, 0xfffe, 0xffff, 0x10000,
    0x1f600, 0x10ffff, 0x110000, 0x7fffffff, -1, -2, (wchar_t)0x80000000,
    0xdf80, 0xdf7f, 0xdfff, 0xdf81, 0xdffe,
};
#define WIDE_VALUE_COUNT (sizeof wide_values / sizeof wide_values[0])

static void section(const char *name)
{
    put_s("== ");
    put_s(name);
    nl();
}

static int select_global_locale(const char *name)
{
    if (setlocale(LC_ALL, name))
        return 0;
    put_s("setlocale-failed ");
    put_s(name);
    nl();
    return 1;
}

static void dump_mbstate(const mbstate_t *st)
{
    put_s(" init=");
    put_i(mbsinit(st) != 0);
}

static void test_mbrtowc_bytes(void)
{
    section("mbrtowc-single-bytes");
    for (int b = 0; b < 256; b++) {
        char s[2] = { (char)b, 0 };
        mbstate_t st;
        memset(&st, 0, sizeof st);
        wchar_t wc = (wchar_t)0x5a5a5a5a;
        errno = SENTINEL_ERRNO;
        size_t r = mbrtowc(&wc, s, 1, &st);
        put_x((unsigned)b);
        put_s(" r=");
        put_z(r);
        put_s(" wc=");
        put_x((unsigned)wc);
        put_errno(errno);
        dump_mbstate(&st);
        /* mbrlen and mblen/mbtowc */
        errno = SENTINEL_ERRNO;
        memset(&st, 0, sizeof st);
        put_s(" mbrlen=");
        put_z(mbrlen(s, 1, &st));
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        mbtowc(NULL, NULL, 0);
        wc = (wchar_t)0x5a5a5a5a;
        put_s(" mbtowc=");
        put_i(mbtowc(&wc, s, 1));
        put_s(" wc=");
        put_x((unsigned)wc);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        put_s(" mblen=");
        put_i(mblen(s, 1));
        put_errno(errno);
        put_s(" btowc=");
        put_x((unsigned)btowc(b));
        nl();
    }
    put_s("btowc(EOF)=");
    put_x((unsigned)btowc(EOF));
    put_s(" btowc(256)=");
    put_x((unsigned)btowc(256));
    put_s(" btowc(-2)=");
    put_x((unsigned)btowc(-2));
    nl();
}

static void test_mbrtowc_corpus(void)
{
    section("mbrtowc-corpus");
    for (size_t i = 0; i < CORPUS_COUNT; i++) {
        const char *s = corpus[i].bytes;
        size_t len = corpus[i].len;
        put_s("seq ");
        put_hexbytes(s, len);
        nl();
        /* whole-sequence calls with n = 0..len */
        for (size_t n = 0; n <= len; n++) {
            mbstate_t st;
            memset(&st, 0, sizeof st);
            wchar_t wc = (wchar_t)0x5a5a5a5a;
            errno = SENTINEL_ERRNO;
            size_t r = mbrtowc(&wc, s, n, &st);
            put_s("  n=");
            put_u(n);
            put_s(" r=");
            put_z(r);
            put_s(" wc=");
            put_x((unsigned)wc);
            put_errno(errno);
            dump_mbstate(&st);
            /* continue after -2 with remaining bytes */
            if (r == (size_t)-2 && n < len) {
                wc = (wchar_t)0x5a5a5a5a;
                errno = SENTINEL_ERRNO;
                r = mbrtowc(&wc, s + n, len - n, &st);
                put_s(" cont=");
                put_z(r);
                put_s(" wc=");
                put_x((unsigned)wc);
                put_errno(errno);
                dump_mbstate(&st);
            }
            nl();
        }
        /* byte at a time */
        {
            mbstate_t st;
            memset(&st, 0, sizeof st);
            put_s("  bytewise:");
            for (size_t k = 0; k < len; k++) {
                wchar_t wc = (wchar_t)0x5a5a5a5a;
                errno = SENTINEL_ERRNO;
                size_t r = mbrtowc(&wc, s + k, 1, &st);
                put_s(" ");
                put_z(r);
                put_s("/");
                put_x((unsigned)wc);
                put_s("/");
                put_i(errno);
                if (r == (size_t)-1)
                    memset(&st, 0, sizeof st);
            }
            nl();
        }
        /* null pwc; null-state channel */
        {
            errno = SENTINEL_ERRNO;
            size_t r1 = mbrtowc(NULL, s, len, NULL);
            int e1 = errno;
            mbrtowc(NULL, NULL, 0, NULL);
            errno = SENTINEL_ERRNO;
            size_t r2 = mbrlen(s, len, NULL);
            int e2 = errno;
            mbrlen(NULL, 0, NULL);
            put_s("  nullpwc r=");
            put_z(r1);
            put_errno(e1);
            put_s(" mbrlen-null r=");
            put_z(r2);
            put_errno(e2);
            nl();
        }
    }
    /* reset forms */
    {
        mbstate_t st;
        memset(&st, 0, sizeof st);
        wchar_t wc = 7;
        errno = SENTINEL_ERRNO;
        size_t r = mbrtowc(&wc, NULL, 5, &st);
        put_s("reset-clean r=");
        put_z(r);
        put_s(" wc=");
        put_x((unsigned)wc);
        put_errno(errno);
        nl();
        mbrtowc(&wc, "\xe2", 1, &st);
        errno = SENTINEL_ERRNO;
        r = mbrtowc(&wc, NULL, 5, &st);
        put_s("reset-pending r=");
        put_z(r);
        put_errno(errno);
        dump_mbstate(&st);
        nl();
        memset(&st, 0, sizeof st);
        mbrtowc(&wc, "\xe2", 1, &st);
        errno = SENTINEL_ERRNO;
        r = mbrtowc(&wc, "\x82", 0, &st);
        put_s("pending-n0 r=");
        put_z(r);
        put_errno(errno);
        dump_mbstate(&st);
        nl();
    }
}

static void test_wcrtomb(void)
{
    section("wcrtomb");
    for (size_t i = 0; i < WIDE_VALUE_COUNT; i++) {
        wchar_t w = wide_values[i];
        char buf[8];
        memset(buf, 0x5a, sizeof buf);
        mbstate_t st;
        memset(&st, 0, sizeof st);
        errno = SENTINEL_ERRNO;
        size_t r = wcrtomb(buf, w, &st);
        put_x((unsigned)w);
        put_s(" r=");
        put_z(r);
        put_s(" ");
        put_hexbytes(buf, 5);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        r = wcrtomb(NULL, w, &st);
        put_s(" null=");
        put_z(r);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        memset(buf, 0x5a, sizeof buf);
        wctomb(NULL, 0);
        int k = wctomb(buf, w);
        put_s(" wctomb=");
        put_i(k);
        put_s(" ");
        put_hexbytes(buf, 5);
        put_errno(errno);
        put_s(" wctob=");
        put_i(wctob((wint_t)w));
        errno = SENTINEL_ERRNO;
        memset(buf, 0x5a, sizeof buf);
        r = c32rtomb(buf, (char32_t)w, NULL);
        put_s(" c32=");
        put_z(r);
        put_s(" ");
        put_hexbytes(buf, 5);
        put_errno(errno);
        nl();
    }
    /* wcrtomb with pending mbstate from mbrtowc */
    {
        mbstate_t st;
        memset(&st, 0, sizeof st);
        wchar_t wc;
        mbrtowc(&wc, "\xe2", 1, &st);
        char buf[8];
        errno = SENTINEL_ERRNO;
        size_t r = wcrtomb(buf, L'A', &st);
        put_s("wcrtomb-after-pending r=");
        put_z(r);
        put_errno(errno);
        nl();
    }
    put_s("wctomb(NULL)=");
    put_i(wctomb(NULL, L'A'));
    put_s(" mblen(NULL)=");
    put_i(mblen(NULL, 0));
    put_s(" mbtowc(NULL)=");
    put_i(mbtowc(NULL, NULL, 0));
    nl();
    {
        wchar_t wc = 9;
        errno = SENTINEL_ERRNO;
        put_s("mbtowc-empty=");
        put_i(mbtowc(&wc, "", 1));
        put_s(" wc=");
        put_x((unsigned)wc);
        put_s(" n0=");
        put_i(mbtowc(&wc, "A", 0));
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        put_s(" mblen-n0=");
        put_i(mblen("A", 0));
        put_errno(errno);
        nl();
    }
}

static const char *const mb_strings[] = {
    "",
    "hello",
    "A\xe2\x82\xac" "B\xf0\x9f\x98\x80" "C",
    "\xe2\x82",
    "ab\xff" "cd",
    "\xc3\xa9t\xc3\xa9",
    "x\xed\xa0\x80y",
    "\x80\x81\xfe",
};
#define MB_STRING_COUNT (sizeof mb_strings / sizeof mb_strings[0])

static void test_mbsrtowcs(void)
{
    section("mbsrtowcs");
    for (size_t i = 0; i < MB_STRING_COUNT; i++) {
        const char *base = mb_strings[i];
        size_t blen = strlen(base);
        put_s("str ");
        put_hexbytes(base, blen);
        nl();
        for (size_t cap = 0; cap <= 8; cap++) {
            wchar_t dst[16];
            for (int k = 0; k < 16; k++)
                dst[k] = (wchar_t)0x5a5a;
            const char *src = base;
            mbstate_t st;
            memset(&st, 0, sizeof st);
            errno = SENTINEL_ERRNO;
            size_t r = mbsrtowcs(dst, &src, cap, &st);
            put_s("  cap=");
            put_u(cap);
            put_s(" r=");
            put_z(r);
            put_s(" src=");
            if (src)
                put_i(src - base);
            else
                put_s("NULL");
            put_errno(errno);
            dump_mbstate(&st);
            put_s(" ");
            put_wstr(dst, cap < 9 ? cap + 1 : 9);
            nl();
            for (size_t nms = 0; nms <= blen + 1; nms++) {
                for (int k = 0; k < 16; k++)
                    dst[k] = (wchar_t)0x5a5a;
                src = base;
                memset(&st, 0, sizeof st);
                errno = SENTINEL_ERRNO;
                r = mbsnrtowcs(dst, &src, nms, cap, &st);
                put_s("    nms=");
                put_u(nms);
                put_s(" r=");
                put_z(r);
                put_s(" src=");
                if (src)
                    put_i(src - base);
                else
                    put_s("NULL");
                put_errno(errno);
                dump_mbstate(&st);
                put_s(" ");
                put_wstr(dst, cap < 9 ? cap + 1 : 9);
                nl();
            }
        }
        {
            const char *src = base;
            mbstate_t st;
            memset(&st, 0, sizeof st);
            errno = SENTINEL_ERRNO;
            size_t r = mbsrtowcs(NULL, &src, 0, &st);
            put_s("  null-dst r=");
            put_z(r);
            put_s(" src=");
            put_i(src ? src - base : -1);
            put_errno(errno);
            for (size_t nms = 0; nms <= blen + 1; nms++) {
                src = base;
                memset(&st, 0, sizeof st);
                errno = SENTINEL_ERRNO;
                r = mbsnrtowcs(NULL, &src, nms, 0, &st);
                put_s(" nr(");
                put_u(nms);
                put_s(")=");
                put_z(r);
                put_s("/");
                put_i(errno);
            }
            nl();
            wchar_t dst[16];
            errno = SENTINEL_ERRNO;
            r = mbstowcs(dst, base, 16);
            put_s("  mbstowcs=");
            put_z(r);
            put_errno(errno);
            errno = SENTINEL_ERRNO;
            r = mbstowcs(NULL, base, 0);
            put_s(" null=");
            put_z(r);
            put_errno(errno);
            nl();
        }
    }
    /* pending state entering mbsrtowcs */
    {
        mbstate_t st;
        memset(&st, 0, sizeof st);
        wchar_t wc;
        mbrtowc(&wc, "\xf0\x9f", 2, &st);
        const char tail[] = "\x98\x80Z";
        const char *src = tail;
        wchar_t dst[4] = { 1, 1, 1, 1 };
        errno = SENTINEL_ERRNO;
        size_t r = mbsrtowcs(dst, &src, 4, &st);
        put_s("pending-entry r=");
        put_z(r);
        put_s(" src=");
        put_i(src ? src - tail : -1);
        put_errno(errno);
        put_wstr(dst, 4);
        nl();
        memset(&st, 0, sizeof st);
        mbrtowc(&wc, "\xf0\x9f", 2, &st);
        src = tail;
        errno = SENTINEL_ERRNO;
        r = mbsnrtowcs(dst, &src, 1, 4, &st);
        put_s("pending-entry-nr r=");
        put_z(r);
        put_s(" src=");
        put_i(src ? src - tail : -1);
        put_errno(errno);
        dump_mbstate(&st);
        nl();
        memset(&st, 0, sizeof st);
        mbrtowc(&wc, "\xf0\x9f", 2, &st);
        src = tail;
        errno = SENTINEL_ERRNO;
        r = mbsrtowcs(NULL, &src, 0, &st);
        put_s("pending-entry-null r=");
        put_z(r);
        put_errno(errno);
        dump_mbstate(&st);
        nl();
    }
}

static const wchar_t w_str0[] = { 0 };
static const wchar_t w_str1[] = { L'h', L'i', 0 };
static const wchar_t w_str2[] = { L'A', 0x20ac, L'B', 0x1f600, L'C', 0 };
static const wchar_t w_str3[] = { L'x', 0xd800, L'y', 0 };
static const wchar_t w_str4[] = { 0x80, 0xff, 0xdf80, 0 };
static const wchar_t w_str5[] = { L'a', 0x110000, 0 };
static const wchar_t *const w_strings[] = { w_str0, w_str1, w_str2, w_str3, w_str4, w_str5 };
#define W_STRING_COUNT (sizeof w_strings / sizeof w_strings[0])

static void test_wcsrtombs(void)
{
    section("wcsrtombs");
    for (size_t i = 0; i < W_STRING_COUNT; i++) {
        const wchar_t *base = w_strings[i];
        size_t wl = wcslen(base);
        put_s("wstr ");
        put_wstr(base, wl + 1);
        nl();
        for (size_t cap = 0; cap <= 14; cap++) {
            char dst[32];
            memset(dst, 0x5a, sizeof dst);
            const wchar_t *src = base;
            mbstate_t st;
            memset(&st, 0, sizeof st);
            errno = SENTINEL_ERRNO;
            size_t r = wcsrtombs(dst, &src, cap, &st);
            put_s("  cap=");
            put_u(cap);
            put_s(" r=");
            put_z(r);
            put_s(" src=");
            if (src)
                put_i(src - base);
            else
                put_s("NULL");
            put_errno(errno);
            put_s(" ");
            put_hexbytes(dst, cap + 1 < 16 ? cap + 1 : 16);
            nl();
            for (size_t nwc = 0; nwc <= wl + 1; nwc++) {
                memset(dst, 0x5a, sizeof dst);
                src = base;
                errno = SENTINEL_ERRNO;
                r = wcsnrtombs(dst, &src, nwc, cap, &st);
                put_s("    nwc=");
                put_u(nwc);
                put_s(" r=");
                put_z(r);
                put_s(" src=");
                if (src)
                    put_i(src - base);
                else
                    put_s("NULL");
                put_errno(errno);
                put_s(" ");
                put_hexbytes(dst, cap + 1 < 16 ? cap + 1 : 16);
                nl();
            }
        }
        {
            const wchar_t *src = base;
            errno = SENTINEL_ERRNO;
            size_t r = wcsrtombs(NULL, &src, 0, NULL);
            put_s("  null-dst r=");
            put_z(r);
            put_s(" src=");
            put_i(src ? src - base : -1);
            put_errno(errno);
            for (size_t nwc = 0; nwc <= wl + 1; nwc++) {
                src = base;
                errno = SENTINEL_ERRNO;
                r = wcsnrtombs(NULL, &src, nwc, 0, NULL);
                put_s(" nr(");
                put_u(nwc);
                put_s(")=");
                put_z(r);
                put_s("/");
                put_i(errno);
            }
            nl();
            char dst[32];
            memset(dst, 0x5a, sizeof dst);
            errno = SENTINEL_ERRNO;
            r = wcstombs(dst, base, sizeof dst);
            put_s("  wcstombs=");
            put_z(r);
            put_errno(errno);
            put_hexbytes(dst, 16);
            errno = SENTINEL_ERRNO;
            r = wcstombs(NULL, base, 0);
            put_s(" null=");
            put_z(r);
            put_errno(errno);
            nl();
        }
    }
}

static void test_uchar(void)
{
    section("uchar");
    for (size_t i = 0; i < CORPUS_COUNT; i++) {
        const char *s = corpus[i].bytes;
        size_t len = corpus[i].len;
        put_s("seq ");
        put_hexbytes(s, len);
        mbstate_t st;
        memset(&st, 0, sizeof st);
        size_t off = 0;
        int steps = 0;
        while (steps++ < 8) {
            char16_t c16 = 0x5a5a;
            errno = SENTINEL_ERRNO;
            size_t r = mbrtoc16(&c16, s + off, len - off, &st);
            put_s(" c16:");
            put_z(r);
            put_s("/");
            put_x(c16);
            put_s("/");
            put_i(errno);
            if (r == (size_t)-1 || r == (size_t)-2 || r == 0)
                break;
            if (r != (size_t)-3)
                off += r;
        }
        memset(&st, 0, sizeof st);
        {
            char32_t c32 = 0x5a5a;
            errno = SENTINEL_ERRNO;
            size_t r = mbrtoc32(&c32, s, len, &st);
            put_s(" c32:");
            put_z(r);
            put_s("/");
            put_x(c32);
            put_s("/");
            put_i(errno);
            dump_mbstate(&st);
        }
        nl();
    }
    /* c16rtomb sequences */
    static const char16_t seqs[][3] = {
        { 0x41, 0, 0 }, { 0x20ac, 0, 0 }, { 0xd83d, 0xde00, 0 }, { 0xd83d, 0x41, 0 },
        { 0xde00, 0, 0 }, { 0xd800, 0xd800, 0 }, { 0xdbff, 0xdfff, 0 }, { 0, 0, 0 },
        { 0xd800, 0, 0 }, { 0x80, 0, 0 }, { 0xdf80, 0, 0 },
    };
    for (size_t i = 0; i < sizeof seqs / sizeof seqs[0]; i++) {
        mbstate_t st;
        memset(&st, 0, sizeof st);
        put_s("c16rtomb");
        size_t n = seqs[i][1] || (seqs[i][0] >= 0xd800 && seqs[i][0] < 0xdc00) ? 2 : 1;
        for (size_t k = 0; k < n; k++) {
            char buf[8];
            memset(buf, 0x5a, sizeof buf);
            errno = SENTINEL_ERRNO;
            size_t r = c16rtomb(buf, seqs[i][k], &st);
            put_s(" ");
            put_x(seqs[i][k]);
            put_s(":");
            put_z(r);
            put_s("/");
            put_hexbytes(buf, 5);
            put_s("/");
            put_i(errno);
        }
        dump_mbstate(&st);
        {
            char buf[8];
            errno = SENTINEL_ERRNO;
            size_t r = c16rtomb(NULL, 0x41, &st);
            put_s(" nullbuf=");
            put_z(r);
            put_errno(errno);
            (void)buf;
        }
        nl();
    }
    {
        /* NULL state (internal) round trip */
        char buf[8];
        memset(buf, 0x5a, sizeof buf);
        errno = SENTINEL_ERRNO;
        size_t r1 = c16rtomb(buf, 0xd83d, NULL);
        size_t r2 = c16rtomb(buf, 0xde00, NULL);
        put_s("c16-internal ");
        put_z(r1);
        put_s(" ");
        put_z(r2);
        put_s(" ");
        put_hexbytes(buf, 4);
        put_errno(errno);
        char16_t c = 0;
        r1 = mbrtoc16(&c, "\xf0\x9f\x98\x80", 4, NULL);
        put_s(" m16 ");
        put_z(r1);
        put_s("/");
        put_x(c);
        r2 = mbrtoc16(&c, "", 0, NULL);
        put_s(" ");
        put_z(r2);
        put_s("/");
        put_x(c);
        char32_t c32;
        r1 = mbrtoc32(&c32, "\xe2\x82", 2, NULL);
        r2 = mbrtoc32(&c32, "\xac", 1, NULL);
        put_s(" m32 ");
        put_z(r1);
        put_s(" ");
        put_z(r2);
        put_s("/");
        put_x(c32);
        nl();
        /* mbrtoc16 with NULL output after surrogate pending */
        mbstate_t st;
        memset(&st, 0, sizeof st);
        r1 = mbrtoc16(NULL, "\xf0\x9f\x98\x80", 4, &st);
        r2 = mbrtoc16(NULL, "x", 1, &st);
        put_s("m16-nullout ");
        put_z(r1);
        put_s(" ");
        put_z(r2);
        dump_mbstate(&st);
        memset(&st, 0, sizeof st);
        r1 = mbrtoc16(&c, "\xf0\x9f\x98\x80", 4, &st);
        r2 = mbrtoc16(&c, NULL, 0, &st);
        put_s(" pending-null-s ");
        put_z(r1);
        put_s(" ");
        put_z(r2);
        put_s("/");
        put_x(c);
        nl();
    }
}

static const char *const class_names[] = {
    "alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print",
    "punct", "space", "upper", "xdigit", "", "foo", "ALPHA", "alpha ",
};

static int classify(int which, wint_t c)
{
    switch (which) {
    case 0: return iswalnum(c) != 0;
    case 1: return iswalpha(c) != 0;
    case 2: return iswblank(c) != 0;
    case 3: return iswcntrl(c) != 0;
    case 4: return iswdigit(c) != 0;
    case 5: return iswgraph(c) != 0;
    case 6: return iswlower(c) != 0;
    case 7: return iswprint(c) != 0;
    case 8: return iswpunct(c) != 0;
    case 9: return iswspace(c) != 0;
    case 10: return iswupper(c) != 0;
    case 11: return iswxdigit(c) != 0;
    }
    return -1;
}

static void test_wide_classes(void)
{
    section("wide-classes");
    wctype_t types[16];
    for (int i = 0; i < 16; i++) {
        types[i] = wctype(class_names[i]);
        put_s("wctype(");
        put_cstr(class_names[i]);
        put_s(")=");
        put_i(types[i] != 0);
        nl();
    }
    for (int which = 0; which < 12; which++) {
        put_s("class ");
        put_s(class_names[which]);
        put_s(":");
        int last = -1;
        int mismatch_iswctype = 0;
        for (long c = -2; c <= 0x110001; c++) {
            wint_t wc = (wint_t)c;
            int v = classify(which, wc);
            int v2 = iswctype(wc, types[which]) != 0;
            if (v != v2)
                mismatch_iswctype++;
            if (v != last) {
                put_s(" ");
                put_i(c);
                put_s("=");
                put_i(v);
                last = v;
            }
        }
        put_s(" ctypemis=");
        put_i(mismatch_iswctype);
        nl();
    }
    put_s("iswctype(invalid)=");
    put_i(iswctype(L'a', 0));
    put_s(" ");
    put_i(iswctype(L'a', 12345));
    nl();
}

static void test_wide_case(void)
{
    section("wide-case");
    wctrans_t tu = wctrans("toupper"), tl = wctrans("tolower");
    put_s("wctrans toupper=");
    put_i(tu != 0);
    put_s(" tolower=");
    put_i(tl != 0);
    put_s(" bad=");
    put_i(wctrans("toUpper") != 0);
    put_s(" empty=");
    put_i(wctrans("") != 0);
    nl();
    for (int dir = 0; dir < 2; dir++) {
        put_s(dir ? "towlower:" : "towupper:");
        long last = LONG_MIN;
        int mismatch = 0;
        for (long c = -2; c <= 0x110001; c++) {
            wint_t wc = (wint_t)c;
            wint_t r = dir ? towlower(wc) : towupper(wc);
            wint_t r2 = towctrans(wc, dir ? tl : tu);
            if (r != r2)
                mismatch++;
            long delta = (long)(int)r - c;
            if (delta != last) {
                put_s(" ");
                put_i(c);
                put_s(":");
                put_i(delta);
                last = delta;
            }
        }
        put_s(" transmis=");
        put_i(mismatch);
        nl();
    }
    put_s("towctrans(0)=");
    put_x(towctrans(L'a', 0));
    nl();
}

static void test_wcwidth(void)
{
    section("wcwidth");
    int last = 99;
    put_s("wcwidth:");
    for (long c = -2; c <= 0x110001; c++) {
        int v = wcwidth((wchar_t)c);
        if (v != last) {
            put_s(" ");
            put_i(c);
            put_s("=");
            put_i(v);
            last = v;
        }
    }
    nl();
    static const wchar_t s1[] = { L'a', 0x4e00, 0x301, L'b', 0 };
    static const wchar_t s2[] = { L'a', 0x7, L'b', 0 };
    static const wchar_t s3[] = { 0 };
    put_s("wcswidth ");
    for (size_t n = 0; n <= 5; n++) {
        put_i(wcswidth(s1, n));
        put_s(",");
        put_i(wcswidth(s2, n));
        put_s(",");
        put_i(wcswidth(s3, n));
        put_s(" ");
    }
    nl();
}

static void test_wide_strings(void)
{
    section("wide-strings");
    static const wchar_t hay[] = { L'a', L'b', L'c', L'a', L'b', L'd', 0x20ac, L'a', 0 };
    static const wchar_t e[] = { 0 };
    static const wchar_t ab[] = { L'a', L'b', 0 };
    static const wchar_t abd[] = { L'a', L'b', L'd', 0 };
    static const wchar_t zz[] = { L'z', L'z', 0 };
    static const wchar_t eu[] = { 0x20ac, 0 };
    const wchar_t *needles[] = { e, ab, abd, zz, eu, hay };
    for (size_t i = 0; i < 6; i++) {
        const wchar_t *p = wcsstr(hay, needles[i]);
        const wchar_t *q = wcswcs(hay, needles[i]);
        put_s("wcsstr ");
        put_i(p ? p - hay : -1);
        put_s(" wcswcs ");
        put_i(q ? q - hay : -1);
        put_s(" spn ");
        put_u(wcsspn(hay, needles[i]));
        put_s(" cspn ");
        put_u(wcscspn(hay, needles[i]));
        p = wcspbrk(hay, needles[i]);
        put_s(" pbrk ");
        put_i(p ? p - hay : -1);
        nl();
    }
    {
        static const wchar_t longhay[] = { L'a', L'a', L'a', L'a', L'a', L'a', L'a', L'a', L'a', L'b', L'a', 0 };
        static const wchar_t longneedle[] = { L'a', L'a', L'a', L'b', 0 };
        const wchar_t *p = wcsstr(longhay, longneedle);
        put_s("wcsstr-long ");
        put_i(p ? p - longhay : -1);
        nl();
    }
    const wint_t chars[] = { L'a', L'd', 0, 0x20ac, L'q', (wint_t)-1 };
    for (size_t i = 0; i < 6; i++) {
        const wchar_t *p = wcschr(hay, (wchar_t)chars[i]);
        const wchar_t *r = wcsrchr(hay, (wchar_t)chars[i]);
        const wchar_t *m = wmemchr(hay, (wchar_t)chars[i], 9);
        const wchar_t *m2 = wmemchr(hay, (wchar_t)chars[i], 3);
        put_s("chr ");
        put_i(p ? p - hay : -1);
        put_s(" rchr ");
        put_i(r ? r - hay : -1);
        put_s(" memchr ");
        put_i(m ? m - hay : -1);
        put_s(" ");
        put_i(m2 ? m2 - hay : -1);
        nl();
    }
    static const wchar_t neg1[] = { (wchar_t)-1, 0 };
    static const wchar_t pos1[] = { 1, 0 };
    static const wchar_t hi[] = { 0x7fffffff, 0 };
    static const wchar_t upA[] = { L'A', L'B', 0x100, 0 };
    static const wchar_t loA[] = { L'a', L'b', 0x101, 0 };
    const wchar_t *cmp_set[] = { e, ab, abd, neg1, pos1, hi, upA, loA };
    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 8; j++) {
            int a = wcscmp(cmp_set[i], cmp_set[j]);
            int b = wcsncmp(cmp_set[i], cmp_set[j], 1);
            int c = wmemcmp(cmp_set[i], cmp_set[j], 1);
            int d = wcscasecmp(cmp_set[i], cmp_set[j]);
            int f = wcsncasecmp(cmp_set[i], cmp_set[j], 2);
            int g = wcscoll(cmp_set[i], cmp_set[j]);
            put_s("cmp ");
            put_u(i);
            put_s(",");
            put_u(j);
            put_s(" ");
            put_i((a > 0) - (a < 0));
            put_s(" ");
            put_i((b > 0) - (b < 0));
            put_s(" ");
            put_i((c > 0) - (c < 0));
            put_s(" ");
            put_i((d > 0) - (d < 0));
            put_s(" ");
            put_i((f > 0) - (f < 0));
            put_s(" ");
            put_i((g > 0) - (g < 0));
            nl();
        }
    }
    {
        wchar_t buf[16];
        for (int k = 0; k < 16; k++)
            buf[k] = 0x5a;
        wchar_t *end = wcpcpy(buf, ab);
        put_s("wcpcpy ");
        put_i(end - buf);
        put_wstr(buf, 5);
        for (int k = 0; k < 16; k++)
            buf[k] = 0x5a;
        end = wcpncpy(buf, ab, 5);
        put_s(" wcpncpy ");
        put_i(end - buf);
        put_wstr(buf, 7);
        for (int k = 0; k < 16; k++)
            buf[k] = 0x5a;
        end = wcpncpy(buf, abd, 2);
        put_s(" wcpncpy-trunc ");
        put_i(end - buf);
        put_wstr(buf, 4);
        for (int k = 0; k < 16; k++)
            buf[k] = 0x5a;
        wchar_t *r = wcsncpy(buf, ab, 5);
        put_s(" wcsncpy ");
        put_i(r - buf);
        put_wstr(buf, 7);
        nl();
        for (int k = 0; k < 16; k++)
            buf[k] = 0x5a;
        wcscpy(buf, ab);
        wcscat(buf, abd);
        put_s("wcscat ");
        put_wstr(buf, 8);
        wcsncat(buf, zz, 1);
        put_s(" wcsncat ");
        put_wstr(buf, 9);
        wcsncat(buf, zz, 0);
        put_s(" ");
        put_wstr(buf, 9);
        put_s(" len ");
        put_u(wcslen(buf));
        put_s(" nlen ");
        put_u(wcsnlen(buf, 3));
        put_s(" ");
        put_u(wcsnlen(buf, 100));
        nl();
        wmemset(buf, 0x20ac, 4);
        wmemcpy(buf + 4, ab, 2);
        wmemmove(buf + 1, buf, 5);
        put_s("wmem ");
        put_wstr(buf, 8);
        wmemmove(buf, buf + 2, 4);
        put_wstr(buf, 8);
        nl();
        wchar_t *d = wcsdup(hay);
        put_s("wcsdup ");
        put_i(d != NULL && wcscmp(d, hay) == 0);
        free(d);
        nl();
    }
    {
        wchar_t text[] = { L' ', L'a', L'b', L',', L',', L'c', L' ', L'd', L',', 0 };
        static const wchar_t delim[] = { L' ', L',', 0 };
        wchar_t *save = (wchar_t *)0x1;
        put_s("wcstok");
        wchar_t *tok = wcstok(text, delim, &save);
        while (tok) {
            put_s(" ");
            put_i(tok - text);
            put_s("/");
            put_i(save ? save - text : -1);
            tok = wcstok(NULL, delim, &save);
        }
        put_s(" end/");
        put_i(save ? save - text : -1);
        nl();
        wchar_t empty[] = { L',', L',', 0 };
        save = NULL;
        tok = wcstok(empty, delim, &save);
        put_s("wcstok-empty ");
        put_i(tok ? tok - empty : -1);
        put_s("/");
        put_i(save ? save - empty : -1);
        nl();
    }
}

static void test_collation(void)
{
    section("collation");
    const char *strs[] = { "", "a", "ab", "b", "A", "\xc3\xa9", "\xff", "abc" };
    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 8; j++) {
            int c = strcoll(strs[i], strs[j]);
            int k = strcasecmp(strs[i], strs[j]);
            int k2 = strncasecmp(strs[i], strs[j], 1);
            put_s("coll ");
            put_u(i);
            put_s(",");
            put_u(j);
            put_s(" ");
            put_i((c > 0) - (c < 0));
            put_s(" ");
            put_i((k > 0) - (k < 0));
            put_s(" ");
            put_i((k2 > 0) - (k2 < 0));
            nl();
        }
        for (size_t n = 0; n <= 5; n++) {
            char buf[8];
            memset(buf, 0x5a, sizeof buf);
            size_t r = strxfrm(buf, strs[i], n);
            put_s("strxfrm ");
            put_u(i);
            put_s(" n=");
            put_u(n);
            put_s(" r=");
            put_u(r);
            put_s(" ");
            put_hexbytes(buf, 6);
            nl();
        }
        {
            size_t r = strxfrm(NULL, strs[i], 0);
            put_s("strxfrm-null ");
            put_u(r);
            nl();
        }
    }
    static const wchar_t w1[] = { L'a', 0x20ac, 0 };
    for (size_t n = 0; n <= 4; n++) {
        wchar_t buf[6];
        for (int k = 0; k < 6; k++)
            buf[k] = 0x5a;
        size_t r = wcsxfrm(buf, w1, n);
        put_s("wcsxfrm n=");
        put_u(n);
        put_s(" r=");
        put_u(r);
        put_s(" ");
        put_wstr(buf, 5);
        nl();
    }
    {
        int x = strcasecmp("\xc4", "\xe4");
        put_s("strcasecmp-high ");
        put_i((x > 0) - (x < 0));
        x = strcasecmp("[", "{");
        put_s(" ");
        put_i((x > 0) - (x < 0));
        x = strcasecmp("_", "A");
        put_s(" ");
        put_i((x > 0) - (x < 0));
        nl();
    }
}

static void test_narrow_ctype(locale_t loc, const char *label)
{
    put_s("narrow-ctype ");
    put_s(label);
    nl();
    for (int c = -1; c < 256; c++) {
        unsigned mask = 0;
        mask |= (isalnum_l(c, loc) != 0) << 0;
        mask |= (isalpha_l(c, loc) != 0) << 1;
        mask |= (isblank_l(c, loc) != 0) << 2;
        mask |= (iscntrl_l(c, loc) != 0) << 3;
        mask |= (isdigit_l(c, loc) != 0) << 4;
        mask |= (isgraph_l(c, loc) != 0) << 5;
        mask |= (islower_l(c, loc) != 0) << 6;
        mask |= (isprint_l(c, loc) != 0) << 7;
        mask |= (ispunct_l(c, loc) != 0) << 8;
        mask |= (isspace_l(c, loc) != 0) << 9;
        mask |= (isupper_l(c, loc) != 0) << 10;
        mask |= (isxdigit_l(c, loc) != 0) << 11;
        unsigned plain = 0;
        plain |= (isalnum(c) != 0) << 0;
        plain |= (isalpha(c) != 0) << 1;
        plain |= (isblank(c) != 0) << 2;
        plain |= (iscntrl(c) != 0) << 3;
        plain |= (isdigit(c) != 0) << 4;
        plain |= (isgraph(c) != 0) << 5;
        plain |= (islower(c) != 0) << 6;
        plain |= (isprint(c) != 0) << 7;
        plain |= (ispunct(c) != 0) << 8;
        plain |= (isspace(c) != 0) << 9;
        plain |= (isupper(c) != 0) << 10;
        plain |= (isxdigit(c) != 0) << 11;
        put_i(c);
        put_s(" ");
        put_x(mask);
        put_s(" ");
        put_x(plain);
        put_s(" ");
        put_i(toupper_l(c, loc));
        put_s(" ");
        put_i(tolower_l(c, loc));
        put_s(" ");
        put_i(toupper(c));
        put_s(" ");
        put_i(tolower(c));
        nl();
    }
    const unsigned short *b = *__ctype_b_loc();
    const int32_t *lo = *__ctype_tolower_loc();
    const int32_t *up = *__ctype_toupper_loc();
    put_s("tables");
    for (int c = -128; c < 256; c++) {
        put_s(" ");
        put_x(b[c]);
        put_s("/");
        put_i(lo[c]);
        put_s("/");
        put_i(up[c]);
    }
    nl();
    for (int which = 0; which < 12; which++) {
        put_s("wide_l ");
        put_s(class_names[which]);
        put_s(":");
        int last = -1;
        wctype_t t = wctype_l(class_names[which], loc);
        for (long c = -1; c <= 0x300; c++) {
            int v = 0;
            switch (which) {
            case 0: v = iswalnum_l(c, loc) != 0; break;
            case 1: v = iswalpha_l(c, loc) != 0; break;
            case 2: v = iswblank_l(c, loc) != 0; break;
            case 3: v = iswcntrl_l(c, loc) != 0; break;
            case 4: v = iswdigit_l(c, loc) != 0; break;
            case 5: v = iswgraph_l(c, loc) != 0; break;
            case 6: v = iswlower_l(c, loc) != 0; break;
            case 7: v = iswprint_l(c, loc) != 0; break;
            case 8: v = iswpunct_l(c, loc) != 0; break;
            case 9: v = iswspace_l(c, loc) != 0; break;
            case 10: v = iswupper_l(c, loc) != 0; break;
            case 11: v = iswxdigit_l(c, loc) != 0; break;
            }
            v |= (iswctype_l(c, t, loc) != 0) << 1;
            if (v != last) {
                put_s(" ");
                put_i(c);
                put_s("=");
                put_i(v);
                last = v;
            }
        }
        nl();
    }
    put_s("tow_l");
    wctrans_t tu = wctrans_l("toupper", loc);
    for (long c = 0x60; c <= 0x7b; c++) {
        put_s(" ");
        put_x(towupper_l(c, loc));
        put_s("/");
        put_x(towlower_l(c - 0x20, loc));
        put_s("/");
        put_x(towctrans_l(c, tu, loc));
    }
    put_s(" ");
    put_x(towupper_l(0xe9, loc));
    nl();
    {
        static const wchar_t a[] = { L'A', 0xc9, 0 };
        static const wchar_t b2[] = { L'a', 0xe9, 0 };
        put_s("wcscasecmp_l ");
        put_i(wcscasecmp_l(a, b2, loc));
        put_s(" ");
        put_i(wcsncasecmp_l(a, b2, 1, loc));
        put_s(" strcasecmp_l ");
        put_i(strcasecmp_l("ABC", "abd", loc) < 0);
        put_s(" ");
        put_i(strncasecmp_l("ABC", "abd", 2, loc));
        put_s(" strcoll_l ");
        put_i(strcoll_l("a", "b", loc) < 0);
        put_s(" wcscoll_l ");
        put_i(wcscoll_l(a, b2, loc) < 0);
        char buf[8];
        memset(buf, 0x5a, 8);
        put_s(" strxfrm_l ");
        put_u(strxfrm_l(buf, "abc", 2, loc));
        put_hexbytes(buf, 4);
        wchar_t wbuf[4] = { 9, 9, 9, 9 };
        put_s(" wcsxfrm_l ");
        put_u(wcsxfrm_l(wbuf, a, 3, loc));
        put_wstr(wbuf, 4);
        nl();
    }
}

static const int langinfo_items[] = {
    CODESET, RADIXCHAR, THOUSEP, D_T_FMT, D_FMT, T_FMT, T_FMT_AMPM, AM_STR, PM_STR,
    DAY_1, DAY_7, ABDAY_1, ABDAY_7, MON_1, MON_12, ABMON_1, ABMON_12, ERA, ERA_D_FMT,
    ALT_DIGITS, ERA_D_T_FMT, ERA_T_FMT, YESEXPR, NOEXPR, CRNCYSTR,
    0, 1, 0x10000 - 1, 0x10000 + 2, 0x10000 + 3, 0x20000 + 0x31, 0x20000 + 0x32,
    0x20000 + 0x33, 0x30000 + 3, 0x40000 + 0, 0x40000 + 1, 0x50000 + 0, 0x50000 + 1,
    0x50000 + 2, 0x50000 + 4, 0x60000, 0x60000 + 0xffff, 0x50000 + 0xffff, 0x70000,
};

static void test_langinfo(locale_t loc, const char *label)
{
    put_s("langinfo ");
    put_s(label);
    nl();
    for (size_t i = 0; i < sizeof langinfo_items / sizeof langinfo_items[0]; i++) {
        put_x((unsigned)langinfo_items[i]);
        put_s(" ");
        put_cstr(nl_langinfo(langinfo_items[i]));
        if (loc != LC_GLOBAL_LOCALE) {
            put_s(" ");
            put_cstr(nl_langinfo_l(langinfo_items[i], loc));
        }
        nl();
    }
}

static void test_strerror_l(locale_t loc, const char *label)
{
    put_s("strerror_l ");
    put_s(label);
    nl();
    for (int e = -2; e <= 135; e++) {
        errno = SENTINEL_ERRNO;
        char *s = strerror_l(e, loc);
        put_i(e);
        put_s(" ");
        put_cstr(s);
        put_errno(errno);
        put_s(" same=");
        put_i(strcmp(s, strerror(e)) == 0);
        put_s(" internal=");
        put_i(strcmp(s, __strerror_l(e, loc)) == 0);
        nl();
    }
}

static void test_wcsftime(locale_t loc)
{
    section("wcsftime");
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = 124;
    tm.tm_mon = 1;
    tm.tm_mday = 29;
    tm.tm_hour = 13;
    tm.tm_min = 5;
    tm.tm_sec = 9;
    tm.tm_wday = 4;
    tm.tm_yday = 59;
    static const wchar_t f1[] = { L'%', L'Y', L'-', L'%', L'm', L'-', L'%', L'd', L' ', L'%', L'a', L' ', L'%', L'b', L' ', L'%', L'H', L':', L'%', L'M', L':', L'%', L'S', L' ', L'%', L'%', L' ', 0x20ac, 0 };
    static const wchar_t f2[] = { L'%', L'c', L'|', L'%', L'x', L'|', L'%', L'X', L'|', L'%', L'p', L'|', L'%', L'j', L'|', L'%', L'U', L'|', L'%', L'G', 0 };
    static const wchar_t f3[] = { L'%', L'E', L'c', L'%', L'O', L'd', L'%', L'q', 0 };
    const wchar_t *fmts[] = { f1, f2, f3 };
    for (size_t i = 0; i < 3; i++) {
        for (size_t cap = 0; cap <= 60; cap += (cap < 8 ? 1 : 13)) {
            wchar_t buf[64];
            for (int k = 0; k < 64; k++)
                buf[k] = 0x5a;
            size_t r = wcsftime(buf, cap, fmts[i], &tm);
            put_s("fmt");
            put_u(i);
            put_s(" cap=");
            put_u(cap);
            put_s(" r=");
            put_u(r);
            put_s(" ");
            put_wstr(buf, r + 1 < 64 ? r + 1 : 64);
            wchar_t buf2[64];
            size_t r2 = wcsftime_l(buf2, cap, fmts[i], &tm, loc);
            put_s(" l=");
            put_i(r2 == r && (r == 0 || wmemcmp(buf, buf2, r + 1) == 0));
            wchar_t buf3[64];
            size_t r3 = __wcsftime_l(buf3, cap, fmts[i], &tm, loc);
            put_s(" internal=");
            put_i(r3 == r && (r == 0 || wmemcmp(buf, buf3, r + 1) == 0));
            nl();
        }
    }
}

static const char *const locale_environment_names[] = {
    "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
    "LC_MESSAGES", "LANG",
};
#define LOCALE_ENVIRONMENT_COUNT (sizeof locale_environment_names / sizeof locale_environment_names[0])

/* Newlocale categories outside its mask and empty names consult the process
 * environment in musl, so each scenario installs an exact environment and the
 * caller's original values are restored afterwards. */
static void clear_locale_environment(void)
{
    for (size_t i = 0; i < LOCALE_ENVIRONMENT_COUNT; i++)
        unsetenv(locale_environment_names[i]);
}

static void test_locale_environment_scenarios(locale_t c_object, locale_t utf8_object)
{
    static const struct {
        const char *label;
        const char *assignments[4][2];
    } scenarios[] = {
        { "unset", { { NULL, NULL } } },
        { "lc-all-c", { { "LC_ALL", "C" }, { NULL, NULL } } },
        { "lang-utf8-ctype-posix", { { "LANG", "C.UTF-8" }, { "LC_CTYPE", "POSIX" }, { NULL, NULL } } },
        { "empty-lc-all-lang-utf8", { { "LC_ALL", "" }, { "LANG", "C.UTF-8" }, { NULL, NULL } } },
        { "lc-all-over-ctype", { { "LC_CTYPE", "C.UTF-8" }, { "LC_ALL", "C" }, { NULL, NULL } } },
        { "numeric-only-utf8", { { "LC_NUMERIC", "C.UTF-8" }, { "LANG", "C" }, { NULL, NULL } } },
    };
    for (size_t i = 0; i < sizeof scenarios / sizeof scenarios[0]; i++) {
        clear_locale_environment();
        for (size_t k = 0; scenarios[i].assignments[k][0]; k++)
            setenv(scenarios[i].assignments[k][0], scenarios[i].assignments[k][1], 1);
        locale_t n1 = newlocale(LC_NUMERIC_MASK, "C.UTF-8", (locale_t)0);
        locale_t e1 = newlocale(LC_ALL_MASK, "", (locale_t)0);
        locale_t z1 = newlocale(0, "C", (locale_t)0);
        locale_t t1 = newlocale(LC_TIME_MASK, "", (locale_t)0);
        put_s("env ");
        put_s(scenarios[i].label);
        put_s(" n1=");
        put_i(n1 == c_object ? 1 : n1 == utf8_object ? 2 : n1 ? 3 : 0);
        put_s(" e1=");
        put_i(e1 == c_object ? 1 : e1 == utf8_object ? 2 : e1 ? 3 : 0);
        put_s(" z1=");
        put_i(z1 == c_object ? 1 : z1 == utf8_object ? 2 : z1 ? 3 : 0);
        put_s(" t1=");
        put_i(t1 == c_object ? 1 : t1 == utf8_object ? 2 : t1 ? 3 : 0);
        if (e1) {
            uselocale(e1);
            put_s(" e1-mb=");
            put_u(MB_CUR_MAX);
            put_s(" e1-codeset=");
            put_cstr(nl_langinfo(CODESET));
            uselocale(LC_GLOBAL_LOCALE);
        }
        setlocale(LC_ALL, "C");
        put_s(" setlocale-all=");
        put_cstr(setlocale(LC_ALL, ""));
        put_s(" mb=");
        put_u(MB_CUR_MAX);
        setlocale(LC_ALL, "C");
        put_s(" setlocale-ctype=");
        put_cstr(setlocale(LC_CTYPE, ""));
        put_s(" setlocale-numeric=");
        put_cstr(setlocale(LC_NUMERIC, ""));
        put_s(" all=");
        put_cstr(setlocale(LC_ALL, NULL));
        setlocale(LC_ALL, "C");
        nl();
        if (n1)
            freelocale(n1);
        if (e1)
            freelocale(e1);
        if (z1)
            freelocale(z1);
        if (t1)
            freelocale(t1);
    }
}

static void test_locale_objects(void)
{
    section("locale-objects");
    char *saved[LOCALE_ENVIRONMENT_COUNT];
    for (size_t i = 0; i < LOCALE_ENVIRONMENT_COUNT; i++) {
        const char *value = getenv(locale_environment_names[i]);
        saved[i] = value ? strdup(value) : NULL;
    }
    /* Every object below names every category explicitly or has a base. */
    locale_t c1 = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    locale_t c2 = newlocale(LC_ALL_MASK, "POSIX", (locale_t)0);
    locale_t u1 = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    locale_t u3 = newlocale(LC_CTYPE_MASK, "C.UTF-8", c1);
    locale_t c3 = newlocale(LC_CTYPE_MASK, "C", u1);
    put_s("objs nonnull ");
    put_i(c1 != 0);
    put_i(c2 != 0);
    put_i(u1 != 0);
    put_i(u3 != 0);
    put_i(c3 != 0);
    put_s(" eq c1c2=");
    put_i(c1 == c2);
    put_s(" u1u3=");
    put_i(u1 == u3);
    put_s(" c1c3=");
    put_i(c1 == c3);
    nl();
    test_locale_environment_scenarios(c1, u1);
    clear_locale_environment();
    for (size_t i = 0; i < LOCALE_ENVIRONMENT_COUNT; i++) {
        if (saved[i]) {
            setenv(locale_environment_names[i], saved[i], 1);
            free(saved[i]);
        }
    }
    errno = SENTINEL_ERRNO;
    locale_t bad = newlocale(1 << 13, "C", (locale_t)0);
    put_s("badmask ");
    put_i(bad != 0);
    put_errno(errno);
    nl();
    locale_t d1 = duplocale(LC_GLOBAL_LOCALE);
    locale_t d2 = duplocale(u1);
    put_s("dup ");
    put_i(d1 != 0);
    put_i(d2 != 0);
    nl();
    locale_t prev = uselocale((locale_t)0);
    put_s("uselocale-initial-global ");
    put_i(prev == LC_GLOBAL_LOCALE);
    nl();
    for (int round = 0; round < 3; round++) {
        locale_t objs[3] = { c1, u1, u3 };
        locale_t old = uselocale(objs[round]);
        put_s("use ");
        put_i(round);
        put_s(" old-global=");
        put_i(old == LC_GLOBAL_LOCALE);
        put_s(" MB_CUR_MAX=");
        put_u(MB_CUR_MAX);
        wchar_t wc = 0;
        mbstate_t st;
        memset(&st, 0, sizeof st);
        size_t r = mbrtowc(&wc, "\xc3\xa9", 2, &st);
        put_s(" mbrtowc=");
        put_z(r);
        put_s("/");
        put_x((unsigned)wc);
        put_s(" codeset=");
        put_cstr(nl_langinfo(CODESET));
        put_s(" btowc80=");
        put_x(btowc(0x80));
        char buf[8];
        memset(&st, 0, sizeof st);
        r = wcrtomb(buf, 0xe9, &st);
        put_s(" wcrtomb=");
        put_z(r);
        put_s(" isalpha_e9=");
        put_i(isalpha(0xe9) != 0);
        put_s(" setlocale-query=");
        put_cstr(setlocale(LC_ALL, NULL));
        put_s(" ctype-query=");
        put_cstr(setlocale(LC_CTYPE, NULL));
        nl();
        uselocale(LC_GLOBAL_LOCALE);
    }
    locale_t back = uselocale((locale_t)0);
    put_s("restored ");
    put_i(back == LC_GLOBAL_LOCALE);
    nl();
    /* modify an allocated duplicate through newlocale's base */
    locale_t m2 = newlocale(LC_CTYPE_MASK, "C.UTF-8", d1);
    put_s("modify m2-nonnull=");
    put_i(m2 != 0);
    uselocale(m2);
    put_s(" MB=");
    put_u(MB_CUR_MAX);
    uselocale(LC_GLOBAL_LOCALE);
    locale_t m3 = newlocale(LC_MESSAGES_MASK | LC_TIME_MASK, "C.UTF-8", m2);
    uselocale(m3);
    put_s(" m3-MB=");
    put_u(MB_CUR_MAX);
    put_s(" m3-codeset=");
    put_cstr(nl_langinfo(CODESET));
    uselocale(LC_GLOBAL_LOCALE);
    nl();
    freelocale(m3);
    freelocale(d2);
    freelocale(c1);
    freelocale(c2);
    freelocale(u1);
    freelocale(u3);
    freelocale(c3);
}

/* iconv */
static const char *const iconv_names[] = {
    "UTF-8", "utf8", "ASCII", "US-ASCII", "ISO646-US", "UTF-16LE", "UTF-16BE",
    "UTF-32LE", "UTF-32BE", "UCS-4LE", "UCS-4BE", "WCHAR_T", "char", "",
    "u_t_f_8", "UTF8//TRANSLIT", "utf-8 ", "utf:8", "BOGUS", "UTF-7",
};
#define ICONV_NAME_COUNT (sizeof iconv_names / sizeof iconv_names[0])

static const char *const iconv_codecs[] = {
    "UTF-8", "ASCII", "UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE", "WCHAR_T",
};
#define ICONV_CODEC_COUNT (sizeof iconv_codecs / sizeof iconv_codecs[0])

static size_t encode_input(const char *codec, const uint32_t *cps, size_t n, unsigned char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t c = cps[i];
        if (!strcmp(codec, "UTF-8") || !strcmp(codec, "ASCII")) {
            if (c < 0x80) out[o++] = (unsigned char)c;
            else if (c < 0x800) { out[o++] = 0xc0 | (c >> 6); out[o++] = 0x80 | (c & 63); }
            else if (c < 0x10000) { out[o++] = 0xe0 | (c >> 12); out[o++] = 0x80 | ((c >> 6) & 63); out[o++] = 0x80 | (c & 63); }
            else { out[o++] = 0xf0 | (c >> 18); out[o++] = 0x80 | ((c >> 12) & 63); out[o++] = 0x80 | ((c >> 6) & 63); out[o++] = 0x80 | (c & 63); }
        } else if (!strncmp(codec, "UTF-16", 6)) {
            int be = codec[6] == 'B';
            uint16_t u[2];
            size_t k = 0;
            if (c >= 0x10000) { u[0] = 0xd800 | ((c - 0x10000) >> 10); u[1] = 0xdc00 | ((c - 0x10000) & 0x3ff); k = 2; }
            else { u[0] = (uint16_t)c; k = 1; }
            for (size_t j = 0; j < k; j++) {
                if (be) { out[o++] = u[j] >> 8; out[o++] = u[j] & 255; }
                else { out[o++] = u[j] & 255; out[o++] = u[j] >> 8; }
            }
        } else {
            int be = !strcmp(codec, "UTF-32BE");
            if (be) { out[o++] = c >> 24; out[o++] = c >> 16; out[o++] = c >> 8; out[o++] = c; }
            else { out[o++] = c; out[o++] = c >> 8; out[o++] = c >> 16; out[o++] = c >> 24; }
        }
    }
    return o;
}

static void iconv_run(iconv_t cd, const unsigned char *in, size_t inlen, size_t outcap)
{
    unsigned char outb[64];
    memset(outb, 0x5a, sizeof outb);
    char *ip = (char *)in;
    size_t il = inlen;
    char *op = (char *)outb;
    size_t ol = outcap;
    errno = SENTINEL_ERRNO;
    size_t r = iconv(cd, &ip, &il, &op, &ol);
    put_s(" r=");
    put_z(r);
    put_s(" in=");
    put_u((size_t)(ip - (char *)in));
    put_s(" il=");
    put_u(il);
    put_s(" out=");
    put_u((size_t)(op - (char *)outb));
    put_s(" ol=");
    put_u(ol);
    put_errno(errno);
    put_s(" ");
    put_hexbytes(outb, (size_t)(op - (char *)outb) + 1);
}

static void test_iconv(void)
{
    section("iconv-open");
    for (size_t i = 0; i < ICONV_NAME_COUNT; i++) {
        for (size_t j = 0; j < ICONV_NAME_COUNT; j++) {
            errno = SENTINEL_ERRNO;
            iconv_t cd = iconv_open(iconv_names[i], iconv_names[j]);
            put_cstr(iconv_names[i]);
            put_s("<-");
            put_cstr(iconv_names[j]);
            put_s(" ok=");
            put_i(cd != (iconv_t)-1);
            if (cd == (iconv_t)-1)
                put_errno(errno);
            else {
                errno = SENTINEL_ERRNO;
                put_s(" close=");
                put_i(iconv_close(cd));
                put_errno(errno);
            }
            nl();
        }
    }
    section("iconv-convert");
    static const uint32_t text_cps[] = { 0x41, 0xe9, 0x20ac, 0x1f600, 0x7f, 0 , 0x10ffff };
    for (size_t f = 0; f < ICONV_CODEC_COUNT; f++) {
        for (size_t t = 0; t < ICONV_CODEC_COUNT; t++) {
            iconv_t cd = iconv_open(iconv_codecs[t], iconv_codecs[f]);
            put_s(iconv_codecs[t]);
            put_s("<-");
            put_s(iconv_codecs[f]);
            if (cd == (iconv_t)-1) {
                put_s(" open-failed");
                nl();
                continue;
            }
            nl();
            unsigned char in[64];
            size_t inlen = encode_input(iconv_codecs[f], text_cps, 7, in);
            if (!strcmp(iconv_codecs[f], "ASCII"))
                inlen = encode_input(iconv_codecs[f], text_cps, 1, in);
            for (size_t cap = 0; cap <= 30; cap += (cap < 12 ? 1 : 9)) {
                put_s("  cap=");
                put_u(cap);
                iconv_run(cd, in, inlen, cap);
                nl();
            }
            for (size_t k = 0; k <= inlen; k++) {
                put_s("  partial=");
                put_u(k);
                iconv_run(cd, in, k, 64);
                nl();
            }
            /* reset forms */
            {
                char *op;
                size_t ol = 8;
                unsigned char ob[8];
                op = (char *)ob;
                errno = SENTINEL_ERRNO;
                size_t r = iconv(cd, NULL, NULL, &op, &ol);
                put_s("  reset1=");
                put_z(r);
                put_s(" ol=");
                put_u(ol);
                put_errno(errno);
                errno = SENTINEL_ERRNO;
                r = iconv(cd, NULL, NULL, NULL, NULL);
                put_s(" reset2=");
                put_z(r);
                put_errno(errno);
                char *nullin = NULL;
                size_t zero = 5;
                errno = SENTINEL_ERRNO;
                r = iconv(cd, &nullin, &zero, &op, &ol);
                put_s(" reset3=");
                put_z(r);
                put_errno(errno);
                char *ip = (char *)in;
                zero = 0;
                r = iconv(cd, &ip, &zero, NULL, NULL);
                put_s(" empty=");
                put_z(r);
                nl();
            }
            iconv_close(cd);
        }
    }
    section("iconv-invalid");
    static const struct {
        const char *from;
        const char *bytes;
        size_t len;
    } bad[] = {
        { "UTF-8", "A\xc0\x80" "B", 4 },
        { "UTF-8", "A\xed\xa0\x80" "B", 5 },
        { "UTF-8", "A\xf4\x90\x80\x80", 5 },
        { "UTF-8", "A\xe2\x82", 3 },
        { "UTF-8", "A\x80", 2 },
        /* Truncated sequences whose available continuation bytes are
         * already invalid: musl's mbrtowc decoder reports EILSEQ before it
         * would report the incomplete tail. */
        { "UTF-8", "A\xf4\xed", 3 },
        { "UTF-8", "A\xe0\x80", 3 },
        { "UTF-8", "A\xed\xa0", 3 },
        { "UTF-8", "A\xf4\x90", 3 },
        { "UTF-8", "A\xf0\x9f\x41", 4 },
        { "UTF-8", "A\xe0\xe0", 3 },
        { "UTF-8", "A\xf0\x9f\x98", 4 },
        { "ASCII", "A\x80" "B", 3 },
        { "UTF-16LE", "A\x00\x00\xd8" "B\x00", 6 },
        { "UTF-16LE", "A\x00\x00\xdc", 4 },
        { "UTF-16LE", "A\x00\x00\xd8", 4 },
        { "UTF-16LE", "A\x00\x00", 3 },
        { "UTF-16BE", "\xd8\x3d\xde", 3 },
        { "UTF-32LE", "\x00\xd8\x00\x00", 4 },
        { "UTF-32LE", "\x00\x00\x11\x00", 4 },
        { "UTF-32BE", "\x00\x00\x00\x41\x00\x00", 6 },
        { "WCHAR_T", "\xff\xff\xff\xff", 4 },
        { "WCHAR_T", "\x00\xdc\x00\x00", 4 },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        for (size_t t = 0; t < ICONV_CODEC_COUNT; t++) {
            iconv_t cd = iconv_open(iconv_codecs[t], bad[i].from);
            put_s(iconv_codecs[t]);
            put_s("<-");
            put_s(bad[i].from);
            put_s(" ");
            put_hexbytes(bad[i].bytes, bad[i].len);
            iconv_run(cd, (const unsigned char *)bad[i].bytes, bad[i].len, 64);
            nl();
            iconv_close(cd);
        }
    }
    /* multiple ascii substitutions */
    {
        iconv_t cd = iconv_open("ASCII", "UTF-8");
        const char in[] = "a\xc3\xa9" "b\xe2\x82\xac" "c\xf0\x9f\x98\x80";
        put_s("ascii-subst");
        iconv_run(cd, (const unsigned char *)in, sizeof in - 1, 64);
        put_s(" small");
        iconv_run(cd, (const unsigned char *)in, sizeof in - 1, 3);
        nl();
        iconv_close(cd);
        cd = iconv_open("UTF-16LE", "UTF-8");
        put_s("utf16-surrogate-out-cap2");
        iconv_run(cd, (const unsigned char *)"\xf0\x9f\x98\x80", 4, 2);
        put_s(" cap3");
        iconv_run(cd, (const unsigned char *)"\xf0\x9f\x98\x80", 4, 3);
        nl();
        iconv_close(cd);
        cd = iconv_open("UTF-8", "UTF-16LE");
        put_s("utf8-out-cap");
        for (size_t cap = 0; cap <= 4; cap++)
            iconv_run(cd, (const unsigned char *)"\x3d\xd8\x00\xde", 4, cap);
        nl();
        iconv_close(cd);
    }
}


/* numeric wide/narrow parsing */
static const wchar_t *wnum_inputs[] = {
    L"0", L"  +42xyz", L"-0x1Fg", L"0x", L"0X", L"08", L"0b101", L"z", L"Zz",
    L"\x3000\x2003-17", L"\x00a0" L"5", L"9223372036854775807", L"9223372036854775808",
    L"-9223372036854775808", L"-9223372036854775809", L"18446744073709551615",
    L"18446744073709551616", L"-1", L"99999999999999999999999999", L"", L"+", L"-",
    L"\t\n\v\f\r 7", L"1\x0661", L"\x0661",
};

static void test_wide_integers(void)
{
    section("wide-integers");
    static const int bases[] = { 0, 2, 8, 10, 16, 36, 1, 37, -1 };
    for (size_t i = 0; i < sizeof wnum_inputs / sizeof wnum_inputs[0]; i++) {
        const wchar_t *in = wnum_inputs[i];
        put_s("in ");
        put_wstr(in, wcslen(in) + 1);
        nl();
        for (size_t b = 0; b < sizeof bases / sizeof bases[0]; b++) {
            wchar_t *end;
            errno = SENTINEL_ERRNO;
            long l = wcstol(in, &end, bases[b]);
            int e1 = errno;
            long e1p = end - in;
            errno = SENTINEL_ERRNO;
            unsigned long ul = wcstoul(in, &end, bases[b]);
            int e2 = errno;
            long e2p = end - in;
            errno = SENTINEL_ERRNO;
            long long ll = wcstoll(in, &end, bases[b]);
            int e3 = errno;
            long e3p = end - in;
            errno = SENTINEL_ERRNO;
            unsigned long long ull = wcstoull(in, &end, bases[b]);
            int e4 = errno;
            long e4p = end - in;
            errno = SENTINEL_ERRNO;
            intmax_t im = wcstoimax(in, &end, bases[b]);
            int e5 = errno;
            long e5p = end - in;
            errno = SENTINEL_ERRNO;
            uintmax_t um = wcstoumax(in, &end, bases[b]);
            int e6 = errno;
            long e6p = end - in;
            put_s("  b=");
            put_i(bases[b]);
            put_s(" l=");
            put_i(l);
            put_s("/");
            put_i(e1p);
            put_s("/");
            put_i(e1);
            put_s(" ul=");
            put_u(ul);
            put_s("/");
            put_i(e2p);
            put_s("/");
            put_i(e2);
            put_s(" ll=");
            put_i(ll);
            put_s("/");
            put_i(e3p);
            put_s("/");
            put_i(e3);
            put_s(" ull=");
            put_u(ull);
            put_s("/");
            put_i(e4p);
            put_s("/");
            put_i(e4);
            put_s(" im=");
            put_i(im);
            put_s("/");
            put_i(e5p);
            put_s("/");
            put_i(e5);
            put_s(" um=");
            put_u(um);
            put_s("/");
            put_i(e6p);
            put_s("/");
            put_i(e6);
            nl();
        }
    }
}

static const wchar_t *wfloat_inputs[] = {
    L"0", L"-0", L"1.5e3xyz", L"  .5", L".", L"-.e1", L"1e", L"1e+", L"1e-400", L"1e400",
    L"-1e400", L"inf", L"-INFINITY", L"infin", L"nan", L"NaN(123)", L"nan(", L"nan(abc_9)x",
    L"0x1.8p1", L"0x", L"0x.p1", L"0x1p-1074", L"0x1p-1075", L"0x1p-1076", L"0x1.fffffffffffff8p1023",
    L"4.9406564584124654e-324", L"2.4703282292062327e-324", L"2.4703282292062328e-324",
    L"1.7976931348623157e308", L"1.7976931348623158e308", L"1.7976931348623159e308",
    L"3.4028235e38", L"3.40282357e38", L"1e-45", L"0.1", L"123456789012345678901234567890",
    L"\x3000" L"2.5", L"1,5", L"0x1P+3", L"   -0x0.0p0", L"1e-4950", L"1e4933", L"1.18973149535723176502e+4932",
};

static void put_ld(long double v)
{
    unsigned char b[16];
    memset(b, 0, sizeof b);
    memcpy(b, &v, 10);
    put_hexbytes(b, 10);
}

static void test_wide_floats(void)
{
    section("wide-floats");
    for (size_t i = 0; i < sizeof wfloat_inputs / sizeof wfloat_inputs[0]; i++) {
        const wchar_t *in = wfloat_inputs[i];
        wchar_t *end;
        put_wstr(in, wcslen(in) + 1);
        errno = SENTINEL_ERRNO;
        double d = wcstod(in, &end);
        uint64_t db;
        memcpy(&db, &d, 8);
        put_s(" d=");
        put_x(db);
        put_s("/");
        put_i(end - in);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        float f = wcstof(in, &end);
        uint32_t fb;
        memcpy(&fb, &f, 4);
        put_s(" f=");
        put_x(fb);
        put_s("/");
        put_i(end - in);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        long double ld = wcstold(in, &end);
        put_s(" ld=");
        put_ld(ld);
        put_s("/");
        put_i(end - in);
        put_errno(errno);
        /* narrow twin through the C locale object */
        char narrow[128];
        size_t k = 0;
        for (; in[k] && k < sizeof narrow - 1; k++)
            narrow[k] = in[k] < 0x80 ? (char)in[k] : '?';
        narrow[k] = 0;
        char *nend;
        locale_t c = newlocale(LC_ALL_MASK, "C", (locale_t)0);
        errno = SENTINEL_ERRNO;
        d = strtod_l(narrow, &nend, c);
        memcpy(&db, &d, 8);
        put_s(" strtod_l=");
        put_x(db);
        put_s("/");
        put_i(nend - narrow);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        ld = strtold_l(narrow, &nend, c);
        put_s(" strtold_l=");
        put_ld(ld);
        put_s("/");
        put_i(nend - narrow);
        put_errno(errno);
        errno = SENTINEL_ERRNO;
        f = strtof_l(narrow, &nend, c);
        memcpy(&fb, &f, 4);
        put_s(" strtof_l=");
        put_x(fb);
        put_s("/");
        put_i(nend - narrow);
        put_errno(errno);
        d = atof(narrow);
        memcpy(&db, &d, 8);
        put_s(" atof=");
        put_x(db);
        freelocale(c);
        nl();
    }
}

static void test_legacy_decimal(void)
{
    section("legacy-decimal");
    static const double values[] = { 0.0, -0.0, 1.0, -1.5, 123.456, 1e-5, 9.99999, 1e300, 0.5, 2.5, 1e22, 1.0 / 3.0 };
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        for (int nd = 0; nd <= 17; nd += 3) {
            int dec = 0, sign = 0;
            char *e = ecvt(values[i], nd, &dec, &sign);
            put_s("ecvt ");
            put_u(i);
            put_s(" ");
            put_i(nd);
            put_s(" ");
            put_cstr(e);
            put_s(" ");
            put_i(dec);
            put_s(" ");
            put_i(sign);
            char *f = fcvt(values[i], nd, &dec, &sign);
            put_s(" fcvt ");
            put_cstr(f);
            put_s(" ");
            put_i(dec);
            put_s(" ");
            put_i(sign);
            char buf[64];
            memset(buf, 0, sizeof buf);
            char *g = gcvt(values[i], nd ? nd : 1, buf);
            put_s(" gcvt ");
            put_i(g == buf);
            put_s(" ");
            put_cstr(buf);
            nl();
        }
    }
    {
        char opts[] = "ro,rw=5,bogus,,size=10,ro";
        char *const tokens[] = { "ro", "rw", "size", NULL };
        char *p = opts;
        put_s("getsubopt");
        while (*p) {
            char *value = (char *)0x1;
            char *before = p;
            int r = getsubopt(&p, tokens, &value);
            put_s(" ");
            put_i(r);
            put_s("/");
            put_i(p - opts);
            put_s("/");
            if (value == (char *)0x1)
                put_s("untouched");
            else
                put_cstr(value);
            put_s("/");
            put_cstr(before);
        }
        nl();
    }
}

static void *thread_locale_body(void *arg)
{
    locale_t u = arg;
    locale_t initial = uselocale((locale_t)0);
    put_s("thread initial-global=");
    put_i(initial == LC_GLOBAL_LOCALE);
    put_s(" mb=");
    put_u(MB_CUR_MAX);
    uselocale(u);
    put_s(" after-use mb=");
    put_u(MB_CUR_MAX);
    wchar_t wc = 0;
    size_t r = mbrtowc(&wc, "\xc3\xa9", 2, NULL);
    put_s(" mbrtowc=");
    put_z(r);
    put_s("/");
    put_x((unsigned)wc);
    nl();
    return NULL;
}

static void test_thread_locale(void)
{
    section("thread-locale");
    setlocale(LC_ALL, "C");
    locale_t u = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    pthread_t t;
    if (pthread_create(&t, NULL, thread_locale_body, u) != 0) {
        put_s("pthread_create failed");
        nl();
        return;
    }
    pthread_join(t, NULL);
    put_s("main after thread mb=");
    put_u(MB_CUR_MAX);
    put_s(" current-global=");
    put_i(uselocale((locale_t)0) == LC_GLOBAL_LOCALE);
    nl();
    /* global change is visible to a thread that uses the global locale */
    setlocale(LC_CTYPE, "C.UTF-8");
    pthread_create(&t, NULL, thread_locale_body, u);
    pthread_join(t, NULL);
    setlocale(LC_ALL, "C");
    freelocale(u);
}

static void test_mbrtowc_extreme(void)
{
    section("mbrtowc-extreme");
    mbstate_t st;
    memset(&st, 0, sizeof st);
    wchar_t wc = 0;
    errno = SENTINEL_ERRNO;
    size_t r = mbrtowc(&wc, "\xe2\x82\xac", (size_t)-1, &st);
    put_s("huge-n r=");
    put_z(r);
    put_s(" wc=");
    put_x((unsigned)wc);
    put_errno(errno);
    r = mbrlen("\xf0\x9f\x98\x80", (size_t)-1, &st);
    put_s(" mbrlen=");
    put_z(r);
    nl();
    /* mbsinit on garbage nonzero second word */
    unsigned words[2] = { 0, 0x12345678 };
    put_s("mbsinit-second-word=");
    put_i(mbsinit((mbstate_t *)words) != 0);
    put_s(" null=");
    put_i(mbsinit(NULL) != 0);
    nl();
    /* state carried from C.UTF-8 into C locale */
    setlocale(LC_ALL, "C.UTF-8");
    memset(&st, 0, sizeof st);
    mbrtowc(&wc, "\xe2", 1, &st);
    setlocale(LC_ALL, "C");
    errno = SENTINEL_ERRNO;
    wc = 0;
    r = mbrtowc(&wc, "\x82\xac", 2, &st);
    put_s("cross-locale-resume r=");
    put_z(r);
    put_s(" wc=");
    put_x((unsigned)wc);
    put_errno(errno);
    dump_mbstate(&st);
    nl();
    setlocale(LC_ALL, "C.UTF-8");
    memset(&st, 0, sizeof st);
    mbrtowc(&wc, "\xe2", 1, &st);
    setlocale(LC_ALL, "C");
    const char *src = "\x82\xac" "Z";
    wchar_t dst[4] = { 1, 1, 1, 1 };
    errno = SENTINEL_ERRNO;
    r = mbsrtowcs(dst, &src, 4, &st);
    put_s("cross-locale-mbsrtowcs r=");
    put_z(r);
    put_errno(errno);
    put_wstr(dst, 4);
    nl();
    setlocale(LC_ALL, "C");
}

static void test_iconv_more(void)
{
    section("iconv-more");
    static const char *const pairs[][2] = {
        { "", "" }, { "UTF-8", "" }, { "", "WCHAR_T" }, { "ascii", "utf8" }, { "UTF16LE", "utf32be" },
        { "WCHAR_T", "UTF-16BE" }, { "ASCII", "WCHAR_T" }, { "ASCII", "UTF-32LE" },
    };
    static const unsigned char payload[] = { 'h', 0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80, 'x' };
    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
        iconv_t cd = iconv_open(pairs[i][0], pairs[i][1]);
        put_cstr(pairs[i][0]);
        put_s("<-");
        put_cstr(pairs[i][1]);
        if (cd == (iconv_t)-1) {
            put_s(" fail");
            nl();
            continue;
        }
        /* feed UTF-8 converted into the source encoding via a first pass */
        iconv_t pre = iconv_open(pairs[i][1], "UTF-8");
        unsigned char mid[64];
        char *ip = (char *)payload;
        size_t il = sizeof payload;
        char *op = (char *)mid;
        size_t ol = sizeof mid;
        size_t pr = iconv(pre, &ip, &il, &op, &ol);
        iconv_close(pre);
        size_t midlen = (size_t)(op - (char *)mid);
        put_s(" pre=");
        put_z(pr);
        put_s(" ");
        put_hexbytes(mid, midlen);
        for (size_t cap = 0; cap < 40; cap += 3) {
            put_s(" |");
            put_u(cap);
            iconv_run(cd, mid, midlen, cap);
        }
        nl();
        iconv_close(cd);
    }
}

int crabc_x86_64_text_locale_differential_probe(void)
{
    section("initial");
    put_s("setlocale-query=");
    put_cstr(setlocale(LC_ALL, NULL));
    put_s(" MB_CUR_MAX=");
    put_u(MB_CUR_MAX);
    nl();
    section("setlocale");
    {
        static const char *const names[] = {
            "C", "POSIX", "C.UTF-8", "C.UTF-8;C;C;C;C;C", NULL,
        };
        for (int cat = 0; cat <= 7; cat++) {
            for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
                /* Outside LC_ALL musl treats a `;` list as one arbitrary
                 * map name, which the fixed profile rejects; keep that
                 * intentional difference out. */
                if (i == 3 && cat != LC_ALL)
                    continue;
                setlocale(LC_ALL, "C");
                char *r = setlocale(cat, names[i]);
                put_i(cat);
                put_s(" ");
                put_cstr(names[i]);
                put_s(" -> ");
                put_cstr(r);
                put_s(" all=");
                put_cstr(setlocale(LC_ALL, NULL));
                put_s(" mb=");
                put_u(MB_CUR_MAX);
                nl();
            }
        }
        setlocale(LC_ALL, "C");
        /* Musl's LC_ALL parser: six `;` components, the last one reused
         * once the name is exhausted, extra components ignored, and empty
         * components resolved from the environment, which each pass sets
         * explicitly. Every component here is a profile name. */
        static const char *const composites[] = {
            "C.UTF-8;C", "C;C.UTF-8", "POSIX;C;C;C;C;C", "C.UTF-8;POSIX;C;C;C;C",
            "C.UTF-8;C;C;C;C;C;C", "C.UTF-8;C;C;C;C;C;junk", "C;C;C;C;C;C.UTF-8",
            "C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8;C.UTF-8", "C.UTF-8;", "C;",
            "C.UTF-8;;;;;", "POSIX;C.UTF-8", ";C.UTF-8", "C.UTF-8;C;C;C;C", ";",
        };
        const char *saved = getenv("LC_ALL");
        char saved_copy[32] = "";
        if (saved != NULL && strlen(saved) < sizeof saved_copy)
            strcpy(saved_copy, saved);
        for (size_t i = 0; i < 2 * (sizeof composites / sizeof composites[0]); i++) {
            size_t pass = i / (sizeof composites / sizeof composites[0]);
            if (i % (sizeof composites / sizeof composites[0]) == 0) {
                setenv("LC_ALL", pass ? "C.UTF-8" : "C", 1);
                put_s("composite-env LC_ALL=");
                put_s(pass ? "C.UTF-8" : "C");
                nl();
            }
            setlocale(LC_ALL, "C");
            const char *name = composites[i % (sizeof composites / sizeof composites[0])];
            char *r = setlocale(LC_ALL, name);
            put_s("composite ");
            put_cstr(name);
            put_s(" -> ");
            put_cstr(r);
            for (int cat = 0; cat < LC_ALL; cat++) {
                put_s(" ");
                put_cstr(setlocale(cat, NULL));
            }
            put_s(" mb=");
            put_u(MB_CUR_MAX);
            nl();
        }
        if (saved != NULL)
            setenv("LC_ALL", saved_copy, 1);
        else
            unsetenv("LC_ALL");
        setlocale(LC_ALL, "C");
    }
    /* POSIX is the same byte-oriented profile as C; the per-locale matrix
     * below therefore runs C and C.UTF-8 only. */
    static const char *const locales[] = { "C", "C.UTF-8" };
    for (size_t li = 0; li < sizeof locales / sizeof locales[0]; li++) {
        if (select_global_locale(locales[li]) != 0) {
            flush_out();
            return 1;
        }
        put_s("##### locale ");
        put_s(locales[li]);
        put_s(" MB_CUR_MAX=");
        put_u(MB_CUR_MAX);
        nl();
        test_mbrtowc_bytes();
        test_mbrtowc_corpus();
        test_wcrtomb();
        test_mbsrtowcs();
        test_wcsrtombs();
        test_uchar();
        test_collation();
        test_langinfo(LC_GLOBAL_LOCALE, "global");
    }
    if (select_global_locale("C") != 0) {
        flush_out();
        return 2;
    }
    test_wide_classes();
    test_wide_case();
    test_wcwidth();
    test_wide_strings();
    {
        locale_t c = newlocale(LC_ALL_MASK, "C", (locale_t)0);
        locale_t u = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
        if (c == (locale_t)0 || u == (locale_t)0) {
            flush_out();
            return 3;
        }
        test_narrow_ctype(c, "C");
        test_narrow_ctype(u, "C.UTF-8");
        test_langinfo(c, "obj-C");
        test_langinfo(u, "obj-UTF8");
        test_strerror_l(c, "C");
        test_strerror_l(u, "C.UTF-8");
        test_wcsftime(c);
        freelocale(c);
        freelocale(u);
    }
    test_locale_objects();
    test_iconv();
    test_iconv_more();
    test_wide_integers();
    test_wide_floats();
    test_legacy_decimal();
    test_mbrtowc_extreme();
    test_thread_locale();
    section("end");
    flush_out();
    /* Leave the global and calling-thread locale as the next role expects. */
    setlocale(LC_ALL, "C");
    uselocale(LC_GLOBAL_LOCALE);
    return 0;
}

int main(void)
{
    return crabc_x86_64_text_locale_differential_probe();
}
