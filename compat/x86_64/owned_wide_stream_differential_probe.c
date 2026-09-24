/* Installed wide FILE entry differential transcript for text.wide-multibyte.
 *
 * The frozen text.wide-multibyte capability includes thirty FILE-oriented
 * wide entries. Their stream engine is owned by the stdio implementation; this
 * role only proves the text capability's observable C results against pinned
 * musl 1.2.6. Like the text/locale transcript it records exact results and
 * carries no expected values: the component runner requires the same bytes
 * from musl and every supplied static/dynamic product.
 *
 * Streams are anonymous memfd descriptors, memory streams, and standard
 * streams, so dynamic chroot execution needs no writable filesystem. Standard
 * input is replaced by a memfd before its first use. Standard output is
 * reopened with freopen(NULL, "w", stdout) around the stdout-only wide entries
 * so that its orientation starts unoriented and is reset afterwards; mixing
 * byte and wide output on one stream is undefined in C and never exercised.
 * Byte output from this role uses write(2) directly.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <locale.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

static char out_buffer[1 << 15];
static size_t out_used;

static int flush_out(void)
{
    size_t done = 0;
    while (done < out_used) {
        ssize_t n = write(1, out_buffer + done, out_used - done);
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    out_used = 0;
    return 0;
}

static void put_bytes(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (out_used == sizeof out_buffer)
            (void)flush_out();
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

#define SENTINEL_ERRNO 1234

static void section(const char *name)
{
    put_s("== ");
    put_s(name);
    nl();
}

/* An anonymous descriptor-backed stream; no filesystem path is required. */
static FILE *memfd_stream(const char *bytes, size_t length)
{
    int fd = memfd_create("crabc-wide-stream", MFD_CLOEXEC);
    if (fd < 0)
        return NULL;
    if (length && write(fd, bytes, length) != (ssize_t)length) {
        close(fd);
        return NULL;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        return NULL;
    }
    FILE *f = fdopen(fd, "w+");
    if (!f)
        close(fd);
    return f;
}

static void dump_file(FILE *f)
{
    fflush(f);
    long end = ftell(f);
    put_s(" pos=");
    put_i(end);
    unsigned char buf[256];
    ssize_t n = pread(fileno(f), buf, sizeof buf, 0);
    put_s(" bytes=");
    put_hexbytes(buf, n > 0 ? (size_t)n : 0);
}

static void put_weof(wint_t c, FILE *f)
{
    put_s(" ");
    put_x(c);
    if (c == WEOF) {
        put_s("/e");
        put_i(errno);
        put_s("/eof");
        put_i(feof(f) != 0);
        put_s("/err");
        put_i(ferror(f) != 0);
        put_s("/tell");
        put_i(ftell(f));
        clearerr(f);
        errno = SENTINEL_ERRNO;
    }
}

static int vcall(wchar_t *buf, size_t n, const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vswprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}

static int vscall(const wchar_t *in, const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vswscanf(in, fmt, ap);
    va_end(ap);
    return r;
}

static int vfcall(FILE *f, const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vfwprintf(f, fmt, ap);
    va_end(ap);
    return r;
}

static int vfscall(FILE *f, const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vfwscanf(f, fmt, ap);
    va_end(ap);
    return r;
}

static int vstdout_call(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vwprintf(fmt, ap);
    va_end(ap);
    return r;
}

static int vstdin_call(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = vwscanf(fmt, ap);
    va_end(ap);
    return r;
}

static void test_swprintf(void)
{
    section("swprintf");
    static const wchar_t *const fmts[] = {
        L"%d|%5d|%-5d|%05d|%+d|% d",
        L"%x|%#x|%o|%#o|%X|%u",
        L"%s|%.2s|%10s|%-10s|",
        L"%ls|%.2ls|%5ls|",
        L"%c|%lc|%5lc",
        L"%f|%e|%g|%a|%.3f|%10.2e",
        L"%%|%n",
        L"%p",
        L"%zd|%jd|%hhd|%hd|%lld",
        L"%Lf|%Le|%La",
        L"%1$d %2$ls %1$d",
        L"%s",
        L"%lc",
        L"%ls",
    };
    static const wchar_t wide_arg[] = { L'w', 0x20ac, 0x1f600, L'z', 0 };
    static const wchar_t bad_wide_arg[] = { L'a', 0xd800, 0 };
    for (int loc = 0; loc < 2; loc++) {
        setlocale(LC_ALL, loc ? "C.UTF-8" : "C");
        for (size_t i = 0; i < sizeof fmts / sizeof fmts[0]; i++) {
            for (size_t cap = 0; cap <= 64; cap += (cap < 6 ? 1 : 29)) {
                wchar_t buf[128];
                for (int k = 0; k < 128; k++)
                    buf[k] = 0x5a;
                int r = 0;
                int n = -7;
                errno = SENTINEL_ERRNO;
                switch (i) {
                case 0: r = swprintf(buf, cap, fmts[i], 42, -42, 42, -42, 42, 42); break;
                case 1: r = swprintf(buf, cap, fmts[i], 255u, 255u, 8u, 8u, 0xabcu, 4000000000u); break;
                case 2: r = swprintf(buf, cap, fmts[i], "a\xc3\xa9z", "a\xc3\xa9z", "a\xc3\xa9z", "a\xc3\xa9z"); break;
                case 3: r = swprintf(buf, cap, fmts[i], wide_arg, wide_arg, wide_arg); break;
                case 4: r = swprintf(buf, cap, fmts[i], 'q', (wint_t)0x20ac, (wint_t)0x1f600); break;
                case 5: r = swprintf(buf, cap, fmts[i], 1.5, 1234.5, 0.0001, 1.0, 2.0 / 3.0, -12345.678); break;
                case 6: r = swprintf(buf, cap, fmts[i], &n); break;
                case 7: r = swprintf(buf, cap, fmts[i], (void *)0x1234); break;
                case 8: r = swprintf(buf, cap, fmts[i], (size_t)7, (intmax_t)-8, 300, 70000, -5LL); break;
                case 9: r = swprintf(buf, cap, fmts[i], 1.5L, 1.5L, 1.5L); break;
                case 10: r = swprintf(buf, cap, fmts[i], 5, wide_arg); break;
                case 11: r = swprintf(buf, cap, fmts[i], "a\xff" "b"); break;
                case 12: r = swprintf(buf, cap, fmts[i], (wint_t)0xd800); break;
                case 13: r = swprintf(buf, cap, fmts[i], bad_wide_arg); break;
                }
                int e = errno;
                put_s("loc");
                put_i(loc);
                put_s(" case");
                put_u(i);
                put_s(" cap=");
                put_u(cap);
                put_s(" r=");
                put_i(r);
                put_s(" errno=");
                put_i(e);
                put_s(" n=");
                put_i(n);
                put_s(" ");
                put_wstr(buf, cap < 64 ? cap + 1 : 64);
                nl();
            }
        }
        wchar_t buf[32];
        int r = vcall(buf, 32, L"%s=%d", "k", 5);
        put_s("vswprintf=");
        put_i(r);
        put_wstr(buf, 5);
        nl();
    }
    setlocale(LC_ALL, "C");
}

static void test_swscanf(void)
{
    section("swscanf");
    for (int loc = 0; loc < 2; loc++) {
        setlocale(LC_ALL, loc ? "C.UTF-8" : "C");
        int a = -1, b = -1, n = -1;
        char s[32];
        wchar_t ws[32];
        double d = -1;
        memset(s, 0x5a, sizeof s);
        for (int k = 0; k < 32; k++)
            ws[k] = 0x5a;
        errno = SENTINEL_ERRNO;
        int r = swscanf(L"  12 34 ab\x20ac" L"cd 2.5e1 rest", L"%d %d %s %lf%n", &a, &b, s, &d, &n);
        put_s("loc");
        put_i(loc);
        put_s(" r=");
        put_i(r);
        put_s(" a=");
        put_i(a);
        put_s(" b=");
        put_i(b);
        put_s(" s=");
        put_hexbytes(s, 10);
        put_s(" d=");
        put_i((long long)(d * 10));
        put_s(" n=");
        put_i(n);
        put_s(" errno=");
        put_i(errno);
        nl();
        r = swscanf(L"x\x20ac" L"yz 9", L"%ls %d", ws, &a);
        put_s("  ls r=");
        put_i(r);
        put_wstr(ws, 6);
        put_s(" a=");
        put_i(a);
        memset(s, 0x5a, sizeof s);
        r = swscanf(L"\x20ac\x20ac", L"%2c", s);
        put_s(" c r=");
        put_i(r);
        put_hexbytes(s, 8);
        r = swscanf(L"abcXYZ", L"%[a-c]", s);
        put_s(" set r=");
        put_i(r);
        put_hexbytes(s, 5);
        for (int k = 0; k < 32; k++)
            ws[k] = 0x5a;
        r = swscanf(L"abc\x20acX", L"%l[a-c\x20ac]", ws);
        put_s(" lset r=");
        put_i(r);
        put_wstr(ws, 6);
        r = swscanf(L"", L"%d", &a);
        put_s(" empty r=");
        put_i(r);
        r = swscanf(L"0x1f 077 -0", L"%i %i %i", &a, &b, &n);
        put_s(" i r=");
        put_i(r);
        put_s(" ");
        put_i(a);
        put_s(",");
        put_i(b);
        put_s(",");
        put_i(n);
        r = vscall(L"3,4", L"%d,%d", &a, &b);
        put_s(" vswscanf=");
        put_i(r);
        put_s(" ");
        put_i(a);
        put_s(",");
        put_i(b);
        nl();
    }
    setlocale(LC_ALL, "C");
}

static void test_file_wide(void)
{
    section("file-wide");
    static const char *const locs[] = { "C", "C.UTF-8" };
    for (int li = 0; li < 2; li++) {
        setlocale(LC_ALL, locs[li]);
        put_s("locale ");
        put_s(locs[li]);
        nl();
        FILE *f = memfd_stream(NULL, 0);
        if (!f) {
            put_s("memfd stream failed");
            nl();
            continue;
        }
        put_s("fwide0=");
        put_i(fwide(f, 0));
        errno = SENTINEL_ERRNO;
        wint_t r = fputwc(L'A', f);
        put_s(" fputwc=");
        put_x(r);
        put_s(" fwide=");
        put_i(fwide(f, -1));
        r = fputwc(0x20ac, f);
        put_s(" euro=");
        put_x(r);
        put_s(" errno=");
        put_i(errno);
        put_s(" ferr=");
        put_i(ferror(f) != 0);
        clearerr(f);
        r = fputwc_unlocked(0xdf80, f);
        put_s(" cu-unlocked=");
        put_x(r);
        clearerr(f);
        int k = fputws(L"xy\x1f600", f);
        put_s(" fputws=");
        put_i(k >= 0 ? 1 : k);
        clearerr(f);
        k = fputws_unlocked(L"\x00e9!", f);
        put_s(" fputws_unlocked=");
        put_i(k >= 0 ? 1 : k);
        clearerr(f);
        put_s(" putwc=");
        put_x(putwc(L'Q', f));
        put_s(" putwc_unlocked=");
        put_x(putwc_unlocked(L'R', f));
        dump_file(f);
        nl();
        rewind(f);
        put_s("read:");
        errno = SENTINEL_ERRNO;
        for (int i = 0; i < 12; i++) {
            wint_t c;
            switch (i % 3) {
            case 0: c = fgetwc(f); break;
            case 1: c = fgetwc_unlocked(f); break;
            default: c = getwc_unlocked(f); break;
            }
            put_weof(c, f);
            if (c == WEOF)
                break;
        }
        nl();
        rewind(f);
        wint_t u = ungetwc(0x1f600, f);
        put_s("ungetwc=");
        put_x(u);
        put_s(" get=");
        put_x(fgetwc(f));
        put_s(" tell=");
        put_i(ftell(f));
        put_s(" getwc=");
        put_x(getwc(f));
        u = ungetwc(WEOF, f);
        put_s(" unget-weof=");
        put_x(u);
        wchar_t line[8];
        for (int i = 0; i < 8; i++)
            line[i] = 0x5a;
        wchar_t *lr = fgetws(line, 3, f);
        put_s(" fgetws=");
        put_i(lr == line);
        put_wstr(line, 4);
        for (int i = 0; i < 8; i++)
            line[i] = 0x5a;
        lr = fgetws_unlocked(line, 8, f);
        put_s(" fgetws_unlocked=");
        put_i(lr == line);
        put_wstr(line, 8);
        lr = fgetws(line, 8, f);
        put_s(" at-eof=");
        put_i(lr == NULL);
        put_s("/eof");
        put_i(feof(f) != 0);
        nl();
        fclose(f);

        /* invalid and truncated bytes decoded by the wide reader */
        f = memfd_stream("a\xe2\x82" "b\xff\xc3", 6);
        put_s("decode:");
        errno = SENTINEL_ERRNO;
        for (int i = 0; i < 8; i++)
            put_weof(fgetwc(f), f);
        put_s(" fwide=");
        put_i(fwide(f, 0));
        nl();
        fclose(f);

        /* ungetwc of a multibyte character then byte position arithmetic */
        f = memfd_stream("\xc3\xa9xyz", 5);
        wint_t first = fgetwc(f);
        long after = ftell(f);
        u = ungetwc(first, f);
        put_s("unget-mb first=");
        put_x(first);
        put_s(" after=");
        put_i(after);
        put_s(" unget=");
        put_x(u);
        put_s(" tell=");
        put_i(ftell(f));
        put_s(" again=");
        put_x(fgetwc(f));
        u = ungetwc(L'Q', f);
        put_s(" unget2=");
        put_x(u);
        u = ungetwc(L'P', f);
        put_s(" unget3=");
        put_x(u);
        put_s(" read=");
        put_x(fgetwc(f));
        put_x(fgetwc(f));
        nl();
        fclose(f);

        /* orientation stickiness */
        f = memfd_stream(NULL, 0);
        fputc('x', f);
        put_s("byte-first fwide=");
        put_i(fwide(f, 1));
        dump_file(f);
        nl();
        fclose(f);

        /* formatted wide output and input on a descriptor stream */
        f = memfd_stream(NULL, 0);
        int pr = fwprintf(f, L"%d-%ls-%s-%lc", 7, L"w\x20ac", "n\xc3\xa9", (wint_t)0xe9);
        put_s("fwprintf=");
        put_i(pr);
        pr = vfcall(f, L"|%05.1f|%ls", 2.25, L"v");
        put_s(" vfwprintf=");
        put_i(pr);
        dump_file(f);
        rewind(f);
        int a = 0;
        wchar_t w1[8];
        char n1[8];
        memset(n1, 0x5a, 8);
        for (int i = 0; i < 8; i++)
            w1[i] = 0x5a;
        pr = fwscanf(f, L"%d-%3l[^-]-%3[^-]", &a, w1, n1);
        put_s(" fwscanf=");
        put_i(pr);
        put_s(" a=");
        put_i(a);
        put_wstr(w1, 4);
        put_hexbytes(n1, 5);
        double dv = 0;
        wchar_t w2[4] = { 9, 9, 9, 9 };
        pr = vfscall(f, L"-%*lc|%lf|%1ls", &dv, w2);
        put_s(" vfwscanf=");
        put_i(pr);
        put_s(" dv*4=");
        put_i((long long)(dv * 4));
        put_wstr(w2, 3);
        nl();
        fclose(f);
    }
    setlocale(LC_ALL, "C");
}

static void test_memory_streams(void)
{
    section("memory-streams");
    for (int li = 0; li < 2; li++) {
        setlocale(LC_ALL, li ? "C.UTF-8" : "C");
        wchar_t *buf = NULL;
        size_t size = 99;
        FILE *f = open_wmemstream(&buf, &size);
        if (!f) {
            put_s("open_wmemstream failed");
            nl();
            continue;
        }
        put_s("fwide=");
        put_i(fwide(f, 0));
        fputwc(L'a', f);
        fwprintf(f, L"%ls|%d", L"\x20ac" L"b", 12);
        fflush(f);
        put_s(" size=");
        put_u(size);
        put_wstr(buf, size + 1);
        fseek(f, 1, SEEK_SET);
        fputwc(L'Z', f);
        fflush(f);
        put_s(" after-seek size=");
        put_u(size);
        put_wstr(buf, size + 1);
        fclose(f);
        put_s(" closed size=");
        put_u(size);
        put_wstr(buf, size + 1);
        free(buf);
        nl();

        char *nb = NULL;
        size_t ns = 0;
        f = open_memstream(&nb, &ns);
        errno = SENTINEL_ERRNO;
        int pr = fwprintf(f, L"x%lcy", (wint_t)0x20ac);
        fclose(f);
        put_s("memstream fwprintf=");
        put_i(pr);
        put_s(" errno=");
        put_i(errno);
        put_s(" size=");
        put_u(ns);
        put_hexbytes(nb, ns);
        free(nb);
        nl();

        char mem[16];
        memset(mem, 0, sizeof mem);
        memcpy(mem, "h\xc3\xa9llo", 6);
        f = fmemopen(mem, 6, "r");
        put_s("fmemopen read:");
        errno = SENTINEL_ERRNO;
        for (int i = 0; i < 7; i++) {
            wint_t c = fgetwc(f);
            put_weof(c, f);
            if (c == WEOF)
                break;
        }
        fclose(f);
        nl();
    }
    setlocale(LC_ALL, "C");
}

static void test_standard_input(void)
{
    section("stdin-wide");
    static const char input[] = "\xc3\xa9" "z 41 \xe2\x82\xac" "7 3.5 tail\nnext";
    int fd = memfd_create("crabc-wide-stdin", MFD_CLOEXEC);
    if (fd < 0 || write(fd, input, sizeof input - 1) != (ssize_t)(sizeof input - 1) ||
        lseek(fd, 0, SEEK_SET) != 0 || dup2(fd, 0) != 0) {
        put_s("stdin setup failed");
        nl();
        if (fd >= 0)
            close(fd);
        return;
    }
    close(fd);
    setlocale(LC_ALL, "C.UTF-8");
    wint_t c1 = getwchar();
    wint_t c2 = getwchar_unlocked();
    int a = -1;
    int r = wscanf(L"%d", &a);
    wchar_t w[4] = { 9, 9, 9, 9 };
    int b = -1;
    int r2 = vstdin_call(L" %1lc%d", w, &b);
    double d = 0;
    int r3 = wscanf(L"%lf", &d);
    put_s("getwchar=");
    put_x(c1);
    put_s(" getwchar_unlocked=");
    put_x(c2);
    put_s(" wscanf=");
    put_i(r);
    put_s("/");
    put_i(a);
    put_s(" vwscanf=");
    put_i(r2);
    put_wstr(w, 2);
    put_s("/");
    put_i(b);
    put_s(" wscanf2=");
    put_i(r3);
    put_s("/");
    put_i((long long)(d * 2));
    put_s(" fwide(stdin)=");
    put_i(fwide(stdin, 0));
    wchar_t line[16];
    wchar_t *lr = fgetws(line, 16, stdin);
    put_s(" rest=");
    put_i(lr == line);
    if (lr)
        put_wstr(line, 16);
    nl();
    setlocale(LC_ALL, "C");
}

static int test_standard_output(void)
{
    section("stdout-wide");
    if (flush_out() != 0 || fflush(stdout) != 0)
        return 1;
    /* Start from an unoriented stdout, as musl's freopen(NULL) resets it. */
    if (freopen(NULL, "w", stdout) != stdout)
        return 2;
    setlocale(LC_ALL, "C.UTF-8");
    int before = fwide(stdout, 0);
    int r1 = wprintf(L"wprintf %ls %d|", L"\x20ac", 5);
    int r2 = vstdout_call(L"vwprintf %lc|", (wint_t)0x1f600);
    wint_t r3 = putwchar(L'P');
    wint_t r4 = putwchar_unlocked(0xe9);
    wint_t r5 = fputwc_unlocked(L'\n', stdout);
    int after = fwide(stdout, 0);
    if (fflush(stdout) != 0)
        return 3;
    if (freopen(NULL, "w", stdout) != stdout)
        return 4;
    setlocale(LC_ALL, "C");
    put_s("stdout before=");
    put_i(before);
    put_s(" wprintf=");
    put_i(r1);
    put_s(" vwprintf=");
    put_i(r2);
    put_s(" putwchar=");
    put_x(r3);
    put_s(" putwchar_unlocked=");
    put_x(r4);
    put_s(" fputwc_unlocked=");
    put_x(r5);
    put_s(" after=");
    put_i(after);
    put_s(" reset=");
    put_i(fwide(stdout, 0));
    nl();
    return 0;
}

int crabc_x86_64_wide_stream_differential_probe(void)
{
    test_swprintf();
    test_swscanf();
    test_file_wide();
    test_memory_streams();
    test_standard_input();
    int status = test_standard_output();
    section("end");
    if (flush_out() != 0)
        return 100;
    return status;
}

int main(void)
{
    return crabc_x86_64_wide_stream_differential_probe();
}
