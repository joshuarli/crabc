#ifndef _LIBINTL_H
#define _LIBINTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define __USE_GNU_GETTEXT 1
#define __GNU_GETTEXT_SUPPORTED_REVISION(major) ((major) == 0 ? 1 : -1)

#if __GNUC__ >= 3
#define __LIBINTL_FORMAT_ARG(n) __attribute__((__format_arg__(n)))
#else
#define __LIBINTL_FORMAT_ARG(n)
#endif

char *gettext(const char *) __LIBINTL_FORMAT_ARG(1);
char *dgettext(const char *, const char *) __LIBINTL_FORMAT_ARG(2);
char *dcgettext(const char *, const char *, int) __LIBINTL_FORMAT_ARG(2);
char *ngettext(const char *, const char *, unsigned long)
    __LIBINTL_FORMAT_ARG(1) __LIBINTL_FORMAT_ARG(2);
char *dngettext(const char *, const char *, const char *, unsigned long)
    __LIBINTL_FORMAT_ARG(2) __LIBINTL_FORMAT_ARG(3);
char *dcngettext(const char *, const char *, const char *, unsigned long, int)
    __LIBINTL_FORMAT_ARG(2) __LIBINTL_FORMAT_ARG(3);
char *textdomain(const char *);
char *bindtextdomain(const char *, const char *);
char *bind_textdomain_codeset(const char *, const char *);

#undef __LIBINTL_FORMAT_ARG

#ifdef __cplusplus
}
#endif

#endif
