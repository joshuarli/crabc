#ifndef _NL_TYPES_H
#define _NL_TYPES_H

typedef void *nl_catd;
typedef int nl_item;

#define NL_SETD 1
#define NL_CAT_LOCALE 1

#ifdef __cplusplus
extern "C" {
#endif

nl_catd catopen(const char *, int);
int catclose(nl_catd);
char *catgets(nl_catd, int, int, const char *);

#ifdef __cplusplus
}
#endif

#endif
