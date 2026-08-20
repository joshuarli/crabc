#ifndef _DN_EXPAND_H
#define _DN_EXPAND_H

#ifdef __cplusplus
extern "C" {
#endif

int dn_expand(const unsigned char *, const unsigned char *, const unsigned char *, char *, int);
int dn_skipname(const unsigned char *, const unsigned char *);

#ifdef __cplusplus
}
#endif

#endif
