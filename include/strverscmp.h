#ifndef _CRABC_STRVERSCMP_H
#define _CRABC_STRVERSCMP_H

/*
 * Project-only compatibility spelling for callers that explicitly opt into
 * version comparison. The musl-compatible public spelling lives in
 * <string.h> and is visible there only under _GNU_SOURCE.
 */
#ifdef __cplusplus
extern "C" {
#endif

int strverscmp(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif
