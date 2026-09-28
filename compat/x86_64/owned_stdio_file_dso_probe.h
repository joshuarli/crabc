/* Narrow cross-image FILE operation used by the executable and DSO. */
#ifndef CRABC_OWNED_STDIO_FILE_DSO_PROBE_H
#define CRABC_OWNED_STDIO_FILE_DSO_PROBE_H
#include <stdio.h>
int crabc_file_dso_transfer(FILE *stream, int descriptor, int *main_errno);
#endif
