/* Narrow cross-image FILE operation used by the executable and DSO. */
#ifndef CRABC_OWNED_STDIO_FILE_DSO_PROBE_H
#define CRABC_OWNED_STDIO_FILE_DSO_PROBE_H
#include <stdio.h>

struct crabc_cookie_state {
    unsigned char data[32];
    size_t length;
    size_t position;
    unsigned reads;
    unsigned writes;
    unsigned seeks;
    unsigned closes;
};

int crabc_file_dso_transfer(FILE *stream, int descriptor, int *main_errno);
int crabc_cookie_dso_transfer(FILE *stream, const struct crabc_cookie_state *state,
                              int *main_errno);

enum crabc_cookie_dso_stage {
    CRABC_COOKIE_DSO_BUFFERED,
    CRABC_COOKIE_DSO_FLUSHED,
    CRABC_COOKIE_DSO_CLOSED
};

FILE *crabc_cookie_dso_open(int *main_errno);
int crabc_cookie_dso_check(enum crabc_cookie_dso_stage stage, int *main_errno);
int crabc_file_dso_write_wide(FILE *stream, int *main_errno);
int crabc_file_dso_buffer_exit(const char *stream_path, const char *marker_path,
                               int *main_errno);
int crabc_file_dso_reopen(FILE *stream, const char *replacement_path,
                          int *main_errno);
#endif
