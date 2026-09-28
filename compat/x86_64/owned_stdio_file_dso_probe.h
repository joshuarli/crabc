/* Narrow cross-image FILE operation used by the executable and DSO. */
#ifndef CRABC_OWNED_STDIO_FILE_DSO_PROBE_H
#define CRABC_OWNED_STDIO_FILE_DSO_PROBE_H
#include <stdio.h>
#include <wchar.h>

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

enum crabc_memstream_dso_stage {
    CRABC_MEMSTREAM_DSO_FIRST_BUFFERED = 1,
    CRABC_MEMSTREAM_DSO_MAIN_REWRITE_FLUSHED,
    CRABC_MEMSTREAM_DSO_APPEND_BUFFERED,
    CRABC_MEMSTREAM_DSO_MAIN_HOLE_FLUSHED
};

FILE *crabc_memstream_dso_open(char ***buffer_slot, size_t **length_slot,
                               int *main_errno);
int crabc_memstream_dso_checkpoint(FILE *stream, enum crabc_memstream_dso_stage stage,
                                    int *main_errno);
int crabc_memstream_dso_release(int *main_errno);

enum crabc_fixed_dso_stage {
    CRABC_FIXED_DSO_FIRST_BUFFERED = 1,
    CRABC_FIXED_DSO_WRITE_DE,
    CRABC_FIXED_DSO_MAIN_FLUSHED,
    CRABC_FIXED_DSO_APPEND_BUFFERED,
    CRABC_FIXED_DSO_SHORT_WRITE
};

FILE *crabc_fixed_dso_open(unsigned char **buffer, size_t *capacity,
                            int *main_errno);
int crabc_fixed_dso_step(FILE *stream, enum crabc_fixed_dso_stage stage,
                          int *main_errno);
int crabc_fixed_dso_after_close(int *main_errno);

enum crabc_wide_memory_dso_stage {
    CRABC_WIDE_MEMORY_DSO_MAIN_EURO = 1,
    CRABC_WIDE_MEMORY_DSO_WRITE_HAN,
    CRABC_WIDE_MEMORY_DSO_MAIN_REWRITE,
    CRABC_WIDE_MEMORY_DSO_APPEND_FACE,
    CRABC_WIDE_MEMORY_DSO_MAIN_GAP
};

FILE *crabc_wide_memory_dso_open(wchar_t ***buffer_slot, size_t **length_slot,
                                  int *main_errno);
int crabc_wide_memory_dso_step(FILE *stream, enum crabc_wide_memory_dso_stage stage,
                                int *main_errno);
int crabc_wide_memory_dso_release(int *main_errno);
#endif
