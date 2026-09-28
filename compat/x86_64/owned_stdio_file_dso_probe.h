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

int crabc_global_dso_buffer(FILE *main_stream, const char *path, int *main_errno);
int crabc_global_dso_flush(FILE *main_stream, int *main_errno);
int crabc_global_dso_tail(FILE *main_stream, int *main_errno);
int crabc_global_dso_after_second(FILE *main_stream, int *main_errno);
int crabc_global_dso_close(int *main_errno);

int crabc_orientation_dso_set_wide(FILE *stream, int *main_errno);
FILE *crabc_orientation_dso_open_byte(const char *path, int *main_errno);
int crabc_orientation_dso_use_byte(FILE *stream, int *main_errno);
int crabc_orientation_dso_close_byte(FILE *stream, int *main_errno);

FILE *crabc_full_dso_open(int *main_errno);
int crabc_full_dso_close(FILE *stream, int *main_errno);
FILE *crabc_full_dso_open_pending_close(int *main_errno);
int crabc_full_dso_close_pending(FILE *stream, int *main_errno);
FILE *crabc_full_dso_open_recovery(int *main_errno);
int crabc_full_dso_write_recovery(FILE *stream, int *main_errno);
int crabc_full_dso_close_recovery(FILE *stream, int *main_errno);
FILE *crabc_pushback_dso_open(const char *path, int *main_errno);
int crabc_pushback_dso_consume(FILE *stream, int *main_errno);
int crabc_pushback_dso_close(FILE *stream, int *main_errno);
FILE *crabc_lock_dso_open(const char *path, int *main_errno);
int crabc_lock_dso_try_busy(FILE *stream, int *worker_errno);
int crabc_lock_dso_write_unlock(FILE *stream, int *main_errno);
int crabc_lock_dso_worker_write(FILE *stream, int *worker_errno);
int crabc_lock_dso_close(FILE *stream, int *main_errno);
#endif
