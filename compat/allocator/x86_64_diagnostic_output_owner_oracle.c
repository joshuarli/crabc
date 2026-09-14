/*
 * Pinned mimalloc v3.5.0 `src/options.c` diagnostic-output source fixture.
 *
 * This is a private future C half for `x86_64_diagnostic_output_owner_evidence.py`.
 * It does not select a public mi_* API, a libc backend, a VM receiver, or a
 * runtime integration path.
 */

#include "mimalloc.h"
#include "mimalloc/internal.h"

#include <stdio.h>
#include <string.h>

#define MAX_MESSAGES 8
#define MAX_MESSAGE_BYTES 256

typedef struct capture_s {
  size_t count;
  size_t lengths[MAX_MESSAGES];
  char messages[MAX_MESSAGES][MAX_MESSAGE_BYTES];
} capture_t;

static void capture_reset(capture_t* capture) {
  memset(capture, 0, sizeof(*capture));
}

static void capture_output(const char* message, void* argument) {
  capture_t* const capture = (capture_t*)argument;
  if (message == NULL || capture == NULL || capture->count >= MAX_MESSAGES) return;
  const size_t length = _mi_strnlen(message, MAX_MESSAGE_BYTES - 1);
  const size_t index = capture->count++;
  memcpy(capture->messages[index], message, length);
  capture->messages[index][length] = 0;
  capture->lengths[index] = length;
}

static void print_capture(const char* scenario, const capture_t* capture) {
  printf("%s=", scenario);
  for (size_t index = 0; index < capture->count; index++) {
    if (index != 0) printf(":");
    for (size_t byte = 0; byte < capture->lengths[index]; byte++) {
      printf("%02x", (unsigned char)capture->messages[index][byte]);
    }
  }
  printf("\n");
}

static void initialize_diagnostic_options(long show_errors, long verbose, long max_warnings) {
  mi_option_set(mi_option_show_errors, show_errors);
  mi_option_set(mi_option_verbose, verbose);
  mi_option_set(mi_option_max_warnings, max_warnings);
  _mi_options_init();
}

static int run_release(void) {
  capture_t capture;
  initialize_diagnostic_options(0, 0, 32);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);  /* source registration flushed its empty buffer */
  _mi_warning_message("%s", "selected mbind failure\n");
  print_capture("release", &capture);
  return 0;
}

static int run_enabled(void) {
  capture_t capture;
  initialize_diagnostic_options(1, 0, 1);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  _mi_warning_message("%s", "selected mbind failure\n");
  print_capture("enabled", &capture);
  return 0;
}

static int run_cap(void) {
  capture_t capture;
  initialize_diagnostic_options(1, 0, 1);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  _mi_warning_message("%s", "first\n");
  _mi_warning_message("%s", "second\n");
  print_capture("cap", &capture);
  return 0;
}

static int run_verbose(void) {
  capture_t capture;
  initialize_diagnostic_options(0, 1, 0);
  capture_reset(&capture);
  mi_register_output(&capture_output, &capture);
  capture_reset(&capture);
  _mi_warning_message("%s", "first\n");
  _mi_warning_message("%s", "second\n");
  print_capture("verbose", &capture);
  return 0;
}

static int run_delayed(void) {
  capture_t capture;
  capture_reset(&capture);
  _mi_raw_message("early\n");
  mi_register_output(&capture_output, &capture);
  _mi_raw_message("later\n");
  print_capture("delayed", &capture);
  return 0;
}

static int run_null(void) {
  capture_t capture;
  capture_reset(&capture);
  _mi_raw_message("early\n");
  mi_register_output(NULL, NULL);
  mi_register_output(&capture_output, &capture);
  print_capture("null", &capture);
  return 0;
}

static int run_post_init(void) {
  capture_t capture;
  initialize_diagnostic_options(0, 0, 32);
  capture_reset(&capture);
  _mi_raw_message("early\n");
  _mi_options_post_init();
  _mi_raw_message("later\n");
  mi_register_output(&capture_output, &capture);
  print_capture("post_init", &capture);
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s SCENARIO\n", argv[0]);
    return 64;
  }
  if (strcmp(argv[1], "release") == 0) return run_release();
  if (strcmp(argv[1], "enabled") == 0) return run_enabled();
  if (strcmp(argv[1], "cap") == 0) return run_cap();
  if (strcmp(argv[1], "verbose") == 0) return run_verbose();
  if (strcmp(argv[1], "delayed") == 0) return run_delayed();
  if (strcmp(argv[1], "null") == 0) return run_null();
  if (strcmp(argv[1], "post_init") == 0) return run_post_init();
  fprintf(stderr, "unknown scenario: %s\n", argv[1]);
  return 64;
}
