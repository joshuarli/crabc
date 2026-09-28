/* Read the default release configuration printed by either allocator image. */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "mimalloc.h"

static void capture(const char* message, void* argument) {
  (void)argument;
  if (message == NULL) return;
  if (strncmp(message, "debug level : ", 14) == 0 ||
      strncmp(message, "secure level: ", 14) == 0 ||
      strncmp(message, "mem tracking: ", 14) == 0 ||
      strncmp(message, "free: ", 6) == 0) {
    fputs(message, stdout);
  }
}

int main(void) {
  mi_options_print_out(&capture, NULL);
  return 0;
}
