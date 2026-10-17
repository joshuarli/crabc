#ifndef CRABC_MI_M6_HEAP_OWNERSHIP_DIAGNOSTIC_H
#define CRABC_MI_M6_HEAP_OWNERSHIP_DIAGNOSTIC_H

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

#include "mimalloc/internal.h"

#if !defined(__x86_64__)
#error "M6 heap ownership diagnostic requires x86-64"
#endif

static size_t m6_diagnostic_text(char* output, size_t length, size_t capacity, const char* value) {
  while (*value != '\0' && length < capacity) output[length++] = *value++;
  return length;
}

static size_t m6_diagnostic_hex(char* output, size_t length, size_t capacity, uintptr_t value) {
  static const char digits[] = "0123456789abcdef";
  char reversed[2 * sizeof(value)];
  size_t count = 0;
  do {
    reversed[count++] = digits[value & 0xf];
    value >>= 4;
  } while (value != 0);
  if (length < capacity) output[length++] = '0';
  if (length < capacity) output[length++] = 'x';
  while (count > 0 && length < capacity) output[length++] = reversed[--count];
  return length;
}

static void m6_diagnostic_fault(int signal_number, siginfo_t* info, void* context) {
  const ucontext_t* machine = (const ucontext_t*)context;
  char output[192];
  size_t length = 0;
  length = m6_diagnostic_text(output, length, sizeof(output), "m6-pointer-diagnostic signal=");
  if (signal_number >= 10 && length < sizeof(output)) {
    output[length++] = (char)('0' + signal_number / 10);
  }
  if (length < sizeof(output)) output[length++] = (char)('0' + signal_number % 10);
  length = m6_diagnostic_text(output, length, sizeof(output), " address=");
  length = m6_diagnostic_hex(output, length, sizeof(output), (uintptr_t)info->si_addr);
  length = m6_diagnostic_text(output, length, sizeof(output), " instruction=");
  length = m6_diagnostic_hex(output, length, sizeof(output),
      (uintptr_t)machine->uc_mcontext.gregs[REG_RIP]);
  length = m6_diagnostic_text(output, length, sizeof(output), " frame=");
  length = m6_diagnostic_hex(output, length, sizeof(output),
      (uintptr_t)machine->uc_mcontext.gregs[REG_RBP]);
  if (length < sizeof(output)) output[length++] = '\n';
  (void)write(STDERR_FILENO, output, length);
  _exit(128 + signal_number);
}

static int m6_diagnostic_install(void) {
  struct sigaction action = {0};
  action.sa_sigaction = m6_diagnostic_fault;
  action.sa_flags = SA_SIGINFO | SA_RESETHAND;
  if (sigemptyset(&action.sa_mask) != 0) return -1;
  return sigaction(SIGSEGV, &action, NULL);
}

static void m6_diagnostic_page(const char* stage, const void* block, const mi_heap_t* deleted_heap) {
  const mi_page_t* page = _mi_ptr_page(block);
  mi_heap_t* main_heap = _mi_subproc_heap_main(_mi_subproc());
  mi_heap_t* page_heap = page == NULL ? NULL : page->heap;
  mi_subproc_t* main_subproc = main_heap == NULL ? NULL : main_heap->subproc;
  mi_subproc_t* page_subproc = page_heap == main_heap ? main_subproc : NULL;
  mi_theap_t* main_theap_meta = main_subproc == NULL ? NULL : main_subproc->theap_meta;
  fprintf(stderr,
      "m6-pointer-diagnostic stage=%s block=%p page=%p page_heap=%p deleted_heap=%p main_heap=%p page_heap_is_deleted=%d page_heap_is_main=%d page_heap_subproc=%p main_subproc=%p main_theap_meta=%p\n",
      stage, block, (const void*)page, (void*)page_heap, (const void*)deleted_heap,
      (void*)main_heap, page_heap == deleted_heap, page_heap == main_heap,
      (void*)page_subproc, (void*)main_subproc, (void*)main_theap_meta);
}

#endif
