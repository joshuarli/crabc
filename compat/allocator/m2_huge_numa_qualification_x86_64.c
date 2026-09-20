/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/*
 * Hardware-only companion to the source-policy and ownership witnesses.
 *
 * `static.c` is the pinned mimalloc v3.5.0 amalgamation.  This fixture calls
 * its actual `mi_reserve_huge_os_pages_at` source entry once for each supplied
 * NUMA node; it does not replace the huge primitive, simulate a successful
 * map, or choose an allocator policy of its own.  The process exits directly
 * after its observations, which returns the two private mappings to the
 * kernel.  The Python collector verifies the pool counters before, between,
 * and after the C/Rust children.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "static.c"

enum {
  huge_page_kib = 1024 * 1024,
  maximum_source_numa_node = 62,
};

static bool parse_node(const char* value, int* node) {
  char* end = NULL;
  errno = 0;
  const long parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < 0 ||
      parsed > maximum_source_numa_node) {
    return false;
  }
  *node = (int)parsed;
  return true;
}

static bool parse_positive_node_token(const char* token, int* node) {
  if (token[0] != 'N') return false;
  char* end = NULL;
  errno = 0;
  const long parsed_node = strtol(token + 1, &end, 10);
  if (errno != 0 || end == token + 1 || *end != '=') return false;
  const long pages = strtol(end + 1, &end, 10);
  if (errno != 0 || end == NULL || (*end != '\0' && *end != '\n') ||
      parsed_node < 0 || pages <= 0 || parsed_node > maximum_source_numa_node) {
    return false;
  }
  *node = (int)parsed_node;
  return true;
}

/* A successful source map is a distinct 1-GiB mapping.  Because this fixture
 * begins before either reservation, every such line in /proc/self/numa_maps
 * belongs to one of its source calls.  Each requested node is distinct, so
 * the exactly-one-positive-node rule proves the requested-node set against
 * the kernel's physical placement observation without inventing an ordering
 * relationship between source calls and address-sorted numa_maps rows.
 */
static bool observe_huge_maps(const int requested[2], size_t completed,
                              int observed_nodes[2], unsigned long observed_addresses[2]) {
  FILE* maps = fopen("/proc/self/numa_maps", "r");
  if (maps == NULL) return false;
  char* line = NULL;
  size_t capacity = 0;
  size_t line_count = 0;
  bool requested_seen[2] = { false, false };
  while (getline(&line, &capacity, maps) >= 0) {
    if (strstr(line, "kernelpagesize_kB=1048576") == NULL) continue;
    char* address_token = strtok(line, " \t\n");
    char* address_end = NULL;
    errno = 0;
    const unsigned long address = (address_token == NULL ? 0 : strtoul(address_token, &address_end, 16));
    if (errno != 0 || address_token == NULL || address_end == address_token || *address_end != '\0') {
      free(line);
      fclose(maps);
      return false;
    }
    int observed_node = -1;
    size_t node_count = 0;
    for (char* token = strtok(NULL, " \t\n"); token != NULL;
         token = strtok(NULL, " \t\n")) {
      int token_node = -1;
      if (parse_positive_node_token(token, &token_node)) {
        observed_node = token_node;
        node_count++;
      }
    }
    if (node_count != 1 || line_count >= completed) {
      free(line);
      fclose(maps);
      return false;
    }
    size_t requested_index = 0;
    while (requested_index < completed && requested[requested_index] != observed_node) {
      requested_index++;
    }
    if (requested_index == completed || requested_seen[requested_index]) {
      free(line);
      fclose(maps);
      return false;
    }
    requested_seen[requested_index] = true;
    observed_nodes[line_count] = observed_node;
    observed_addresses[line_count] = address;
    line_count++;
  }
  free(line);
  fclose(maps);
  if (line_count != completed) return false;
  for (size_t index = 0; index < completed; index++) {
    if (!requested_seen[index]) return false;
  }
  return true;
}

int main(int argc, char** argv) {
  if (argc != 3) return 64;
  int requested[2];
  if (!parse_node(argv[1], &requested[0]) || !parse_node(argv[2], &requested[1]) ||
      requested[0] == requested[1]) {
    return 65;
  }
  printf("CRABC_MI_HUGE_NUMA_C_TRACE_BEGIN\n");
  int observed_nodes[2] = { -1, -1 };
  unsigned long observed_addresses[2] = { 0, 0 };
  for (size_t index = 0; index < 2; index++) {
    if (mi_reserve_huge_os_pages_at(1, requested[index], 0) != 0 ||
        !observe_huge_maps(requested, index + 1, observed_nodes, observed_addresses)) {
      return 66 + (int)index;
    }
  }
  /* numa_maps itself is address-sorted, not reservation ordered.  Retain its
   * two live mapping identities in that kernel order and prove only the exact
   * requested-node set, never an incidental source-call-to-address ordering.
   */
  for (size_t index = 0; index < 2; index++) {
    printf("CRABC_MI_HUGE_NUMA_C_MAP.%zu.observed_node=%d\n", index, observed_nodes[index]);
    printf("CRABC_MI_HUGE_NUMA_C_MAP.%zu.kernel_page_kib=%d\n", index, huge_page_kib);
    printf("CRABC_MI_HUGE_NUMA_C_MAP.%zu.mapping_address=%lu\n", index, observed_addresses[index]);
  }
  printf("CRABC_MI_HUGE_NUMA_C_TRACE_END\n");
  return 0;
}
