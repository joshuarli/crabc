/* Exercise the public JSON entry points against one fixed statistics image.
   The image isolates serialization and caller-buffer semantics from producers. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mimalloc.h"
#include "mimalloc-stats.h"

static void show_count(const char* name, const char* json) {
  char key[80];
  snprintf(key, sizeof(key), "\"%s\": { \"total\": ", name);
  const char* start = strstr(json, key);
  long long total = -1, peak = -1, current = -1;
  if (start != NULL) {
    start += strlen(key);
    if (sscanf(start, "%lld, \"peak\": %lld, \"current\": %lld", &total, &peak, &current) != 3) abort();
  }
  printf("json.%s=%lld,%lld,%lld\n", name, total, peak, current);
}

static void show_bin(const char* name, const char* json) {
  char key[80];
  snprintf(key, sizeof(key), "\"%s\": [", name);
  const char* cursor = strstr(json, key);
  if (cursor == NULL) abort();
  cursor += strlen(key);
  for (unsigned index = 0; index <= 8; index++) {
    cursor = strchr(cursor, '{');
    if (cursor == NULL) abort();
    if (index < 8) cursor++;
  }
  long long total, peak, current;
  size_t block_size, page_size;
  if (sscanf(cursor, "{ \"total\": %lld, \"peak\": %lld, \"current\": %lld, \"block_size\": %zu, \"page_size\": %zu",
             &total, &peak, &current, &block_size, &page_size) != 5) abort();
  printf("json.%s.bin8=%lld,%lld,%lld,%zu,%zu\n", name, total, peak, current, block_size, page_size);
}

static uint64_t normalized_hash(const char* json) {
  const char* process = strstr(json, "\"process\": {");
  if (process == NULL) abort();
  const char* end = strstr(process, "  },\n");
  if (end == NULL) abort();
  uint64_t hash = UINT64_C(14695981039346656037);
  for (const unsigned char* cursor = (const unsigned char*)json; *cursor != 0; cursor++) {
    unsigned char byte = *cursor;
    if ((const char*)cursor > process && (const char*)cursor < end && byte >= '0' && byte <= '9') {
      if (cursor > (const unsigned char*)process && cursor[-1] >= '0' && cursor[-1] <= '9') continue;
      byte = 'N';
    }
    hash = (hash ^ byte) * UINT64_C(1099511628211);
  }
  return hash;
}

static void show_fixed(const char* name, mi_stats_t* image, size_t size) {
  unsigned char memory[80];
  memset(memory, 'X', sizeof(memory));
  char* result = mi_stats_as_json(image, size, (char*)memory);
  printf("%s.result=%d\n", name, result == NULL ? 0 : result == (char*)memory ? 1 : 2);
  printf("%s.prefix=", name);
  for (size_t index = 0; index < (size < 8 ? size : 8); index++) printf("%02x", memory[index]);
  printf("\n%s.guard=%d\n", name, memory[size] == 'X');
  if (result != NULL && result != (char*)memory) mi_free(result);
}

int main(void) {
  mi_stats_t_decl(image);
  image.pages = (mi_stat_count_t){6, 4, 3};
  image.malloc_normal = (mi_stat_count_t){320, 160, 96};
  image.malloc_huge = (mi_stat_count_t){8192, 4096, 2048};
  image.malloc_requested = (mi_stat_count_t){280, 140, 70};
  image.malloc_bins[8] = (mi_stat_count_t){5, 4, 2};
  image.page_bins[8] = (mi_stat_count_t){3, 2, 1};

  printf("CRABC_MI_M7_STATISTICS_JSON_TRACE_BEGIN\n");
  printf("profile.level=%d\n", MI_STAT);
  char* json = mi_stats_as_json(&image, 0, NULL);
  if (json == NULL) abort();
  const size_t length = strlen(json);
  printf("json.grown=1\n");
  printf("json.version=%d\n", strstr(json, "\"stat_version\": 5,") != NULL);
  printf("json.mimalloc_version=%d\n", strstr(json, "\"mimalloc_version\": 30500,") != NULL);
  printf("json.process=%d\n", strstr(json, "\"process\": {") != NULL);
  printf("json.chunk_bins=%d\n", strstr(json, "\"chunk_bins\": [") != NULL);
  printf("json.hash=%016llx\n", (unsigned long long)normalized_hash(json));
  show_count("pages", json);
  show_count("malloc_normal", json);
  show_count("malloc_huge", json);
  show_count("malloc_requested", json);
  show_bin("malloc_bins", json);
  show_bin("page_bins", json);
  mi_free(json);

  show_fixed("fixed.one", &image, 1);
  show_fixed("fixed.two", &image, 2);
  show_fixed("fixed.three", &image, 3);
  show_fixed("fixed.sixtyfour", &image, 64);
  if (length + 2 >= 65536) abort();
  static char exact[65536];
  memset(exact, 'X', sizeof(exact));
  char* result = mi_stats_as_json(&image, length + 1, exact);
  printf("fixed.length_plus_one=%d\n", result == NULL ? 0 : result == exact ? 1 : 2);
  result = mi_stats_as_json(&image, length + 2, exact);
  printf("fixed.length_plus_two=%d\n", result == NULL ? 0 : result == exact ? 1 : 2);

  char sentinel[2] = {'X', 'Y'};
  result = mi_stats_as_json(&image, 0, sentinel);
  printf("zero_size.grown=%d\n", result != NULL && result != sentinel);
  printf("zero_size.caller_intact=%d\n", sentinel[0] == 'X' && sentinel[1] == 'Y');
  if (result != NULL) mi_free(result);
  result = mi_stats_as_json(&image, 64, NULL);
  printf("null_buffer.grown=%d\n", result != NULL);
  if (result != NULL) mi_free(result);

  mi_stats_t bad = image;
  bad.version = 0;
  char invalid[4] = {'X', 'Y', 'Z', 0};
  printf("invalid.version=%d\n", mi_stats_as_json(&bad, sizeof(invalid), invalid) == NULL);
  printf("invalid.caller_intact=%d\n", invalid[0] == 'X' && invalid[1] == 'Y');
  printf("invalid.null_image=%d\n", mi_stats_as_json(NULL, 0, NULL) == NULL);

  result = mi_stats_get_json(0, NULL);
  printf("get.grown=%d\n", result != NULL);
  if (result != NULL) {
    printf("get.version=%d\n", strstr(result, "\"stat_version\": 5,") != NULL);
    mi_free(result);
  }
  char get_small[4] = {'X', 'X', 'X', 'Y'};
  result = mi_stats_get_json(3, get_small);
  printf("get.short=%d\n", result == NULL ? 0 : result == get_small ? 1 : 2);
  printf("get.short.prefix=%02x%02x%02x\n", (unsigned char)get_small[0], (unsigned char)get_small[1], (unsigned char)get_small[2]);
  printf("get.short.guard=%d\n", get_small[3] == 'Y');
  printf("CRABC_MI_M7_STATISTICS_JSON_TRACE_END\n");
  return 0;
}
