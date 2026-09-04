/* Native scalar bitmap component oracle. Directly includes fixed mimalloc
 * v3.5.0 bitmap.c; it does not translate or replace any bitmap algorithm.
 * Ordered cases mirror bitmap_native_tests.rs. Output includes actual words,
 * return values, visitor order, conservative maps, and the unconditional
 * subprocess statistics events that execute even with MI_STAT=0. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "bitmap.c"

/* Fixed scalar memory-initialization input, not a bitmap implementation. */
size_t _mi_cpu_stosb_max = 0;
static mi_subproc_t subprocess;

static _Alignas(64) unsigned char storage[34000];
static size_t serial;
static void value(size_t v) { printf("m2.bitmap.native.%zu=%zu\n", serial++, v); }
static mi_bitmap_t *ordinary(size_t bits) {
    memset(storage, 0, sizeof storage);
    mi_bitmap_t *b = (mi_bitmap_t *)storage;
    mi_bitmap_init(b, bits, true);
    return b;
}
static mi_bbitmap_t *binned(size_t bits) {
    memset(storage, 0, sizeof storage);
    mi_bbitmap_t *b = (mi_bbitmap_t *)storage;
    memset(&subprocess, 0, sizeof subprocess);
    mi_bbitmap_init(&subprocess, b, bits, true);
    return b;
}
static void bitmap_state(mi_bitmap_t *b, size_t first, size_t last) {
    size_t high;
    value(mi_bitmap_popcount(b));
    value(mi_bitmap_bsr(b, &high) ? high : SIZE_MAX);
    value(mi_bitmap_is_all_clear(b));
    for (size_t f=0; f<MI_BCHUNK_FIELDS; ++f) value(mi_atomic_load_relaxed(&b->chunkmap.bfields[f]));
    for (size_t f=first/MI_BFIELD_BITS; f<=last/MI_BFIELD_BITS; ++f)
        value(mi_atomic_load_relaxed(&b->chunks[f/MI_BCHUNK_FIELDS].bfields[f%MI_BCHUNK_FIELDS]));
}
static void binned_state(mi_bbitmap_t *b) {
    for (size_t i=0; i<MI_CBIN_NONE; ++i) {
        value(mi_atomic_load_relaxed(&subprocess.stats.chunk_bins[i].total));
        value(mi_atomic_load_relaxed(&subprocess.stats.chunk_bins[i].peak));
        value(mi_atomic_load_relaxed(&subprocess.stats.chunk_bins[i].current));
    }
    size_t high;
    value(mi_atomic_load_relaxed(&b->chunk_max_accessed));
    value(mi_bbitmap_bsr_inv(b, &high) ? high : SIZE_MAX);
    for (size_t f=0; f<MI_BCHUNK_FIELDS; ++f) value(mi_atomic_load_relaxed(&b->chunkmap.bfields[f]));
    for (size_t c=0; c<mi_bbitmap_chunk_count(b); ++c) {
        value(mi_bbitmap_debug_get_bin(b->chunkmap_bins, c));
        for (size_t f=0; f<MI_BCHUNK_FIELDS; ++f) value(mi_atomic_load_relaxed(&b->chunks[c].bfields[f]));
    }
}
static const size_t lengths[] = {1,2,7,8,9,31,63,64,65,127,255,511,512,513,777,1025};
#define EACH(a, i) for (size_t i=0; i<sizeof(a)/sizeof((a)[0]); ++i)
static mi_bitmap_t *visited;
static size_t visits, stop_after, disposition;
static bool visit(size_t index, size_t len, mi_arena_t *arena, void *arg) {
    (void)arena; (void)arg;
    value(index); value(len);
    if (++visits == 1) mi_bitmap_set(visited, 4);
    return stop_after == 0 || visits < stop_after;
}
static bool claim(size_t index, mi_arena_t *arena, bool *keep_set) {
    (void)arena;
    value(index);
    *keep_set = disposition == 0;
    return disposition == 2;
}
static void *wait_clear(void *bitmap) {
    mi_bitmap_clear_once_set(&subprocess, bitmap, 7);
    return NULL;
}
int main(void) {
    value(MI_STAT); value(MI_BFIELD_BITS); value(MI_BCHUNK_BITS);
    const size_t sizes[] = {512,1024,1536,33280};
    EACH(sizes,s) {
        size_t max = _mi_align_up(sizes[s], MI_BCHUNK_BITS);
        size_t indices[] = {0,1,7,8,31,62,63,64,65,127,255,448,510,511,512,513,max-64,max-1};
        EACH(indices,i) EACH(lengths,n) {
            size_t index=indices[i], len=lengths[n], already=0;
            if (index+len>max) continue;
            mi_bitmap_t *b=ordinary(sizes[s]);
            value(sizes[s]); value(index); value(len);
            bool first=mi_bitmap_setN(b,index,len,&already); value(first); value(already);
            bool second=mi_bitmap_setN(b,index,len,&already); value(second); value(already);
            value(mi_bitmap_popcountN(b,index,len)); value(mi_bitmap_is_setN(b,index,len));
            value(mi_bitmap_clear(b,index+len/2)); value(mi_bitmap_clear(b,index+len/2));
            bitmap_state(b,index,index+len-1);
            value(mi_bitmap_clearN(b,index,len));
            bitmap_state(b,index,index+len-1);
        }
    }
    const size_t alignments[] = {SIZE_MAX,0,1,2,3,7,8,63,64,65,513};
    const size_t stops[] = {0,1,3,17};
    const size_t chunks[] = {0,1,63,64};
    EACH(alignments,a) EACH(stops,s) {
        mi_bitmap_t *b=ordinary(33280);
        EACH(chunks,c) {
            size_t base=chunks[c]*MI_BCHUNK_BITS;
            mi_bitmap_setN(b,base,64,NULL); mi_bitmap_clear(b,base+4);
            mi_bitmap_setN(b,base+67,11,NULL); mi_bitmap_setN(b,base+510,2,NULL);
        }
        value(alignments[a]); value(stops[s]);
        visited=b; visits=0; stop_after=stops[s];
        bool completed = alignments[a]==SIZE_MAX ? _mi_bitmap_forall_set(b,visit,NULL,NULL)
            : _mi_bitmap_forall_setc_rangesn(b,alignments[a],visit,NULL,NULL);
        value(completed); value(visits);
        bitmap_state(b,0,mi_bitmap_max_bits(b)-1);
    }
    const size_t chunk_counts[] = {3,65};
    const size_t sequences[] = {0,1,7,63,64,UINT64_C(0x100000001)};
    EACH(chunk_counts,c) EACH(sequences,s) EACH(lengths,n) {
        size_t len=lengths[n], claims[12], count=0;
        mi_bbitmap_t *b=binned(chunk_counts[c]*MI_BCHUNK_BITS);
        value(chunk_counts[c]); value(sequences[s]); value(len);
        value(mi_bbitmap_setN(b,0,mi_bbitmap_max_bits(b)));
        for (size_t k=0;k<12;++k) {
            size_t index;
            bool claimed=mi_bbitmap_try_find_and_clearN(b,sequences[s],len,&index);
            value(claimed?index:SIZE_MAX);
            if (claimed) claims[count++]=index;
        }
        for (size_t k=0;k<count;k+=3) value(mi_bbitmap_setN(b,claims[k],len));
        binned_state(b);
    }
    for (disposition=0;disposition<3;++disposition) {
        mi_bitmap_t *b=ordinary(33280);
        EACH(chunks,c) mi_bitmap_set(b,chunks[c]*MI_BCHUNK_BITS+7);
        value(disposition);
        size_t index;
        bool claimed=mi_bitmap_try_find_and_claim(b,5,&index,claim,NULL);
        value(claimed?index:SIZE_MAX);
        bitmap_state(b,0,mi_bitmap_max_bits(b)-1);
    }
    mi_bitmap_t *waiting = ordinary(512);
    memset(&subprocess, 0, sizeof subprocess);
    mi_bitmap_set(waiting, 7);
    mi_bitmap_clear_once_set(&subprocess, waiting, 7);
    value(mi_atomic_load_relaxed(&subprocess.stats.pages_unabandon_busy_wait.total));
    pthread_t thread;
    if (pthread_create(&thread, NULL, wait_clear, waiting) != 0) return 2;
    while (mi_atomic_load_relaxed(&subprocess.stats.pages_unabandon_busy_wait.total) == 0) { }
    mi_bitmap_set(waiting, 7);
    if (pthread_join(thread, NULL) != 0) return 3;
    value(mi_atomic_load_relaxed(&subprocess.stats.pages_unabandon_busy_wait.total));
    bitmap_state(waiting, 0, 511);
    return 0;
}
