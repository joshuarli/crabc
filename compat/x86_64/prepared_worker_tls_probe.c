/* Installed pthread/loader prepared-token lifecycle.
 *
 * All ordinary behavior uses one compiled installed-header C object in musl
 * and candidate links. The `owned` argument enables only source-defined
 * Variant-II/view and post-quiescence mapping observations. Musl's pthread
 * allocation layout, cache/reclamation policy and DTV are never inferred.
 * No pointer is dereferenced after its worker lifetime ends. mincore observes
 * the former page address only after kernel task retirement/join; it is not
 * an access to the former C object. No stale pthread_t is queried.
 */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(c) do { if (!(c)) { dprintf(2, "prepared-worker failure line=%d\n", __LINE__); _Exit(91); } } while (0)
#define INITIAL 0x51a7
#define MAX_VIEWS 8
#define WORKER_GENERATIONS 3
static _Thread_local _Alignas(64) int initialized = INITIAL;
static _Thread_local unsigned char zero[513];
static pthread_key_t key;
static int owned, dynamic;
static int active_generations=2;
static const char *generation3_path;
static int *(*image[WORKER_GENERATIONS])(void);
static unsigned char *(*tbss[WORKER_GENERATIONS])(void);

/* Exact source-owned observer layout from x86_64_runtime_tls_view.rs.
 * A view is borrowed only while this worker remains live and the loader has
 * completed publication. Retained previous views stay valid until release. */
struct runtime_view {
    uintptr_t mapping_bytes;
    struct runtime_view *previous;
    uintptr_t module_count;
    uintptr_t *dtv;
    uintptr_t *sizes;
};
_Static_assert(sizeof(struct runtime_view)==40, "native current-view layout");

enum action { NORMAL, EXPLICIT, DETACHED, CANCELLED, FORK_WORKER };
struct worker {
    int role;
    enum action action;
    int already_loaded;
    atomic_int ready, phase, destructor;
    pid_t tid;
    uintptr_t tp, initialized_address, zero_address;
    uintptr_t initial_dtv, initial_count;
    uintptr_t view_addresses[MAX_VIEWS];
    unsigned view_count;
    uintptr_t runtime_addresses[WORKER_GENERATIONS];
    unsigned runtime_count;
};

static void wait_at_least(atomic_int *value, int wanted)
{
    while (atomic_load_explicit(value, memory_order_acquire)<wanted)
        sched_yield();
}
static uintptr_t thread_pointer(void)
{
    return (uintptr_t)__builtin_thread_pointer();
}
static struct runtime_view *current_view(uintptr_t tp)
{
    return __atomic_load_n((struct runtime_view **)(tp+24), __ATOMIC_ACQUIRE);
}
static void require_zero(const unsigned char *p, size_t size)
{
    for (size_t n=0;n<size;n++) REQUIRE(p[n]==0);
}
static void require_mapped(uintptr_t pointer, int wanted)
{
    if (!owned) return;
    long page=sysconf(_SC_PAGESIZE);
    REQUIRE(page>0 && ((unsigned long)page & ((unsigned long)page-1))==0);
    unsigned char vector;
    errno=0;
    int result=mincore((void *)(pointer & ~((uintptr_t)page-1)),(size_t)page,&vector);
    REQUIRE(wanted ? result==0 : (result==-1 && errno==ENOMEM));
}
static void remember_views(struct worker *worker)
{
    if (!owned || !dynamic) return;
    struct runtime_view *view=current_view(worker->tp);
    REQUIRE(view && view->module_count>=2 && view->dtv && view->sizes);
    for (;view;view=view->previous) {
        REQUIRE(worker->view_count<MAX_VIEWS);
        worker->view_addresses[worker->view_count++]=(uintptr_t)view;
        require_mapped((uintptr_t)view,1);
    }
    REQUIRE(*(uintptr_t *)(worker->tp+8)==worker->initial_dtv);
    REQUIRE(*(uintptr_t *)(worker->tp+16)==worker->initial_count);
}
static void check_live(struct worker *worker)
{
    REQUIRE(*(int *)worker->initialized_address==INITIAL+worker->role);
    REQUIRE(*(unsigned char *)worker->zero_address==(unsigned char)worker->role);
    require_mapped(worker->tp,1);
    if (dynamic) {
        REQUIRE(worker->runtime_count==active_generations);
        for (unsigned n=0;n<worker->runtime_count;n++) {
            REQUIRE(worker->runtime_addresses[n]);
            REQUIRE(*(int *)worker->runtime_addresses[n]==700+10*worker->role+(int)n);
            require_mapped(worker->runtime_addresses[n],1);
        }
    }
}
static void destructor(void *opaque)
{
    struct worker *worker=opaque;
    REQUIRE(thread_pointer()==worker->tp);
    check_live(worker);
    atomic_fetch_add_explicit(&worker->destructor,1,memory_order_release);
}
static void inspect_runtime(struct worker *worker, int index)
{
    REQUIRE(index>=0 && index<WORKER_GENERATIONS);
    REQUIRE((unsigned)index==worker->runtime_count);
    REQUIRE(image[index] && tbss[index]);
    int *cell=image[index]();
    unsigned char *bytes=tbss[index]();
    REQUIRE(*cell==301+index);
    require_zero(bytes,257);
    *cell=700+10*worker->role+index;
    bytes[256]=(unsigned char)worker->role;
    worker->runtime_addresses[index]=(uintptr_t)cell;
    worker->runtime_count=(unsigned)index+1;
}
static void *entry(void *opaque);
static void load_generation(const char *path, int index, int mutate_caller_tls);
static void worker_fork(struct worker *worker)
{
    pid_t child=fork();
    REQUIRE(child>=0);
    if (!child) {
        REQUIRE(thread_pointer()==worker->tp);
        check_live(worker);
        if (dynamic) {
            uintptr_t old0=worker->runtime_addresses[0],old1=worker->runtime_addresses[1];
            struct runtime_view *before=owned ? current_view(worker->tp) : 0;
            load_generation(generation3_path,2,0);
            active_generations=3;
            inspect_runtime(worker,2);
            REQUIRE(worker->runtime_addresses[0]==old0 && worker->runtime_addresses[1]==old1);
            REQUIRE(*(int *)old0==700+10*worker->role && *(int *)old1==701+10*worker->role);
            if (owned) {
                struct runtime_view *after=current_view(worker->tp);
                REQUIRE(before && after && after!=before && after->previous==before);
                REQUIRE(after->module_count==before->module_count+1);
                REQUIRE(worker->view_count<MAX_VIEWS);
                worker->view_addresses[worker->view_count++]=(uintptr_t)after;
                require_mapped((uintptr_t)after,1);
            }
            check_live(worker);
        }
        struct worker fresh={.role=4,.action=NORMAL,.already_loaded=1};
        pthread_t thread;
        REQUIRE(pthread_create(&thread,0,entry,&fresh)==0);
        wait_at_least(&fresh.ready,3);
        REQUIRE(fresh.tp!=worker->tp);
        check_live(&fresh);
        for (int n=0;dynamic && n<active_generations;n++) REQUIRE(fresh.runtime_addresses[n]!=worker->runtime_addresses[n]);
        atomic_store_explicit(&fresh.phase,3,memory_order_release);
        void *result=0;
        REQUIRE(pthread_join(thread,&result)==0 && result==&fresh);
        REQUIRE(atomic_load_explicit(&fresh.destructor,memory_order_acquire)==1);
        require_mapped(fresh.tp,0);
        check_live(worker);
        _Exit(0);
    }
    int status=-1;
    REQUIRE(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
}
static void *entry(void *opaque)
{
    struct worker *worker=opaque;
    REQUIRE(initialized==INITIAL);
    require_zero(zero,sizeof(zero));
    REQUIRE(errno==0);
    worker->tp=thread_pointer();
    worker->tid=(pid_t)syscall(SYS_gettid);
    worker->initialized_address=(uintptr_t)&initialized;
    worker->zero_address=(uintptr_t)zero;
    if (owned && dynamic) {
        REQUIRE(*(uintptr_t *)worker->tp==worker->tp);
        worker->initial_dtv=*(uintptr_t *)(worker->tp+8);
        worker->initial_count=*(uintptr_t *)(worker->tp+16);
        REQUIRE(worker->initial_dtv && worker->initial_count);
    }
    initialized+=worker->role;
    zero[0]=(unsigned char)worker->role;
    REQUIRE(pthread_setspecific(key,worker)==0);
    atomic_store_explicit(&worker->ready,1,memory_order_release);
    if (!worker->already_loaded) wait_at_least(&worker->phase,1);
    struct runtime_view *first=0;
    if (dynamic) {
        inspect_runtime(worker,0);
        if (owned) first=current_view(worker->tp);
    }
    atomic_store_explicit(&worker->ready,2,memory_order_release);
    if (!worker->already_loaded) wait_at_least(&worker->phase,2);
    if (dynamic) {
        REQUIRE((uintptr_t)image[0]()==worker->runtime_addresses[0]);
        REQUIRE(*image[0]()==700+10*worker->role);
        inspect_runtime(worker,1);
        if (worker->already_loaded && active_generations==3) inspect_runtime(worker,2);
        if (owned && !worker->already_loaded) {
            struct runtime_view *last=current_view(worker->tp);
            REQUIRE(first && last && first!=last && last->module_count==first->module_count+1);
            REQUIRE(last->previous==first);
        }
    }
    remember_views(worker);
    atomic_store_explicit(&worker->ready,3,memory_order_release);
    while (atomic_load_explicit(&worker->phase,memory_order_acquire)<3) {
        if (worker->action==CANCELLED) pthread_testcancel();
        sched_yield();
    }
    check_live(worker);
    if (worker->action==FORK_WORKER) worker_fork(worker);
    if (worker->action==EXPLICIT) pthread_exit(worker);
    return worker;
}
static void load_generation(const char *path, int index, int mutate_caller_tls)
{
    if (!dynamic) return;
    void *handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    REQUIRE(handle);
    image[index]=(int *(*)(void))dlsym(handle,"prepared_worker_initialized");
    tbss[index]=(unsigned char *(*)(void))dlsym(handle,"prepared_worker_zero");
    REQUIRE(image[index] && tbss[index]);
    REQUIRE(*image[index]()==301+index);
    require_zero(tbss[index](),257);
    /* Only the pre-worker main mutations prove that later workers receive
     * relocated ELF templates rather than a copied live TLS image. The
     * fork-surviving worker must retain generation 3's initial image until
     * inspect_runtime records its own independent mutation. */
    if (mutate_caller_tls) {
        *image[index]()=900+index;
        tbss[index]()[256]=99;
    }
}
static void released(struct worker *worker)
{
    REQUIRE(atomic_load_explicit(&worker->destructor,memory_order_acquire)==1);
    require_mapped(worker->tp,0);
    for (unsigned n=0;n<worker->view_count;n++) require_mapped(worker->view_addresses[n],0);
}
int main(int argc,char **argv)
{
    REQUIRE(argc==6);
    owned=!strcmp(argv[2],"owned");
    REQUIRE(owned || !strcmp(argv[2],"portable"));
    dynamic=strcmp(argv[3],"-")!=0;
    generation3_path=argv[5];
    REQUIRE(!dynamic || strcmp(generation3_path,"-"));
    enum action action;
    if (!strcmp(argv[1],"normal")) action=NORMAL;
    else if (!strcmp(argv[1],"explicit")) action=EXPLICIT;
    else if (!strcmp(argv[1],"detached")) action=DETACHED;
    else if (!strcmp(argv[1],"cancelled")) action=CANCELLED;
    else if (!strcmp(argv[1],"fork-worker")) action=FORK_WORKER;
    else { REQUIRE(0); return 1; }
    REQUIRE(pthread_key_create(&key,destructor)==0);
    initialized=INITIAL+99;
    zero[0]=99;
    struct worker first={.role=1,.action=action}, fresh={.role=2,.action=NORMAL,.already_loaded=1};
    pthread_t first_thread,fresh_thread;
    REQUIRE(pthread_create(&first_thread,0,entry,&first)==0);
    wait_at_least(&first.ready,1);
    REQUIRE(first.tp!=thread_pointer() && first.initialized_address!=(uintptr_t)&initialized);
    if (action==DETACHED) REQUIRE(pthread_detach(first_thread)==0);
    load_generation(argv[3],0,1);
    atomic_store_explicit(&first.phase,1,memory_order_release);
    wait_at_least(&first.ready,2);
    load_generation(argv[4],1,1);
    atomic_store_explicit(&first.phase,2,memory_order_release);
    wait_at_least(&first.ready,3);
    check_live(&first);
    REQUIRE(pthread_create(&fresh_thread,0,entry,&fresh)==0);
    wait_at_least(&fresh.ready,3);
    REQUIRE(fresh.tp!=first.tp && fresh.initialized_address!=first.initialized_address);
    check_live(&fresh);
    for (int n=0;dynamic && n<active_generations;n++) REQUIRE(fresh.runtime_addresses[n]!=first.runtime_addresses[n]);
    if (action==CANCELLED) REQUIRE(pthread_cancel(first_thread)==0);
    else atomic_store_explicit(&first.phase,3,memory_order_release);
    if (action==DETACHED) {
        /* Do not query the retired pthread handle. The native kernel task ID
         * establishes retirement; the still-live fresh worker prevents a last
         * task/process-exit path and supplies a later ordinary join boundary. */
        for (;;) {
            errno=0;
            long alive=syscall(SYS_tgkill,getpid(),first.tid,0);
            if (alive==-1 && errno==ESRCH) break;
            REQUIRE(alive==0);
            sched_yield();
        }
        REQUIRE(atomic_load_explicit(&first.destructor,memory_order_acquire)==1);
        require_mapped(first.tp,1);
    } else {
        void *result=0;
        REQUIRE(pthread_join(first_thread,&result)==0);
        REQUIRE(result==(action==CANCELLED?PTHREAD_CANCELED:(void *)&first));
        released(&first);
    }
    atomic_store_explicit(&fresh.phase,3,memory_order_release);
    void *result=0;
    REQUIRE(pthread_join(fresh_thread,&result)==0 && result==&fresh);
    released(&fresh);
    if (action==DETACHED) released(&first);
    REQUIRE(initialized==INITIAL+99 && zero[0]==99);
    for (int n=0;dynamic && n<active_generations;n++) REQUIRE(*image[n]()==900+n && tbss[n]()[256]==99);
    REQUIRE(pthread_key_delete(key)==0);
    printf("prepared-worker-tls case=%s initial=ready distinct=1 retained=1 cleanup=1 reclaimed=%s fork=%d\n",
           argv[1],owned?"owned":"unspecified",action==FORK_WORKER);
    return 0;
}
