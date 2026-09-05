#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/mman.h>

/* musl 1.2.6 src/linux/getrandom.c and src/misc/getentropy.c: the
 * getrandom syscall checks cancellation even for zero length and rejected
 * flags. getentropy rejects >256 first, then disables cancellation across
 * its complete fill/retry loop and restores the prior state on every exit.
 * Random bytes are never compared to an oracle or judged by their values. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"entropy-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum operation { RANDOM_ZERO, RANDOM_FILL, RANDOM_FLAGS, RANDOM_FAULT,
    ENTROPY_ZERO, ENTROPY_FILL, ENTROPY_MAX, ENTROPY_LIMIT, ENTROPY_FAULT };
struct entropy_state {
    enum operation operation;
    int cancel_state;
    void *inaccessible;
    unsigned char bytes[257];
    _Atomic int returned, result, error, previous_state, cleaned;
};
static void cleanup_entropy(void *opaque) {
    struct entropy_state *s=opaque; atomic_store(&s->cleaned,1);
}
static void *entropy_worker(void *opaque) {
    struct entropy_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(81);
    pthread_cleanup_push(cleanup_entropy,s);
    if (pthread_cancel(pthread_self())) _exit(82);
    errno=90;
    int result;
    switch (s->operation) {
    case RANDOM_ZERO: result=(int)getrandom(s->bytes,0,0); break;
    case RANDOM_FILL: result=(int)getrandom(s->bytes,32,0); break;
    case RANDOM_FLAGS: result=(int)getrandom(s->bytes,32,0x80000000u); break;
    case RANDOM_FAULT: result=(int)getrandom(s->inaccessible,32,0); break;
    case ENTROPY_ZERO: result=getentropy(s->bytes,0); break;
    case ENTROPY_FILL: result=getentropy(s->bytes,32); break;
    case ENTROPY_MAX: result=getentropy(s->bytes,256); break;
    case ENTROPY_LIMIT: result=getentropy(s->inaccessible,257); break;
    case ENTROPY_FAULT: result=getentropy(s->inaccessible,32); break;
    default: _exit(83);
    }
    atomic_store(&s->result,result); atomic_store(&s->error,errno); atomic_store(&s->returned,1);
    int previous=-1; if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(84);
    atomic_store(&s->previous_state,previous);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static int pending_entropy(enum operation operation, int state, void *inaccessible) {
    struct entropy_state s={.operation=operation,.cancel_state=state,.inaccessible=inaccessible,.previous_state=-1};
    memset(s.bytes,0x5a,sizeof s.bytes);
    pthread_t thread; void *result=NULL;
    CHECK(!pthread_create(&thread,NULL,entropy_worker,&s));
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED && atomic_load(&s.cleaned));
    int cancellation_point=operation<=RANDOM_FAULT;
    int returned=!cancellation_point || state!=PTHREAD_CANCEL_ENABLE;
    CHECK(atomic_load(&s.returned)==returned);
    if (returned) {
        int expected_result=operation==RANDOM_FILL ? 32 : 0;
        int expected_error=90;
        if (operation==RANDOM_FLAGS) { expected_result=-1; expected_error=EINVAL; }
        if (operation==RANDOM_FAULT || operation==ENTROPY_FAULT) { expected_result=-1; expected_error=EFAULT; }
        if (operation==ENTROPY_LIMIT) { expected_result=-1; expected_error=EIO; }
        if (cancellation_point && state==2) { expected_result=-1; expected_error=ECANCELED; }
        CHECK(atomic_load(&s.result)==expected_result && atomic_load(&s.error)==expected_error);
        CHECK(atomic_load(&s.previous_state)==(cancellation_point && state==2 ? PTHREAD_CANCEL_DISABLE : state));
    }
    int written=operation==ENTROPY_MAX ? 256 : operation==ENTROPY_FILL ||
        (operation==RANDOM_FILL && state==PTHREAD_CANCEL_DISABLE) ? 32 : 0;
    for (int i=written;i<(int)sizeof s.bytes;i++) CHECK(s.bytes[i]==0x5a);
    printf("entropy pending operation=%d state=%d returned=%d preserved-state=%d\n",
        operation,state,returned,returned ? atomic_load(&s.previous_state) : -1);
    return 0;
}
int main(void) {
    alarm(30);
    void *inaccessible=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(inaccessible!=MAP_FAILED);
    for (int operation=RANDOM_ZERO;operation<=ENTROPY_FAULT;operation++)
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) CHECK(!pending_entropy(operation,state,inaccessible));
    CHECK(!munmap(inaccessible,4096));
    puts("owned-entropy-cancellation-ok");
    return 0;
}
