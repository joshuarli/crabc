#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

/* musl 1.2.6 sem_wait -> sem_timedwait tests cancellation before consuming
 * an already available unit. This isolated regression also runs against a
 * runtime that has not yet supplied the timed-wait entry. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"semaphore-wait-cancel:%d\n",__LINE__); return 1; } } while (0)
static sem_t semaphore;
static int returned, cleaned;
static void cleanup(void *unused) { (void)unused; cleaned=1; }
static void *worker(void *unused) {
    (void)unused;
    pthread_cleanup_push(cleanup,NULL);
    if (pthread_cancel(pthread_self())) _exit(91);
    if (sem_wait(&semaphore)) _exit(92);
    returned=1;
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return NULL;
}
int main(void) {
    alarm(10);
    CHECK(!sem_init(&semaphore,0,1));
    pthread_t thread; void *result=NULL;
    CHECK(!pthread_create(&thread,NULL,worker,NULL) && !pthread_join(thread,&result));
    CHECK(result==PTHREAD_CANCELED && cleaned && !returned);
    CHECK(!sem_trywait(&semaphore) && sem_trywait(&semaphore)==-1 && errno==EAGAIN);
    CHECK(!sem_destroy(&semaphore));
    puts("owned-semaphore-wait-cancellation-ok");
    return 0;
}
