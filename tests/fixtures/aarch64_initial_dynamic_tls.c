#include <pthread.h>
#include <stdio.h>

extern int tls_read(void);
extern void tls_write(int);
static void *worker(void *unused) {
    (void)unused;
    if (tls_read() != 28) return (void *)1;
    tls_write(30);
    return (void *)(long)(tls_read() != 61);
}
int main(void) {
    pthread_t thread;
    void *result;
    if (tls_read() != 28 || pthread_create(&thread, 0, worker, 0)) return 1;
    if (pthread_join(thread, &result) || result || tls_read() != 28) return 2;
    puts("initial dynamic TLS ok");
    return 0;
}
