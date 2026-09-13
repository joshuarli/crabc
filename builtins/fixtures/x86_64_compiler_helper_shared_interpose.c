/* A public executable definition must not preempt libc.so's local helper call. */

extern void *malloc(unsigned long);
extern void free(void *);

int __popcountdi2(unsigned long long ignored)
{
    (void)ignored;
    return 777;
}

int main(void)
{
    void *allocation = malloc(96);
    if (allocation == 0) return 1;
    free(allocation);
    return 0;
}
