int deferred_value = 73;
static __thread int deferred_tls = 73;
int deferred_function(void) { return deferred_tls; }

#ifdef DEFERRED_BAD
extern int unrelated_missing;
/* R_X86_64_64 is not a deferrable GOT/PLT import. */
void *unrelated_address = &unrelated_missing;
__attribute__((constructor)) static void must_not_construct(void)
{
    deferred_value = 99;
}
#endif
