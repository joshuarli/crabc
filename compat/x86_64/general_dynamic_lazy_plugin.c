/* Ordinary unresolved imports: the provider is loaded after this DSO. */
#ifdef DEFERRED_GOT
extern int deferred_value;
int deferred_run(void) { return deferred_value; }
#else
extern int deferred_function(void);
int deferred_run(void) { return deferred_function(); }
#endif
