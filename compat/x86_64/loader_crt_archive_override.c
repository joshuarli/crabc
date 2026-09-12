extern int loader_crt_events;
int loader_crt_expected = 1;
void _init(void) { loader_crt_events += 1; }
void _fini(void) { loader_crt_events += 2; }
