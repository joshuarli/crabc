/* A timer callback closes and reopens this retained module between visits.
   The callback thread keeps its TLS addresses while each visit sees the
   initialized template and zero TBSS again. */
static _Thread_local int initialized = 137;
static _Thread_local int zeroed;
static int visits;
int timer_tls_touch(void **initialized_address, void **zeroed_address, int *visit)
{
    *initialized_address = &initialized;
    *zeroed_address = &zeroed;
    *visit = ++visits;
    int result = initialized == 137 && zeroed == 0;
    initialized = 9; zeroed = 9;
    return result;
}

/* Keep a live callback's TLS value observable while another timer worker
   completes a callback and resets only its own thread's image. */
void timer_tls_exchange(void **initialized_address, void **zeroed_address,
                        int *before_initialized, int *before_zeroed, int next)
{
    *initialized_address = &initialized;
    *zeroed_address = &zeroed;
    *before_initialized = initialized;
    *before_zeroed = zeroed;
    initialized = next;
    zeroed = next;
}
