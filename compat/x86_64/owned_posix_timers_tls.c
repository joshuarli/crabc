/* Loaded by the first live timer callback; every next invocation must see
   the relocated initialized template and zero TBSS at identical addresses. */
static _Thread_local int initialized = 137;
static _Thread_local int zeroed;
int timer_tls_touch(void)
{
    int result = initialized == 137 && zeroed == 0;
    initialized = 9; zeroed = 9;
    return result;
}
