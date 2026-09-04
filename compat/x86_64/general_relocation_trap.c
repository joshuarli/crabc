/* Harness-only regression: a fatal candidate signal must not be suppressed. */
int main(void) { __builtin_trap(); }
