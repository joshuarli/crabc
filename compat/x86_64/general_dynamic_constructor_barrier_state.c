#include "general_dynamic_constructor_barrier_state.h"
#include <stdatomic.h>

static atomic_int entered;
static atomic_int attempts;
static atomic_int completed;
static atomic_int early_completions;
static atomic_int symbol_results;
static atomic_int iterate_results;

void constructor_barrier_reset(void)
{
    atomic_store(&entered, 0);
    atomic_store(&attempts, 0);
    atomic_store(&completed, 0);
    atomic_store(&early_completions, 0);
    atomic_store(&symbol_results, 0);
    atomic_store(&iterate_results, 0);
}

void constructor_barrier_entered(void) { atomic_store(&entered, 1); }
int constructor_barrier_is_entered(void) { return atomic_load(&entered); }
void constructor_barrier_attempt(void) { atomic_fetch_add(&attempts, 1); }
int constructor_barrier_attempts(void) { return atomic_load(&attempts); }
void constructor_barrier_complete(void) { atomic_fetch_add(&completed, 1); }
int constructor_barrier_completed(void) { return atomic_load(&completed); }
void constructor_barrier_early_completion(int value)
{
    if (value < 0) {
        atomic_store(&early_completions, value);
        return;
    }
    int expected = 0;
    atomic_compare_exchange_strong(&early_completions, &expected, value);
}
int constructor_barrier_early_completions(void) { return atomic_load(&early_completions); }
void constructor_barrier_symbol_result(int found) { atomic_fetch_add(&symbol_results, found); }
int constructor_barrier_symbol_results(void) { return atomic_load(&symbol_results); }
void constructor_barrier_iterate_result(int found) { atomic_fetch_add(&iterate_results, found); }
int constructor_barrier_iterate_results(void) { return atomic_load(&iterate_results); }
