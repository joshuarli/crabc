#ifndef CRABC_GENERAL_DYNAMIC_CONSTRUCTOR_BARRIER_STATE_H
#define CRABC_GENERAL_DYNAMIC_CONSTRUCTOR_BARRIER_STATE_H

void constructor_barrier_reset(void);
void constructor_barrier_entered(void);
int constructor_barrier_is_entered(void);
void constructor_barrier_attempt(void);
int constructor_barrier_attempts(void);
void constructor_barrier_complete(void);
int constructor_barrier_completed(void);
void constructor_barrier_early_completion(int completed);
int constructor_barrier_early_completions(void);
void constructor_barrier_symbol_result(int found);
int constructor_barrier_symbol_results(void);
void constructor_barrier_iterate_result(int found);
int constructor_barrier_iterate_results(void);

#endif
