#include <stdint.h>

#ifdef PC32_LIBRARY
int pc32_target = 19;
uintptr_t pc32_slot = (uintptr_t)&pc32_target;

int pc32_probe(void) {
    int32_t displacement = (int32_t)(uint32_t)pc32_slot;
    return (uint32_t)(pc32_slot >> 32) == 0
        && (void *)((char *)&pc32_slot + displacement) == (void *)&pc32_target
        && pc32_target == 19;
}
#else
extern int pc32_probe(void);

int main(void) {
    return pc32_probe() ? 33 : 41;
}
#endif
