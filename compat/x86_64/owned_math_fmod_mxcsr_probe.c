/* Compare the raw MXCSR effects of the binary32/binary64 fmod C ABI. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "the fmod MXCSR probe requires native Linux/x86-64 LP64"
#endif

#include <math.h>
#include <stdint.h>

typedef double (*double_fmod)(double, double);
typedef float (*float_fmod)(float, float);
static double_fmod volatile call_fmod = (fmod);
static float_fmod volatile call_fmodf = (fmodf);

struct record {
	uint64_t result;
	uint32_t mxcsr;
	uint32_t case_id;
};

static struct record records[32];
static unsigned int count;

static double as_double(uint64_t bits)
{
	union { uint64_t bits; double value; } view = { .bits = bits };
	return view.value;
}

static float as_float(uint32_t bits)
{
	union { uint32_t bits; float value; } view = { .bits = bits };
	return view.value;
}

static uint64_t double_bits(double value)
{
	union { uint64_t bits; double value; } view = { .value = value };
	return view.bits;
}

static uint32_t float_bits(float value)
{
	union { uint32_t bits; float value; } view = { .value = value };
	return view.bits;
}

static void observe(uint32_t id, uint64_t result)
{
	uint32_t mxcsr;
	__asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
	records[count++] = (struct record){ result, mxcsr, id };
}

static void run_case(uint32_t control, uint32_t id)
{
	__asm__ volatile("ldmxcsr %0" : : "m"(control) : "memory");
	switch (id) {
	case 0:
		observe(id, double_bits(call_fmod(as_double(UINT64_C(0x0003b3e29a21487a)),
			as_double(UINT64_C(0x00044c79f1fe9d67)))));
		break;
	case 1:
		observe(id, float_bits(call_fmodf(as_float(UINT32_C(0x00012345)),
			as_float(UINT32_C(0x00054321)))));
		break;
	case 2:
		observe(id, double_bits(call_fmod(1.0,
			as_double(UINT64_C(0x0000000000000001)))));
		break;
	case 3:
		observe(id, float_bits(call_fmodf(1.0f,
			as_float(UINT32_C(0x00000001)))));
		break;
	}
}

static uint32_t current_mxcsr(void)
{
	uint32_t value;
	__asm__ volatile("stmxcsr %0" : "=m"(value));
	return value;
}

int main(void)
{
	const uint32_t original = current_mxcsr();
	for (uint32_t mode = 0; mode < 4; mode++)
		for (uint32_t denormal_mode = 0; denormal_mode < 2; denormal_mode++) {
			uint32_t control = UINT32_C(0x1f80) | mode << 13;
			if (denormal_mode)
				control |= UINT32_C(0x8040);
			for (uint32_t id = 0; id < 4; id++)
				run_case(control, id);
		}
	__asm__ volatile("ldmxcsr %0" : : "m"(original) : "memory");
	const unsigned char *data = (const unsigned char *)records;
	unsigned long left = sizeof(records);
	while (left) {
		long written;
		__asm__ volatile("syscall" : "=a"(written) :
			"a"(1), "D"(1), "S"(data), "d"(left) : "rcx", "r11", "memory");
		if (written <= 0)
			return 1;
		data += written;
		left -= (unsigned long)written;
	}
	return 0;
}
