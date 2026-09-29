/* Compare fmod/fmodf results, errno, and raw x87/MXCSR state with pinned musl. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "the fmod MXCSR probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <math.h>
#include <stdint.h>

typedef double (*double_fmod)(double, double);
typedef float (*float_fmod)(float, float);
static double_fmod volatile call_fmod = (fmod);
static float_fmod volatile call_fmodf = (fmodf);

/* The freestanding candidate has no TLS startup. fmod leaves errno alone. */
static int local_errno;
int *__errno_location(void) { return &local_errno; }

struct pair64 { uint64_t x, y; };
struct pair32 { uint32_t x, y; };

static const struct pair64 double_cases[] = {
	{ 0x4016000000000000, 0x4000000000000000 },
	{ 0xc016000000000000, 0x4000000000000000 },
	{ 0xc010000000000000, 0x4000000000000000 },
	{ 0x8000000000000000, 0x3ff0000000000000 },
	{ 0x3ff0000000000000, 0x0000000000000000 },
	{ 0x7ff0000000000000, 0x3ff0000000000000 },
	{ 0x3ff0000000000000, 0x7ff0000000000000 },
	{ 0x7ff8000000000041, 0x3ff0000000000000 },
	{ 0x3ff0000000000000, 0x7ff8000000000041 },
	{ 0x7ff0000000000042, 0x3ff0000000000000 },
	{ 0x3ff0000000000000, 0x7ff0000000000042 },
	{ 0x3fffffffffffffff, 0x3ff0000000000000 },
	{ 0x4000000000000000, 0x3ff0000000000001 },
	{ 0x4000000000000001, 0x3fefffffffffffff },
	{ 0x3ff0000000000000, 0x3fefffffffffffff },
	{ 0x3ff0000000000000, 0x3ff0000000000001 },
	{ 0x3ff0000000000001, 0x3ff0000000000000 },
	{ 0x0010000000000001, 0x0010000000000000 },
	{ 0x0010000000000000, 0x000fffffffffffff },
	{ 0x000fffffffffffff, 0x0000000000000001 },
	{ 0x0000000000000001, 0x0000000000000002 },
	{ 0x0000000000000002, 0x0000000000000001 },
	{ 0x0003b3e29a21487a, 0x00044c79f1fe9d67 },
	{ 0x3ff0000000000000, 0x0000000000000001 },
	{ 0x7fefffffffffffff, 0x0000000000000001 },
	{ 0x7fefffffffffffff, 0x4000000000000000 },
	{ 0x433fffffffffffff, 0x4026000000000000 },
};

static const struct pair32 float_cases[] = {
	{ 0x40b00000, 0x40000000 },
	{ 0xc0b00000, 0x40000000 },
	{ 0xc0800000, 0x40000000 },
	{ 0x80000000, 0x3f800000 },
	{ 0x3f800000, 0x00000000 },
	{ 0x7f800000, 0x3f800000 },
	{ 0x3f800000, 0x7f800000 },
	{ 0x7fc00041, 0x3f800000 },
	{ 0x3f800000, 0x7fc00041 },
	{ 0x7f800042, 0x3f800000 },
	{ 0x3f800000, 0x7f800042 },
	{ 0x3fffffff, 0x3f800000 },
	{ 0x40000000, 0x3f800001 },
	{ 0x40000001, 0x3f7fffff },
	{ 0x3f800000, 0x3f7fffff },
	{ 0x3f800000, 0x3f800001 },
	{ 0x3f800001, 0x3f800000 },
	{ 0x00800001, 0x00800000 },
	{ 0x00800000, 0x007fffff },
	{ 0x007fffff, 0x00000001 },
	{ 0x00000001, 0x00000002 },
	{ 0x00000002, 0x00000001 },
	{ 0x00012345, 0x00054321 },
	{ 0x3f800000, 0x00000001 },
	{ 0x7f7fffff, 0x00000001 },
	{ 0x7f7fffff, 0x40000000 },
	{ 0x4b7fffff, 0x41300000 },
};

struct record {
	uint64_t result;
	uint32_t mxcsr;
	uint32_t case_id;
	uint32_t error;
	uint32_t x87_status;
};

#define DOUBLE_COUNT (sizeof(double_cases) / sizeof(double_cases[0]))
#define FLOAT_COUNT (sizeof(float_cases) / sizeof(float_cases[0]))
#define DOUBLE_POWER_COUNT 29
#define FLOAT_POWER_COUNT 23
#define CASE_COUNT (DOUBLE_COUNT + FLOAT_COUNT + \
	4 * (DOUBLE_POWER_COUNT + FLOAT_POWER_COUNT))
#define EXPECTED_COUNT (4 * 2 * 2 * CASE_COUNT)
static struct record records[EXPECTED_COUNT];
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
	unsigned short x87_status;
	__asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
	__asm__ volatile("fnstsw %0" : "=am"(x87_status));
	records[count++] = (struct record){ result, mxcsr, id,
		(uint32_t)local_errno, x87_status };
}

static void run_double(uint32_t control, uint32_t id, uint64_t x, uint64_t y)
{
	__asm__ volatile("ldmxcsr %0" : : "m"(control) : "memory");
	local_errno = 77;
	observe(id, double_bits(call_fmod(as_double(x), as_double(y))));
}

static void run_float(uint32_t control, uint32_t id, uint32_t x, uint32_t y)
{
	__asm__ volatile("ldmxcsr %0" : : "m"(control) : "memory");
	local_errno = 77;
	observe(id, float_bits(call_fmodf(as_float(x), as_float(y))));
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
			for (uint32_t sticky = 0; sticky < 2; sticky++) {
				uint32_t control = UINT32_C(0x1f80) | mode << 13;
				if (denormal_mode)
					control |= UINT32_C(0x8040);
				if (sticky)
					control |= UINT32_C(0x0004);
				for (uint32_t id = 0; id < DOUBLE_COUNT; id++)
					run_double(control, id, double_cases[id].x,
						double_cases[id].y);
				for (uint32_t id = 0; id < FLOAT_COUNT; id++)
					run_float(control, (uint32_t)DOUBLE_COUNT + id,
						float_cases[id].x, float_cases[id].y);
				/* Span the finite exponent range with exact powers and adjacent ulps. */
				for (uint32_t index = 0; index < DOUBLE_POWER_COUNT; index++) {
					uint64_t y = (uint64_t)(1 + index * 73) << 52;
					uint64_t twice = y + (UINT64_C(1) << 52);
					uint32_t id = (uint32_t)(DOUBLE_COUNT + FLOAT_COUNT) + 4 * index;
					run_double(control, id, twice - 1, y);
					run_double(control, id + 1, twice, y + 1);
					run_double(control, id + 2, twice + 1, y - 1);
					run_double(control, id + 3, twice - 1, y - 1);
				}
				for (uint32_t index = 0; index < FLOAT_POWER_COUNT; index++) {
					uint32_t y = (1 + index * 11) << 23;
					uint32_t twice = y + (UINT32_C(1) << 23);
					uint32_t id = (uint32_t)(DOUBLE_COUNT + FLOAT_COUNT +
						4 * DOUBLE_POWER_COUNT) + 4 * index;
					run_float(control, id, twice - 1, y);
					run_float(control, id + 1, twice, y + 1);
					run_float(control, id + 2, twice + 1, y - 1);
					run_float(control, id + 3, twice - 1, y - 1);
				}
			}
		}
	__asm__ volatile("ldmxcsr %0" : : "m"(original) : "memory");
	if (count != EXPECTED_COUNT)
		return 1;
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
