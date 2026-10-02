/* Exercise declarations as ordinary C and C++ callers. Binary80 values
 * cross the public function-pointer ABI; evaluation types follow the compiler
 * mode independently of the storage format of long double. */
#define _GNU_SOURCE 1
#include <float.h>
#include <math.h>
#include <stdlib.h>
#ifdef __cplusplus
#define ASSERT static_assert
extern "C"
#else
#define ASSERT _Static_assert
#endif
int header_x87_calling_convention_probe(void);
ASSERT(sizeof(long double)==16,"x87 storage");
ASSERT(LDBL_MANT_DIG==64 && LDBL_MAX_EXP==16384,"x87 format");
ASSERT(sizeof(float_t)==(FLT_EVAL_METHOD==0?sizeof(float):FLT_EVAL_METHOD==1?sizeof(double):sizeof(long double)),"compiler-selected float evaluation");
ASSERT(sizeof(double_t)==(FLT_EVAL_METHOD<2?sizeof(double):sizeof(long double)),"compiler-selected double evaluation");
int header_x87_calling_convention_probe(void)
{
    long double (*volatile difference)(long double,long double)=(fdiml);
    long double (*volatile power)(long double)=(exp10l);
    long double (*volatile alias)(long double)=(pow10l);
    long double (*volatile parse)(const char*,char**)=(strtold);
    char *end;
    return difference(3.0L,1.0L)!=2.0L || power(1.0L)!=10.0L || alias(0.0L)!=1.0L || parse("1.25",&end)!=1.25L || *end;
}
