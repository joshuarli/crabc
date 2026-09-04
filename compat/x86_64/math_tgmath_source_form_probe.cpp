/* The source-form runner selects either <math.h> or <tgmath.h> directly. */

#ifndef CRABC_MATH_TGMATH_HEADER
#error "source-form runner must select a direct math header"
#endif
#include CRABC_MATH_TGMATH_HEADER

#ifndef math_errhandling
#error "math_errhandling must remain a public math-header macro"
#endif

static_assert(sizeof(float_t) >= sizeof(float), "float_t remains usable");
static_assert(sizeof(double_t) >= sizeof(double), "double_t remains usable");

static double (*const math_tgmath_sqrt_address)(double) = &sqrt;

int math_tgmath_source_form_cpp(double value)
{
    return isfinite(value) + isinf(value) + isnan(value) + isnormal(value)
        + static_cast<int>(sizeof(math_tgmath_sqrt_address));
}
