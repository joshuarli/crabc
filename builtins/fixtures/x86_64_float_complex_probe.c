/* Ordinary C arithmetic emits both single-complex compiler helpers. */
static float _Complex multiply(float _Complex a, float _Complex b) { return a * b; }
static float _Complex divide(float _Complex a, float _Complex b) { return a / b; }
int main(void)
{
    volatile float _Complex a = 3.0f + 4.0fi;
    volatile float _Complex b = 1.0f + 2.0fi;
    float _Complex product = multiply(a, b);
    float _Complex quotient = divide(a, b);
    return __real__ product != -5.0f || __imag__ product != 10.0f ||
           __real__ quotient != 2.2f || __imag__ quotient != -0.4f;
}
