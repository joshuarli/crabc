typedef double _Complex complex_double;

__attribute__((noinline)) complex_double divide(complex_double a, complex_double b)
{
    return a / b;
}

int main(void)
{
    volatile complex_double a = 3.0 + 4.0i;
    volatile complex_double b = 1.0 + 2.0i;
    complex_double value = divide(a, b);
    return !(__real__ value > 2.199999999999 && __real__ value < 2.200000000001 &&
             __imag__ value > -0.400000000001 && __imag__ value < -0.399999999999);
}
