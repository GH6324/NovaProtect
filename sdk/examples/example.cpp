// NovaProtect SDK example: mark one function for virtualization.
//
// VM regions only support a register-only subset of x86-64. Compile this file
// with -O0 (or use volatile locals) so the marked body stays simple enough to
// translate. In production, keep VM targets to the register-only arithmetic
// subset; anything else is safely left native by the packer.
#include "novaprotect_sdk.h"
#include <cstdio>

volatile int g_seed = 0x5A5A5A5A;

int secret_calc(int x)
{
    NOVAPROTECT_BEGIN("secret_calc");
    int a = x + 3;
    int b = x - 7;
    int c = a ^ b;
    c = c * 0x9E3779B9 + a;
    c = c ^ g_seed;
    NOVAPROTECT_END();
    return c;
}

int main()
{
    std::printf("result=%d\n", secret_calc(42));
    return 0;
}