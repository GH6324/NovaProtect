// vm_target.c - NovaProtect VM virtualization end-to-end fixture.
#include <stdio.h>
#include <stdint.h>

extern uint64_t np_vm_demo(uint64_t a, uint64_t b);

static uint64_t ref_demo(uint64_t a, uint64_t b) {
    uint64_t rax = a, rcx = b;
    rax += rcx; rax ^= rcx; rax += 0x1234; rax <<= 3; rax -= rcx;
    rax |= rcx; rax &= 0x00FFFF00ull; rax += 1; rax -= 1; rax = ~rax; rax = (uint64_t)(-(int64_t)rax);
    rax += 0x40; rax += rcx; rax ^= a; rax -= 0x77; rax <<= 5; rax >>= 2;
    rax |= 0x0101; rax &= 0x7FFFFFFFull; rax += rcx; rax ^= b; rax = ~rax; rax = (uint64_t)(-(int64_t)rax);
    rax += 0x1111; rax -= 0x2222; rax <<= 1; rax |= a; rax &= 0x0F0F0F0Full; rax += 1;
    rax ^= rcx; rax += b; rax += 0x100; rax -= 0x33; rax >>= 4; rax |= 0x2020;
    rax &= 0x00FF00FFull; rax += a; rax ^= b; rax += 1; rax -= 1; rax = ~rax;
    rax = (uint64_t)(-(int64_t)rax); rax += 0x7; rax -= 0x9; rax <<= 2; rax |= rcx;
    rax &= 0x0000FFFFull; rax += b; rax ^= a; rax += 0x20; rax += 0x5555; rax -= 0x111;
    return rax;
}

int main(void) {
    uint64_t a = 0x123456789ABCDEF0ull, b = 0x0FEDCBA987654321ull;
    uint64_t got = np_vm_demo(a, b);
    uint64_t want = ref_demo(a, b);
    printf("vm_demo: got=%016llX want=%016llX\n",
           (unsigned long long)got, (unsigned long long)want);
    if (got != want) { printf("VM-MISMATCH\n"); return 1; }
    printf("VM-OK\n");
    return 0;
}