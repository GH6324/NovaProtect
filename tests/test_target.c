// test_target.c - Test program for packer benchmarking
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "VMProtectSDK.h"

__declspec(noinline) uint32_t secret_hash(const char* data, size_t len) {
    VMProtectBeginUltra("secret_hash");
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)(unsigned char)data[i];
        h *= 0x01000193;
        h = (h << 13) | (h >> 19);
        h += 0x9E3779B9;
    }
    VMProtectEnd();
    return h;
}

__declspec(noinline) int complex_calc(int a, int b, int c) {
    VMProtectBeginMutation("complex_calc");
    int result = 0;
    int t1 = a ^ (b << 3);
    int t2 = b | (c >> 2);
    int t3 = c + (a * 7);
    if (t1 > t2) {
        result = t3 - t1;
    } else {
        result = t2 + t3;
    }
    if (result < 0) {
        result = -result | (t1 & 0xFF);
    }
    VMProtectEnd();
    return result;
}

__declspec(noinline) uint64_t fibonacci_mix(uint64_t seed, int rounds) {
    VMProtectBeginUltra("fibonacci_mix");
    uint64_t a = seed, b = seed ^ 0xDEADBEEF;
    for (int i = 0; i < rounds; i++) {
        uint64_t t = a + b;
        a = b;
        b = t;
        if (b & 1) {
            b ^= (a << 7) | (a >> 57);
        } else {
            a ^= (b << 13) | (b >> 51);
        }
        b ^= seed;
    }
    VMProtectEnd();
    return b;
}

__declspec(noinline) void print_protected_string(void) {
    VMProtectBeginVirtualization("print_protected_string");
    const char* msg = VMProtectDecryptStringA("This is an encrypted string!");
    printf("Protected: %s\n", msg);
    VMProtectFreeString(msg);
    VMProtectEnd();
}

int main(int argc, char* argv[]) {
    printf("=== Benchmark Target ===\n");
    if (VMProtectIsDebuggerPresent(true)) { printf("Debugger!\n"); return 1; }
    if (VMProtectIsVirtualMachinePresent()) { printf("VM!\n"); return 2; }
    if (!VMProtectIsValidImageCRC()) { printf("CRC!\n"); return 3; }

    const char* test_data = "HelloWorld";
    uint32_t h = secret_hash(test_data, strlen(test_data));
    printf("Hash: 0x%08X\n", h);

    int r1 = complex_calc(42, 17, 99);
    int r2 = complex_calc(-5, 200, 3);
    printf("Calc1: %d Calc2: %d\n", r1, r2);

    uint64_t fib = fibonacci_mix(0x12345678, 64);
    printf("FibMix: %016llX\n", (unsigned long long)fib);

    print_protected_string();
    printf("OK\n");
    return 0;
}
