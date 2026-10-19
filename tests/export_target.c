#include <stdio.h>

__declspec(dllexport) int novaprotect_export_probe(int value) {
    return value + 7;
}

int main(void) {
    if (novaprotect_export_probe(35) != 42) return 1;
    puts("EXPORT-OK");
    return 0;
}
