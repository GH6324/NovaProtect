#include <windows.h>

__declspec(dllexport) int novaprotect_dll_probe(int value) {
    return value ^ 0x5A5A;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
