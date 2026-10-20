#pragma once
// NovaProtect SDK - function / region protection markers.
//
// Usage:
//   1. Wrap a function body with NOVAPROTECT_BEGIN("name") / NOVAPROTECT_END().
//   2. Compile the EXE (markers are inert in the unprotected build).
//   3. Run the EXE through the NovaProtect client. The detector scans for the
//      BEGIN/END byte pattern and the packer lowers the enclosed region to VM
//      bytecode (or applies the selected object rule).
//
// VM constraint (important):
//   The x64 VM translator only lowers a register-only, straight-line subset.
//   A region that touches RSP/RBP or memory stays native ("VM skip region:
//   uses RSP/RBP"). For full virtualization, mark a hand-written assembly
//   block (see sdk/examples/example_vm.S) or a simple register-only body
//   compiled without a stack frame. Anything else is safely left native.
//
// Backward compatibility: NOVAPACK_* names continue to work and emit the same
// bytes.

#if defined(_MSC_VER) && !defined(__clang__)
#define NOVAPROTECT_INLINE __forceinline
#elif defined(__GNUC__)
#define NOVAPROTECT_INLINE __attribute__((always_inline))
#else
#define NOVAPROTECT_INLINE inline
#endif

#if defined(_WIN64)
#define NOVAPROTECT_BEGIN(name) \
    __asm__ volatile(".byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#elif defined(_WIN32)
#define NOVAPROTECT_BEGIN(name) \
    __asm__ volatile(".byte 0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#else
#error "NovaProtect SDK markers require x86 or x64 Windows"
#endif

#define NOVAPROTECT_END() \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")

// Legacy aliases kept for existing projects.
#define NOVAPACK_BEGIN(name) NOVAPROTECT_BEGIN(name)
#define NOVAPACK_END() NOVAPROTECT_END()

#define NOVAPROTECT_SDK_VERSION "2.2.7"