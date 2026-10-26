#pragma once
// BUILD-TIME STUB for the public source snapshot.
//
// The production header links the commercial VMProtect SDK import library.
// Core protection sources are not part of this repository, so this stand-in
// keeps the same public surface and compiles the marker call sites to no-ops.
// See sdk/include/novaprotect_sdk.h for the supported integration API.

// NovaProtect SDK marker byte pattern. Stable on disk across releases: the
// packer locates regions by this exact encoding, so neither the compiler nor
// the optimisation level may change it.
#if defined(_WIN64)
#define NOVAPROTECT_BEGIN(name) \
    __asm__ volatile(".byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")

#define NOVAPROTECT_END() \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop"); \
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop")
#else
#define NOVAPROTECT_BEGIN(name)
#define NOVAPROTECT_END()
#endif

// Legacy names remain source compatible; the on-disk pattern is unchanged.
#define NOVAPACK_BEGIN(name) NOVAPROTECT_BEGIN(name)
#define NOVAPACK_END() NOVAPROTECT_END()