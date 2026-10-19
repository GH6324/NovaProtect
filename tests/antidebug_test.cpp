// Standalone harness for the NovaProtect anti-debug code generator.
//
// Every blob produced by AntiDebugModule is copied into executable memory and
// actually executed, so the test proves the emitted machine code is valid x64
// and behaves as documented (0 = clean, 1 = detected, 2 = API unavailable).
//
// Build:
//   g++ -std=c++17 -I include -o tests\antidebug_test.exe tests\antidebug_test.cpp src\anti_debug.cpp -O1

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// The individual check generators are private members; expose them for the
// harness only (the header itself is untouched for production users).
#define private public
#include "anti_debug.h"
#undef private

#include <windows.h>

using np::AntiDebugModule;
using np::AntiDebugConfig;

static int g_pass = 0;
static int g_fail = 0;

static void check(const char* name, bool ok, uint32_t got, const char* note = "") {
    if (ok) { g_pass++; std::printf("  [PASS] %-36s -> %u %s\n", name, got, note); }
    else    { g_fail++; std::printf("  [FAIL] %-36s -> %u (unexpected) %s\n", name, got, note); }
}

typedef uint32_t (*fn_void_t)(void);
typedef uint32_t (*fn_ptr_t)(void*);
typedef void (*tls_fn_t)(void*, uint32_t, void*);

static void* allocExec(const std::vector<uint8_t>& code) {
    if (code.empty()) return nullptr;
    void* m = VirtualAlloc(nullptr, code.size() + 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m) return nullptr;
    std::memcpy(m, code.data(), code.size());
    FlushInstructionCache(GetCurrentProcess(), m, code.size());
    return m;
}

static void dumpBytes(const char* tag, const std::vector<uint8_t>& c) {
    std::printf("  %-32s %4zu bytes: ", tag, c.size());
    for (size_t i = 0; i < c.size() && i < 20; i++) std::printf("%02X ", c[i]);
    std::printf("%s\n", c.size() > 20 ? "..." : "");
}

// ---------------------------------------------------------------------------
// non volatile register preservation probe (Windows x64 ABI: f in rcx)
// ---------------------------------------------------------------------------
extern "C" uint32_t np_call_preserve(uint32_t (*f)(void), uint64_t* out);
__asm__(
    ".text\n"
    ".globl np_call_preserve\n"
    "np_call_preserve:\n"
    "  push %rbx\n  push %rbp\n  push %rsi\n  push %rdi\n"
    "  push %r12\n  push %r13\n  push %r14\n  push %r15\n"
    "  sub $24, %rsp\n"                      // 24 keeps rsp 16 byte aligned at the call site
    "  mov %rdx, 0(%rsp)\n"                 // stash the out pointer on the stack: every
                                             // volatile register (incl. r11) may be clobbered
    "  movabs $0x1111111111111111, %rbx\n"
    "  movabs $0x2222222222222222, %rbp\n"
    "  movabs $0x3333333333333333, %rsi\n"
    "  movabs $0x4444444444444444, %rdi\n"
    "  movabs $0x5555555555555555, %r12\n"
    "  movabs $0x6666666666666666, %r13\n"
    "  movabs $0x7777777777777777, %r14\n"
    "  movabs $0x8888888888888888, %r15\n"
    "  call *%rcx\n"
    "  mov 0(%rsp), %r11\n"
    "  mov %rbx, 0(%r11)\n  mov %rbp, 8(%r11)\n  mov %rsi, 16(%r11)\n  mov %rdi, 24(%r11)\n"
    "  mov %r12, 32(%r11)\n  mov %r13, 40(%r11)\n  mov %r14, 48(%r11)\n  mov %r15, 56(%r11)\n"
    "  add $24, %rsp\n"
    "  pop %r15\n  pop %r14\n  pop %r13\n  pop %r12\n"
    "  pop %rdi\n  pop %rsi\n  pop %rbp\n  pop %rbx\n"
    "  ret\n"
);

static void testPreserves(fn_void_t f, const char* name) {
    uint64_t regs[8] = {0};
    np_call_preserve((uint32_t (*)(void))f, regs);
    static const uint64_t want[8] = {
        0x1111111111111111ULL, 0x2222222222222222ULL, 0x3333333333333333ULL, 0x4444444444444444ULL,
        0x5555555555555555ULL, 0x6666666666666666ULL, 0x7777777777777777ULL, 0x8888888888888888ULL };
    bool ok = true;
    for (int i = 0; i < 8; i++) if (regs[i] != want[i]) ok = false;
    check(name, ok, 0, ok ? "(rbx/rbp/rsi/rdi/r12-r15 intact)" : "(clobbered a non volatile register)");
}

// ---------------------------------------------------------------------------
// PEB helpers: the harness flips the very flags the checks read so we can prove
// the generated code actually reports a detection, not just a constant 0.
// ---------------------------------------------------------------------------
static uint8_t* peb() { return (uint8_t*)__readgsqword(0x60); }
static uint8_t& beingDebugged() { return peb()[0x02]; }
static uint32_t& ntGlobalFlag() { return *(uint32_t*)(peb() + 0xBC); }

// run one generated block and report its verdict
static void runBlock(const char* name, const std::vector<uint8_t>& code, bool expect_clean,
                     const char* note = "") {
    dumpBytes(name, code);
    void* mem = allocExec(code);
    if (!mem) { check(name, false, 0, "(VirtualAlloc failed)"); return; }
    uint32_t r = ((fn_void_t)mem)();
    bool ok;
    if (expect_clean) ok = (r == 0) || (r == 2);   // 2 = API unavailable, still a sane answer
    else              ok = (r != 0);
    check(name, ok, r, note);
    testPreserves((fn_void_t)mem, "  nonvolatile regs preserved");
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);

    // Child mode: prove the TLS callback really terminates a process when a
    // detection trips (ExitProcess is resolved from ntdll/kernel32 at runtime).
    if (argc > 1 && std::strcmp(argv[1], "tls-detect") == 0) {
        AntiDebugConfig cfg;
        cfg.level = 1;
        AntiDebugModule m(cfg);
        void* f = allocExec(m.generateTLSCallback(true));
        if (!f) return 8;
        beingDebugged() = 1;                 // simulate an attached debugger
        ((tls_fn_t)f)(nullptr, 1, nullptr);  // DLL_PROCESS_ATTACH
        std::printf("NOT EXITED\n");        // reached only if ExitProcess was not called
        return 7;
    }

    std::printf("NovaProtect anti-debug generator tests\n");
    std::printf("----------------------------------------------------------\n");

    {
        AntiDebugConfig cfg;
        cfg.level = 3;
        AntiDebugModule m(cfg);

        std::printf("[individual checks]\n");
        runBlock("genIsDebuggerPresent", m.genIsDebuggerPresent(), true, "(PEB->BeingDebugged)");
        runBlock("genPEBCheck", m.genPEBCheck(), true, "(PEB->NtGlobalFlag)");
        runBlock("genHeapCheck", m.genHeapCheck(), true, "(heap ForceFlags/Flags)");
        runBlock("genNtQueryInfoProcess", m.genNtQueryInfoProcess(), true, "(ProcessDebugPort/Flags/Object)");
        runBlock("genHardwareBreakpointCheck", m.genHardwareBreakpointCheck(), true, "(GetThreadContext Dr0-Dr3)");
        runBlock("genTimingCheck", m.genTimingCheck(), true, "(RDTSC delta < 8192)");
        runBlock("genCPUIDCheck", m.genCPUIDCheck(), true, "(hypervisor bit / vendor string)");
        runBlock("generateAntiVMRoutine", m.generateAntiVMRoutine(true), true, "(anti VM entry point)");
    }

    std::printf("[detection actually fires]\n");
    {
        AntiDebugConfig cfg;
        cfg.level = 3;
        AntiDebugModule m(cfg);
        auto c1 = m.genIsDebuggerPresent();
        auto c2 = m.genPEBCheck();
        void* f1 = allocExec(c1);
        void* f2 = allocExec(c2);

        uint8_t savedBd = beingDebugged();
        uint32_t savedNg = ntGlobalFlag();

        beingDebugged() = 1;
        uint32_t r1 = ((fn_void_t)f1)();
        check("genIsDebuggerPresent(flag set)", r1 == 1, r1, "(BeingDebugged=1 detected)");
        beingDebugged() = savedBd;

        ntGlobalFlag() = savedNg | 0x70u;
        uint32_t r2 = ((fn_void_t)f2)();
        check("genPEBCheck(flag set)", r2 == 1, r2, "(NtGlobalFlag=0x70 detected)");
        ntGlobalFlag() = savedNg;

        // the composed routine must name the first tripped check (1 = PEB, 2 = NtGlobalFlag)
        AntiDebugConfig l1; l1.level = 1;
        AntiDebugModule m1(l1);
        void* cr = allocExec(m1.generateCheckRoutine(true));
        beingDebugged() = 1;
        uint32_t id1 = ((fn_void_t)cr)();
        beingDebugged() = savedBd;
        ntGlobalFlag() = savedNg | 0x70u;
        uint32_t id2 = ((fn_void_t)cr)();
        ntGlobalFlag() = savedNg;
        check("checkRoutine reports id 1", id1 == 1, id1, "(BeingDebugged tripped)");
        check("checkRoutine reports id 2", id2 == 2, id2, "(NtGlobalFlag tripped)");

        check("PEB flags restored", beingDebugged() == savedBd && ntGlobalFlag() == savedNg, 0, "");
    }

    std::printf("[timing stability]\n");
    {
        AntiDebugConfig cfg; cfg.level = 3;
        AntiDebugModule m(cfg);
        void* f = allocExec(m.genTimingCheck());
        int clean = 0, dirty = 0;
        for (int i = 0; i < 200; i++) {
            uint32_t r = ((fn_void_t)f)();
            if (r == 0) clean++; else dirty++;
        }
        check("genTimingCheck x200 clean", dirty == 0, (uint32_t)clean, "(no false positive across 200 runs)");
    }

    std::printf("[composed routines]\n");
    {
        AntiDebugConfig cfg;
        cfg.level = 1;
        AntiDebugModule m(cfg);
        runBlock("generateCheckRoutine(L1)", m.generateCheckRoutine(true), true, "(4 basic checks)");
    }
    {
        AntiDebugConfig cfg;
        cfg.level = 3;
        AntiDebugModule m(cfg);
        runBlock("generateCheckRoutine(L3)", m.generateCheckRoutine(true), true, "(all 7 checks)");
    }

    std::printf("[integrity]\n");
    {
        const uint32_t kSize = 512;
        uint8_t* region = (uint8_t*)VirtualAlloc(nullptr, kSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        for (uint32_t i = 0; i < kSize; i++) region[i] = (uint8_t)(i * 7 + 3);

        AntiDebugModule m;
        uint64_t want = AntiDebugModule::fnv1a64(region, kSize);
        m.setIntegrityHash(want);
        auto code = m.generateIntegrityCheck(true, 0, kSize);
        dumpBytes("generateIntegrityCheck", code);
        std::printf("  expected fnv1a64 = 0x%016llX\n", (unsigned long long)want);

        void* mem = allocExec(code);
        if (mem) {
            fn_ptr_t f = (fn_ptr_t)mem;
            uint32_t good = f(region);
            check("integrity(matching data)", good == 0, good, "(hash matches)");
            region[100] ^= 0x40;
            uint32_t bad = f(region);
            check("integrity(tampered data)", bad == 1, bad, "(hash mismatch reported)");
            region[100] ^= 0x40;
            testPreserves((fn_void_t)mem, "  nonvolatile regs preserved");
        } else {
            check("generateIntegrityCheck", false, 0, "(VirtualAlloc failed)");
        }
    }

    std::printf("[tls callback]\n");
    {
        AntiDebugConfig cfg;
        cfg.level = 1;
        AntiDebugModule m(cfg);
        auto code = m.generateTLSCallback(true);
        dumpBytes("generateTLSCallback", code);
        void* mem = allocExec(code);
        if (mem) {
            tls_fn_t f = (tls_fn_t)mem;
            f(nullptr, 0, nullptr);   // DLL_PROCESS_DETACH: must return at once
            check("tls(reason 0 = detach)", true, 0, "(returned without exiting)");
            f(nullptr, 1, nullptr);   // DLL_PROCESS_ATTACH: clean machine -> returns
            check("tls(reason 1 = attach, clean)", true, 0, "(returned, nothing detected)");
        } else {
            check("generateTLSCallback", false, 0, "(VirtualAlloc failed)");
        }
    }

    std::printf("[tls detection path]\n");
    {
        char exe[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, exe, MAX_PATH);
        std::string cmd = std::string("\"") + exe + "\" tls-detect";
        std::vector<char> cmdline(cmd.begin(), cmd.end());
        cmdline.push_back('\0');
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessA(nullptr, cmdline.data(), nullptr, nullptr, FALSE, 0,
                           nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 15000);
            DWORD code = 0xFFFFFFFFu;
            GetExitCodeProcess(pi.hProcess, &code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            check("tls(attach+detected -> ExitProcess)", code == 0, code,
                  "(child terminated by ExitProcess)");
        } else {
            check("tls(attach+detected -> ExitProcess)", false, 0, "(CreateProcess failed)");
        }
    }

    std::printf("----------------------------------------------------------\n");
    if (g_fail == 0) std::printf("ANTIDEBUG TESTS PASSED (%d/%d)\n", g_pass, g_pass + g_fail);
    else             std::printf("ANTIDEBUG TESTS FAILED (%d/%d, %d failed)\n", g_pass, g_pass + g_fail, g_fail);
    return g_fail == 0 ? 0 : 1;
}
