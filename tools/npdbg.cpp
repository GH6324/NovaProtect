#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <vector>

struct Mod { ULONG_PTR base; DWORD size; std::string name; };

static std::vector<Mod> EnumMods(DWORD pid) {
    std::vector<Mod> v;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return v;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    if (Module32FirstW(s, &me)) {
        do {
            Mod m; m.base = (ULONG_PTR)me.modBaseAddr; m.size = me.modBaseSize;
            char buf[MAX_PATH * 2]; buf[0] = 0;
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, buf, sizeof(buf), 0, 0);
            m.name = buf; v.push_back(m);
        } while (Module32NextW(s, &me));
    }
    CloseHandle(s);
    return v;
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: npdbg <exe> [args...]\n"); return 2; }
    std::string cmd;
    for (int i = 1; i < argc; i++) { if (i > 1) cmd += " "; cmd += "\""; cmd += argv[i]; cmd += "\""; }
    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, (char*)cmd.c_str(), nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi)) {
        printf("CreateProcess failed %lu\n", GetLastError()); return 3;
    }
    int count = 0;
    for (;;) {
        DEBUG_EVENT de;
        if (!WaitForDebugEvent(&de, INFINITE)) break;
        DWORD cont = DBG_CONTINUE;
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto& ex = de.u.Exception;
            DWORD code = ex.ExceptionRecord.ExceptionCode;
            ULONG_PTR addr = (ULONG_PTR)ex.ExceptionRecord.ExceptionAddress;
            ULONG_PTR acc = 0;
            if (ex.ExceptionRecord.NumberParameters >= 2) acc = (ULONG_PTR)ex.ExceptionRecord.ExceptionInformation[1];
            HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, de.dwThreadId);
            CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
            ULONG_PTR rip = 0, rsp = 0;
            if (ht && GetThreadContext(ht, &ctx)) { rip = ctx.Rip; rsp = ctx.Rsp; }
            auto mods = EnumMods(de.dwProcessId);
            std::string where = "?";
            for (auto& m : mods) if (rip >= m.base && rip < m.base + m.size) {
                char b[512]; sprintf(b, "%s+0x%llX", m.name.c_str(), (unsigned long long)(rip - m.base)); where = b;
            }
            printf("[%d] code=0x%08lX addr=0x%llX acc=0x%llX rip=0x%llX rsp=0x%llX %s first=%d\n",
                   count, (unsigned long)code, (unsigned long long)addr, (unsigned long long)acc,
                   (unsigned long long)rip, (unsigned long long)rsp, where.c_str(), ex.dwFirstChance);
            if (ht && GetThreadContext(ht, &ctx)) {
                printf("     rax=%016llX rbx=%016llX rcx=%016llX rdx=%016llX\n",
                       (unsigned long long)ctx.Rax,(unsigned long long)ctx.Rbx,(unsigned long long)ctx.Rcx,(unsigned long long)ctx.Rdx);
                printf("     rsi=%016llX rdi=%016llX rbp=%016llX rsp=%016llX\n",
                       (unsigned long long)ctx.Rsi,(unsigned long long)ctx.Rdi,(unsigned long long)ctx.Rbp,(unsigned long long)ctx.Rsp);
                printf("     r8=%016llX r9=%016llX r10=%016llX r11=%016llX\n",
                       (unsigned long long)ctx.R8,(unsigned long long)ctx.R9,(unsigned long long)ctx.R10,(unsigned long long)ctx.R11);
                printf("     r12=%016llX r13=%016llX r14=%016llX r15=%016llX\n",
                       (unsigned long long)ctx.R12,(unsigned long long)ctx.R13,(unsigned long long)ctx.R14,(unsigned long long)ctx.R15);
            }
            if (ht) CloseHandle(ht);
            fflush(stdout);
            count++;
            if (count > 60) { printf("too many events, detaching\n"); DebugActiveProcessStop(de.dwProcessId); break; }
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
        if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("process exited code=0x%08lX\n", (unsigned long)de.u.ExitProcess.dwExitCode);
            break;
        }
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}