#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
int main(int argc,char**argv){ if(argc<2){printf("usage: debugrun exe [args]\n");return 2;}
 std::string cmd=argv[1]; for(int i=2;i<argc;i++){cmd+=" ";cmd+=argv[i];}
 STARTUPINFOA si{}; PROCESS_INFORMATION pi{}; si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,cmd.data(),nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("CreateProcess failed %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{}; for(;;){ if(!WaitForDebugEvent(&de,INFINITE)) break;
  DWORD st=DBG_CONTINUE; bool go=true;
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){ const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode!=EXCEPTION_BREAKPOINT){ CONTEXT c{}; c.ContextFlags=CONTEXT_FULL; HANDLE h=pi.hThread; GetThreadContext(h,&c);
    printf("accessinfo %llu %llu\\n",(unsigned long long)(r.NumberParameters>0?r.ExceptionInformation[0]:999),(unsigned long long)(r.NumberParameters>1?r.ExceptionInformation[1]:0)); printf("exception %08lX addr=%p rip=%llx rsp=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx r9=%llx r10=%llx r11=%llx r12=%llx r13=%llx r14=%llx r15=%llx flags=%llx\n",(unsigned long)r.ExceptionCode,r.ExceptionAddress,(unsigned long long)c.Rip,(unsigned long long)c.Rsp,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi,(unsigned long long)c.R8,(unsigned long long)c.R9,(unsigned long long)c.R10,(unsigned long long)c.R11,(unsigned long long)c.R12,(unsigned long long)c.R13,(unsigned long long)c.R14,(unsigned long long)c.R15,(unsigned long long)c.EFlags); st=DBG_EXCEPTION_NOT_HANDLED; }
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){ go=false; }
  if(go) ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st); else { ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE); break; } }
 CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0; }


