#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
static void dumpc(CONTEXT&c){
  printf("  eip=%08llx esp=%08llx ebp=%08llx eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx efl=%08llx\n",
   (unsigned long long)c.Rip,(unsigned long long)c.Rsp,(unsigned long long)c.Rbp,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi,(unsigned long long)c.EFlags);
}
int main(int argc,char**argv){ if(argc<3){printf("usage: trc exe steps\n");return 2;}
 int steps=atoi(argv[2]);
 STARTUPINFOA si{}; PROCESS_INFORMATION pi{}; si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS|CREATE_NEW_CONSOLE,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{}; bool tf=false; unsigned long long base=0; int n=0;
 for(;;){ if(!WaitForDebugEvent(&de,INFINITE)) break; DWORD st=DBG_CONTINUE; bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){ base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage; printf("base=%llx\n",base); }
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){ const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   CONTEXT c{}; c.ContextFlags=CONTEXT_FULL; GetThreadContext(pi.hThread,&c);
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT && n==0){ n++; printf("first bp at %llx\n",(unsigned long long)c.Rip);
     unsigned long long entry=base+0x8000; c.Rip=entry; c.EFlags|=0x100; c.ContextFlags=CONTEXT_FULL; SetThreadContext(pi.hThread,&c); printf("jump to stub %llx, single step\n",entry); }
   else if(r.ExceptionCode==EXCEPTION_SINGLE_STEP){
     printf("[%d] eip=%08llx eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx ebp=%08llx esp=%08llx\n", n,(unsigned long long)c.Rip,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi,(unsigned long long)c.Rbp,(unsigned long long)c.Rsp);
     n++; if(n>steps){printf("done\n");go=false;} else { c.EFlags|=0x100; c.ContextFlags=CONTEXT_FULL; SetThreadContext(pi.hThread,&c);} }
   else { printf("EXC %08lX addr=%p\n",(unsigned long)r.ExceptionCode,r.ExceptionAddress); dumpc(c); go=false; }
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){ printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode); break; }
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE); if(!go)break; }
 CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0; }
