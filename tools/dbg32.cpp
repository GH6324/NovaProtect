#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
int main(int argc,char**argv){ if(argc<2){printf("usage\n");return 2;}
 STARTUPINFOA si{}; PROCESS_INFORMATION pi{}; si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("CreateProcess failed %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{}; for(;;){ if(!WaitForDebugEvent(&de,INFINITE)) break; DWORD st=DBG_CONTINUE; bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){printf("PROC base=%p\n",de.u.CreateProcessInfo.lpBaseOfImage);}
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){ const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   printf("EXC %08lX addr=%p n=%lu [",(unsigned long)r.ExceptionCode,r.ExceptionAddress,(unsigned long)r.NumberParameters);
   for(DWORD k=0;k<r.NumberParameters&&k<2;k++)printf("%llx ",(unsigned long long)r.ExceptionInformation[k]);
   printf("]\n");
   if(r.ExceptionCode!=EXCEPTION_BREAKPOINT){ CONTEXT c{}; c.ContextFlags=CONTEXT_FULL; GetThreadContext(pi.hThread,&c);
     printf("  eip=%08llx esp=%08llx eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx ebp=%08llx\n",(unsigned long long)c.Rip,(unsigned long long)c.Rsp,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi,(unsigned long long)c.Rbp);
     unsigned char code[16]; SIZE_T rd=0; ReadProcessMemory(pi.hProcess,(void*)(ULONG_PTR)c.Rip,code,16,&rd); printf("  bytes:"); for(SIZE_T k=0;k<rd;k++)printf(" %02x",code[k]); printf("\n");
     st=DBG_EXCEPTION_NOT_HANDLED; }
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){ printf("EXIT code=%08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode); go=false; }
  if(go) ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st); else { ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE); break; } }
 CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0; }
