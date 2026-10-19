#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
static void dumpc(HANDLE h,CONTEXT&c){
  printf("  eip=%08llx esp=%08llx ebp=%08llx eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx efl=%08llx\n",
   (unsigned long long)c.Rip,(unsigned long long)c.Rsp,(unsigned long long)c.Rbp,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi,(unsigned long long)c.EFlags);
}
static bool setbp(HANDLE th,unsigned long long addr,int idx){
  CONTEXT c{}; c.ContextFlags=CONTEXT_DEBUG_REGISTERS; if(!GetThreadContext(th,&c))return false;
  if(idx==0)c.Dr0=addr; else if(idx==1)c.Dr1=addr; else c.Dr2=addr;
  c.Dr7 &= ~(0xFull<<(idx*2));
  c.Dr7 |= (0x1ull<<(idx*2));
  c.ContextFlags=CONTEXT_DEBUG_REGISTERS; return SetThreadContext(th,&c)!=0;
}
int main(int argc,char**argv){ if(argc<4){printf("usage: dbg32b exe bpRva1 bpRva2\n");return 2;}
 unsigned long long rva1=strtoull(argv[2],0,16), rva2=strtoull(argv[3],0,16);
 STARTUPINFOA si{}; PROCESS_INFORMATION pi{}; si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{}; bool bpset=false;
 for(;;){ if(!WaitForDebugEvent(&de,INFINITE)) break; DWORD st=DBG_CONTINUE; bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){printf("base=%p\n",de.u.CreateProcessInfo.lpBaseOfImage);}
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){ const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT){
     if(!bpset){ bpset=true; unsigned long long base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
       setbp(pi.hThread,base+rva1,0); setbp(pi.hThread,base+rva2,1); printf("bps set at %llx %llx\n",base+rva1,base+rva2); }
     else { CONTEXT c{}; c.ContextFlags=CONTEXT_FULL; GetThreadContext(pi.hThread,&c); printf("BP hit:\n"); dumpc(pi.hThread,c); }
     st=DBG_CONTINUE;
   } else {
     CONTEXT c{}; c.ContextFlags=CONTEXT_FULL; GetThreadContext(pi.hThread,&c);
     printf("EXC %08lX addr=%p n=%lu [",(unsigned long)r.ExceptionCode,r.ExceptionAddress,(unsigned long)r.NumberParameters);
     for(DWORD k=0;k<r.NumberParameters&&k<2;k++)printf("%llx ",(unsigned long long)r.ExceptionInformation[k]);
     printf("]\n"); dumpc(pi.hThread,c);
     st=DBG_EXCEPTION_NOT_HANDLED; go=false;
   }
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){ printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode); break; }
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE); if(!go)break; }
 CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return 0; }
