#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
int main(int argc,char**argv){
  STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
  if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
  DEBUG_EVENT de{};unsigned long long base=0;int cnt=0;
  for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;bool go=true;
    if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
    if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
      if(r.ExceptionCode==EXCEPTION_BREAKPOINT){}
      else{CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(pi.hThread,&c);
        unsigned long long rip=(unsigned long long)c.Rip;
        printf("EXC %08lX RIP=%llx (base+%llx) RSP=%llx RBP=%llx RAX=%llx RBX=%llx RCX=%llx RDX=%llx RSI=%llx RDI=%llx\n",
          (unsigned long)r.ExceptionCode,rip,rip-base,(unsigned long long)c.Rsp,(unsigned long long)c.Rbp,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi);
        printf("info:");for(DWORD k=0;k<r.NumberParameters&&k<4;k++)printf(" %llx",(unsigned long long)r.ExceptionInformation[k]);printf("\n");
        unsigned char buf[64];SIZE_T rd=0;
        if(ReadProcessMemory(pi.hProcess,(void*)(rip-24),buf,64,&rd)&&rd==64){
          printf("bytes@-24:");for(int i=0;i<64;i++){if(i==24)printf(" |");printf(" %02X",buf[i]);}printf("\n");
        } else printf("ReadProcessMemory failed %lu\n",GetLastError());
        // also dump stub section range
        go=false;cnt++;}
    } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode);break;}
    ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE);if(!go)break;}
  CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;}