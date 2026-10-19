#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
static void pr(CONTEXT&c){printf("eip=%08llx esp=%08llx ebp=%08llx eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx\n",(unsigned long long)c.Rip,(unsigned long long)c.Rsp,(unsigned long long)c.Rbp,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,(unsigned long long)c.Rsi,(unsigned long long)c.Rdi);}
static void setdr(HANDLE th,int i,unsigned long long a,bool en){CONTEXT c{};c.ContextFlags=CONTEXT_DEBUG_REGISTERS;GetThreadContext(th,&c);if(i==0)c.Dr0=a;else if(i==1)c.Dr1=a;else if(i==2)c.Dr2=a;else if(i==3)c.Dr3=a;c.Dr7&=~(0xFull<<(i*2));if(en)c.Dr7|=(0x1ull<<(i*2));c.ContextFlags=CONTEXT_DEBUG_REGISTERS;SetThreadContext(th,&c);}
int main(int argc,char**argv){if(argc<3){printf("usage: dbgd exe rva1[,rva2]\n");return 2;}
 unsigned long long rv[4]={0};int nr=0;char buf[64];int bi=0;for(const char*p=argv[2];;p++){if(*p==','||*p==0){buf[bi]=0;if(bi)rv[nr++]=strtoull(buf,0,16);bi=0;if(*p==0)break;}else if(bi<60)buf[bi++]=*p;}
 STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{};bool bpset=false;unsigned long long base=0;int hits=0;
 for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;}
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT&&!bpset){bpset=true;for(int i=0;i<nr;i++)setdr(pi.hThread,i,base+rv[i],true);}
   else if(r.ExceptionCode==0x4000001EULL){CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(pi.hThread,&c);
     unsigned long long eip=(unsigned long long)c.Rip;printf("HIT at %llx\n",eip);pr(c);
     for(int i=0;i<nr;i++){if(eip==base+rv[i])setdr(pi.hThread,i,0,false);}
     hits++;if(hits>=nr){for(int i=0;i<nr;i++)setdr(pi.hThread,i,0,false);} }
   else if(r.ExceptionCode==EXCEPTION_BREAKPOINT){}
   else{CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(pi.hThread,&c);printf("EXC %08lX addr=%p n=%lu [",(unsigned long)r.ExceptionCode,r.ExceptionAddress,(unsigned long)r.NumberParameters);for(DWORD k=0;k<r.NumberParameters&&k<2;k++)printf("%llx ",(unsigned long long)r.ExceptionInformation[k]);printf("]\n");pr(c);}
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode);break;}
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE);if(!go)break;}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;}
