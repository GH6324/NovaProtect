#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
static unsigned long long base=0; static HANDLE hp=0,ht=0;
static void dumpregs(CONTEXT&c,unsigned long long off){
 printf("  %04llx rip=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx r9=%llx r10=%llx r11=%llx r12=%llx r13=%llx r14=%llx r15=%llx\n",
   off,(unsigned long long)c.Rip,(unsigned long long)c.Rax,(unsigned long long)c.Rbx,(unsigned long long)c.Rcx,(unsigned long long)c.Rdx,
   (unsigned long long)c.Rsi,(unsigned long long)c.Rdi,(unsigned long long)c.R8,(unsigned long long)c.R9,(unsigned long long)c.R10,
   (unsigned long long)c.R11,(unsigned long long)c.R12,(unsigned long long)c.R13,(unsigned long long)c.R14,(unsigned long long)c.R15);
}
static void dumpmem(unsigned long long a,const char*label,int n){
 unsigned char b[32]; SIZE_T rd=0;
 if(ReadProcessMemory(hp,(void*)a,b,n,&rd)){printf("  %s @%llx: ",label,a);for(int i=0;i<n;i++)printf("%02x ",b[i]);printf("\n");}
 else printf("  %s @%llx: <unreadable>\n",label,a);
}
static void setdr0(unsigned long long a,bool en){CONTEXT c{};c.ContextFlags=CONTEXT_DEBUG_REGISTERS;GetThreadContext(ht,&c);c.Dr0=a;c.Dr7&=~0xFull;if(en)c.Dr7|=0x1;c.ContextFlags=CONTEXT_DEBUG_REGISTERS;SetThreadContext(ht,&c);}
int main(int argc,char**argv){
 if(argc<3){printf("usage: trace64 exe rva [steps]\n");return 2;}
 unsigned long long rva=strtoull(argv[2],0,16); int maxsteps=argc>3?atoi(argv[3]):200;
 STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 hp=pi.hProcess;ht=pi.hThread;
 DEBUG_EVENT de{};bool brk=false;bool bp=false;int steps=0;
 for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT&&!brk){brk=true;setdr0(base+rva,true);}
   else if(r.ExceptionCode==0x4000001EULL){
     CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(ht,&c);
     printf("BP HIT rip=%llx base=%llx\n",(unsigned long long)c.Rip,base);
     dumpmem(base+0x15000,"np_data",32);
     dumpmem(base+0x17000,"np_stub",16);
     setdr0(0,false);
     c.EFlags|=0x100; SetThreadContext(ht,&c); // trap
   }
   else if(r.ExceptionCode==EXCEPTION_SINGLE_STEP){
     CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(ht,&c);
     if(steps<maxsteps){dumpregs(c,(unsigned long long)c.Rip-base);steps++;}
     if(steps>=maxsteps){printf("done\n");break;}
     c.EFlags|=0x100;SetThreadContext(ht,&c);
   }
   else if(r.ExceptionCode==EXCEPTION_BREAKPOINT){}
   else{CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(ht,&c);
     printf("EXC %08lX addr=%p\n",(unsigned long)r.ExceptionCode,r.ExceptionAddress);dumpregs(c,(unsigned long long)c.Rip-base);
     if(r.NumberParameters>=2)printf("  params %llx %llx\n",(unsigned long long)r.ExceptionInformation[0],(unsigned long long)r.ExceptionInformation[1]);
     break;}
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode);break;}
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st);}
 CloseHandle(ht);CloseHandle(hp);return 0;}