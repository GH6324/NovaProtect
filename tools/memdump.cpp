#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
static void dump(HANDLE hp,unsigned long long base,unsigned long long rva,const char*tag){
  unsigned char buf[32]={0};SIZE_T rd=0;
  if(ReadProcessMemory(hp,(void*)(base+rva),buf,32,&rd)){
    printf("  %s base+%llx:",tag,rva);
    for(int i=0;i<32;i++)printf(" %02x",buf[i]);
    printf("\n");
  } else printf("  %s base+%llx: READ FAIL\n",tag,rva);
}
int main(int argc,char**argv){STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{};unsigned long long base=0;bool brk=false;
 for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT&&!brk){brk=true;} else if(r.ExceptionCode==0x4000001FULL){}
   else if(r.ExceptionCode==EXCEPTION_BREAKPOINT){}
   else{CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(pi.hThread,&c);
     unsigned int marker=0;SIZE_T rd=0;ReadProcessMemory(pi.hProcess,(void*)(base+0x701c),&marker,4,&rd);
     printf("EXC %08lX eip=%08llx marker=%08x base=%llx\n",(unsigned long)r.ExceptionCode,(unsigned long long)c.Rip,marker,base);
     dump(pi.hProcess,base,0x1000,".text+0");
     dump(pi.hProcess,base,0x1d00,".text ep-");
     dump(pi.hProcess,base,0x1d10,".text EP");
     dump(pi.hProcess,base,0x2000,".text reg");
     dump(pi.hProcess,base,0x200c,".text fau");
     dump(pi.hProcess,base,0x2100,".text +");
     dump(pi.hProcess,base,0x2300,".text tail");
     go=false;}
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode);break;}
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE);if(!go)break;}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;}