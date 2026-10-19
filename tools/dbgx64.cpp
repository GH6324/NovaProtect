#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
int main(int argc,char**argv){
 STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{};unsigned long long base=0;bool brk=false;int seen=0;
 for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT&&!brk){brk=true;}
   else if(r.ExceptionCode==0x4000001FULL){}
   else if(r.ExceptionCode==EXCEPTION_BREAKPOINT){}
   else{CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(pi.hThread,&c);
     printf("EXC %08lX addr=%p eip=%llx rsp=%llx rbp=%llx base=%llx\n",(unsigned long)r.ExceptionCode,r.ExceptionAddress,(unsigned long long)c.Rip,(unsigned long long)c.Rsp,(unsigned long long)c.Rbp,base);
     if(r.NumberParameters>=2)printf("  params: %llx %llx\n",(unsigned long long)r.ExceptionInformation[0],(unsigned long long)r.ExceptionInformation[1]);
     unsigned char buf[16];SIZE_T rd=0;
     if(ReadProcessMemory(pi.hProcess,(void*)(base+0x15000),buf,16,&rd)){printf("  np_data: ");for(int i=0;i<16;i++)printf("%02x ",buf[i]);printf("\n");}
     if(ReadProcessMemory(pi.hProcess,(void*)(base+0x17000),buf,16,&rd)){printf("  np_stub: ");for(int i=0;i<16;i++)printf("%02x ",buf[i]);printf("\n");}
     break;}
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT %08lX\n",(unsigned long)de.u.ExitProcess.dwExitCode);break;}
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st);}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;}