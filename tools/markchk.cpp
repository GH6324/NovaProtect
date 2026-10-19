#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
int main(int argc,char**argv){STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{};unsigned long long base=0;bool brk=false;
 for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT&&!brk){brk=true;} else if(r.ExceptionCode==0x4000001FULL){}
   else if(r.ExceptionCode==EXCEPTION_BREAKPOINT){}
   else{CONTEXT c{};c.ContextFlags=CONTEXT_FULL;GetThreadContext(pi.hThread,&c);
     unsigned int m[8]={0};SIZE_T rd=0;
     for(int i=0;i<8;i++) ReadProcessMemory(pi.hProcess,(void*)(base+0x701c+i*4),&m[i],4,&rd);
     printf("EXC %08lX eip=%08llx ebp=%08llx esp=%08llx imagebase=%llx\n",(unsigned long)r.ExceptionCode,(unsigned long long)c.Rip,(unsigned long long)c.Rbp,(unsigned long long)c.Rsp,base);
     printf("  [+1C]marker=%08x [+20]esp=%08x [+24][esp0]=%08x [+28]ebp12=%08x\n",m[0],m[1],m[2],m[3]);
     printf("  [+2C]=%08x [+30]=%08x [+34]=%08x [+38]=%08x\n",m[4],m[5],m[6],m[7]);
     go=false;}
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){unsigned int marker=0;SIZE_T rd=0;ReadProcessMemory(pi.hProcess,(void*)(base+0x701c),&marker,4,&rd);printf("EXIT %08lX marker=%08x\n",(unsigned long)de.u.ExitProcess.dwExitCode,marker);break;}
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE);if(!go)break;}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;}