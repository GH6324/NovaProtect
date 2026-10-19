#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
int main(int argc,char**argv){STARTUPINFOA si{};PROCESS_INFORMATION pi{};si.cb=sizeof(si);
 if(!CreateProcessA(nullptr,argv[1],nullptr,nullptr,FALSE,DEBUG_ONLY_THIS_PROCESS,nullptr,nullptr,&si,&pi)){printf("cp fail %lu\n",GetLastError());return 1;}
 DEBUG_EVENT de{};bool done=false;unsigned long long base=0;
 for(;;){if(!WaitForDebugEvent(&de,INFINITE))break;DWORD st=DBG_CONTINUE;bool go=true;
  if(de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)base=(unsigned long long)de.u.CreateProcessInfo.lpBaseOfImage;
  if(de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){const EXCEPTION_RECORD&r=de.u.Exception.ExceptionRecord;
   if(r.ExceptionCode==EXCEPTION_BREAKPOINT&&!done){done=true;
     unsigned char buf[32];SIZE_T rd=0;unsigned long long a=base+0x8000;
     BOOL ok=ReadProcessMemory(pi.hProcess,(void*)a,buf,32,&rd);
     printf("RPM %llx ok=%d rd=%llu bytes:",a,ok,(unsigned long long)rd);for(SIZE_T i=0;i<rd;i++)printf(" %02x",buf[i]);printf("\n");
     MEMORY_BASIC_INFORMATION mbi{};VirtualQueryEx(pi.hProcess,(void*)a,&mbi,sizeof(mbi));
     printf("protect=%lx state=%lx type=%lx region=%p size=%llx\n",(unsigned long)mbi.Protect,(unsigned long)mbi.State,(unsigned long)mbi.Type,mbi.BaseAddress,(unsigned long long)mbi.RegionSize);
     unsigned long long a2=base+0x7f00;VirtualQueryEx(pi.hProcess,(void*)a2,&mbi,sizeof(mbi));
     printf("at 7f00 protect=%lx state=%lx type=%lx region=%p size=%llx\n",(unsigned long)mbi.Protect,(unsigned long)mbi.State,(unsigned long)mbi.Type,mbi.BaseAddress,(unsigned long long)mbi.RegionSize);
     go=false;}
  } else if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){break;}
  ContinueDebugEvent(de.dwProcessId,de.dwThreadId,go?st:DBG_CONTINUE);if(!go)break;}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;}
