#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
int main(){
  unsigned char* peb=(unsigned char*)__readgsqword(0x60);
  unsigned char* ldr=*(unsigned char**)(peb+0x18);
  LIST_ENTRY* head=(LIST_ENTRY*)(ldr+0x10);
  printf("peb=%p ldr=%p head=%p flink=%p\n",(void*)peb,(void*)ldr,(void*)head,(void*)head->Flink);
  for(LIST_ENTRY* e=head->Flink; e!=head; e=e->Flink){
    struct US { USHORT len; USHORT max; PWSTR buf; };
    US* bn=(US*)((unsigned char*)e+0x58);
    char nm[64]={0}; WideCharToMultiByte(CP_ACP,0,bn->buf,bn->len/2,nm,63,0,0);
    if(nm[0]=='k'||nm[0]=='K'||nm[0]=='n'||nm[0]=='N'){
      printf("  entry=%p base=%p bn.len@0x58=%u name=%s\n",(void*)e,*(void**)((unsigned char*)e+0x30),bn->len,nm);
    }
  }
  return 0;
}