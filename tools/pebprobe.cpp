#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
int main(){
  unsigned char* peb=(unsigned char*)__readgsqword(0x60);
  unsigned char* ldr=*(unsigned char**)(peb+0x18);
  LIST_ENTRY* head=(LIST_ENTRY*)(ldr+0x10);
  printf("peb=%p ldr=%p head=%p\n",(void*)peb,(void*)ldr,(void*)head);
  int n=0;
  for(LIST_ENTRY* e=head->Flink; e!=head && n<8; e=e->Flink,n++){
    void* base=*(void**)((unsigned char*)e+0x30);
    struct US { USHORT len; USHORT max; PWSTR buf; };
    US* bn=(US*)((unsigned char*)e+0x58);
    wprintf(L"  [%d] entry=%p base=%p len=%u name=%.*s\n",n,(void*)e,base,bn->len/2,bn->len/2,bn->buf);
  }
  return 0;
}