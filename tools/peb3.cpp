#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
int main(){
  // Reproduce np_find_module in isolation with the CURRENT stub constants to see which load faults.
  unsigned char* peb=(unsigned char*)__readgsqword(0x60);
  printf("peb=%p\n",(void*)peb);
  unsigned char* p1=*(unsigned char**)(peb+0x10); printf("peb+0x10 -> %p\n",(void*)p1);
  unsigned char* p2=*(unsigned char**)(peb+0x18); printf("peb+0x18 -> %p\n",(void*)p2);
  return 0;
}