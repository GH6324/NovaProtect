#include <cstdio>
#include <cstring>
static void cpuid(int r[4], int leaf){ __asm__ volatile("cpuid":"=a"(r[0]),"=b"(r[1]),"=c"(r[2]),"=d"(r[3]):"a"(leaf),"c"(0)); }
int main(){
  int r[4];
  for(int leaf=0x40000000; leaf<=0x40000006; ++leaf){
    cpuid(r,leaf);
    printf("leaf %08X: eax=%08X ebx=%08X ecx=%08X edx=%08X\n",leaf,(unsigned)r[0],(unsigned)r[1],(unsigned)r[2],(unsigned)r[3]);
  }
  cpuid(r,1);
  printf("leaf1 ecx=%08X\n",(unsigned)r[2]);
  return 0;
}