#include <cstdio>
#include "pe_lib.h"
#include "disasm.h"
#include "vm_isa.h"
using namespace np;

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: vmeval file\n"); return 1; }
    PELib pe; if (!pe.load(argv[1])) return 1;
    auto m = pe.findMarkers();
    uint32_t start = m[0].rva + 27, len = m[1].rva - start;
    const uint8_t* code = pe.rvaToPtr(start);
    if (!code) { printf("no ptr\n"); return 1; }
    auto blk = VMTranslator::translate(code, len, pe.imageBase()+start, pe.imageBase(), 5, 1);
    printf("ok=%d tr=%u bc=%zu\n", (int)blk.ok, blk.insnsTranslated, blk.bytecode.size());
    // Dump the reverse table as C array
    printf("static const unsigned char REV[256]={");
    for (int i=0;i<256;i++) printf("%u,", (unsigned)blk.reverse[i]);
    printf("};\n");
    // Dump bytecode as C array
    printf("static const unsigned char BC[]=");
    for (auto b : blk.bytecode) printf("%u,", (unsigned)b);
    printf("0};\n#define BCLEN %zu\n", blk.bytecode.size());
    return 0;
}