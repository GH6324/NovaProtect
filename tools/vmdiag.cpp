#include <cstdio>
#include "pe_lib.h"
#include "disasm.h"
#include "vm_isa.h"
using namespace np;

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: vmdiag file\n"); return 1; }
    PELib pe;
    if (!pe.load(argv[1])) { printf("load failed\n"); return 1; }
    auto m = pe.findMarkers();
    printf("markers=%zu\n", m.size());
    for (auto& x : m) printf("  rva=%08X type=%d\n", x.rva, x.type);
    if (m.size() < 2) return 0;
    uint32_t begin = m[0].rva, end = m[1].rva;
    uint32_t start = begin + 27;
    uint32_t len = end - start;
    printf("region %08X..%08X len=%u\n", start, end, len);
    const uint8_t* code = pe.rvaToPtr(start);
    if (!code) { printf("no ptr\n"); return 1; }
    Disassembler dis;
    size_t off = 0; int n = 0;
    while (off < len) {
        DisasmInsn in;
        uint32_t l = dis.disassemble(code + off, len - off, in);
        if (!l) { printf("STOP@+%zu decode failed\n", off); break; }
        printf("%04zu %-16s len=%u dst(%d,%s) src(%d,%s)\n", off,
               Disassembler::categoryToString(in.category), l,
               (int)in.dst.type, reg_util::regName(in.dst.reg),
               (int)in.src.type, reg_util::regName(in.src.reg));
        off += l; n++;
    }
    printf("decoded=%d off=%zu/%u\n", n, off, len);
    auto blk = VMTranslator::translate(code, len, pe.imageBase()+start, pe.imageBase(), 5, 1);
    printf("translate ok=%d tr=%u skip=%u reason=%s bc=%zu\n",
           (int)blk.ok, blk.insnsTranslated, blk.insnsSkipped,
           blk.skipReason.c_str(), blk.bytecode.size());
    return 0;
}