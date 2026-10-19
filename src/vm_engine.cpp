// NovaProtect VM Engine Implementation
// =================================
// Implements:
//   * VMOpcodeMapper  - per-build opcode permutation + reverse table
//   * VMTranslator    - real x86-64 -> wire bytecode lowering
//   * VMBytecodeGenerator - wire-level emit helpers
//
// The wire format is defined in include/vm_isa.h and consumed by
// runtime/prot64.c::np_vm_run.

#include "vm_isa.h"
#include "disasm.h"
#include <cstring>
#include <algorithm>
#include <random>
#include <string>

namespace np {

// ============================================================
// VMOpcodeMapper
// ============================================================
static void fillPermutation(uint8_t* mapping, uint8_t* reverse, uint64_t seed) {
    std::vector<uint8_t> values(256);
    for (int i = 0; i < 256; i++) values[i] = (uint8_t)i;

    std::mt19937_64 g(seed);
    std::shuffle(values.begin(), values.end(), g);

    std::memset(reverse, 0xFF, 256);
    for (int i = 0; i < NP_WIRE_OPCODE_SLOTS; i++) {
        mapping[i] = values[i];
        reverse[values[i]] = (uint8_t)i;
    }
    // Every other physical byte decodes to a no-op slot so stray bytes are inert.
    for (int i = NP_WIRE_OPCODE_SLOTS; i < 256; i++)
        reverse[values[i]] = (uint8_t)0;
}

void VMOpcodeMapper::generateMapping() {
    std::random_device rd;
    uint64_t seed = ((uint64_t)rd() << 32) ^ (uint64_t)rd();
    fillPermutation(mapping_, reverse_, seed ? seed : 0x9E3779B97F4A7C15ull);
}

void VMOpcodeMapper::generateMapping(uint64_t seed) {
    fillPermutation(mapping_, reverse_, seed ? seed : 0x9E3779B97F4A7C15ull);
}

// ============================================================
// VMTranslator
// ============================================================
namespace {

// A tiny register allocator that never touches the two registers we keep for
// scratch (VM_R14/VM_R15 by default) or the stack pointer register.
struct RegMap {
    uint8_t guest_to_vm[16];
    uint8_t vmSp;
    bool used[NP_VM_REGS];

    void init(uint8_t sp) {
        // guest GPR i -> VM register i, but reserve the top two VM regs for
        // translator scratch and the guest stack pointer.
        std::memset(used, 0, sizeof(used));
        for (int i = 0; i < 16; i++) { guest_to_vm[i] = (uint8_t)i; used[i] = true; }
        vmSp = sp;
    }
    uint8_t g2v(Reg r) const {
        uint8_t i = (uint8_t)r;
        if (i > 15) return 0xFF;
        return guest_to_vm[i];
    }
};

// Scratch VM registers (must differ from any guest mapping).
static const uint8_t SCRATCH_A = 14; // VM_R14
static const uint8_t SCRATCH_B = 15; // VM_R15

static bool isGPR(Reg r) { return (uint8_t)r <= 15; }

// Map an x86 condition code (TTTTN of the Jcc opcode) to a wire Jcc opcode.
static uint8_t jccWire(uint8_t cc, uint8_t prefixes) {
    // x86 condition codes:
    //  0 O   1 NO  2 B/NAE  3 AE/NB  4 E/Z  5 NE/NZ  6 BE/NA  7 A/NBE
    //  8 S   9 NS  A P      B NP      C L/NGE D GE/NL E LE/NG F G/NLE
    switch (cc) {
    case 0x0: case 0x1: return 0;                       // O  - unsupported
    case 0x2: case 0x3: return WIRE_JB;                 // approximate
    case 0x4: return WIRE_JZ;
    case 0x5: return WIRE_JNZ;
    case 0x6: case 0x7: return WIRE_JAE;
    case 0x8: case 0x9: return 0;                       // S  - unsupported
    case 0xA: case 0xB: return 0;                       // P  - unsupported
    case 0xC: return WIRE_JL;
    case 0xD: return WIRE_JGE;
    case 0xE: return WIRE_JLE;
    case 0xF: return WIRE_JG;
    default:  return 0;
    }
}

} // namespace

VMLoweredBlock VMTranslator::translate(const uint8_t* code, size_t size,
                                       uint64_t guestRip, uint64_t imageBase,
                                       uint8_t complexity, uint8_t mutationLevel) {
    (void)imageBase;
    VMLoweredBlock out;
    out.vmSp = SCRATCH_B; // guest RSP stays mapped to VM_R4; message says SP reg

    RegMap regs;
    regs.init(out.vmSp);

    VMOpcodeMapper mapper;
    mapper.generateMapping();

    std::vector<uint8_t> bc;
    auto emit  = [&](uint8_t logical) { bc.push_back(mapper.encode(logical)); };
    auto b8    = [&](uint8_t v) { bc.push_back(v); };
    auto d32   = [&](uint32_t v) { bc.push_back(v & 0xFF); bc.push_back((v >> 8) & 0xFF);
                                   bc.push_back((v >> 16) & 0xFF); bc.push_back((v >> 24) & 0xFF); };
    auto q64   = [&](uint64_t v) { for (int k = 0; k < 8; k++) bc.push_back((uint8_t)(v >> (k * 8))); };

    // Guest offset -> bytecode offset, for internal branch fixups.
    std::unordered_map<uint32_t, uint32_t> offMap;
    std::vector<std::pair<size_t, uint32_t>> fixups; // (bc offset of target dword, guest target)

    Disassembler dis;
    size_t off = 0;
    uint32_t translated = 0, skipped = 0;

    while (off < size) {
        // Stop at a terminator we cannot express; caller keeps the rest native.
        DisasmInsn insn;
        uint32_t len = dis.disassemble(code + off, size - off, insn);
        if (len == 0) { out.skipReason = "decode failed"; break; }

        uint32_t guestOff = (uint32_t)off;
        offMap[guestOff] = (uint32_t)bc.size();

        bool handled = true;
        uint8_t rexW = (insn.prefixes & PREFIX_REX_W) ? 1 : 0;

        // Helper for reg-reg / reg-imm binary ALU ops with a known wire op.
        auto needGPR = [&](Reg r) { return isGPR(r); };

        switch (insn.category) {
        case InsnCategory::MOV: {
            // mov dst, src  (dst = reg field, src = rm field)
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            if (insn.src.type == OperandType::Register) {
                if (!needGPR(insn.src.reg)) { handled = false; break; }
                uint8_t d = regs.g2v(insn.dst.reg), s = regs.g2v(insn.src.reg);
                if (rexW) { emit(WIRE_MOVE); b8(d); b8(s); }
                else      { emit(WIRE_MOVE); b8(d); b8(s); }  // 32-bit: MOV zeroes upper
            } else if (insn.src.type == OperandType::Immediate) {
                uint8_t d = regs.g2v(insn.dst.reg);
                emit(WIRE_LOADIMM); b8(d); q64((uint64_t)insn.src.immediate);
                if (rexW == 0 && insn.src.size == 8) { /* imm64 mov r64 */ }
                else if (rexW == 0) { /* 32-bit imm: upper 32 already zero */ }
            } else {
                handled = false; // memory forms not translated here
            }
            break;
        }
        case InsnCategory::LEA: {
            if (!needGPR(insn.dst.reg)) { handled = false; break; }
            if (insn.src.type != OperandType::Memory || insn.src.index != Reg::NONE) { handled = false; break; }
            if (!needGPR(insn.src.base)) { handled = false; break; }
            uint8_t d = regs.g2v(insn.dst.reg), b = regs.g2v(insn.src.base);
            if (d != b) { emit(WIRE_MOVE); b8(d); b8(b); }
            emit(WIRE_ADDI); b8(d); q64((uint64_t)(int64_t)insn.src.displacement);
            break;
        }
        case InsnCategory::ADD: case InsnCategory::SUB:
        case InsnCategory::AND: case InsnCategory::OR: case InsnCategory::XOR: {
            uint8_t wire = (insn.category == InsnCategory::ADD) ? WIRE_ADD :
                           (insn.category == InsnCategory::SUB) ? WIRE_SUB :
                           (insn.category == InsnCategory::AND) ? WIRE_AND :
                           (insn.category == InsnCategory::OR)  ? WIRE_OR  : WIRE_XOR;
            uint8_t wireImm = (insn.category == InsnCategory::ADD) ? WIRE_ADDI :
                              (insn.category == InsnCategory::SUB) ? WIRE_SUBI :
                              (insn.category == InsnCategory::AND) ? WIRE_ANDI :
                              (insn.category == InsnCategory::OR)  ? WIRE_ORI  : WIRE_XORI;
            Reg dstReg = insn.dst.reg;
            // For rm,reg encodings dst may be in src; normalise.
            if (!needGPR(dstReg)) { handled = false; break; }
            uint8_t d = regs.g2v(dstReg);
            if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                uint8_t s = regs.g2v(insn.src.reg);
                if (wire == WIRE_XOR) { emit(WIRE_XOR); b8(d); b8(s); }
                else { emit(wire); b8(d); b8(s); }
            } else if (insn.src.type == OperandType::Immediate) {
                emit(wireImm); b8(d); q64((uint64_t)insn.src.immediate);
            } else { handled = false; }
            break;
        }
        case InsnCategory::CMP: case InsnCategory::TEST: {
            uint8_t d = regs.g2v(insn.dst.reg);
            if (d == 0xFF) { handled = false; break; }
            if (insn.src.type == OperandType::Register && needGPR(insn.src.reg)) {
                uint8_t s = regs.g2v(insn.src.reg);
                emit(insn.category == InsnCategory::CMP ? WIRE_CMP : WIRE_TEST); b8(d); b8(s);
            } else if (insn.src.type == OperandType::Immediate) {
                if (insn.category == InsnCategory::CMP) { emit(WIRE_CMPI); b8(d); q64((uint64_t)insn.src.immediate); }
                else { emit(WIRE_TEST); b8(d); b8(d); }
            } else { handled = false; }
            break;
        }
        case InsnCategory::INC: case InsnCategory::DEC: case InsnCategory::NEG: case InsnCategory::NOT: {
            Reg r = insn.dst.reg;
            if (!needGPR(r)) { handled = false; break; }
            uint8_t v = regs.g2v(r);
            if (insn.category == InsnCategory::INC) { emit(WIRE_ADDI); b8(v); q64(1); }
            else if (insn.category == InsnCategory::DEC) { emit(WIRE_SUBI); b8(v); q64(1); }
            else if (insn.category == InsnCategory::NEG) { emit(WIRE_NEG); b8(v); }
            else { emit(WIRE_NOT); b8(v); }
            break;
        }
        case InsnCategory::SHL: case InsnCategory::SHR: case InsnCategory::SAR: {
            uint8_t v = regs.g2v(insn.dst.reg);
            if (v == 0xFF) { handled = false; break; }
            uint8_t wire = insn.category == InsnCategory::SHL ? WIRE_SHL :
                           insn.category == InsnCategory::SHR ? WIRE_SHR : WIRE_SAR;
            if (insn.src.type == OperandType::Immediate) {
                if (insn.category == InsnCategory::SHL && insn.src.immediate == 1) { emit(WIRE_ADD); b8(v); b8(v); }
                else if (insn.category == InsnCategory::SHL) { emit(WIRE_SHLI); b8(v); q64((uint64_t)insn.src.immediate); }
                else if (insn.category == InsnCategory::SHR) { emit(WIRE_SHRI); b8(v); q64((uint64_t)insn.src.immediate); }
                else { emit(WIRE_SARI); b8(v); q64((uint64_t)insn.src.immediate); }
            } else if (insn.src.type == OperandType::Register) {
                uint8_t s = regs.g2v(insn.src.reg);
                if (s == 0xFF) { handled = false; break; }
                emit(wire); b8(v); b8(s);
            } else { handled = false; }
            break;
        }
        case InsnCategory::PUSH: case InsnCategory::POP: {
            // The interpreter models its stack with VM_R15 while the guest
            // mapping is the identity, so a guest PUSH/POP would read and
            // write through the guest R15 value instead of the real stack.
            // Until the register map allocates a dedicated VM stack slot,
            // these forms stay native (the translator reports them as
            // unsupported, which makes the packer skip the region).
            handled = false;
            break;
        }
        case InsnCategory::JMP: {
            uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
            emit(WIRE_JMP); fixups.push_back({ bc.size(), target }); d32(0);
            break;
        }
        case InsnCategory::JCC: {
            uint8_t wire = jccWire(insn.condition, insn.prefixes);
            if (!wire) { handled = false; break; }
            uint32_t target = (uint32_t)((int64_t)off + (int32_t)len + insn.rel_target);
            emit(wire); fixups.push_back({ bc.size(), target }); d32(0);
            break;
        }
        case InsnCategory::NOP:
            emit(0); // WIRE_ENDBR / nop slot
            break;
        default:
            handled = false;
            break;
        }

        if (!handled) {
            skipped++;
            bc.resize(offMap[guestOff]); // roll back partial emission for this insn
            out.skipReason = "unsupported instruction";
            // Stop translation; caller keeps [off, end) native.
            break;
        }

        translated++;
        off += len;
    }

    if (skipped && translated == 0) {
        out.ok = false;
        out.skipReason = out.skipReason.empty() ? "no translatable instruction" : out.skipReason;
        return out;
    }

    // Terminator: halt at end of block.
    emit(WIRE_HALT);

    // Resolve internal branch targets.
    for (auto& fx : fixups) {
        size_t bcOff = fx.first;
        uint32_t guestTarget = fx.second;
        uint32_t dst;
        auto it = offMap.find(guestTarget);
        if (it != offMap.end()) {
            dst = it->second;
        } else {
            // Target outside the translated range: cannot represent.
            out.ok = false;
            out.skipReason = "branch target outside translated range";
            return out;
        }
        bc[bcOff + 0] = (uint8_t)(dst & 0xFF);
        bc[bcOff + 1] = (uint8_t)((dst >> 8) & 0xFF);
        bc[bcOff + 2] = (uint8_t)((dst >> 16) & 0xFF);
        bc[bcOff + 3] = (uint8_t)((dst >> 24) & 0xFF);
    }

    out.bytecode = std::move(bc);
    out.reverse = mapper.reverseTable();
    for (int i = 0; i < 16; i++) out.guestReg[i] = regs.guest_to_vm[i];
    out.insnsTranslated = translated;
    out.insnsSkipped = skipped;
    out.ok = (skipped == 0);
    (void)complexity; (void)mutationLevel;
    return out;
}

// ============================================================
// VMBytecodeGenerator (wire-level emit helpers)
// ============================================================
VMBytecodeGenerator::VMBytecodeGenerator() { output_.reserve(4096); }

void VMBytecodeGenerator::emitByte(uint8_t b) { output_.push_back(b); }
void VMBytecodeGenerator::emitDword(uint32_t d) {
    emitByte(d & 0xFF); emitByte((d >> 8) & 0xFF);
    emitByte((d >> 16) & 0xFF); emitByte((d >> 24) & 0xFF);
}
void VMBytecodeGenerator::emitQword(uint64_t q) {
    for (int k = 0; k < 8; k++) emitByte((uint8_t)(q >> (k * 8)));
}
void VMBytecodeGenerator::emitOp(uint8_t logical) { emitByte(mapper_.encode(logical)); }
void VMBytecodeGenerator::padForAlignment() { while (output_.size() & 7) emitByte(0x00); }

void VMBytecodeGenerator::emitLoadImm(uint8_t reg, uint64_t value) {
    emitOp(WIRE_LOADIMM); emitByte(reg); emitQword(value); instrCount_++;
}
void VMBytecodeGenerator::emitLoadReg(uint8_t dst, uint8_t src) {
    emitOp(WIRE_MOVE); emitByte(dst); emitByte(src); instrCount_++;
}
void VMBytecodeGenerator::emitMemLoad(uint8_t dst, uint8_t base, uint32_t disp) {
    emitOp(WIRE_LOADQ); emitByte(dst); emitByte(base); emitDword(disp); instrCount_++;
}
void VMBytecodeGenerator::emitMemStore(uint8_t base, uint32_t disp, uint8_t src) {
    emitOp(WIRE_STOREQ); emitByte(base); emitDword(disp); emitByte(src); instrCount_++;
}
void VMBytecodeGenerator::emitArith(uint8_t wireOp, uint8_t dst, uint8_t src) {
    emitOp(wireOp); emitByte(dst); emitByte(src); instrCount_++;
}
void VMBytecodeGenerator::emitArithImm(uint8_t wireOp, uint8_t dst, uint64_t imm) {
    emitOp(wireOp); emitByte(dst); emitQword(imm); instrCount_++;
}
void VMBytecodeGenerator::emitCmp(uint8_t a, uint8_t b) {
    emitOp(WIRE_CMP); emitByte(a); emitByte(b); instrCount_++;
}
void VMBytecodeGenerator::emitTest(uint8_t a, uint8_t b) {
    emitOp(WIRE_TEST); emitByte(a); emitByte(b); instrCount_++;
}
void VMBytecodeGenerator::emitJmp(uint32_t target) {
    emitOp(WIRE_JMP); emitDword(target); instrCount_++;
}
void VMBytecodeGenerator::emitJcc(uint8_t wireOp, uint32_t target) {
    emitOp(wireOp); emitDword(target); instrCount_++;
}
void VMBytecodeGenerator::emitPush(uint8_t reg) {
    emitArithImm(WIRE_SUBI, 15, 8);
    emitOp(WIRE_STOREQ); emitByte(15); emitDword(0); emitByte(reg);
    instrCount_++;
}
void VMBytecodeGenerator::emitPop(uint8_t reg) {
    emitOp(WIRE_LOADQ); emitByte(reg); emitByte(15); emitDword(0);
    emitArithImm(WIRE_ADDI, 15, 8);
    instrCount_++;
}
void VMBytecodeGenerator::emitHalt() { emitOp(WIRE_HALT); instrCount_++; }
void VMBytecodeGenerator::emitEnter() { instrCount_++; }
void VMBytecodeGenerator::emitLeave() { instrCount_++; }

std::vector<uint8_t> VMBytecodeGenerator::generate(const std::vector<uint8_t>& x86_code,
                                                   uint32_t code_rva,
                                                   uint8_t complexity,
                                                   uint8_t mutation_level) {
    VMTranslator tr;
    VMLoweredBlock blk = tr.translate(x86_code.data(), x86_code.size(),
                                      code_rva, 0, complexity, mutation_level);
    if (blk.ok) {
        mapper_.generateMapping();
        output_ = blk.bytecode;
    }
    return output_;
}

} // namespace np