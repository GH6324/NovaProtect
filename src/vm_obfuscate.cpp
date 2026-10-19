// vm_obfuscate.cpp — post-translation VM bytecode obfuscator
// ============================================================
// Emits two anti-analysis transforms on NovaProtect wire bytecode:
//
//   1. Dead-register junk emission (any complexity > 0)
//   2. Control-flow flattening (complexity >= 3, straight-line code only)
//
// Both transforms preserve semantics: junk never touches live registers
// and never modifies flags, and the flattening dispatcher reproduces the
// original block order through a state variable.
#include "vm_isa.h"
#include <vector>
#include <random>

namespace np {

namespace {

uint32_t wireInsnLen(uint8_t op) {
    switch (op) {
    case WIRE_LOADIMM: case WIRE_MULI: case WIRE_ADDI: case WIRE_SUBI:
    case WIRE_ANDI: case WIRE_RORI: case WIRE_CMPI: case WIRE_XORI:
    case WIRE_SHRI: case WIRE_ORI: case WIRE_SHLI: case WIRE_SARI:
        return 10;
    case WIRE_LOADB: case WIRE_LOADQ: case WIRE_STOREB: case WIRE_STOREQ:
        return 7;
    case WIRE_JE: case WIRE_JNE: case WIRE_JMP: case WIRE_JNZ:
    case WIRE_JZ: case WIRE_JAE: case WIRE_JB: case WIRE_JGE:
    case WIRE_JL: case WIRE_JG: case WIRE_JLE:
        return 5;
    case WIRE_MOVE: case WIRE_XOREQ: case WIRE_ADD: case WIRE_SUB:
    case WIRE_MUL: case WIRE_AND: case WIRE_OR: case WIRE_XOR:
    case WIRE_SHL: case WIRE_SHR: case WIRE_SAR:
    case WIRE_CMP: case WIRE_TEST:
        return 3;
    case WIRE_NOT: case WIRE_NEG:
        return 2;
    case WIRE_HALT: case WIRE_ENDBR:
        return 1;
    default:
        return 1;
    }
}

bool wireIsBranch(uint8_t op) {
    return (op >= WIRE_JE && op <= WIRE_JMP) ||
           (op >= WIRE_JNZ && op <= WIRE_JLE);
}

struct WI {
    uint8_t op;
    std::vector<uint8_t> ops;
    WI() : op(0) {}
    explicit WI(uint8_t o) : op(o) {}
    WI(uint8_t o, std::vector<uint8_t> v) : op(o), ops(std::move(v)) {}
    uint32_t size() const { return 1 + (uint32_t)ops.size(); }
};

WI mkNot(uint8_t reg) {
    return WI(WIRE_NOT, {reg});
}

WI mkMove(uint8_t dst, uint8_t src) {
    return WI(WIRE_MOVE, {dst, src});
}

WI mkLoadImm(uint8_t reg, uint64_t v) {
    std::vector<uint8_t> o = {reg};
    for (int k = 0; k < 8; k++) o.push_back((uint8_t)(v >> (k * 8)));
    return WI(WIRE_LOADIMM, std::move(o));
}

WI mkJmp(uint32_t target) {
    std::vector<uint8_t> o(4);
    for (int k = 0; k < 4; k++) o[k] = (uint8_t)(target >> (k * 8));
    return WI(WIRE_JMP, std::move(o));
}

WI mkCmpi(uint8_t reg, uint64_t v) {
    std::vector<uint8_t> o = {reg};
    for (int k = 0; k < 8; k++) o.push_back((uint8_t)(v >> (k * 8)));
    return WI(WIRE_CMPI, std::move(o));
}

WI mkJe(uint32_t target) {
    std::vector<uint8_t> o(4);
    for (int k = 0; k < 4; k++) o[k] = (uint8_t)(target >> (k * 8));
    return WI(WIRE_JE, std::move(o));
}

void emitQword(std::vector<uint8_t>& v, uint64_t q) {
    for (int k = 0; k < 8; k++) v.push_back((uint8_t)(q >> (k * 8)));
}

} // namespace

std::vector<uint8_t> vmObfuscate(const std::vector<uint8_t>& bc,
                                  const uint8_t* reverse,
                                  const uint8_t* mapping,
                                  uint32_t reg_mask,
                                  uint8_t complexity) {
    if (bc.size() < 16 || complexity == 0) return bc;

    // ---- decode -------------------------------------------------------
    std::vector<WI> prog;
    {
        size_t ip = 0;
        while (ip < bc.size()) {
            uint8_t op = reverse[bc[ip]];
            uint32_t len = wireInsnLen(op);
            if (ip + len > bc.size()) return bc;
            std::vector<uint8_t> ops(bc.begin() + ip + 1,
                                     bc.begin() + ip + len);
            prog.push_back(WI(op, std::move(ops)));
            ip += len;
        }
    }
    if (prog.empty()) return bc;

    bool hasBranches = false;
    for (auto& wi : prog)
        if (wireIsBranch(wi.op)) { hasBranches = true; break; }

    // ---- dead register for junk / state -------------------------------
    int deadReg = -1;
    for (int r = 0; r < 16; r++) {
        if (!(reg_mask & (1u << r))) { deadReg = r; break; }
    }
    if (deadReg < 0) return bc;   // no dead register, stay safe

    std::mt19937 rng(0xA5A5u ^ (uint32_t)complexity ^ (uint32_t)bc.size());
    (void)rng; // silence unused in release

    std::vector<WI> body;
    std::vector<WI>* outStream = &body;

    const bool flatten = !hasBranches && complexity >= 3 && prog.size() >= 4;

    if (!flatten) {
        // ---------------------------------------------------------------
        // Junk emission only
        // ---------------------------------------------------------------
        for (size_t i = 0; i < prog.size(); i++) {
            uint32_t junkCount = rng() % 3;
            for (uint32_t j = 0; j < junkCount; j++) {
                switch (rng() % 3) {
                case 0: body.push_back(mkNot((uint8_t)deadReg)); break;
                case 1: body.push_back(mkMove((uint8_t)deadReg, (uint8_t)deadReg)); break;
                default: {
                    uint64_t v = ((uint64_t)rng() << 32) ^ rng();
                    body.push_back(mkLoadImm((uint8_t)deadReg, v));
                    break;
                }
                }
            }
            body.push_back(prog[i]);
        }
    } else {
        // ---------------------------------------------------------------
        // Control-flow flattening
        // ---------------------------------------------------------------
        // Split into blocks of 1-3 instructions.
        std::vector<std::vector<WI>> blocks;
        {
            size_t i = 0;
            while (i < prog.size()) {
                uint32_t n = 1 + (rng() % 3);
                std::vector<WI> blk;
                for (uint32_t k = 0; k < n && i < prog.size(); k++, i++)
                    blk.push_back(prog[i]);
                blocks.push_back(std::move(blk));
            }
        }
        uint32_t nBlocks = (uint32_t)blocks.size();
        if (nBlocks < 2) {
            for (auto& wi : prog) body.push_back(wi);
            outStream = &body;
            // fall through to re-encode below
            std::vector<uint8_t> out;
            out.reserve(body.size() * 8);
            for (auto& wi : body) {
                out.push_back(mapping[wi.op]);
                out.insert(out.end(), wi.ops.begin(), wi.ops.end());
            }
            return out;
        }

        // Shuffle block order.
        std::vector<uint32_t> order(nBlocks);
        for (uint32_t i = 0; i < nBlocks; i++) order[i] = i;
        for (uint32_t i = nBlocks - 1; i > 0; i--) {
            uint32_t j = rng() % (i + 1);
            std::swap(order[i], order[j]);
        }

        // Layout:
        //   [0] LOADIMM state, 0
        //   [1] JMP dispatch            <- patch
        //   blocks in shuffled order:
        //     blockStart[b]
        //     <block instructions>
        //     LOADIMM state, b+1
        //     JMP dispatch              <- patch
        //   dispatch:
        //     CMPI state, 0; JE blockStart[0]
        //     ...
        //     CMPI state, nBlocks-1; JE blockStart[nBlocks-1]
        //     HALT

        size_t entryJmpIdx = 0;
        std::vector<size_t> blockJmpIdx;   // index of each block's JMP
        std::vector<size_t> blockStartIdx; // index of first insn of each block
        std::vector<size_t> jeIdx;         // index of each JE in dispatch
        size_t dispatchStart = 0;

        // prologue
        body.push_back(mkLoadImm((uint8_t)deadReg, 0));
        entryJmpIdx = body.size();
        body.push_back(mkJmp(0)); // patched later

        for (uint32_t pos = 0; pos < nBlocks; pos++) {
            uint32_t b = order[pos];
            blockStartIdx.push_back(body.size());
            for (auto& wi : blocks[b]) body.push_back(wi);
            // junk between blocks
            uint32_t junkCount = rng() % 2;
            for (uint32_t j = 0; j < junkCount; j++)
                body.push_back(mkNot((uint8_t)deadReg));
            // transition
            body.push_back(mkLoadImm((uint8_t)deadReg, b + 1));
            blockJmpIdx.push_back(body.size());
            body.push_back(mkJmp(0)); // patched later
        }

        dispatchStart = body.size();
        for (uint32_t b = 0; b < nBlocks; b++) {
            body.push_back(mkCmpi((uint8_t)deadReg, b));
            jeIdx.push_back(body.size());
            body.push_back(mkJe(0)); // patched later
        }
        body.push_back(WI(WIRE_HALT));

        // Assign offsets.
        std::vector<uint32_t> off(body.size(), 0);
        {
            uint32_t cur = 0;
            for (size_t i = 0; i < body.size(); i++) {
                off[i] = cur;
                cur += body[i].size();
            }
        }

        // Patch entry JMP -> dispatch
        {
            uint32_t tgt = off[dispatchStart];
            for (int k = 0; k < 4; k++)
                body[entryJmpIdx].ops[k] = (uint8_t)(tgt >> (k * 8));
        }
        // Patch block transition JMPs -> dispatch
        for (size_t i = 0; i < blockJmpIdx.size(); i++) {
            uint32_t tgt = off[dispatchStart];
            for (int k = 0; k < 4; k++)
                body[blockJmpIdx[i]].ops[k] = (uint8_t)(tgt >> (k * 8));
        }
        // Patch JE targets -> block starts.
        // blockStartIdx was filled in shuffled order; jeIdx[b] must jump to
        // the start of block with state == b.
        // blockStartIdx[pos] corresponds to the block whose original id is
        // order[pos], so the target for state b is the pos where order[pos]==b.
        std::vector<size_t> posOfState(nBlocks);
        for (uint32_t pos = 0; pos < nBlocks; pos++)
            posOfState[order[pos]] = (size_t)pos;
        for (uint32_t b = 0; b < nBlocks; b++) {
            uint32_t tgt = off[blockStartIdx[posOfState[b]]];
            for (int k = 0; k < 4; k++)
                body[jeIdx[b]].ops[k] = (uint8_t)(tgt >> (k * 8));
        }
    }

    // ---- re-encode ----------------------------------------------------
    std::vector<uint8_t> out;
    out.reserve(body.size() * 8);
    for (auto& wi : *outStream) {
        out.push_back(mapping[wi.op]);
        out.insert(out.end(), wi.ops.begin(), wi.ops.end());
    }
    return out;
}

} // namespace np