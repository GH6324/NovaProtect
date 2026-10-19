
// NovaProtect Mutation Engine Implementation
//
// 真实实现：3 阶代码变异引擎（Light / Medium / Heavy）。
//   Light  : 等价替换（立即数取负、德摩根、PUSH/POP 展开、LEA、移位拆分、OR-TEST）
//   Medium : Light + MBA（混合布尔算术）恒等变形 + 垃圾指令注入
//   Heavy  : Medium + 不透明谓词（分支混淆）
//
// 所有生成物均为 x86-64 机器码。
// 约定：临时寄存器只用 r10 / r11（caller-saved / volatile scratch）。
// 语义保证：所有替换在“寄存器数值”层面严格等价；
//           标记为 exact 的替换连标志位也一致（见 isExactReplace）。
//           算术/逻辑/移位的替换会改变 CF/OF/AF 等标志位，调用方需确认上下文安全。

#include "mutation.h"
#include <limits>

namespace np {

namespace {

// ---------- 内部语义操作码 ----------
enum OpK : uint8_t {
    OP_NONE = 0, OP_ADD, OP_SUB, OP_XOR, OP_AND, OP_OR, OP_MOV, OP_TEST,
    OP_CMP, OP_LEA, OP_PUSH, OP_POP, OP_SHL, OP_SHR, OP_NOT, OP_NEG,
    OP_IMUL, OP_SETCC, OP_CMOV, OP_MOVZX
};

struct Dec {
    bool     ok       = false;
    bool     w64      = false;   // 是否为 64 位形式（REX.W）
    uint8_t  op       = OP_NONE;
    uint8_t  dst      = 0;
    uint8_t  src      = 0;
    uint64_t imm      = 0;
    bool     imm_form = false;
};

// r10 / r11：caller-saved 临时寄存器
constexpr uint8_t kT1 = 10;
constexpr uint8_t kT2 = 11;

inline bool isTmp(uint8_t r) { return r == kT1 || r == kT2; }
inline bool inImm32(int64_t v) {
    return v >= (int64_t)std::numeric_limits<int32_t>::min() &&
           v <= (int64_t)std::numeric_limits<int32_t>::max();
}

// ---------- 字节输出工具 ----------
inline void put32(std::vector<uint8_t>& o, uint32_t v) {
    o.push_back((uint8_t)(v & 0xFF));
    o.push_back((uint8_t)((v >> 8) & 0xFF));
    o.push_back((uint8_t)((v >> 16) & 0xFF));
    o.push_back((uint8_t)((v >> 24) & 0xFF));
}
inline void put64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
}
inline uint8_t rexW(uint8_t r, uint8_t b) {
    return (uint8_t)(0x48 | (((r >> 3) & 1) ? 0x04 : 0) | (((b >> 3) & 1) ? 0x01 : 0));
}

// ---------- 指令编码（默认 64 位操作数） ----------

// reg-reg：opcode /r，reg=dst，rm=src（03/2B/33/23/0B/8B/8D/85）
inline void eRR(std::vector<uint8_t>& o, uint8_t opc, uint8_t dst, uint8_t src) {
    o.push_back(rexW(dst, src));
    o.push_back(opc);
    o.push_back((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}
// cmp a, b （39 /r，reg=b，rm=a）
inline void eCmp(std::vector<uint8_t>& o, uint8_t a, uint8_t b) {
    o.push_back(rexW(b, a));
    o.push_back(0x39);
    o.push_back((uint8_t)(0xC0 | ((b & 7) << 3) | (a & 7)));
}
// 81 /ext id：64 位算术/逻辑立即数（32 位符号扩展）
inline void eRI(std::vector<uint8_t>& o, uint8_t ext, uint8_t dst, int32_t imm) {
    o.push_back(rexW(0, dst));
    o.push_back(0x81);
    o.push_back((uint8_t)(0xC0 | ((ext & 7) << 3) | (dst & 7)));
    put32(o, (uint32_t)imm);
}
// 81 /ext id：32 位算术（结果零扩展到 64 位）
inline void eRI32(std::vector<uint8_t>& o, uint8_t ext, uint8_t dst, uint32_t imm) {
    if (dst >= 8) o.push_back(0x41);
    o.push_back(0x81);
    o.push_back((uint8_t)(0xC0 | ((ext & 7) << 3) | (dst & 7)));
    put32(o, imm);
}
// mov r64, imm64
inline void eMovImm64(std::vector<uint8_t>& o, uint8_t dst, uint64_t v) {
    o.push_back(rexW(0, dst));
    o.push_back((uint8_t)(0xB8 | (dst & 7)));
    put64(o, v);
}
// C7 /0 id：mov r/m64, imm32（符号扩展）
inline void eMovImm32Sx(std::vector<uint8_t>& o, uint8_t dst, int32_t v) {
    o.push_back(rexW(0, dst));
    o.push_back(0xC7);
    o.push_back((uint8_t)(0xC0 | (dst & 7)));
    put32(o, (uint32_t)v);
}
// mov r32, imm32（零扩展到 64 位）
inline void eMovImm32Zx(std::vector<uint8_t>& o, uint8_t dst, uint32_t v) {
    if (dst >= 8) o.push_back(0x41);
    o.push_back((uint8_t)(0xB8 | (dst & 7)));
    put32(o, v);
}
// xor r32, r32（零扩展清零，用于 mov r,imm 的等价变形）
inline void eXorSelf32(std::vector<uint8_t>& o, uint8_t r) {
    if (r >= 8) o.push_back(0x45);
    o.push_back(0x31);
    o.push_back((uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7)));
}
inline void ePush(std::vector<uint8_t>& o, uint8_t r) {
    if (r >= 8) o.push_back(0x41);
    o.push_back((uint8_t)(0x50 | (r & 7)));
}
inline void ePop(std::vector<uint8_t>& o, uint8_t r) {
    if (r >= 8) o.push_back(0x41);
    o.push_back((uint8_t)(0x58 | (r & 7)));
}
inline void eNot(std::vector<uint8_t>& o, uint8_t r) {
    o.push_back(rexW(0, r)); o.push_back(0xF7);
    o.push_back((uint8_t)(0xC0 | (2 << 3) | (r & 7)));
}
inline void eNeg(std::vector<uint8_t>& o, uint8_t r) {
    o.push_back(rexW(0, r)); o.push_back(0xF7);
    o.push_back((uint8_t)(0xC0 | (3 << 3) | (r & 7)));
}
inline void eSetcc(std::vector<uint8_t>& o, uint8_t cc, uint8_t r) {
    if (r >= 4) o.push_back((r >= 8) ? 0x41 : 0x40);
    o.push_back(0x0F);
    o.push_back((uint8_t)(0x90 | (cc & 0x0F)));
    o.push_back((uint8_t)(0xC0 | (r & 7)));
}
inline void eIMUL2(std::vector<uint8_t>& o, uint8_t dst, uint8_t src) {
    o.push_back(rexW(dst, src));
    o.push_back(0x0F); o.push_back(0xAF);
    o.push_back((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}
inline void eShlImm(std::vector<uint8_t>& o, uint8_t r, uint8_t n) {
    o.push_back(rexW(0, r)); o.push_back(0xC1);
    o.push_back((uint8_t)(0xC0 | (4 << 3) | (r & 7)));
    o.push_back(n);
}
inline void eShrImm(std::vector<uint8_t>& o, uint8_t r, uint8_t n) {
    o.push_back(rexW(0, r)); o.push_back(0xC1);
    o.push_back((uint8_t)(0xC0 | (5 << 3) | (r & 7)));
    o.push_back(n);
}
// mov [rsp], r  /  mov r, [rsp]
inline void eStRsp(std::vector<uint8_t>& o, uint8_t r) {
    o.push_back(rexW(r, 4)); o.push_back(0x89);
    o.push_back((uint8_t)(((r & 7) << 3) | 4)); o.push_back(0x24);
}
inline void eLdRsp(std::vector<uint8_t>& o, uint8_t r) {
    o.push_back(rexW(r, 4)); o.push_back(0x8B);
    o.push_back((uint8_t)(((r & 7) << 3) | 4)); o.push_back(0x24);
}
// lea rsp, [rsp + disp8]（不改变标志位）
inline void eLeaRsp(std::vector<uint8_t>& o, int8_t disp) {
    o.push_back(0x48); o.push_back(0x8D);
    o.push_back(0x64); o.push_back(0x24);
    o.push_back((uint8_t)disp);
}
inline void ePushfq(std::vector<uint8_t>& o) { o.push_back(0x9C); }
inline void ePopfq(std::vector<uint8_t>& o)  { o.push_back(0x9D); }
// 注意：eRR 把 dst 放在 ModRM.reg 字段，因此只能使用 reg=dst 方向的操作码
// （03/0B/23/2B/33/8B）；0x01/0x21/0x29/0x31 的 r/m 才是目的地，会造成操作数颠倒。
inline void eXorRR(std::vector<uint8_t>& o, uint8_t d, uint8_t s) { eRR(o, 0x33, d, s); }
inline void eOrRR (std::vector<uint8_t>& o, uint8_t d, uint8_t s) { eRR(o, 0x0B, d, s); }
inline void eAndRR(std::vector<uint8_t>& o, uint8_t d, uint8_t s) { eRR(o, 0x23, d, s); }
inline void eAddRR(std::vector<uint8_t>& o, uint8_t d, uint8_t s) { eRR(o, 0x03, d, s); }
inline void eSubRR(std::vector<uint8_t>& o, uint8_t d, uint8_t s) { eRR(o, 0x2B, d, s); }
inline void eMovRR(std::vector<uint8_t>& o, uint8_t d, uint8_t s) { eRR(o, 0x8B, d, s); }
inline void eMovzx8(std::vector<uint8_t>& o, uint8_t d32, uint8_t s8) {
    if (s8 >= 8) o.push_back(0x41);           // REX.B（MOVZX 不用 REX.W）
    o.push_back(0x0F); o.push_back(0xB6);
    o.push_back((uint8_t)(0xC0 | ((d32 & 7) << 3) | (s8 & 7)));
}
inline void eCmovcc(std::vector<uint8_t>& o, uint8_t cc, uint8_t dst, uint8_t src) {
    o.push_back(rexW(dst, src)); o.push_back(0x0F);
    o.push_back((uint8_t)(0x40 | (cc & 0x0F)));
    o.push_back((uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}

// ---------- 轻量指令解码（覆盖变异引擎的输入形式） ----------
inline bool parseInsn(const std::vector<uint8_t>& b, Dec& d) {
    size_t i = 0;
    if (i >= b.size()) return false;

    bool rexW = false;
    uint8_t rex = 0;
    if ((b[i] & 0xF0) == 0x40) { rex = b[i]; rexW = (rex & 8) != 0; ++i; }
    if (i >= b.size()) return false;

    uint8_t op = b[i++];
    d.ok = false;
    d.w64 = rexW;

    if (op >= 0x50 && op <= 0x57) {                       // push r64
        d.op = OP_PUSH; d.dst = (uint8_t)((op - 0x50) | ((rex & 1) << 3));
        d.w64 = true; d.ok = true; return true;
    }
    if (op >= 0x58 && op <= 0x5F) {                       // pop r64
        d.op = OP_POP; d.dst = (uint8_t)((op - 0x58) | ((rex & 1) << 3));
        d.w64 = true; d.ok = true; return true;
    }
    if (op >= 0xB8 && op <= 0xBF) {                       // mov r, imm
        d.op = OP_MOV; d.dst = (uint8_t)((op - 0xB8) | ((rex & 1) << 3));
        d.imm_form = true;
        size_t n = rexW ? 8 : 4;
        if (i + n > b.size()) return false;
        d.imm = 0;
        for (size_t k = 0; k < n; ++k) d.imm |= (uint64_t)b[i + k] << (8 * k);
        d.w64 = true; d.ok = true; return true;
    }
    if (op == 0x0F) {                                     // 二字节转义
        if (i >= b.size()) return false;
        uint8_t o2 = b[i++];
        if (o2 >= 0x90 && o2 <= 0x9F) {                   // setcc r/m8
            if (i + 1 > b.size()) return false;
            uint8_t modrm = b[i];
            if ((modrm >> 6) != 3) return false;
            d.op = OP_SETCC; d.dst = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
            d.ok = true; return true;
        }
        return false;
    }
    if (op == 0x89 || op == 0x8B) {                       // mov r/m64, r64 / mov r64, r/m64
        if (!rexW) return false;
        if (i + 1 > b.size()) return false;
        uint8_t modrm = b[i];
        if ((modrm >> 6) != 3) return false;
        uint8_t rm  = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
        uint8_t reg = (uint8_t)(((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3));
        if (op == 0x89) { d.op = OP_MOV; d.dst = rm; d.src = reg; }
        else            { d.op = OP_MOV; d.dst = reg; d.src = rm; }
        d.ok = true; return true;
    }
    if (op == 0x8D) {                                     // lea r64, [rm]
        if (!rexW) return false;
        if (i + 1 > b.size()) return false;
        uint8_t modrm = b[i];
        if ((modrm >> 6) != 3) return false;
        uint8_t rm  = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
        uint8_t reg = (uint8_t)(((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3));
        d.op = OP_LEA; d.dst = reg; d.src = rm; d.ok = true; return true;
    }
    if (op == 0x84 || op == 0x85) {                       // test r/m, r
        if (!rexW) return false;
        if (i + 1 > b.size()) return false;
        uint8_t modrm = b[i];
        if ((modrm >> 6) != 3) return false;
        uint8_t rm  = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
        uint8_t reg = (uint8_t)(((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3));
        d.op = OP_TEST; d.dst = rm; d.src = reg; d.ok = true; return true;
    }
    if (op >= 0x05 && op <= 0x3D && (op & 7) == 5) {
        // Accumulator, imm32 (sign-extended) forms:
        //   05 add, 0D or, 15 adc, 1D sbb, 25 and, 2D sub, 35 xor, 3D cmp
        if (!rexW) return false;
        if (i + 4 > b.size()) return false;
        static const uint8_t accm[8] = { OP_ADD, OP_OR, OP_NONE, OP_NONE, OP_AND, OP_SUB, OP_XOR, OP_CMP };
        uint8_t which = (uint8_t)((op >> 3) & 7);
        if (accm[which] == OP_NONE) return false;
        d.op = accm[which];
        d.dst = 0;                                        // RAX
        uint32_t raw = (uint32_t)b[i] | ((uint32_t)b[i + 1] << 8) |
                       ((uint32_t)b[i + 2] << 16) | ((uint32_t)b[i + 3] << 24);
        d.imm = (uint64_t)(int64_t)(int32_t)raw;
        d.imm_form = true;
        d.ok = true;
        return true;
    }
    if (op <= 0x3F) {                                     // 算术/逻辑（仅 64 位形式）
        uint8_t form = (uint8_t)(op & 7);
        uint8_t oper = (uint8_t)((op >> 3) & 7);
        if (form != 1 && form != 3) return false;
        if (!rexW) return false;
        if (i + 1 > b.size()) return false;
        uint8_t modrm = b[i];
        if ((modrm >> 6) != 3) return false;
        uint8_t rm  = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
        uint8_t reg = (uint8_t)(((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3));
        static const uint8_t m[8] = { OP_ADD, OP_OR, OP_NONE, OP_NONE, OP_AND, OP_SUB, OP_XOR, OP_CMP };
        if (m[oper] == OP_NONE) return false;
        d.op = m[oper];
        if (form == 1) { d.dst = rm;  d.src = reg; }
        else           { d.dst = reg; d.src = rm;  }
        d.ok = true; return true;
    }
    if (op == 0x81) {                                     // 立即数算术（32 位符号扩展）
        if (!rexW) return false;
        if (i + 5 > b.size()) return false;
        uint8_t modrm = b[i];
        if ((modrm >> 6) != 3) return false;
        uint8_t ext = (uint8_t)((modrm >> 3) & 7);
        uint8_t rm  = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
        uint32_t raw = (uint32_t)b[i + 1] | ((uint32_t)b[i + 2] << 8) |
                       ((uint32_t)b[i + 3] << 16) | ((uint32_t)b[i + 4] << 24);
        d.imm = (uint64_t)(int64_t)(int32_t)raw;
        d.dst = rm; d.imm_form = true;
        switch (ext) {
            case 0: d.op = OP_ADD; break;
            case 5: d.op = OP_SUB; break;
            case 4: d.op = OP_AND; break;
            case 1: d.op = OP_OR;  break;
            case 6: d.op = OP_XOR; break;
            case 7: d.op = OP_CMP; break;
            default: return false;
        }
        d.ok = true; return true;
    }
    if (op == 0xC1) {                                     // 移位立即数
        if (!rexW) return false;
        if (i + 2 > b.size()) return false;
        uint8_t modrm = b[i];
        if ((modrm >> 6) != 3) return false;
        uint8_t ext = (uint8_t)((modrm >> 3) & 7);
        uint8_t rm  = (uint8_t)((modrm & 7) | ((rex & 1) << 3));
        d.dst = rm; d.imm = b[i + 1]; d.imm_form = true;
        if (ext == 4)      d.op = OP_SHL;
        else if (ext == 5) d.op = OP_SHR;
        else return false;
        d.ok = true; return true;
    }
    return false;
}

// 是否存在“精确等价替换”（数值 + 标志位都一致）。只有这些才允许在
// 保守模式（allow_flag_change=false）下直接替换原指令。
inline bool isExactReplace(uint8_t op) {
    switch (op) {
        case OP_PUSH: case OP_POP: return true;   // lea rsp,[rsp+-8] 不动标志
        case OP_TEST:              return true;   // OR 形式，ZF/SF/PF 一致，CF/OF=0
        case OP_MOV:               return true;   // pushfq 包裹 / mov r32 零扩展
        default:                   return false;  // 算术/逻辑/移位会改标志
    }
}

} // namespace

// ---------- 构造器与公共辅助 ----------

MutationEngine::MutationEngine() {
    std::random_device rd;
    ctx_.rng.seed(((uint64_t)rd() << 32) ^ (uint64_t)rd());
}

MutationEngine::MutationEngine(uint64_t seed) { ctx_.rng.seed(seed); }

NativeInsn MutationEngine::makeInsn(const std::vector<uint8_t>& bytes) {
    NativeInsn insn;
    insn.bytes = bytes;
    insn.length = (uint8_t)bytes.size();
    insn.rva = 0;
    insn.has_rel = false;
    insn.is_jcc = insn.is_call = insn.is_ret = false;
    insn.is_push = insn.is_pop = insn.is_mov = false;
    insn.is_arith = insn.is_logic = insn.is_shift = insn.is_test = false;
    insn.mutated = false;
    return insn;
}

NativeInsn MutationEngine::raw(std::initializer_list<uint8_t> b) {
    return makeInsn(std::vector<uint8_t>(b));
}

uint8_t MutationEngine::randomSafeReg() {
    static const uint8_t safe_regs[] = { kT1, kT2 };
    std::uniform_int_distribution<int> dist(0, 1);
    return safe_regs[dist(ctx_.rng)];
}

uint8_t MutationEngine::pickTemp(uint8_t avoid) { return (avoid == kT1) ? kT2 : kT1; }

int MutationEngine::pick(int n) {
    if (n <= 1) return 0;
    std::uniform_int_distribution<int> dist(0, n - 1);
    return dist(ctx_.rng);
}

// ---------- MBA 恒等式（要求 dst、a、b 互不相同，且不与临时寄存器冲突） ----------

// x + y = (x ^ y) + 2 * (x & y)
// 允许 dst == a（就地变形）；要求 a != b，且 a/b/dst 不占用 scratch 寄存器。
std::vector<NativeInsn> MutationEngine::mba_add_x_y(uint8_t dst, uint8_t a, uint8_t b) {
    std::vector<NativeInsn> out;
    if (a == b) return out;
    if (isTmp(a) || isTmp(b) || isTmp(dst)) return out;
    uint8_t t1 = kT1, t2 = kT2;
    std::vector<uint8_t> o;
    eMovRR(o, t1, a);        // t1 = a
    eXorRR(o, t1, b);        // t1 = a ^ b
    eMovRR(o, t2, a);        // t2 = a
    eAndRR(o, t2, b);        // t2 = a & b
    eAddRR(o, t2, t2);       // t2 = 2 * (a & b)
    eAddRR(o, t1, t2);       // t1 = (a ^ b) + 2*(a & b)
    eMovRR(o, dst, t1);      // dst = a + b
    out.push_back(makeInsn(o));
    return out;
}

// x - y = (x ^ -y) + 2 * (x & -y)
// 允许 dst == a（就地变形）；-y 先算好再使用，顺序保证就地安全。
std::vector<NativeInsn> MutationEngine::mba_sub_x_y(uint8_t dst, uint8_t a, uint8_t b) {
    std::vector<NativeInsn> out;
    if (a == b) return out;
    if (isTmp(a) || isTmp(b) || isTmp(dst)) return out;
    uint8_t t1 = kT1, t2 = kT2;
    std::vector<uint8_t> o;
    eMovRR(o, t1, b);        // t1 = b
    eNeg(o, t1);             // t1 = -b
    eMovRR(o, t2, a);        // t2 = a
    eAndRR(o, t2, t1);       // t2 = a & -b
    eAddRR(o, t2, t2);       // t2 = 2 * (a & -b)
    eMovRR(o, dst, a);       // dst = a
    eXorRR(o, dst, t1);      // dst = a ^ -b
    eAddRR(o, dst, t2);      // dst = (a ^ -b) + 2*(a & -b) = a - b
    out.push_back(makeInsn(o));
    return out;
}

// x ^ y = (x | y) - (x & y)
// 允许 dst == a（就地变形）；两个中间量都在 scratch 里算完再写回 dst。
std::vector<NativeInsn> MutationEngine::mba_xor_x_y(uint8_t dst, uint8_t a, uint8_t b) {
    std::vector<NativeInsn> out;
    if (a == b) return out;
    if (isTmp(a) || isTmp(b) || isTmp(dst)) return out;
    uint8_t t1 = kT1, t2 = kT2;
    std::vector<uint8_t> o;
    eMovRR(o, t1, a);        // t1 = a
    eOrRR(o, t1, b);         // t1 = a | b
    eMovRR(o, t2, a);        // t2 = a
    eAndRR(o, t2, b);        // t2 = a & b
    eSubRR(o, t1, t2);       // t1 = (a|b) - (a&b) = a ^ b
    eMovRR(o, dst, t1);      // dst = a ^ b
    out.push_back(makeInsn(o));
    return out;
}

// ---------- 策略 A：栈帧 / 立即数装载形式 ----------
// PUSH r    -> lea rsp,[rsp-8] ; mov [rsp], r
// POP  r    -> mov r,[rsp]    ; lea rsp,[rsp+8]
// MOV r,imm -> 零扩展 / 拆分高位 / pushfq 包裹的 xor+add
std::vector<NativeInsn> MutationEngine::strategyA(uint8_t op, uint8_t dst, uint8_t src,
                                                  bool imm_form, uint64_t imm) {
    std::vector<NativeInsn> out;
    (void)src;
    if (op == OP_PUSH) {
        if (dst == 4) return out;                    // rsp 特殊，保持原样
        std::vector<uint8_t> o;
        eLeaRsp(o, -8);                              // rsp -= 8（不改标志）
        eStRsp(o, dst);                              // [rsp] = r
        out.push_back(makeInsn(o));
        return out;
    }
    if (op == OP_POP) {
        if (dst == 4) return out;
        std::vector<uint8_t> o;
        eLdRsp(o, dst);                              // r = [rsp]
        eLeaRsp(o, 8);                               // rsp += 8（不改标志）
        out.push_back(makeInsn(o));
        return out;
    }
    if (op == OP_MOV && imm_form) {
        std::vector<uint8_t> o;
        if (imm <= 0xFFFFFFFFull) {
            if (pick(2) == 0) {
                // 精确等价：mov r64,imm32(sx) -> mov r32,imm32(zx)
                eMovImm32Zx(o, dst, (uint32_t)imm);
                out.push_back(makeInsn(o));
            } else {
                // xor dst32,dst32 ; add dst32,imm32（pushfq/popfq 保护标志位）
                ePushfq(o);
                eXorSelf32(o, dst);
                eRI32(o, 0, dst, (uint32_t)imm);
                ePopfq(o);
                out.push_back(makeInsn(o));
            }
            return out;
        }
        // 64 位立即数：拆分高低 32 位，用 shl/or 重组（pushfq/popfq 保护标志位）
        uint8_t t = (dst == kT1) ? kT2 : kT1;
        ePushfq(o);
        eMovImm32Zx(o, dst, (uint32_t)(imm & 0xFFFFFFFFull));   // 低 32 位
        eMovImm32Zx(o, t,   (uint32_t)(imm >> 32));             // 高 32 位
        eShlImm(o, t, 32);
        eOrRR(o, dst, t);
        ePopfq(o);
        out.push_back(makeInsn(o));
        return out;
    }
    return out;
}

// ---------- 策略 B：MBA / 代数等价 ----------
std::vector<NativeInsn> MutationEngine::strategyB(uint8_t op, uint8_t dst, uint8_t src,
                                                  bool imm_form, uint64_t imm) {
    std::vector<NativeInsn> out;
    std::vector<uint8_t> o;

    // --- 逻辑：德摩根 ---
    if (op == OP_AND || op == OP_OR) {
        if (imm_form) return out;
        uint8_t x = dst, y = src;
        if (isTmp(x) || isTmp(y) || x == 4 || y == 4 || x == y) return out;
        uint8_t t = kT1, t2 = kT2;
        if (t == x || t == y || t2 == x || t2 == y) return out;
        if (op == OP_AND) {                 // a & b = ~(~a | ~b)
            eMovRR(o, t, x);  eNot(o, t);
            eMovRR(o, t2, y); eNot(o, t2);
            eOrRR(o, t, t2);
            eNot(o, t);
        } else {                            // a | b = ~(~a & ~b)
            eMovRR(o, t, x);  eNot(o, t);
            eMovRR(o, t2, y); eNot(o, t2);
            eAndRR(o, t, t2);
            eNot(o, t);
        }
        eMovRR(o, x, t);
        out.push_back(makeInsn(o));
        return out;
    }

    // --- 异或：两种 MBA ---
    if (op == OP_XOR) {
        if (imm_form || isTmp(dst) || isTmp(src) || dst == src) return out;
        if (pick(2) == 0) {
            auto m = mba_xor_x_y(dst, dst, src);       // (a|b) - (a&b)
            if (!m.empty()) return m;
        }
        uint8_t x = dst, y = src, t = kT1, t2 = kT2;   // (a+b) - 2*(a&b)
        if (t == x || t == y || t2 == x || t2 == y) return out;
        eMovRR(o, t, x);  eAddRR(o, t, y);
        eMovRR(o, t2, x); eAndRR(o, t2, y);
        eAddRR(o, t2, t2);
        eSubRR(o, t, t2);
        eMovRR(o, x, t);
        out.push_back(makeInsn(o));
        return out;
    }

    // --- 加法 ---
    if (op == OP_ADD) {
        if (imm_form) {
            int64_t v = (int64_t)imm;
            if (v == 0) return out;
            if (inImm32(-v)) {                          // ADD a,imm -> SUB a,-imm
                eRI(o, 5, dst, (int32_t)(-v));
                out.push_back(makeInsn(o)); return out;
            }
            if (isTmp(dst) || dst == 4) return out;
            uint8_t t = kT1, t2 = kT2;                  // a + imm = (a^imm) + 2*(a&imm)
            eMovImm64(o, t, imm);
            eMovRR(o, t2, dst);
            eAndRR(o, t2, t);
            eAddRR(o, t2, t2);
            eXorRR(o, dst, t);
            eAddRR(o, dst, t2);
            out.push_back(makeInsn(o));
            return out;
        }
        if (isTmp(dst) || isTmp(src) || dst == src || dst == 4 || src == 4) return out;
        return mba_add_x_y(dst, dst, src);   // dst == a 就地变形已支持
    }

    // --- 减法 ---
    if (op == OP_SUB) {
        if (imm_form) {
            int64_t v = (int64_t)imm;
            if (v == 0) return out;
            if (inImm32(-v)) {                          // SUB a,imm -> ADD a,-imm
                eRI(o, 0, dst, (int32_t)(-v));
                out.push_back(makeInsn(o)); return out;
            }
            if (isTmp(dst) || dst == 4) return out;
            // a - imm = a + (-imm) = (a ^ -imm) + 2*(a & -imm)
            uint64_t nv = (uint64_t)(0 - (uint64_t)imm);
            uint8_t t = kT1, t2 = kT2;
            eMovImm64(o, t, nv);
            eMovRR(o, t2, dst);
            eAndRR(o, t2, t);
            eAddRR(o, t2, t2);
            eXorRR(o, dst, t);
            eAddRR(o, dst, t2);
            out.push_back(makeInsn(o));
            return out;
        }
        if (isTmp(dst) || isTmp(src) || dst == src || dst == 4 || src == 4) return out;
        return mba_sub_x_y(dst, dst, src);   // dst == a 就地变形已支持
    }

    // --- 移位 ---
    if (op == OP_SHL) {
        unsigned n = (unsigned)(imm & 63);
        if (n == 0 || n > 30 || isTmp(dst) || dst == 4) return out;
        eMovImm32Sx(o, kT2, (int32_t)((uint32_t)1 << n));   // t2 = 2^n
        eIMUL2(o, dst, kT2);                                // a *= 2^n
        out.push_back(makeInsn(o));
        return out;
    }
    if (op == OP_SHR) {
        unsigned n = (unsigned)(imm & 63);
        if (n < 2 || n >= 32) return out;                   // 保守：仅拆分 2..31
        unsigned n1 = n / 2, n2 = n - n1;
        if (n1) { eShrImm(o, dst, (uint8_t)n1); out.push_back(makeInsn(o)); o.clear(); }
        if (n2) { eShrImm(o, dst, (uint8_t)n2); out.push_back(makeInsn(o)); }
        return out;
    }

    // --- TEST a,a -> OR a,a（ZF/SF/PF 相同，CF/OF 同为 0） ---
    if (op == OP_TEST) {
        if (imm_form || dst != src || isTmp(dst) || dst == 4) return out;
        eOrRR(o, dst, dst);
        out.push_back(makeInsn(o));
        return out;
    }

    // --- MOV 寄存器形式 ---
    if (op == OP_MOV) {
        if (imm_form) return out;                            // 交给策略 A
        if (dst == src || dst == 4 || src == 4) return out;
        // mov dst,src -> push src ; pop dst（不改标志位；lea reg,reg 是非法编码，不可用）
        ePush(o, src);
        ePop(o, dst);
        out.push_back(makeInsn(o));
        return out;
    }
    return out;
}

// 单条指令变异。
// allow_flag_change=false 时，只允许“精确等价”（数值 + 标志位一致）的替换，
// 否则原样返回；true 时允许改变标志位的等价替换。
std::vector<NativeInsn> MutationEngine::transformOne(const NativeInsn& insn, bool allow_flag_change) {
    std::vector<NativeInsn> out;
    if (insn.bytes.empty()) { out.push_back(insn); return out; }

    Dec d;
    if (!parseInsn(insn.bytes, d) || !d.ok) { out.push_back(insn); return out; }

    std::vector<NativeInsn> sub = strategyB(d.op, d.dst, d.src, d.imm_form, d.imm);
    if (sub.empty()) sub = strategyA(d.op, d.dst, d.src, d.imm_form, d.imm);
    if (sub.empty()) { out.push_back(insn); return out; }

    if (!allow_flag_change && !isExactReplace(d.op)) { out.push_back(insn); return out; }

    for (auto& s : sub) {
        s.mutated = true;
        s.mutation_id = ctx_.mutation_count;
        out.push_back(s);
    }
    ctx_.mutation_count++;
    return out;
}

// ---------- 公开的单策略入口（均为真实等价变形） ----------
std::vector<NativeInsn> MutationEngine::mutateADD(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateSUB(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateXOR(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateAND(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateOR (const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateMOV(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutatePUSH(const NativeInsn& i){ return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutatePOP(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateSHL(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateSHR(const NativeInsn& i) { return transformOne(i, true); }
std::vector<NativeInsn> MutationEngine::mutateTEST(const NativeInsn& i){ return transformOne(i, true); }

// ---------- JCC 消除（无分支选择） ----------
// 可静态证明的等价模式：同一目标寄存器的两路赋值
//     JCC L ; MOV dst, X ; ... ; L: MOV dst, Y
// 等价无分支序列：
//     MOV dst, Y ; CMOVcc dst, X
// 输入不满足该形状时退回原指令，绝不猜测。
std::vector<NativeInsn> MutationEngine::eliminateJCC(
    const NativeInsn& jcc_insn,
    const std::vector<NativeInsn>& true_branch,
    const std::vector<NativeInsn>& false_branch)
{
    std::vector<NativeInsn> result;

    uint8_t cc = 0xFF;
    if (jcc_insn.bytes.size() >= 2 && jcc_insn.bytes[0] >= 0x70 && jcc_insn.bytes[0] <= 0x7F)
        cc = (uint8_t)(jcc_insn.bytes[0] - 0x70);
    else if (jcc_insn.bytes.size() >= 2 && jcc_insn.bytes[0] == 0x0F &&
             jcc_insn.bytes[1] >= 0x80 && jcc_insn.bytes[1] <= 0x8F)
        cc = (uint8_t)(jcc_insn.bytes[1] - 0x80);

    Dec dt, df;
    bool okShape = (cc != 0xFF) &&
                   true_branch.size() == 1 && false_branch.size() == 1 &&
                   parseInsn(true_branch[0].bytes,  dt) && dt.ok &&
                   parseInsn(false_branch[0].bytes, df) && df.ok &&
                   dt.op == OP_MOV && df.op == OP_MOV &&
                   !dt.imm_form && !df.imm_form &&
                   dt.dst == df.dst &&
                   dt.dst != 4 && dt.src != 4 && df.src != 4 &&
                   dt.dst != dt.src && df.dst != df.src;

    if (!okShape) { result.push_back(jcc_insn); ctx_.mutation_count++; return result; }

    uint8_t dst = dt.dst;
    std::vector<uint8_t> b;
    eMovRR(b, dst, df.src);                 // mov dst, <false 值>
    result.push_back(makeInsn(b));
    b.clear(); eCmovcc(b, cc, dst, dt.src); // cmovcc dst, <true 值>
    result.push_back(makeInsn(b));

    for (auto& r : result) r.mutated = true;
    ctx_.mutation_count++;
    return result;
}

// ---------- 无分支 max/min ----------
// 约定（测试与调用方共同遵守）：输入 a=rax, b=rcx；结果写入 rax。
// 使用 r8/r9/r10/rdx 作为 caller-saved 临时寄存器。
//   max(a,b) = a ^ ((a ^ b) & -(a <  b))
//   min(a,b) = a ^ ((a ^ b) & -(a >= b))
std::vector<NativeInsn> MutationEngine::branchlessMax() {
    std::vector<uint8_t> o;
    eMovRR(o, 8, 0);               // mov  r8, rax
    eMovRR(o, 9, 1);               // mov  r9, rcx
    eMovRR(o, 10, 0);              // mov  r10, rax
    eXorRR(o, 10, 9);              // r10 = a ^ b
    eCmp(o, 8, 9);                 // cmp  r8, r9
    eSetcc(o, 0x0C /*l*/, 2);      // setl dl
    eMovzx8(o, 2, 2);              // movzx rdx, dl
    eNeg(o, 2);                    // neg  rdx  -> 掩码 0 / -1
    eAndRR(o, 10, 2);              // r10 = (a^b) & mask
    eXorRR(o, 0, 10);              // rax ^= r10
    std::vector<NativeInsn> r;
    r.push_back(makeInsn(o));
    r[0].mutated = true;
    ctx_.mutation_count++;
    return r;
}

std::vector<NativeInsn> MutationEngine::branchlessMin() {
    std::vector<uint8_t> o;
    eMovRR(o, 8, 0);
    eMovRR(o, 9, 1);
    eMovRR(o, 10, 0);
    eXorRR(o, 10, 9);
    eCmp(o, 8, 9);
    eSetcc(o, 0x0D /*ge*/, 2);     // setge dl
    eMovzx8(o, 2, 2);
    eNeg(o, 2);
    eAndRR(o, 10, 2);
    eXorRR(o, 0, 10);
    std::vector<NativeInsn> r;
    r.push_back(makeInsn(o));
    r[0].mutated = true;
    ctx_.mutation_count++;
    return r;
}

// ---------- 不透明谓词 ----------
// 恒真谓词：K*(K+1) 恒为偶数 => (K*(K+1)) & 1 == 0
//   mov r10d,K ; lea r11,[r10+1] ; imul r11,r10 ; and r11d,1 ; test r11,r11  ; ZF=1
//   jz  taken   （always_true） / jnz taken（always_false）
//   mov r10,0xAAAA…   ; 未走 taken 路径
//   jmp end
// taken:
//   mov r10,0xBBBB…   ; 走了 taken 路径
// end:
// 只使用 r10 / r11 两个 scratch 寄存器，不触碰其它寄存器与内存。
std::vector<NativeInsn> MutationEngine::generateOpaquePredicate(bool always_true) {
    std::vector<NativeInsn> o;
    uint32_t K = (uint32_t)(ctx_.rng() & 0x7FFFFFFF);

    { std::vector<uint8_t> b; b.push_back(0x41); b.push_back(0xBA); put32(b, K);
      o.push_back(makeInsn(b)); }                                        // mov r10d,K
    { std::vector<uint8_t> b; b.push_back(0x4D); b.push_back(0x8D); b.push_back(0x5A); b.push_back(0x01);
      o.push_back(makeInsn(b)); }                                        // lea r11,[r10+1]
    { std::vector<uint8_t> b; eIMUL2(b, 11, 10); o.push_back(makeInsn(b)); } // imul r11,r10
    { std::vector<uint8_t> b; b.push_back(0x41); b.push_back(0x83); b.push_back(0xE3); b.push_back(0x01);
      o.push_back(makeInsn(b)); }                                        // and r11d,1
    { std::vector<uint8_t> b; eRR(b, 0x85, 11, 11); o.push_back(makeInsn(b)); } // test r11,r11

    // 条件跳转：fallthrough 块固定 12 字节
    { std::vector<uint8_t> b; b.push_back(always_true ? 0x74 : 0x75); b.push_back(0x0C);
      o.push_back(makeInsn(b)); }

    // fallthrough：mov r10,0xAAAA… ; jmp end(+10)
    { std::vector<uint8_t> b; b.push_back(0x49); b.push_back(0xBA);
      for (int i = 0; i < 8; ++i) b.push_back(0xAA);
      o.push_back(makeInsn(b)); }
    { std::vector<uint8_t> b; b.push_back(0xEB); b.push_back(0x0A); o.push_back(makeInsn(b)); }

    // taken：mov r10,0xBBBB…
    { std::vector<uint8_t> b; b.push_back(0x49); b.push_back(0xBA);
      for (int i = 0; i < 8; ++i) b.push_back(0xBB);
      o.push_back(makeInsn(b)); }

    for (auto& i : o) i.mutated = true;
    ctx_.mutation_count++;
    return o;
}

// ---------- 垃圾指令（死代码注入） ----------
std::vector<NativeInsn> MutationEngine::generateGarbage(int count) {
    std::vector<NativeInsn> result;
    if (count <= 0) return result;
    std::uniform_int_distribution<int> dist(0, 5);

    for (int i = 0; i < count; i++) {
        switch (dist(ctx_.rng)) {
        case 0:   // 多字节 NOP
            result.push_back(raw({0x0F, 0x1F, 0x44, 0x00, 0x00}));
            break;
        case 1: { // pushfq/popfq 包裹 junk：标志位与用户寄存器完全恢复
            uint8_t r = (ctx_.rng() & 1) ? kT1 : kT2;
            result.push_back(raw({0x9C}));                          // pushfq
            std::vector<uint8_t> b;
            eMovImm64(b, r, ctx_.rng()); result.push_back(makeInsn(b));
            b.clear(); eNot(b, r);       result.push_back(makeInsn(b));
            b.clear(); eAddRR(b, r, r);  result.push_back(makeInsn(b));
            result.push_back(raw({0x9D}));                          // popfq
            break;
        }
        case 2:   // 纯 NOP 变体（不改任何状态）
            switch (ctx_.rng() % 4) {
            case 0: result.push_back(raw({0x90})); break;
            case 1: result.push_back(raw({0x66, 0x90})); break;
            case 2: result.push_back(raw({0x0F, 0x1F, 0x00})); break;
            default: result.push_back(raw({0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00})); break;
            }
            break;
        case 3: { // 死寄存器操作：xor tmp,tmp
            uint8_t r = (ctx_.rng() & 1) ? kT1 : kT2;
            std::vector<uint8_t> b; eXorRR(b, r, r); result.push_back(makeInsn(b));
            break;
        }
        case 4: { // 恒等传送 mov tmp,tmp（合法 no-op，不动标志）
            uint8_t r = (ctx_.rng() & 1) ? kT1 : kT2;
            std::vector<uint8_t> b; eMovRR(b, r, r); result.push_back(makeInsn(b));
            break;
        }
        default:  // 前缀填充 NOP
            result.push_back(raw({0x66, 0x66, 0x90}));
            break;
        }
    }
    for (auto& i : result) i.mutated = true;
    return result;
}

// ---------- MBA 常量装载 ----------
// 生成一段把常量 target_value 装入 reg 的等价 MBA 序列（不读原寄存器值）。
//   form0: mov r,v ; mov t,m ; xor r,t ; xor r,t
//   form1: mov r,v ; mov t,m ; add r,t ; sub r,t
//   form2: mov r,v ; mov t,m ; xor t,r ; xor t,r ; xor r,t ; xor r,t
// 三者结果均精确等于 v（用 pushfq/popfq 保护标志位）。
std::vector<NativeInsn> MutationEngine::generateMBA(int target_value, int reg) {
    std::vector<NativeInsn> o;
    if (reg < 0 || reg > 15 || reg == 4) return o;     // 不支持 rsp
    uint8_t r = (uint8_t)reg;
    uint64_t v = (uint64_t)(int64_t)target_value;
    uint64_t m = ctx_.rng() & 0xFFFFFFFFull;
    int form = pick(3);

    std::vector<uint8_t> b;
    ePushfq(b);
    eMovImm64(b, r, v); o.push_back(makeInsn(b));
    uint8_t mreg = (r != kT1) ? kT1 : kT2;
    b.clear(); eMovImm64(b, mreg, m); o.push_back(makeInsn(b));

    if (form == 0) {
        b.clear(); eXorRR(b, r, mreg); o.push_back(makeInsn(b));
        b.clear(); eXorRR(b, r, mreg); o.push_back(makeInsn(b));
    } else if (form == 1) {
        b.clear(); eAddRR(b, r, mreg); o.push_back(makeInsn(b));
        b.clear(); eSubRR(b, r, mreg); o.push_back(makeInsn(b));
    } else {
        b.clear(); eXorRR(b, mreg, r); o.push_back(makeInsn(b));
        b.clear(); eXorRR(b, mreg, r); o.push_back(makeInsn(b));
        b.clear(); eXorRR(b, r, mreg); o.push_back(makeInsn(b));
        b.clear(); eXorRR(b, r, mreg); o.push_back(makeInsn(b));
    }
    b.clear(); ePopfq(b); o.push_back(makeInsn(b));

    for (auto& i : o) i.mutated = true;
    ctx_.mutation_count++;
    return o;
}

// ---------- 主入口 ----------
std::vector<NativeInsn> MutationEngine::mutate(const std::vector<NativeInsn>& input) {
    std::vector<NativeInsn> result;
    ctx_.mutation_count = 0;
    if (ctx_.strength == MutationStrength::None) return input;

    for (const auto& insn : input) {
        auto mutated = transformOne(insn, true);
        result.insert(result.end(), mutated.begin(), mutated.end());

        // 垃圾代码注入（Medium 及以上）
        if (ctx_.inject_garbage && ctx_.strength >= MutationStrength::Medium) {
            int maxg = ctx_.max_garbage_per_insn;
            int gcount = pick(maxg + 1);
            if (gcount > 0) {
                auto g = generateGarbage(gcount);
                result.insert(result.end(), g.begin(), g.end());
            }
        }

        // 不透明谓词（Heavy）
        if (ctx_.strength >= MutationStrength::Heavy) {
            auto p = generateOpaquePredicate(true);
            result.insert(result.end(), p.begin(), p.end());
        }
    }
    return result;
}

} // namespace np
