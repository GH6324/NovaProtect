#pragma once
// NovaProtect Mutation Engine
// Implements instruction-level mutation with branch elimination
// 3 strength levels, each with multiple mutation strategies per instruction type

#include <cstdint>
#include <vector>
#include <random>
#include <initializer_list>

namespace np {

// Mutation strength levels
enum class MutationStrength : uint8_t {
    None    = 0,
    Light   = 1,   // Basic substitution, add opaque predicates
    Medium  = 2,   // Full substitution + garbage code injection
    Heavy   = 3,   // Maximum mutation, branchless transforms, code reordering
};

// Opaque predicate types (always-true/always-false expressions)
enum class OpaquePredicate : uint8_t {
    Congruence,      // (a*b) mod 2 == 0 for any a,b
    Quadratic,       // x^2 + x is always even
    GCD,            // gcd(a,b) always >= 1
    Arithmetic,      // (a^2 + a) mod 2 == 0
    Sum,            // (a + b) * (a + b - 1) is always even
    Count
};

// Instruction mutation context
struct MutationContext {
    std::mt19937_64 rng;
    MutationStrength strength = MutationStrength::Light;
    uint32_t mutation_count = 0;  // number of mutations applied
    bool eliminate_jcc = true;    // eliminate conditional jumps
    bool inject_garbage = true;   // inject garbage instructions
    bool reorder = false;         // reorder independent instructions
    uint8_t max_garbage_per_insn = 3;
    uint8_t max_substitution_depth = 3;
};

// Represents a native x86/x64 instruction for mutation
struct NativeInsn {
    std::vector<uint8_t> bytes;    // encoded instruction
    uint32_t rva;                   // RVA in original binary
    uint8_t length;                 // instruction length
    // Parsed info (simplified)
    bool has_rel;                   // has relative address
    int64_t rel_target;             // relative target
    bool is_jcc;                    // is conditional jump
    bool is_call;                   // is call
    bool is_ret;                    // is return
    bool is_push;                   // is push
    bool is_pop;                    // is pop
    bool is_mov;                    // is mov
    bool is_arith;                  // is arithmetic
    bool is_logic;                  // is logical
    bool is_shift;                  // is shift
    bool is_test;                   // is test/cmp
    uint8_t modrm;                  // modrm byte if present
    uint8_t sib;                    // sib byte if present
    uint8_t rex;                    // rex prefix if present
    uint8_t opcode;                 // primary opcode
    // For mutation
    bool mutated = false;           // has been mutated
    uint32_t mutation_id = 0;       // which mutation was applied
};

// Mutation engine class
class MutationEngine {
public:
    MutationEngine();
    explicit MutationEngine(uint64_t seed);
    
    // Set mutation parameters
    void setStrength(MutationStrength s) { ctx_.strength = s; }
    void setEliminateJCC(bool e) { ctx_.eliminate_jcc = e; }
    void setInjectGarbage(bool g) { ctx_.inject_garbage = g; }
    void setReorder(bool r) { ctx_.reorder = r; }
    
    // Mutate a list of instructions
    // Returns new instruction list (original may be expanded)
    std::vector<NativeInsn> mutate(const std::vector<NativeInsn>& input);
    
    // Get statistics
    uint32_t mutationCount() const { return ctx_.mutation_count; }
    size_t expansionRatio(size_t original, size_t mutated) const { 
        return original > 0 ? mutated / original : 0; 
    }
    
    // === Individual mutation strategies ===
    
    // Arithmetic substitutions (multiple options per op)
    // ADD a, b -> SUB a, -b
    // ADD a, b -> NOT a; SUB a, ~b  (a + b = a - (-b) = a - (~b + 1))
    std::vector<NativeInsn> mutateADD(const NativeInsn& insn);
    
    // SUB a, b -> ADD a, -b
    // SUB a, b -> XOR a, b; NOT tmp; AND tmp... (complex)
    std::vector<NativeInsn> mutateSUB(const NativeInsn& insn);
    
    // XOR a, b -> (a | b) & ~(a & b)
    // XOR a, b -> (a + b) - 2*(a & b)
    std::vector<NativeInsn> mutateXOR(const NativeInsn& insn);
    
    // AND a, b -> ~(~a | ~b)  (De Morgan)
    std::vector<NativeInsn> mutateAND(const NativeInsn& insn);
    
    // OR a, b -> ~(~a & ~b)  (De Morgan)
    std::vector<NativeInsn> mutateOR(const NativeInsn& insn);
    
    // MOV substitution
    // MOV dst, src -> PUSH src; POP dst
    // MOV dst, src -> LEA dst, [src]
    // MOV dst, imm -> XOR dst, dst; ADD dst, imm
    std::vector<NativeInsn> mutateMOV(const NativeInsn& insn);
    
    // PUSH/POP substitution
    // PUSH reg -> SUB rsp, 8; MOV [rsp], reg
    // POP reg -> MOV reg, [rsp]; ADD rsp, 8
    std::vector<NativeInsn> mutatePUSH(const NativeInsn& insn);
    std::vector<NativeInsn> mutatePOP(const NativeInsn& insn);
    
    // Shift substitutions
    // SHL a, n -> a * 2^n
    // SHR a, n -> a / 2^n (unsigned)
    std::vector<NativeInsn> mutateSHL(const NativeInsn& insn);
    std::vector<NativeInsn> mutateSHR(const NativeInsn& insn);
    
    // TEST/CMP substitution
    // TEST a, a -> CMP a, 0
    // TEST a, a -> OR a, a (preserves flags)
    std::vector<NativeInsn> mutateTEST(const NativeInsn& insn);
    
    // === JCC elimination (branchless) ===
    // Transform conditional jumps into branchless sequences
    // Uses conditional moves, arithmetic, and boolean operations
    
    // If-else elimination: 
    //   JCC target; ...; target: ...
    //   becomes arithmetic selection
    std::vector<NativeInsn> eliminateJCC(const NativeInsn& jcc_insn, 
                                          const std::vector<NativeInsn>& true_branch,
                                          const std::vector<NativeInsn>& false_branch);
    
    // Generate branchless max/min
    std::vector<NativeInsn> branchlessMax();
    std::vector<NativeInsn> branchlessMin();
    
    // Generate opaque predicate (always true/false)
    // Used to confuse control flow analysis
    std::vector<NativeInsn> generateOpaquePredicate(bool always_true);
    
    // Generate garbage instructions (dead code)
    std::vector<NativeInsn> generateGarbage(int count);
    
    // Generate MBA (Mixed Boolean-Arithmetic) expression for a constant
    // e.g., x + 5 -> (x ^ 5) + 2*(x & 5)
    std::vector<NativeInsn> generateMBA(int target_value, int reg);
    
private:
    MutationContext ctx_;

    // Helper: emit raw bytes as instruction
    NativeInsn makeInsn(const std::vector<uint8_t>& bytes);
    NativeInsn raw(std::initializer_list<uint8_t> b);

    // Helper: generate random register choice (from safe regs)
    uint8_t randomSafeReg();
    uint8_t pickTemp(uint8_t avoid);   // pick a temp reg different from avoid
    int     pick(int n);               // uniform in [0,n)

    // Decoded-operand strategy implementations (x64).
    // op uses the internal OpK encoding defined in mutation.cpp.
    std::vector<NativeInsn> strategyA(uint8_t op, uint8_t dst, uint8_t src,
                                      bool imm_form, uint64_t imm);
    std::vector<NativeInsn> strategyB(uint8_t op, uint8_t dst, uint8_t src,
                                      bool imm_form, uint64_t imm);

    // Mutate a single instruction (safe_append keeps the original when the
    // replacement is not bit-exact in flags).
    std::vector<NativeInsn> transformOne(const NativeInsn& insn, bool safe_append);

    // MBA identity generators
    std::vector<NativeInsn> mba_add_x_y(uint8_t dst, uint8_t a, uint8_t b);
    std::vector<NativeInsn> mba_sub_x_y(uint8_t dst, uint8_t a, uint8_t b);
    std::vector<NativeInsn> mba_xor_x_y(uint8_t dst, uint8_t a, uint8_t b);
};

} // namespace np
