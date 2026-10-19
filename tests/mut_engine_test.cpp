// NovaProtect Mutation Engine 自测
// 对每种变异策略：把原指令序列与变异后序列分别放进可执行内存运行，
// 比较被调用方可见寄存器（rax,rbx,rcx,rdx,rsi,rdi,r8,r9,r12..r15）的结果。
// 临时寄存器 r10/r11 为变异引擎的 scratch，不参与比较（除非测试明确断言）。
//
// 构建：g++ -std=c++17 -I include -o tests\mut_engine_test.exe tests\mut_engine_test.cpp src\mutation.cpp -O1

#include "mutation.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

using namespace np;

// ---------------- 执行 harness ----------------
// Ctx 布局必须与下面 asm 中的偏移一致（全部 8 字节）。
struct Ctx {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t flags;   // 偏移 120
    uint64_t result;  // 偏移 128
    uint64_t code;    // 偏移 136
};

static void* allocExec(size_t n) {
    void* p = VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return p;
}
static void freeExec(void* p) { if (p) VirtualFree(p, 0, MEM_RELEASE); }

extern "C" void np_exec_block(Ctx* c);

__attribute__((naked)) void np_exec_block(Ctx* c) {
    __asm__ __volatile__(
        "push %rbx\n\t"
        "push %rbp\n\t"
        "push %r12\n\t"
        "push %r13\n\t"
        "push %r14\n\t"
        "push %r15\n\t"
        "push %rsi\n\t"
        "mov %rcx, %rbp\n\t"          // rbp = ctx  (Win64: 参数 1 = RCX)
        "mov 0(%rbp), %rax\n\t"
        "mov 8(%rbp), %rbx\n\t"
        "mov 16(%rbp), %rcx\n\t"
        "mov 24(%rbp), %rdx\n\t"
        "mov 32(%rbp), %rsi\n\t"
        "mov 40(%rbp), %rdi\n\t"
        "mov 56(%rbp), %r8\n\t"
        "mov 64(%rbp), %r9\n\t"
        "mov 72(%rbp), %r10\n\t"
        "mov 80(%rbp), %r11\n\t"
        "mov 88(%rbp), %r12\n\t"
        "mov 96(%rbp), %r13\n\t"
        "mov 104(%rbp), %r14\n\t"
        "mov 112(%rbp), %r15\n\t"
        "call *136(%rbp)\n\t"
        "mov %rax, 128(%rbp)\n\t"
        "mov %rbx, 8(%rbp)\n\t"
        "mov %rcx, 16(%rbp)\n\t"
        "mov %rdx, 24(%rbp)\n\t"
        "mov %rsi, 32(%rbp)\n\t"
        "mov %rdi, 40(%rbp)\n\t"
        "mov %r8, 56(%rbp)\n\t"
        "mov %r9, 64(%rbp)\n\t"
        "mov %r10, 72(%rbp)\n\t"
        "mov %r11, 80(%rbp)\n\t"
        "mov %r12, 88(%rbp)\n\t"
        "mov %r13, 96(%rbp)\n\t"
        "mov %r14, 104(%rbp)\n\t"
        "mov %r15, 112(%rbp)\n\t"
        "pushfq\n\t"
        "pop %rax\n\t"
        "mov %rax, 120(%rbp)\n\t"
        "pop %rsi\n\t"
        "pop %r15\n\t"
        "pop %r14\n\t"
        "pop %r13\n\t"
        "pop %r12\n\t"
        "pop %rbp\n\t"
        "pop %rbx\n\t"
        "ret\n\t"
    );
}

// ---------------- 测试基础设施 ----------------
static int g_pass = 0, g_fail = 0, g_skip = 0;
static std::string g_failures;

static std::vector<uint8_t> cat(const std::vector<NativeInsn>& v) {
    std::vector<uint8_t> b;
    for (auto& i : v) b.insert(b.end(), i.bytes.begin(), i.bytes.end());
    return b;
}
static std::vector<uint8_t> cat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> r = a; r.insert(r.end(), b.begin(), b.end()); return r;
}
static NativeInsn I(std::initializer_list<uint8_t> b) {
    NativeInsn i; i.bytes.assign(b); i.length = (uint8_t)i.bytes.size(); return i;
}

static void runBytes(const std::vector<uint8_t>& codeIn, Ctx& c) {
    // 执行块必须以 ret 结尾（被测指令序列本身不含 ret）
    std::vector<uint8_t> code = codeIn;
    code.push_back(0xC3);
    void* mem = allocExec(4096);
    memset(mem, 0xCC, 4096);
    memcpy(mem, code.data(), code.size());
    FlushInstructionCache(GetCurrentProcess(), mem, code.size());
    c.code = (uint64_t)mem;
    np_exec_block(&c);
    c.rax = c.result;   // 取回被调用块中的 rax
    freeExec(mem);
}

struct RegSnap { uint64_t v[12]; uint64_t flags; };

static RegSnap snap(const Ctx& c) {
    RegSnap s;
    s.v[0]=c.rax; s.v[1]=c.rbx; s.v[2]=c.rcx; s.v[3]=c.rdx; s.v[4]=c.rsi;
    s.v[5]=c.rdi; s.v[6]=c.r8;  s.v[7]=c.r9;  s.v[8]=c.r12; s.v[9]=c.r13;
    s.v[10]=c.r14; s.v[11]=c.r15;
    s.flags = c.flags;
    return s;
}
static const char* kRegNames[12] = {"rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r12","r13","r14","r15"};

// 比较原序列与变异序列的执行结果（用户可见寄存器）
static bool compareRun(const char* name,
                       const std::vector<uint8_t>& orig,
                       const std::vector<uint8_t>& mut,
                       const Ctx& seed,
                       bool compareFlags) {
    Ctx c1 = seed, c2 = seed;
    runBytes(orig, c1);
    runBytes(mut, c2);
    RegSnap a = snap(c1), b = snap(c2);
    for (int i = 0; i < 12; ++i) {
        if (a.v[i] != b.v[i]) {
            g_fail++;
            char buf[256];
            snprintf(buf, sizeof buf, "  [FAIL] %s: %s orig=0x%llX mut=0x%llX\n",
                     name, kRegNames[i], (unsigned long long)a.v[i], (unsigned long long)b.v[i]);
            g_failures += buf;
            return false;
        }
    }
    if (compareFlags && ((a.flags ^ b.flags) & 0x8D5 /* CF PF AF ZF SF OF */)) {
        g_fail++;
        char buf[256];
        snprintf(buf, sizeof buf, "  [FAIL] %s: flags orig=0x%llX mut=0x%llX\n",
                 name, (unsigned long long)a.flags, (unsigned long long)b.flags);
        g_failures += buf;
        return false;
    }
    g_pass++;
    return true;
}

static Ctx makeSeed(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    Ctx x; memset(&x, 0, sizeof x);
    x.rax = a; x.rbx = b; x.rcx = c; x.rdx = d;
    x.rsi = 0x1111222233334444ull; x.rdi = 0x5555666677778888ull;
    x.r8 = 0x0F0F0F0F0F0F0F0Full;  x.r9 = 0xF0F0F0F0F0F0F0F0ull;
    x.r12 = 0x123456789ABCDEF0ull; x.r13 = 0x0DEADBEEFCAFEBABull;
    x.r14 = 0x00FF00FF00FF00FFull; x.r15 = 0xFFFFFFFF00000000ull;
    x.r10 = 0xAAAAAAAAAAAAAAAAull; x.r11 = 0x5555555555555555ull;
    return x;
}

// 对某个单指令策略，跨多组输入验证等价性
static void testSingleInsn(const char* name, const NativeInsn& origInsn,
                           std::vector<NativeInsn> (MutationEngine::*fn)(const NativeInsn&),
                           bool compareFlags) {
    bool anyReal = false;
    const uint64_t vals[8] = { 0x123456789ABCDEFull, 0xFFFFFFFFFFFFFFFFull,
                               0x00000000DEADBEEFull, 0x7FEDCBA987654321ull,
                               0x0000000000000000ull, 0x8000000000000000ull,
                               0x00000000FFFFFFFFull, 0xAAAAAAAA55555555ull };
    // 多组随机种子：覆盖 pick()/随机分支的所有等价路径
    const uint64_t engSeeds[3] = { 0xC0FFEE1234ull, 0x1234ABCDull, 0xDEADBEEFull };
    for (int si = 0; si < 3; ++si) {
        MutationEngine eng(engSeeds[si]);
        for (int i = 0; i < 8; ++i) {
            Ctx seed = makeSeed(vals[i], vals[(i + 1) & 7], vals[(i + 2) & 7], vals[(i + 3) & 7]);
            auto mut = (eng.*fn)(origInsn);
            std::vector<uint8_t> mb = cat(mut);
            if (mb != origInsn.bytes) anyReal = true;
            char label[128]; snprintf(label, sizeof label, "%s[seed%d,i%d]", name, si, i);
            compareRun(label, origInsn.bytes, mb, seed, compareFlags);
        }
    }
    if (!anyReal) {
        g_skip++;
        printf("  [SKIP] %s: 所有轮次均未发生替换（策略未命中）\n", name);
    }
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== NovaProtect Mutation Engine Test ===\n\n");

    // ---------- 算术 / 逻辑 ----------
    printf("-- 算术/逻辑替换 --\n");
    testSingleInsn("ADD r,r",   I({0x48,0x03,0xC3}), &MutationEngine::mutateADD,  false); // add rax,rbx
    testSingleInsn("ADD r,imm", I({0x48,0x81,0xC0,0x34,0x12,0x00,0x00}), &MutationEngine::mutateADD, false);
    testSingleInsn("SUB r,r",   I({0x48,0x2B,0xC3}), &MutationEngine::mutateSUB,  false); // sub rax,rbx
    testSingleInsn("SUB r,imm", I({0x48,0x81,0xE8,0x78,0x56,0x34,0x12}), &MutationEngine::mutateSUB, false);
    testSingleInsn("XOR r,r",   I({0x48,0x31,0xD8}), &MutationEngine::mutateXOR,  false); // xor rax,rbx
    testSingleInsn("AND r,r",   I({0x48,0x21,0xD8}), &MutationEngine::mutateAND,  false); // and rax,rbx
    testSingleInsn("OR  r,r",   I({0x48,0x09,0xD8}), &MutationEngine::mutateOR,   false); // or  rax,rbx

    // ---------- MOV ----------
    printf("-- MOV 替换 --\n");
    testSingleInsn("MOV r,r",   I({0x48,0x89,0xD8}), &MutationEngine::mutateMOV,  true);  // mov rax,rbx
    testSingleInsn("MOV r,imm32", I({0x48,0xB8,0x78,0x56,0x34,0x12,0x00,0x00,0x00,0x00}),
                   &MutationEngine::mutateMOV, true);                                     // mov rax,0x12345678
    testSingleInsn("MOV r,imm64", I({0x48,0xB8,0xEF,0xCD,0xAB,0x89,0x67,0x45,0x23,0x01}),
                   &MutationEngine::mutateMOV, true);                                     // mov rax,0x0123456789ABCDEF

    // ---------- SHL / SHR ----------
    printf("-- 移位替换 --\n");
    testSingleInsn("SHL r,5",   I({0x48,0xC1,0xE0,0x05}), &MutationEngine::mutateSHL, false); // shl rax,5
    testSingleInsn("SHL r,20",  I({0x48,0xC1,0xE0,0x14}), &MutationEngine::mutateSHL, false);
    testSingleInsn("SHR r,6",   I({0x48,0xC1,0xE8,0x06}), &MutationEngine::mutateSHR, false); // shr rax,6
    testSingleInsn("SHR r,3",   I({0x48,0xC1,0xE8,0x03}), &MutationEngine::mutateSHR, false);

    // ---------- TEST ----------
    printf("-- TEST 替换（含标志位比较）--\n");
    testSingleInsn("TEST r,r",  I({0x48,0x85,0xC0}), &MutationEngine::mutateTEST, true);  // test rax,rax

    // ---------- 参数扫描（立即数 / 移位量）----------
    printf("-- 参数扫描 --\n");
    {
        struct Case { const char* tag; std::vector<uint8_t> bytes;
                      std::vector<NativeInsn> (MutationEngine::*fn)(const NativeInsn&); };
        std::vector<Case> cases;
        auto addImm = [&](const char* tag, uint8_t ext,
                          std::vector<NativeInsn> (MutationEngine::*fn)(const NativeInsn&), uint32_t v) {
            std::vector<uint8_t> b = {0x48,0x81,(uint8_t)(0xC0|((ext&7)<<3)),0,0,0,0};
            b[3]=(uint8_t)v; b[4]=(uint8_t)(v>>8); b[5]=(uint8_t)(v>>16); b[6]=(uint8_t)(v>>24);
            cases.push_back({tag, b, fn});
        };
        const uint32_t iv[6] = {0x00000001u, 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, 0x12345678u, 0x00000000u};
        for (int k=0;k<6;k++) addImm("ADD imm", 0, &MutationEngine::mutateADD, iv[k]);
        for (int k=0;k<6;k++) addImm("SUB imm", 5, &MutationEngine::mutateSUB, iv[k]);
        for (int n=1;n<=30;n++) cases.push_back({"SHL n", {0x48,0xC1,0xE0,(uint8_t)n}, &MutationEngine::mutateSHL});
        for (int n=1;n<=31;n++) cases.push_back({"SHR n", {0x48,0xC1,0xE8,(uint8_t)n}, &MutationEngine::mutateSHR});
        const uint32_t mv[4] = {0x12345678u, 0xFFFFFFFFu, 0x00000001u, 0x80000000u};
        for (int k=0;k<4;k++){ std::vector<uint8_t> b={0xB8,0,0,0,0};
            b[1]=(uint8_t)mv[k]; b[2]=(uint8_t)(mv[k]>>8); b[3]=(uint8_t)(mv[k]>>16); b[4]=(uint8_t)(mv[k]>>24);
            cases.push_back({"MOV imm32", b, &MutationEngine::mutateMOV}); }

        MutationEngine e2(0x5CA1E5ull);
        for (auto& cs : cases) {
            NativeInsn insn; insn.bytes = cs.bytes; insn.length=(uint8_t)cs.bytes.size();
            Ctx seed = makeSeed(0x0123456789ABCDEFull, 0xFEDCBA9876543210ull,
                                0x00FF00FF00FF00FFull, 0xFF00FF00FF00FF00ull);
            auto mut = (e2.*cs.fn)(insn);
            std::vector<uint8_t> mb = cat(mut);
            compareRun(cs.tag, cs.bytes, mb, seed, false);
        }
        printf("  扫描 %zu 条指令组合完成\n", cases.size());
    }

    // ---------- PUSH / POP（配对执行，保持栈平衡）----------
    printf("-- PUSH/POP 替换 --\n");
    {
        MutationEngine eng(0xABCDEF01ull);
        const uint64_t vals[3] = { 0x1122334455667788ull, 0xFFFFFFFFFFFFFFFFull, 0x00C0FFEE00BEEF00ull };
        for (int i = 0; i < 3; ++i) {
            Ctx seed = makeSeed(0, vals[i], 0, 0);

            // PUSH rbx 变异 + 原样 POP rax
            auto pushMut = eng.mutatePUSH(I({0x53}));              // push rbx
            auto seq = cat(pushMut);
            auto tail = cat(std::vector<NativeInsn>{ I({0x58}) }); // pop rax
            Ctx c = seed;
            runBytes(cat(seq, tail), c);
            if (c.rax == vals[i]) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] PUSH rbx 变异: pop 得到 0x%llX，期望 0x%llX\n",
                    (unsigned long long)c.rax,(unsigned long long)vals[i]); g_failures += b; }

            // 原样 PUSH rbx + POP rax 变异
            auto popMut = eng.mutatePOP(I({0x58}));                // pop rax
            Ctx c2 = seed;
            auto head = cat(std::vector<NativeInsn>{ I({0x53}) }); // push rbx
            runBytes(cat(head, cat(popMut)), c2);
            if (c2.rax == vals[i]) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] POP rax 变异: 得到 0x%llX，期望 0x%llX\n",
                    (unsigned long long)c2.rax,(unsigned long long)vals[i]); g_failures += b; }
        }
        printf("  PUSH/POP 配对测试完成\n");
    }

    // ---------- JCC 消除 ----------
    printf("-- JCC 消除 --\n");
    {
        MutationEngine eng(0x5EED5EEDull);
        NativeInsn jz = I({0x74,0x08});                     // jz +8
        std::vector<NativeInsn> tb{ I({0x48,0x89,0xD8}) };  // mov rax,rbx
        std::vector<NativeInsn> fb{ I({0x48,0x89,0xC8}) };  // mov rax,rcx
        auto mut = eng.eliminateJCC(jz, tb, fb);
        std::vector<uint8_t> mb = cat(mut);

        // 前置 cmp 控制 ZF：cmp rdx,rdx => ZF=1；cmp rdx,r8 (不等) => ZF=0
        std::vector<uint8_t> cmpEq = {0x48,0x39,0xD2};
        std::vector<uint8_t> cmpNe = {0x4C,0x39,0xC2};
        for (int z = 0; z < 2; ++z) {
            Ctx seed = makeSeed(0, 0xAAAA1111BBBB2222ull, 0xCCCC3333DDDD4444ull, 0x55ull);
            seed.r8 = 0x99ull;
            Ctx c = seed;
            runBytes(cat(z == 0 ? cmpEq : cmpNe, mb), c);
            uint64_t expect = (z == 0) ? seed.rbx : seed.rcx;
            if (c.rax == expect) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] eliminateJCC ZF=%d: rax=0x%llX 期望 0x%llX\n", z,
                    (unsigned long long)c.rax,(unsigned long long)expect); g_failures += b; }
        }
        printf("  eliminateJCC 输出 %zu 字节\n", mb.size());
    }

    // ---------- 无分支 max/min ----------
    printf("-- 无分支 max/min --\n");
    {
        MutationEngine eng(0x1234ABCDull);
        auto mx = cat(eng.branchlessMax());
        auto mn = cat(eng.branchlessMin());
        const uint64_t pairs[][2] = {
            {5,9},{9,5},{0,0},{1000000000ull,999999999ull},
            {0x12345678ull,0x12345677ull},{42,42},{0,1},{1,0}
        };
        for (auto& pr : pairs) {
            Ctx c1 = makeSeed(pr[0], 0, pr[1], 0);
            runBytes(mx, c1);
            uint64_t e1 = pr[0] > pr[1] ? pr[0] : pr[1];
            if (c1.rax == e1) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] branchlessMax(%llu,%llu)=%llu 期望 %llu\n",
                    (unsigned long long)pr[0],(unsigned long long)pr[1],
                    (unsigned long long)c1.rax,(unsigned long long)e1); g_failures += b; }

            Ctx c2 = makeSeed(pr[0], 0, pr[1], 0);
            runBytes(mn, c2);
            uint64_t e2 = pr[0] < pr[1] ? pr[0] : pr[1];
            if (c2.rax == e2) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] branchlessMin(%llu,%llu)=%llu 期望 %llu\n",
                    (unsigned long long)pr[0],(unsigned long long)pr[1],
                    (unsigned long long)c2.rax,(unsigned long long)e2); g_failures += b; }
        }
    }

    // ---------- 不透明谓词 ----------
    printf("-- 不透明谓词 --\n");
    {
        MutationEngine eng(0x77777777ull);
        for (int t = 0; t < 2; ++t) {
            auto p = cat(eng.generateOpaquePredicate(t == 0));
            Ctx c; memset(&c, 0, sizeof c);
            runBytes(p, c);
            // 谓词只使用 scratch 寄存器 r10/r11，不写 rax
            uint64_t expect = (t == 0) ? 0xBBBBBBBBBBBBBBBBull : 0xAAAAAAAAAAAAAAAAull;
            if (c.r10 == expect) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] opaque(always_true=%d): r10=0x%llX 期望 0x%llX\n", t==0,
                    (unsigned long long)c.r10,(unsigned long long)expect); g_failures += b; }
        }
        // 多次随机验证谓词恒真
        int okCount = 0;
        for (int k = 0; k < 20; ++k) {
            auto p = cat(eng.generateOpaquePredicate(true));
            Ctx c; memset(&c, 0, sizeof c);
            runBytes(p, c);
            if (c.r10 == 0xBBBBBBBBBBBBBBBBull) okCount++;
        }
        if (okCount == 20) { g_pass++; }
        else { g_fail++; g_failures += "  [FAIL] opaque 20 次随机谓词未全部走 taken 分支\n"; }

        // 谓词必须只改写 scratch（r10/r11），不能触碰其它用户寄存器
        {
            auto p = cat(eng.generateOpaquePredicate(true));
            Ctx seed = makeSeed(0x1111111122222222ull, 0x3333333344444444ull,
                                0x5555555566666666ull, 0x7777777788888888ull);
            Ctx c = seed;
            runBytes(p, c);
            RegSnap a = snap(seed), b = snap(c);
            bool same = true;
            for (int i = 0; i < 12; ++i) if (a.v[i] != b.v[i]) same = false;
            if (same) g_pass++;
            else { g_fail++; g_failures += "  [FAIL] opaque 谓词改写了用户寄存器（只允许 r10/r11）\n"; }
        }
    }

    // ---------- 垃圾指令 ----------
    printf("-- 垃圾指令注入 --\n");
    {
        MutationEngine eng(0x99999999ull);
        for (int n = 1; n <= 5; ++n) {
            for (int rep = 0; rep < 10; ++rep) {
                auto g = cat(eng.generateGarbage(n));
                Ctx seed = makeSeed(0x1111111122222222ull, 0x3333333344444444ull,
                                    0x5555555566666666ull, 0x7777777788888888ull);
                Ctx c = seed;
                runBytes(g, c);
                RegSnap a = snap(seed), b = snap(c);
                bool same = true;
                for (int i = 0; i < 12; ++i) if (a.v[i] != b.v[i]) same = false;
                if (same) g_pass++;
                else {
                    g_fail++;
                    char buf[200]; snprintf(buf,sizeof buf,
                        "  [FAIL] garbage(%d) 改变了用户寄存器\n", n);
                    g_failures += buf;
                }
            }
        }
    }

    // ---------- MBA 常量装载 ----------
    printf("-- MBA 常量装载 --\n");
    {
        MutationEngine eng(0x2468ACE0ull);
        const int targets[] = { 0, 1, -1, 0x1234, -0x7FFFFFFF, 0x7FFFFFFF };
        for (int t : targets) {
            auto m = cat(eng.generateMBA(t, 0 /* rax */));
            Ctx c; memset(&c, 0, sizeof c);
            c.rax = 0xDEADBEEFDEADBEEFull;
            runBytes(m, c);
            uint64_t expect = (uint64_t)(int64_t)t;
            if (c.rax == expect) g_pass++;
            else { g_fail++; char b[200]; snprintf(b,sizeof b,
                    "  [FAIL] generateMBA(%d): rax=0x%llX 期望 0x%llX\n", t,
                    (unsigned long long)c.rax,(unsigned long long)expect); g_failures += b; }
        }
    }

    // ---------- 主入口 mutate() ----------
    printf("-- mutate() 主入口 --\n");
    {
        std::vector<NativeInsn> input{
            I({0x48,0x03,0xC3}),   // add rax,rbx
            I({0x48,0x31,0xD8}),   // xor rax,rbx
            I({0x48,0x89,0xD8}),   // mov rax,rbx
            I({0x48,0x85,0xC0}),   // test rax,rax
            I({0x53}),             // push rbx
            I({0x5B}),             // pop rbx
        };
        std::vector<uint8_t> origCode = cat(input);
        for (int s = 1; s <= 3; ++s) {
            MutationEngine eng(0x1000 + s);
            eng.setStrength((MutationStrength)s);
            auto out = eng.mutate(input);
            printf("  strength=%d: %zu -> %zu 条, mutations=%u\n",
                   s, input.size(), out.size(), eng.mutationCount());
            if (out.size() >= input.size()) g_pass++;
            else { g_fail++; g_failures += "  [FAIL] mutate() 输出条数少于输入\n"; }

            // 端到端：执行原序列与变异序列，比较用户可见寄存器
            // （strength=3 会注入 opaque 谓词与垃圾指令，只允许 r10/r11 被改写）
            std::vector<uint8_t> mutCode = cat(out);
            const uint64_t svals[6] = { 0x1122334455667788ull, 0xFFFFFFFFFFFFFFFFull,
                                        0x0DEADBEEFCAFEBABull, 0x00000000FFFFFFFFull,
                                        0x8000000000000000ull, 0xAAAAAAAA55555555ull };
            for (int k = 0; k < 6; ++k) {
                Ctx c1 = makeSeed(svals[k], svals[(k + 1) % 6], svals[(k + 2) % 6], svals[(k + 3) % 6]);
                Ctx c2 = c1;
                runBytes(origCode, c1);
                runBytes(mutCode,  c2);
                RegSnap a = snap(c1), b = snap(c2);
                bool same = true;
                for (int r = 0; r < 12; ++r) if (a.v[r] != b.v[r]) same = false;
                if (same) g_pass++;
                else {
                    g_fail++;
                    char buf[256]; snprintf(buf, sizeof buf,
                        "  [FAIL] mutate(strength=%d)[%d]: 用户寄存器不等价\n", s, k);
                    g_failures += buf;
                }
            }
        }
    }

    // ---------- 结果 ----------
    printf("\n=== 结果: PASS=%d FAIL=%d SKIP=%d ===\n", g_pass, g_fail, g_skip);
    if (g_fail) {
        printf("\n失败明细:\n%s", g_failures.c_str());
        printf("\nTESTS FAILED\n");
        return 1;
    }
    printf("TESTS PASSED (%d/%d)\n", g_pass, g_pass + g_fail);
    return 0;
}