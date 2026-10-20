/* ==========================================================================
 * NovaProtect x64 protection runtime (position independent, freestanding).
 *
 * Entered by the loader stub after the image has been restored and the import
 * table rebuilt, immediately before control transfers to the original entry
 * point.
 *
 *   rcx = image base
 *   rdx = payload header pointer
 *   r8  = NPP1 protection data blob pointer
 *   r9  = generated mutation kernel entry (may be 0)
 *
 * Returns eax = 0 when every enabled check passed, otherwise the id of the
 * check that failed. Any non-zero value is treated as fatal by the caller.
 *
 * Callee saved registers are preserved. Nothing is imported: modules and
 * exports are resolved through the PEB loader list.
 *
 * NPP1 data blob layout (little endian):
 *   +0   u32 magic 'NPP1'
 *   +4   u32 version
 *   +8   u32 flags            bit0 anti-debug, bit1 anti-vm, bit2 timing,
 *                             bit3 dr, bit4 license, bit5 vm, bit6 integrity,
 *                             bit7 mutation, bit8 activation binding
 *   +12  u32 anti_debug_level
 *   +16  u32 anti_vm_level
 *   +20  u32 reserved
 *   +24  u64 timing_threshold
 *   +32  u64 expected_mutation_hash
 *   +40  u64 expected_license_hash
 *   +48  u32 license_blob_off
 *   +52  u32 license_blob_len
 *   +56  u32 license_key
 *   +60  u32 vm_bytecode_off
 *   +64  u32 vm_bytecode_len
 *   +68  u32 vm_reverse_off
 *   +72  u32 integrity_off
 *   +76  u32 integrity_count
 *   +80  u64 machine_bind_expected
 *   +88  u64 reserved2
 *   +96  payload area (8 byte aligned)
 * ========================================================================== */

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed   int       i32;
typedef signed   long long i64;

#define NP_FNV_BASIS 0xCBF29CE484222325ULL
#define NP_FNV_PRIME 0x00000100000001B3ULL

#define NPP_MAGIC   0x3150504Eu   /* 'NPP1' */

#define NP_CHK_PEB        1
#define NP_CHK_NTGLOBAL   2
#define NP_CHK_HEAP       3
#define NP_CHK_NTQUERY    4
#define NP_CHK_DR         5
#define NP_CHK_TIMING     6
#define NP_CHK_CPUID      7
#define NP_CHK_MUTATION   8
#define NP_CHK_LICENSE    9
#define NP_CHK_INTEGRITY  10
#define NP_CHK_BADMOD    11
#define NP_CHK_ACTIVATION 12
#define NP_CHK_SANDBOX   13
#define NP_CHK_DUMP      14
#define NP_CHK_ENV       15

/* ---- PEB / loader structures (offsets only, no headers needed) ---------- */
#define PEB_BEING_DEBUGGED 0x02
#define PEB_LDR            0x18
#define PEB_PROCESS_HEAP   0x30
#define PEB_NT_GLOBAL_FLAG 0xBC

#define LDR_IN_LOAD_ORDER  0x10
#define LDR_ENTRY_DLLBASE  0x30
#define LDR_ENTRY_BASENAME 0x58
#define LDR_ENTRY_FULLNAME 0x48

#define HEAP_FLAGS         0x70
#define HEAP_FORCE_FLAGS   0x74

#define CTX_DR0 0x48
#define CTX_SIZE 0x4D0
#define CONTEXT_DEBUG_REGISTERS 0x00100000u

/* ---- strings ------------------------------------------------------------ */
static const char np_s_ntdll[]    = "ntdll.dll";
static const char np_s_kernel32[] = "kernel32.dll";
static const char np_s_qip[]      = "NtQueryInformationProcess";
static const char np_s_getctx[]   = "GetThreadContext";
static const char np_s_vprotect[] = "VirtualProtect";
static const char np_s_qsi[]      = "NtQuerySystemInformation";
static const char np_s_user32[]   = "user32.dll";
static const char np_s_gsm[]      = "GetSystemMetrics";
static const char np_s_gtt[]      = "GetTickCount64";

/* ---- NT information classes ------------------------------------------- */
#define NP_SIC_SYSTEM_BASIC_INFO     0u
#define NP_SIC_SYSTEM_PROCESSOR_INFO 8u
#define NP_SIC_SYSTEM_PROCESS_INFO   5u

/* ========================================================================
 * minimal helpers
 * ======================================================================== */

static void* np_memset(void* d, int c, u64 n) {
    u8* p = (u8*)d;
    while (n--) *p++ = (u8)c;
    return d;
}

static u64 np_fnv1a64(const u8* d, u64 n, u64 h) {
    for (u64 i = 0; i < n; i++) {
        h ^= (u64)d[i];
        h *= NP_FNV_PRIME;
    }
    return h;
}

static void np_cpuid(u32 leaf, u32 subleaf, u32 out[4]) {
    u32 a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(subleaf));
    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
}

static void* np_module_by_name(const char* name);
static void* np_export_by_name(void* mod, const char* name);

static u64 np_volume_serial(void) {
    // Resolve GetVolumeInformationW and GetSystemDirectoryW through kernel32.
    // The volume serial is a per-machine, per-installation identifier, so it
    // separates machines that share the same CPU model.
    void* k32 = np_module_by_name(np_s_kernel32);
    if (!k32) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_gsd_fn)(void*, u32);
    np_gsd_fn gsd = (np_gsd_fn)np_export_by_name(k32, "GetSystemDirectoryW");
    if (!gsd) return 0;
    u16 dir[260];
    u32 n = gsd(dir, 260);
    if (!n || n >= 260) return 0;
    u16 root[4];
    root[0] = dir[0]; root[1] = (u16)L':'; root[2] = (u16)L'\\'; root[3] = 0;
    typedef u32 (__attribute__((ms_abi)) *np_gvi_fn)(const u16*, void*, u32, u32*, void*, void*, void*, u32);
    np_gvi_fn gvi = (np_gvi_fn)np_export_by_name(k32, "GetVolumeInformationW");
    if (!gvi) return 0;
    u32 serial = 0;
    if (!gvi(root, 0, 0, &serial, 0, 0, 0, 0)) return 0;
    return (u64)serial;
}

static u64 np_machine_guid_hash(void) {
    // Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid through advapi32.
    // It is derived from the machine's hardware identity and survives OS
    // reinstalls / disk swaps on the same motherboard, making it the primary
    // stability anchor for one-machine-one-license.
    void* adv = np_module_by_name("advapi32.dll");
    if (!adv) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_rok_fn)(void*, const u16*, u32, u32, void**);
    np_rok_fn rok = (np_rok_fn)np_export_by_name(adv, "RegOpenKeyExW");
    if (!rok) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_rqv_fn)(void*, const u16*, void*, u32*, u8*, u32*);
    np_rqv_fn rqv = (np_rqv_fn)np_export_by_name(adv, "RegQueryValueExW");
    if (!rqv) return 0;
    typedef u32 (__attribute__((ms_abi)) *np_rck_fn)(void*);
    np_rck_fn rck = (np_rck_fn)np_export_by_name(adv, "RegCloseKey");
    static const u16 keyPath[] = { 'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\','C','r','y','p','t','o','g','r','a','p','h','y',0 };
    static const u16 valName[] = { 'M','a','c','h','i','n','e','G','u','i','d',0 };
    void* key = 0;
    if (rok((void*)0x80000002u, keyPath, 0, 0x20019u, &key) != 0 || !key) return 0;
    u16 guid[64];
    u32 size = (u32)sizeof(guid);
    u32 type = 0;
    u32 rc = rqv(key, valName, 0, &type, (u8*)guid, &size);
    if (rck) rck(key);
    if (rc != 0 || type != 1u) return 0;
    u64 h = NP_FNV_BASIS;
    for (u32 i = 0; i < size / 2 && guid[i]; i++) {
        u8 lo = (u8)(guid[i] & 0xFF);
        u8 hi = (u8)((guid[i] >> 8) & 0xFF);
        h = np_fnv1a64(&lo, 1, h);
        h = np_fnv1a64(&hi, 1, h);
    }
    return h;
}
static u64 np_machine_id(void) {
    u32 r[4];
    np_cpuid(0, 0, r);
    u32 max_leaf = r[0];
    u64 h = NP_FNV_BASIS;
    h = np_fnv1a64((const u8*)&r[1], 4, h);
    h = np_fnv1a64((const u8*)&r[3], 4, h);
    h = np_fnv1a64((const u8*)&r[2], 4, h);
    if (max_leaf >= 1) {
        np_cpuid(1, 0, r);
        h = np_fnv1a64((const u8*)&r[0], 4, h);
        h = np_fnv1a64((const u8*)&r[2], 4, h);
        h = np_fnv1a64((const u8*)&r[3], 4, h);
    }
    if (max_leaf >= 7) {
        np_cpuid(7, 0, r);
        h = np_fnv1a64((const u8*)&r[1], 4, h);
        h = np_fnv1a64((const u8*)&r[2], 4, h);
        h = np_fnv1a64((const u8*)&r[3], 4, h);
    }
    u64 vs = np_volume_serial();
    u64 mg = np_machine_guid_hash();
    h = np_fnv1a64((const u8*)&vs, sizeof(vs), h);
    h = np_fnv1a64((const u8*)&mg, sizeof(mg), h);
    return h;
}

static u32 np_rd32(const void* p) { return *(const volatile u32*)p; }
static u64 np_rd64(const void* p) { return *(const volatile u64*)p; }

static u64 np_rdtscp(void) {
    u32 lo, hi, aux;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    (void)aux;
    return ((u64)hi << 32) | lo;
}

static void np_cpuid_leaf(u32 leaf, u32 subleaf, u32 out[4]) {
    __asm__ volatile("cpuid" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "a"(leaf), "c"(subleaf));
}

static u64 np_cpu_core_mask(void) {
    u32 r[4];
    np_cpuid_leaf(0x1, 0, r);
    return ((u64)r[3] << 32) | (u64)r[1];   /* EDX:EBX APIC id, logical cores */
}

static u8* np_peb(void) {
    u8* peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/* ========================================================================
 * module / export resolution through the PEB loader list
 * ======================================================================== */

static void* np_module_by_name(const char* name) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;

    while (cur != head) {
        u16 len = *(u16*)(cur + LDR_ENTRY_BASENAME);
        u16* nm = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
        u8*  base = *(u8**)(cur + LDR_ENTRY_DLLBASE);
        len >>= 1;
        if (nm && base && len) {
            u32 i = 0;
            for (;; i++) {
                if (i >= len) { if (name[i] == 0) return base; break; }
                u16 a = nm[i];
                u8  b = (u8)name[i];
                if (b == 0) break;
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) break;
            }
        }
        cur = *(u8**)cur;
    }
    return 0;
}

static void* np_export_by_name(void* mod, const char* name) {
    if (!mod) return 0;
    u8* base = (u8*)mod;
    i32 lfanew = *(i32*)(base + 0x3C);
    if (lfanew <= 0) return 0;
    u8* nth = base + lfanew + 24;
    u32 exp_rva = np_rd32(nth + 0x70);
    if (!exp_rva) return 0;
    u8* exp = base + exp_rva;
    u32 nnames = np_rd32(exp + 0x18);
    if (!nnames) return 0;
    u32* names    = (u32*)(base + np_rd32(exp + 0x20));
    u16* ordinals = (u16*)(base + np_rd32(exp + 0x24));
    u32* funcs    = (u32*)(base + np_rd32(exp + 0x1C));

    for (u32 i = 0; i < nnames; i++) {
        const char* p = (const char*)(base + np_rd32(names + i));
        u32 k = 0;
        for (;;) {
            if (p[k] != name[k]) break;
            if (p[k] == 0) {
                u32 rva = np_rd32(funcs + ordinals[i]);
                if (!rva) return 0;
                return base + rva;
            }
            k++;
        }
    }
    return 0;
}

/* ========================================================================
 * individual checks - every one returns 0 on pass, non zero on detection
 * ======================================================================== */

static u32 np_chk_peb(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    if (peb[PEB_BEING_DEBUGGED]) return 1;
    return 0;
}

static u32 np_chk_ntglobal(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u32 f = np_rd32(peb + PEB_NT_GLOBAL_FLAG);
    if ((f & 0x70u) == 0x70u) return 1;
    return 0;
}

static u32 np_chk_heap(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* heap = *(u8**)(peb + PEB_PROCESS_HEAP);
    if (!heap) return 0;
    /* ForceFlags is 0 for a normally created heap and non-zero as soon as the
     * process runs under a debugger (or with page heap enabled). Flags always
     * carries HEAP_GROWABLE (0x2); a cleared bit means a debug heap. */
    if (np_rd32(heap + HEAP_FORCE_FLAGS) != 0) return 1;
    if ((np_rd32(heap + HEAP_FLAGS) & 0x2u) == 0) return 1;
    return 0;
}

typedef i32 (__attribute__((ms_abi)) *np_ntqip_fn)(void* h, u32 cls, void* buf, u32 len, u32* ret);
typedef i32 (__attribute__((ms_abi)) *np_getctx_fn)(void* h, void* ctx);

static u32 np_chk_ntquery(void* ntqip) {
    if (!ntqip) return 0;
    np_ntqip_fn fn = (np_ntqip_fn)ntqip;
    u64 buf = 0;
    u32 ret = 0;

    buf = 0;
    fn((void*)-1, 7u, &buf, 8u, &ret);          /* ProcessDebugPort */
    if (buf) return 1;

    buf = 1;
    fn((void*)-1, 0x1Fu, &buf, 4u, &ret);       /* ProcessDebugFlags: 0 == debugged */
    if ((u32)buf == 0) return 1;

    buf = 0;
    fn((void*)-1, 0x1Eu, &buf, 8u, &ret);       /* ProcessDebugObjectHandle */
    if (buf) return 1;

    return 0;
}

static u32 np_chk_dr(void* getctx) {
    if (!getctx) return 0;
    np_getctx_fn fn = (np_getctx_fn)getctx;
    u8 ctx[CTX_SIZE];
    np_memset(ctx, 0, CTX_SIZE);
    *(u32*)(ctx + 0x30) = CONTEXT_DEBUG_REGISTERS;

    if (!fn((void*)-2, ctx)) return 0;          /* GetCurrentThread() pseudo handle */
    u64 dr = np_rd64(ctx + CTX_DR0)
           | np_rd64(ctx + CTX_DR0 + 8)
           | np_rd64(ctx + CTX_DR0 + 16)
           | np_rd64(ctx + CTX_DR0 + 24);
    if (dr) return 1;
    return 0;
}

static u64 np_rdtsc(void) {
    u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

/* Single step detection: an external debugger that traps every instruction
 * makes the measured delta explode. The threshold is calibrated at pack time
 * so genuine CPUs and clock-speed variation never trip it. */
static u32 np_chk_timing(u64 threshold) {
    if (!threshold) return 0;
    u64 best = ~0ULL;
    for (u32 i = 0; i < 8; i++) {
        u64 a = np_rdtsc();
        u64 b = np_rdtsc();
        u64 d = b - a;
        if (d < best) best = d;
    }
    if (best > threshold) return 1;
    return 0;
}

/* CPUID hypervisor vendor check. Microsoft Hyper-V is deliberately allowed
 * because VBS / Memory Integrity on physical Windows hosts reports it. */
static u32 np_chk_cpuid(void) {
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                             : "a"(0x40000000u), "c"(0));
    if (!eax) return 0;

    /* "VMwareVMware" */
    if (ebx == 0x61774D56u && ecx == 0x4D567265u && edx == 0x65726177u) return 1;
    /* "KVMKVMKVM\0\0\0" */
    if (ebx == 0x4B4D564Bu && ecx == 0x564B4D56u && edx == 0x0000004Du) return 1;
    /* "XenVMMXenVMM" */
    if (ebx == 0x566E6558u && ecx == 0x65584D4Du && edx == 0x4D4D566Eu) return 1;
    /* "VBoxVBoxVBox" */
    if (ebx == 0x786F4256u && ecx == 0x786F4256u && edx == 0x786F4256u) return 1;
    /* "prl hyperv  " */
    if (ebx == 0x206C7270u && ecx == 0x65707968u && edx == 0x20207672u) return 1;
    /* "bhyve bhyve " */
    if (ebx == 0x76796862u && ecx == 0x68622065u && edx == 0x20657679u) return 1;
    return 0;
}
/* ========================================================================
 * mutation kernel verification
 *
 * The packer emits a self contained kernel into the protection section and
 * publishes the value it produces for a fixed test vector. Anybody who
 * patches or removes the kernel changes the result and trips the check.
 * ======================================================================== */

typedef u64 (__attribute__((ms_abi)) *np_kernel_fn)(const u8* buf, u64 len);

static u32 np_chk_mutation(const u8* b, void* kern) {
    u64 expected = np_rd64(b + 32);
    if (!expected) return 0;
    if (!kern) return 1;

    u8 probe[32];
    for (u32 i = 0; i < 32; i++) probe[i] = (u8)(0xA5u ^ (i * 0x3Du) ^ (u8)(i << 3));

    np_kernel_fn fn = (np_kernel_fn)kern;
    u64 got = fn(probe, 32);
    if (got != expected) return 1;
    return 0;
}

/* ========================================================================
 * licence / virtual machine interpreter
 *
 * The packer compiles a small bytecode program that walks the encrypted
 * licence blob, decrypts it with a rolling key and folds every byte into an
 * FNV-1a accumulator. Physical opcodes are remapped through a per-build
 * 256 byte translation table so the bytecode stream itself never matches a
 * signature.
 *
 *   bytecode: [phys_op][operands...]
 *   reverse : 256 bytes, reverse[phys_op] = logical op
 * ======================================================================== */

enum {
    VMO_LOADIMM = 0x01,   /* reg u8, imm u64            */
    VMO_LOADB   = 0x02,   /* reg u8, base u8, disp u32  */
    VMO_XOREQ   = 0x03,   /* dst u8, src u8             */
    VMO_MULI    = 0x04,   /* reg u8, imm u64            */
    VMO_ADDI    = 0x05,   /* reg u8, imm u64            */
    VMO_SUBI    = 0x06,   /* reg u8, imm u64            */
    VMO_ANDI    = 0x07,   /* reg u8, imm u64            */
    VMO_RORI    = 0x08,   /* reg u8, imm u64            */
    VMO_CMPI    = 0x09,   /* reg u8, imm u64            */
    VMO_JE      = 0x0A,   /* target u32                 */
    VMO_JNE     = 0x0B,   /* target u32                 */
    VMO_JMP     = 0x0C,   /* target u32                 */
    VMO_MOVE    = 0x0D,   /* dst u8, src u8             */
    VMO_XORI    = 0x0E,   /* reg u8, imm u64            */
    VMO_HALT    = 0x0F,
    VMO_LOADQ   = 0x10,   /* reg u8, base u8, disp u32  */
    VMO_STOREB  = 0x11,   /* base u8, disp u32, src u8  */
    VMO_STOREQ  = 0x12,   /* base u8, disp u32, src u8  */
    VMO_ADD     = 0x13,   /* dst u8, src u8             */
    VMO_SUB     = 0x14,   /* dst u8, src u8             */
    VMO_MUL     = 0x15,   /* dst u8, src u8             */
    VMO_AND     = 0x16,   /* dst u8, src u8             */
    VMO_OR      = 0x17,   /* dst u8, src u8             */
    VMO_XOR     = 0x18,   /* dst u8, src u8             */
    VMO_SHL     = 0x19,   /* dst u8, src u8             */
    VMO_SHR     = 0x1A,   /* dst u8, src u8 (logical)   */
    VMO_SAR     = 0x1B,   /* dst u8, src u8 (arith)     */
    VMO_SHRI    = 0x1C,   /* reg u8, imm u64            */
    VMO_ORI     = 0x1D,   /* reg u8, imm u64            */
    VMO_NOT     = 0x1E,   /* reg u8                     */
    VMO_NEG     = 0x1F,   /* reg u8                     */
    VMO_CMP     = 0x20,   /* a u8, b u8  -> zf/sf/cf     */
    VMO_TEST    = 0x21,   /* a u8, b u8  -> zf/sf        */
    VMO_JNZ     = 0x22,   /* target u32 (jump if !zf)   */
    VMO_JZ      = 0x23,   /* target u32 (jump if zf)    */
    VMO_JAE     = 0x24,   /* target u32 (jump if !cf)   */
    VMO_JB      = 0x25,   /* target u32 (jump if cf)    */
    VMO_JGE     = 0x26,   /* target u32 (jump if sf==of) */
    VMO_JL      = 0x27,   /* target u32 (jump if sf!=of) */
    VMO_JG      = 0x28,   /* target u32 (jump if !zf && sf==of) */
    VMO_JLE     = 0x29,   /* target u32 (jump if zf || sf!=of)  */
    VMO_ENDBR   = 0x2A,   /* no-op: region boundary marker       */
    VMO_SHLI    = 0x2B,   /* reg u8, imm u64 (shift left)        */
    VMO_SARI    = 0x2C,   /* reg u8, imm u64 (shift right arith) */
};

#define NP_VM_REGS 16

static u64 np_vm_run(const u8* code, u64 code_len, const u8* reverse,
                     u64* inout_regs) {
    u64 r[NP_VM_REGS];
    for (u32 i = 0; i < NP_VM_REGS; i++) r[i] = inout_regs[i];

    u64 ip = 0;
    u32 guard = 0;
    int zf = 0, cf = 0, sf = 0, of = 0;

    while (ip < code_len) {
        if (++guard > 4000000u) break;      /* runaway guard */
        u8 phys = code[ip++];
        u8 op = reverse[phys];
        u32 reg, dst, src, base;
        u64 imm;

        switch (op) {
        case VMO_LOADIMM:
            reg = code[ip++];
            imm = 0; for (u32 k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < NP_VM_REGS) r[reg] = imm;
            break;
        case VMO_LOADB:
            reg  = code[ip++];
            base = code[ip++];
            imm  = 0; for (u32 k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < NP_VM_REGS && base < NP_VM_REGS) {
                const u8* p = (const u8*)(r[base] + imm);
                r[reg] = (u64)(*p);
            }
            break;
        case VMO_LOADQ:
            reg  = code[ip++];
            base = code[ip++];
            imm  = 0; for (u32 k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < NP_VM_REGS && base < NP_VM_REGS) {
                const u8* p = (const u8*)(r[base] + imm);
                r[reg] = 0;
                for (u32 k = 0; k < 8; k++) r[reg] |= (u64)p[k] << (k * 8);
            }
            break;
        case VMO_STOREB:
            base = code[ip++];
            imm  = 0; for (u32 k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            src  = code[ip++];
            if (base < NP_VM_REGS && src < NP_VM_REGS) {
                u8* p = (u8*)(r[base] + imm);
                *p = (u8)r[src];
            }
            break;
        case VMO_STOREQ:
            base = code[ip++];
            imm  = 0; for (u32 k = 0; k < 4; k++) imm |= (u64)code[ip++] << (k * 8);
            src  = code[ip++];
            if (base < NP_VM_REGS && src < NP_VM_REGS) {
                u8* p = (u8*)(r[base] + imm);
                for (u32 k = 0; k < 8; k++) p[k] = (u8)(r[src] >> (k * 8));
            }
            break;
        case VMO_XOREQ:
            dst = code[ip++];
            src = code[ip++];
            if (dst < NP_VM_REGS && src < NP_VM_REGS) r[dst] ^= r[src];
            break;
        case VMO_MOVE:
            dst = code[ip++];
            src = code[ip++];
            if (dst < NP_VM_REGS && src < NP_VM_REGS) r[dst] = r[src];
            break;
        case VMO_ADD: case VMO_SUB: case VMO_MUL:
        case VMO_AND: case VMO_OR: case VMO_XOR:
        case VMO_SHL: case VMO_SHR: case VMO_SAR: {
            dst = code[ip++];
            src = code[ip++];
            if (dst < NP_VM_REGS && src < NP_VM_REGS) {
                u64 a = r[dst], b = r[src];
                switch (op) {
                case VMO_ADD: { u64 res = a + b; cf = (res < a); of = (((a ^ res) & (b ^ res)) >> 63) & 1; r[dst] = res; }
                    break;
                case VMO_SUB: { u64 res = a - b; cf = (a < b); of = (((a ^ b) & (a ^ res)) >> 63) & 1; r[dst] = res; }
                    break;
                case VMO_MUL: r[dst] = a * b; break;
                case VMO_AND: r[dst] = a & b; break;
                case VMO_OR:  r[dst] = a | b; break;
                case VMO_XOR: r[dst] = a ^ b; break;
                case VMO_SHL: r[dst] = a << (b & 63u); break;
                case VMO_SHR: r[dst] = a >> (b & 63u); break;
                case VMO_SAR: r[dst] = (u64)(((i64)a) >> (b & 63u)); break;
                default: break;
                }
                if (op != VMO_MUL) { zf = (r[dst] == 0); sf = (int)((r[dst] >> 63) & 1); }
            }
            break;
        }
        case VMO_NOT:
            reg = code[ip++];
            if (reg < NP_VM_REGS) r[reg] = ~r[reg];
            break;
        case VMO_NEG: {
            reg = code[ip++];
            if (reg < NP_VM_REGS) { u64 a = r[reg]; r[reg] = (u64)(-(i64)a); cf = (a != 0); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); }
            break;
        }
        case VMO_CMP: {
            u32 a_reg = code[ip++];
            u32 b_reg = code[ip++];
            if (a_reg < NP_VM_REGS && b_reg < NP_VM_REGS) {
                u64 a = r[a_reg], b = r[b_reg], res = a - b;
                zf = (res == 0); cf = (a < b);
                sf = (int)((res >> 63) & 1);
                of = (int)(((((a ^ b) & (a ^ res)) >> 63)) & 1);
            }
            break;
        }
        case VMO_TEST: {
            u32 a_reg = code[ip++];
            u32 b_reg = code[ip++];
            if (a_reg < NP_VM_REGS && b_reg < NP_VM_REGS) {
                u64 res = r[a_reg] & r[b_reg];
                zf = (res == 0); cf = 0; of = 0;
                sf = (int)((res >> 63) & 1);
            }
            break;
        }
        case VMO_MULI:
        case VMO_ADDI:
        case VMO_SUBI:
        case VMO_ANDI:
        case VMO_RORI:
        case VMO_XORI:
        case VMO_ORI:
        case VMO_SHRI:
        case VMO_SHLI:
        case VMO_SARI:
        case VMO_CMPI:
            reg = code[ip++];
            imm = 0; for (u32 k = 0; k < 8; k++) imm |= (u64)code[ip++] << (k * 8);
            if (reg < NP_VM_REGS) {
                u64 a = r[reg], res = 0;
                switch (op) {
                case VMO_MULI: r[reg] *= imm; break;
                case VMO_ADDI: res = a + imm; cf = (res < a); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); break;
                case VMO_SUBI: res = a - imm; cf = (a < imm); r[reg] = res; zf = (res == 0); sf = (int)((res >> 63) & 1); break;
                case VMO_ANDI: r[reg] &= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; break;
                case VMO_ORI:  r[reg] |= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; break;
                case VMO_XORI: r[reg] ^= imm; zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); cf = 0; break;
                case VMO_SHRI: r[reg] = a >> (imm & 63u); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); break;
                case VMO_SHLI: r[reg] = a << (imm & 63u); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); break;
                case VMO_SARI: r[reg] = (u64)(((i64)a) >> (imm & 63u)); zf = (r[reg] == 0); sf = (int)((r[reg] >> 63) & 1); break;
                case VMO_RORI: {
                    u32 s = (u32)(imm & 63u);
                    r[reg] = (r[reg] >> s) | (r[reg] << ((64u - s) & 63u));
                    break;
                }
                case VMO_CMPI: res = a - imm; zf = (res == 0); cf = (a < imm); sf = (int)((res >> 63) & 1);
                    of = (int)(((((a ^ imm) & (a ^ res)) >> 63)) & 1); break;
                default: break;
                }
            }
            break;
        case VMO_JMP:
        case VMO_JE: case VMO_JNE: case VMO_JZ: case VMO_JNZ:
        case VMO_JAE: case VMO_JB: case VMO_JGE: case VMO_JL:
        case VMO_JG: case VMO_JLE: {
            u32 t = 0; for (u32 k = 0; k < 4; k++) t |= (u32)code[ip++] << (k * 8);
            int take;
            switch (op) {
            case VMO_JMP: take = 1; break;
            case VMO_JE: case VMO_JZ:  take = zf; break;
            case VMO_JNE: case VMO_JNZ: take = !zf; break;
            case VMO_JAE: take = !cf; break;
            case VMO_JB:  take = cf; break;
            case VMO_JGE: take = (sf == of); break;
            case VMO_JL:  take = (sf != of); break;
            case VMO_JG:  take = (!zf && (sf == of)); break;
            default:      take = (zf || (sf != of)); break; /* JLE */
            }
            if (take) ip = t;
            break;
        }
        case VMO_ENDBR:
            break;        case VMO_HALT:
            ip = code_len;
            break;
        default:
            /* unknown opcode - stop rather than run off the buffer */
            ip = code_len;
            break;
        }
    }

    for (u32 i = 0; i < NP_VM_REGS; i++) inout_regs[i] = r[i];
    return r[0];
}

static u32 np_chk_license(const u8* b) {
    u64 expected = np_rd64(b + 40);
    u32 blob_off = np_rd32(b + 48);
    u32 blob_len = np_rd32(b + 52);
    u32 bc_off   = np_rd32(b + 60);
    u32 bc_len   = np_rd32(b + 64);
    u32 rev_off  = np_rd32(b + 68);
    if (!expected) return 0;
    if (!bc_len || !blob_len) return 1;
    if (bc_off + bc_len > 0x7FFFFFFFu) return 1;

    const u8* bytecode = b + bc_off;
    const u8* reverse  = b + rev_off;
    u8* license = (u8*)(b + blob_off);

    /* decrypt the licence blob with the rolling key compiled into the
     * bytecode; the interpreter performs the rolling itself so the key never
     * appears as a contiguous literal. */
    u64 regs[NP_VM_REGS];
    np_memset(regs, 0, sizeof(regs));
    regs[1] = (u64)license;
    regs[2] = (u64)blob_len;

    u64 got = np_vm_run(bytecode, bc_len, reverse, regs);
    if (got != expected) return 1;
    return 0;
}

/* ========================================================================
 * image integrity
 *
 * The packer records (rva, size, fnv1a64) tuples for regions that must not
 * change between builds - typically the SDK marker areas.
 * ======================================================================== */

static u32 np_chk_integrity(void* base, const u8* b) {
    u32 off   = np_rd32(b + 72);
    u32 count = np_rd32(b + 76);
    if (!off || !count) return 0;
    if (count > 4096u) return 1;

    const u8* rec = b + off;
    u8* img = (u8*)base;
    for (u32 i = 0; i < count; i++) {
        u32 rva  = np_rd32(rec + i * 16);
        u32 size = np_rd32(rec + i * 16 + 4);
        u64 want = np_rd64(rec + i * 16 + 8);
        if (!size) continue;
        u64 got = np_fnv1a64(img + rva, size, NP_FNV_BASIS);
        if (got != want) return 1;
    }
    return 0;
}

/* ========================================================================
 * sandbox / analysis-tool detection
 *
 * Themida's strongest mode walks the PEB loader list looking for known
 * sandbox DLLs. This is cheap (no API calls), reliable, and avoids the
 * false-positive risk of registry or file probes.
 * ======================================================================== */

static const char np_s_badmods[] =
    "SandboxieDll\0" "SBIEDLL\0" "api_log\0"
    "vmcheck\0" "wpesype\0" "dirwatch\0"
    "dbghelp\0" "dbgcore\0" "dbgeng\0" "dbgmodel\0"
    "procmon\0" "processhacker\0" "frida\0"
    "wxwork\0" "wpscloudsvr\0" "salamand\0"
    "lilith\0" "sandbox\0" "xworm\0" "antivm\0";

static u32 np_chk_bad_modules(void) {
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* ldr = *(u8**)(peb + PEB_LDR);
    if (!ldr) return 0;
    u8* head = ldr + LDR_IN_LOAD_ORDER;
    u8* cur  = *(u8**)head;
    while (cur != head) {
        u16 len = *(u16*)(cur + LDR_ENTRY_BASENAME);
        u16* nm = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
        if (nm && len) {
            len >>= 1;
            for (const char* bl = np_s_badmods; *bl; ) {
                u32 blen = 0;
                while (bl[blen]) blen++;
                if ((u32)blen <= (u32)len) {
                    u32 match = 1;
                    for (u32 j = 0; j < blen; j++) {
                        u16 a = nm[j];
                        u8  b = (u8)bl[j];
                        if (a >= 'A' && a <= 'Z') a += 32;
                        if (b >= 'A' && b <= 'Z') b += 32;
                        if (a != b) { match = 0; break; }
                    }
                    if (match) return 1;
                }
                bl += blen + 1;
            }
        }
        cur = *(u8**)cur;
    }
    return 0;
}

/* ========================================================================
 * sandbox / analysis-tool scoring (v2 flag bit 9)
 *
 * Each cheap observable contributes a weighted bit. A cumulative score at or
 * above the pack-time threshold trips NP_CHK_SANDBOX. The weights are tuned
 * so a physical desktop stays far below the default threshold while微步 and
 * other online-analysis VMs / instrumented hosts cross it.
 * ======================================================================== */

static u32 np_sandbox_score(void) {
    u32 score = 0;

    /* 1. hypervisor vendor bits via CPUID 0x40000000 (Hyper-V exempt) */
    u32 c[4] = {0};
    np_cpuid_leaf(0x40000000u, 0, c);
    if (c[0]) {
        if (c[1] == 0x61774D56u && c[2] == 0x4D567265u && c[3] == 0x65726177u) score += 8;   /* VMware */
        else if (c[1] == 0x4B4D564Bu && c[2] == 0x564B4D56u && c[3] == 0x0000004Du) score += 8; /* KVM */
        else if (c[1] == 0x566E6558u && c[2] == 0x65584D4Du && c[3] == 0x4D4D566Eu) score += 8; /* Xen */
        else if (c[1] == 0x786F4256u) score += 8;   /* VirtualBox */
        else if (c[1] == 0x206C7270u) score += 8;   /* Parallels */
    }

    /* 2. physical CPU count through NtQuerySystemInformation */
    void* ntdll = np_module_by_name(np_s_ntdll);
    if (ntdll) {
        typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32 cls, void* buf, u32 len, u32* ret);
        np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
        if (qsi) {
            u8 basic[64]; np_memset(basic, 0, sizeof(basic));
            u32 ret = 0;
            if (qsi(NP_SIC_SYSTEM_BASIC_INFO, basic, sizeof(basic), &ret) >= 0) {
                u8 count = basic[0];
                if (count < 2) score += 14;
                else if (count < 4) score += 4;
            }
        }
    }

    /* 3. extremely small RAM is characteristic of online-analysis sandboxes */
    if (ntdll) {
        typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32 cls, void* buf, u32 len, u32* ret);
        np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
        if (qsi) {
            u8 basic[64]; np_memset(basic, 0, sizeof(basic));
            u32 ret = 0;
            if (qsi(NP_SIC_SYSTEM_BASIC_INFO, basic, sizeof(basic), &ret) >= 0) {
                u64 pages = *(u64*)(basic + 24);   /* NumberOfPhysicalPages */
                u64 pageSize = *(u32*)(basic + 32);
                if (pages && pageSize && pages * pageSize < (4ull << 30)) score += 10;
            }
        }
    }

    /* 4. known sandbox / monitoring modules already hard-fail in
     * np_chk_bad_modules; here score the softer instrumented-host markers. */
    u8* peb = np_peb();
    if (peb) {
        u8* ldr = *(u8**)(peb + PEB_LDR);
        if (ldr) {
            u8* head = ldr + LDR_IN_LOAD_ORDER;
            u8* cur  = *(u8**)head;
            while (cur != head) {
                u16 len = *(u16*)(cur + LDR_ENTRY_BASENAME);
                u16* nm = *(u16**)(cur + LDR_ENTRY_BASENAME + 8);
                if (nm && len) {
                    len >>= 1;
                    if (len == 12 && (nm[0]=='d'||nm[0]=='D') && (nm[1]=='b'||nm[1]=='B') &&
                        (nm[2]=='g'||nm[2]=='G') && (nm[3]=='h'||nm[3]=='H')) score += 6;   /* dbghelp/dbgcore */
                    if (len >= 7 && (nm[0]=='s'||nm[0]=='S') && (nm[1]=='b'||nm[1]=='B') &&
                        (nm[2]=='i'||nm[2]=='I') && (nm[3]=='e'||nm[3]=='E')) score += 6;  /* sbie* */
                }
                cur = *(u8**)cur;
            }
        }
    }

    /* 5. RDTSCP + RDTSC timing spread across core migration */
    u64 t1 = np_rdtscp();
    u64 t2 = np_rdtsc();
    u64 spread = t2 > t1 ? t2 - t1 : t1 - t2;
    if (spread > 0x40000000ull) score += 6;

    /* 6. per-CPU core mask consistency: online sandboxes often report a
     * synthetic 1-vCPU topology with an implausible APIC core mask. */
    u64 mask = np_cpu_core_mask();
    if ((mask & 0xFFFF) == 0 || ((mask >> 16) & 0xFF) == 0) score += 3;

    /* 7. known online-analysis sandbox DLLs (微步 and peers) walk the loader
     * list. These hard-fail in np_chk_bad_modules only at the highest level;
     * here they add weight to the cumulative score. */
    if (np_chk_bad_modules()) score += 20;

    /* 8. sleep compression: sandboxes accelerate Sleep/SleepEx and wall-clock
     * time. Measure GetTickCount64 across a short busy-wait; a compressed
     * wall clock (delta far below real elapsed cycles) is a strong VM signal. */
    {
        void* k32 = np_module_by_name(np_s_kernel32);
        if (k32) {
            typedef u64 (__attribute__((ms_abi)) *np_gtt_fn)(void);
            np_gtt_fn gtt = (np_gtt_fn)np_export_by_name(k32, np_s_gtt);
            if (gtt) {
                u64 wall0 = gtt();
                u64 cyc0 = np_rdtsc();
                for (u32 i = 0; i < 64; i++) np_rdtscp();
                u64 cyc1 = np_rdtsc();
                u64 wall1 = gtt();
                u64 cycles = cyc1 > cyc0 ? cyc1 - cyc0 : cyc0 - cyc1;
                u64 wallms = wall1 >= wall0 ? wall1 - wall0 : wall0 - wall1;
                // A real 2+ GHz core advances ~300k cycles per 1 ms of wall
                // time. Sandboxes that virtualize RDTSC but run wall time fast
                // produce an implausible ratio.
                if (wallms == 0 || cycles / (wallms + 1) > 5000000ull) score += 8;
            }
        }
    }

    /* 9. interactive desktop / user environment heuristics for 微步. */
    {
        void* u32mod = np_module_by_name(np_s_user32);
        if (u32mod) {
            typedef int (__attribute__((ms_abi)) *np_gsm_fn)(int);
            np_gsm_fn gsm = (np_gsm_fn)np_export_by_name(u32mod, np_s_gsm);
            if (gsm) {
                if (gsm(0) < 800 || gsm(1) < 600) score += 8;   /* SM_CXSCREEN/SM_CYSCREEN */
            }
        }
        // Environment template names common in ephemeral analysis VMs.
        void* k32 = np_module_by_name(np_s_kernel32);
        if (k32) {
            typedef u32 (__attribute__((ms_abi)) *np_gevw_fn)(const char*, char*, u32);
            np_gevw_fn ge = (np_gevw_fn)np_export_by_name(k32, "GetEnvironmentVariableA");
            if (ge) {
                char name[64]; np_memset(name, 0, sizeof(name));
                char host[64]; np_memset(host, 0, sizeof(host));
                ge("COMPUTERNAME", host, sizeof(host));
                ge("USERNAME", name, sizeof(name));
                const char* tmpl = host[0] ? host : name;
                if ((tmpl[0] == 'W' && tmpl[1] == 'i' && tmpl[2] == 'n') ||
                    (tmpl[0] == 'A' && tmpl[1] == 'd' && tmpl[2] == 'm' && tmpl[3] == 'i' && tmpl[4] == 'n') ||
                    (tmpl[0] == 'U' && tmpl[1] == 's' && tmpl[2] == 'e' && tmpl[3] == 'r')) score += 10;
            }
        }
    }

    return score;
}

/* ========================================================================
 * anti memory-dump (v2 flag bit 10)
 *
 * A live dump is only useful while the image is fully restored. We verify that
 * the image header still has its original loader-consumed DOS/NT signature and
 * that the section table has not been flattened to zero (common Minidump /
 * Procdump post-processing). The strongest signal is the PEB image base still
 * matching the expected base.
 * ======================================================================== */

static u32 np_chk_dump(void* base) {
    u8* img = (u8*)base;
    if (!img) return 0;
    if (img[0] != 'M' || img[1] != 'Z') return 1;
    i32 lfanew = *(i32*)(img + 0x3C);
    if (lfanew <= 0) return 1;
    u8* nth = img + lfanew;
    if (nth[0] != 'P' || nth[1] != 'E' || nth[2] != 0 || nth[3] != 0) return 1;
    u16 nsec = *(u16*)(nth + 6);
    if (nsec < 1 || nsec > 96) return 1;
    u8* peb = np_peb();
    if (!peb) return 0;
    u8* loaded = *(u8**)(peb + 0x10);
    if (loaded && loaded != img) return 1;
    return 0;
}

/* ========================================================================
 * environment self-check (v2 flag bit 11)
 *
 * Validates a real interactive desktop against pack-time thresholds. The
 * fields are absolute minimums so commodity hardware always passes, while
 * headless在线分析沙箱 workers fail. Every probe degrades to "pass" when the
 * backing API is unavailable.
 * ======================================================================== */

static u32 np_chk_env(const u8* b) {
    u32 min_cpu    = np_rd32(b + 100);
    u32 min_ram_mb = np_rd32(b + 104);
    u32 min_uptime = np_rd32(b + 108);
    u32 min_w      = np_rd32(b + 112);
    u32 min_h      = np_rd32(b + 116);
    u32 min_mon    = np_rd32(b + 120);

    /* CPU count from the same NT basic-info block */
    void* ntdll = np_module_by_name(np_s_ntdll);
    void* k32   = np_module_by_name(np_s_kernel32);
    if (min_cpu && ntdll) {
        typedef i32 (__attribute__((ms_abi)) *np_qsi_fn)(u32 cls, void* buf, u32 len, u32* ret);
        np_qsi_fn qsi = (np_qsi_fn)np_export_by_name(ntdll, np_s_qsi);
        if (qsi) {
            u8 basic[64]; np_memset(basic, 0, sizeof(basic));
            u32 ret = 0;
            if (qsi(NP_SIC_SYSTEM_BASIC_INFO, basic, sizeof(basic), &ret) >= 0) {
                if ((u8)basic[0] < min_cpu) return 1;
                u64 pages = *(u64*)(basic + 24);
                u64 pageSize = *(u32*)(basic + 32);
                if (min_ram_mb && pages && pageSize &&
                    pages * pageSize < (u64)min_ram_mb * 1048576ull) return 1;
            }
        }
    }

    if (min_uptime && k32) {
        typedef u64 (__attribute__((ms_abi)) *np_uptime_fn)(void);
        np_uptime_fn gtt = (np_uptime_fn)np_export_by_name(k32, np_s_gtt);
        if (gtt && gtt() < (u64)min_uptime) return 1;
    }

    if (min_w || min_h || min_mon) {
        void* u32mod = np_module_by_name(np_s_user32);
        if (u32mod) {
            typedef int (__attribute__((ms_abi)) *np_gsm_fn)(int);
            np_gsm_fn gsm = (np_gsm_fn)np_export_by_name(u32mod, np_s_gsm);
            if (gsm) {
                int w = gsm(0);   /* SM_CXSCREEN */
                int h = gsm(1);   /* SM_CYSCREEN */
                int m = gsm(80);  /* SM_CMONITORS */
                if (min_w && w < (int)min_w) return 1;
                if (min_h && h < (int)min_h) return 1;
                if (min_mon && m < (int)min_mon) return 1;
            }
        }
    }
    return 0;
}

/* ========================================================================
 * code virtualisation
 *
 * The packer lowers each marked region to wire bytecode and publishes a
 * descriptor table through the NPP1 header (+20 = table offset, +88 = count).
 * At load time we replace the region body with a trampoline that saves the
 * live guest registers, runs the interpreter and jumps to the instruction
 * after the region. The region lives in a .text page that the unpacker
 * already restored as writable, so no protection change is needed.
 *
 * Descriptor (32 bytes): rva, size, bc_off, bc_len, rev_off, reg_mask.
 * ======================================================================== */

#define NP_VM_DESC_SIZE 32u

static u8* np_vm_put8(u8* p, u8 v) { *p++ = v; return p; }

static u8* np_vm_put32(u8* p, u32 v) {
    *p++ = (u8)(v & 0xFF);
    *p++ = (u8)((v >> 8) & 0xFF);
    *p++ = (u8)((v >> 16) & 0xFF);
    *p++ = (u8)((v >> 24) & 0xFF);
    return p;
}

/* mov [rsp+8*slot], reg  (store=1) /  mov reg, [rsp+8*slot]  (store=0) */
static u8* np_vm_mov_rsp(u8* p, u8 reg, u32 slot, int store) {
    u8 disp = (u8)(slot * 8u);
    p = np_vm_put8(p, (u8)(0x48 | (reg >= 8 ? 4u : 0u)));
    p = np_vm_put8(p, (u8)(store ? 0x89 : 0x8B));
    p = np_vm_put8(p, (u8)(0x44 | ((reg & 7) << 3)));
    p = np_vm_put8(p, 0x24);              /* SIB: base=rsp, no index */
    p = np_vm_put8(p, disp);
    return p;
}

/* ---- multi-layer bytecode encryption (mirror of crypto_layers.cpp) ------ */

static void np_derive_key(u8 out[8], u32 nonce, u32 seed, u32 layer) {
    u64 h = 0xCBF29CE484222325ull;
    const u32 vals[3] = { nonce, seed, layer };
    for (int v = 0; v < 3; v++) {
        for (int b = 0; b < 4; b++) {
            h ^= (u64)((vals[v] >> (b * 8)) & 0xFF);
            h *= 0x100000001B3ull;
        }
    }
    for (int i = 0; i < 4; i++) {
        h ^= h >> 29;
        h *= 0xBF58476D1CE4E5B9ull;
    }
    for (int k = 0; k < 8; k++) out[k] = (u8)(h >> (k * 8));
}

typedef struct { u8 S[256]; int i, j; } NP_RC4;

static void np_rc4_init(NP_RC4* st, const u8* key, u64 keyLen) {
    for (int k = 0; k < 256; k++) st->S[k] = (u8)k;
    int j = 0;
    for (int k = 0; k < 256; k++) {
        j = (j + st->S[k] + key[k % keyLen]) & 0xFF;
        u8 t = st->S[k]; st->S[k] = st->S[j]; st->S[j] = t;
    }
    st->i = 0; st->j = 0;
}

static void np_rc4_stream(NP_RC4* st, u8* data, u64 len) {
    for (u64 k = 0; k < len; k++) {
        st->i = (st->i + 1) & 0xFF;
        st->j = (st->j + st->S[st->i]) & 0xFF;
        u8 t = st->S[st->i]; st->S[st->i] = st->S[st->j]; st->S[st->j] = t;
        data[k] ^= st->S[(st->S[st->i] + st->S[st->j]) & 0xFF];
    }
}

/* RC4 + XOR + additive rotation. Reverse order of layeredEncrypt(). */
static void np_layered_decrypt(u8* data, u64 len, u32 nonce, u32 seed) {
    if (!data || len == 0) return;

    u8 k3[8];
    np_derive_key(k3, nonce, seed, 2);
    for (u64 k = 0; k < len; k++) data[k] = (u8)(data[k] - k3[k & 7]);

    u8 k2[8];
    np_derive_key(k2, nonce, seed, 1);
    for (u64 k = 0; k < len; k++) data[k] ^= k2[k & 7];

    u8 k1[8];
    np_derive_key(k1, nonce, seed, 0);
    NP_RC4 rc;
    np_rc4_init(&rc, k1, 8);
    np_rc4_stream(&rc, data, len);
}
static u32 np_vm_install(void* base, const u8* b) {
    u32 off   = np_rd32(b + 20);
    u32 count = np_rd32(b + 88);
    if (!off || !count) return 0;
    if (count > 64u) count = 64u;

    u8* img = (u8*)base;
    const u8* rec = b + off;

    for (u32 i = 0; i < count; i++) {
        u32 rva    = np_rd32(rec + i * NP_VM_DESC_SIZE + 0);
        u32 size   = np_rd32(rec + i * NP_VM_DESC_SIZE + 4);
        u32 bc_off = np_rd32(rec + i * NP_VM_DESC_SIZE + 8);
        u32 bc_len = np_rd32(rec + i * NP_VM_DESC_SIZE + 12);
        u32 rev_off= np_rd32(rec + i * NP_VM_DESC_SIZE + 16);
        u32 mask   = np_rd32(rec + i * NP_VM_DESC_SIZE + 20);
        u32 nonce  = np_rd32(rec + i * NP_VM_DESC_SIZE + 24);
        if (!rva || !size || !bc_len || !mask) continue;

        /* Decrypt the bytecode in place. The .np_prot page is mapped
         * read-execute, so flip it writable for the duration of the
         * decryption and restore it afterwards. */
        if (nonce) {
            void* k32 = np_module_by_name(np_s_kernel32);
            if (k32) {
                typedef int (*np_vprotect_t)(void*, u64, unsigned long, unsigned long*);
                np_vprotect_t vp = (np_vprotect_t)np_export_by_name(k32, np_s_vprotect);
                if (vp) {
                    u8* bc = (u8*)b + bc_off;
                    /* VirtualProtect works on page granularity. */
                    u64 pageAdj = (u64)bc & 0xFFF;
                    u8* pageBase = bc - pageAdj;
                    u64 pageCount = (pageAdj + bc_len + 0xFFF) & ~(u64)0xFFF;
                    unsigned long oldProtect = 0;
                    if (vp(pageBase, pageCount, 0x40, &oldProtect)) {
                        np_layered_decrypt(bc, bc_len, nonce, rva);
                        vp(pageBase, pageCount, oldProtect, &oldProtect);
                    }
                }
            }
        }

        u32 regs = 0;
        for (u32 k = 0; k < 16; k++) if (mask & (1u << k)) regs++;
        u32 need = 51u + 10u * regs;
        if (need + 8u > size) continue;

        u8* t = img + rva;
        u8* p = t;

        /* Frame: keep the original rsp in rbp, align, reserve the 16-qword
         * register array plus 16 bytes so the call below stays 16-aligned. */
        p = np_vm_put8(p, 0x55);                     /* push rbp            */
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xE5);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x83); p = np_vm_put8(p, 0xE4); p = np_vm_put8(p, 0xF0);
        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x81); p = np_vm_put8(p, 0xEC);
        p = np_vm_put32(p, 144);                     /* sub rsp,144         */

        for (u32 k = 0; k < 16; k++)
            if (mask & (1u << k)) p = np_vm_mov_rsp(p, (u8)k, k, 1);

        {   /* lea rcx, [rip+disp] -> bytecode */
            u8* q = p;
            p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x8D); p = np_vm_put8(p, 0x0D);
            u64 tgt = (u64)(const u8*)(b + bc_off);
            u64 nxt = (u64)(q + 7);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }
        p = np_vm_put8(p, 0xBA);                     /* mov edx, bc_len     */
        p = np_vm_put32(p, bc_len);
        {   /* lea r8, [rip+disp] -> reverse table */
            u8* q = p;
            p = np_vm_put8(p, 0x4C); p = np_vm_put8(p, 0x8D); p = np_vm_put8(p, 0x05);
            u64 tgt = (u64)(const u8*)(b + rev_off);
            u64 nxt = (u64)(q + 7);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }
        p = np_vm_put8(p, 0x49); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xE1); /* mov r9,rsp */

        {   /* call rel32 -> np_vm_run */
            u8* q = p;
            p = np_vm_put8(p, 0xE8);
            u64 tgt = (u64)(unsigned long long)&np_vm_run;
            u64 nxt = (u64)(q + 5);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }

        for (u32 k = 0; k < 16; k++)
            if (mask & (1u << k)) p = np_vm_mov_rsp(p, (u8)k, k, 0);

        p = np_vm_put8(p, 0x48); p = np_vm_put8(p, 0x89); p = np_vm_put8(p, 0xEC); /* mov rsp,rbp */
        p = np_vm_put8(p, 0x5D);                     /* pop rbp             */

        {   /* jmp rel32 -> first byte after the region */
            u8* q = p;
            p = np_vm_put8(p, 0xE9);
            u64 tgt = (u64)(img + rva + size);
            u64 nxt = (u64)(q + 5);
            p = np_vm_put32(p, (u32)(i32)(tgt - nxt));
        }

        /* Fill the remainder with NOPs so the region stays deterministic. */
        while (p < t + size) *p++ = 0x90;
    }
    return 0;
}
/* ========================================================================
 * entry point
 * ======================================================================== */

__attribute__((noinline, used))
u32 np_prot_start(void* base, void* hdr, void* blob, void* kern) {
    (void)hdr;
    if (!blob) return 0;

    const u8* b = (const u8*)blob;
    if (np_rd32(b) != NPP_MAGIC) return 0;
    u32 ver = np_rd32(b + 4);
    if (ver < 1 || ver > 2) return 0;

    u32 flags = np_rd32(b + 8);
    if (!flags) return 0;

    void* ntqip = 0;
    void* getctx = 0;
    if (flags & 0x0F) {
        void* ntdll = np_module_by_name(np_s_ntdll);
        if (ntdll) ntqip = np_export_by_name(ntdll, np_s_qip);
        void* k32 = np_module_by_name(np_s_kernel32);
        if (k32) getctx = np_export_by_name(k32, np_s_getctx);
    }

    if (flags & 0x01u) {
        if (np_chk_peb())      return NP_CHK_PEB;
        if (np_chk_ntglobal()) return NP_CHK_NTGLOBAL;
        if (np_chk_heap())     return NP_CHK_HEAP;
        if (ntqip && np_chk_ntquery(ntqip)) return NP_CHK_NTQUERY;
        if ((flags & 0x08u) && getctx && np_chk_dr(getctx)) return NP_CHK_DR;
    }
    if (flags & 0x04u) {
        if (np_chk_timing(np_rd64(b + 24))) return NP_CHK_TIMING;
    }
    if (flags & 0x02u) {
        if (np_chk_cpuid()) return NP_CHK_CPUID;
        if (np_chk_bad_modules()) return NP_CHK_BADMOD;
    }
    if (flags & 0x20u) {
        np_vm_install(base, b);
    }
    if (flags & 0x80u) {
        if (np_chk_mutation(b, kern)) return NP_CHK_MUTATION;
    }
    if (flags & 0x10u) {
        if (np_chk_license(b)) return NP_CHK_LICENSE;
    }
    if (flags & 0x100u) {
        u64 expected = np_rd64(b + 80);
        if (!expected || np_machine_id() != expected) return NP_CHK_ACTIVATION;
    }
    if (flags & 0x200u) {
        u32 threshold = np_rd32(b + 96);
        if (threshold && np_sandbox_score() >= threshold) return NP_CHK_SANDBOX;
    }
    if (flags & 0x400u) {
        if (np_chk_dump(base)) return NP_CHK_DUMP;
    }
    if (flags & 0x800u) {
        if (np_chk_env(b)) return NP_CHK_ENV;
    }
    if (flags & 0x40u) {
        if (np_chk_integrity(base, b)) return NP_CHK_INTEGRITY;
    }
    return 0;
}

/* Marker so the generated blob can be measured by the build script. */
__attribute__((used)) static const u32 np_prot_marker = 0x4E505052u; /* 'NPPR' */
