.intel_syntax noprefix
.code64
.global np_prot_start
.global np_prot_end

# =====================================================================
# NovaProtect x64 protection runtime.
#
# Entered from the loader stub AFTER the image has been restored and the
# import table rebuilt, immediately before control transfers to the
# original entry point.
#
#   rcx = image base
#   rdx = payload header pointer
#   r8  = NPP1 protection data blob pointer
#   r9  = generated mutation kernel entry
#
# Returns eax = 0 when every enabled check passed, otherwise the id of the
# check that failed. The caller treats any non-zero value as fatal.
#
# The routine is fully position independent (RIP relative only) and never
# imports anything: modules and exports are resolved through the PEB
# loader list.
#
# NPP1 data blob layout (little endian):
#   +0   u32 magic 'NPP1'
#   +4   u32 version
#   +8   u32 flags            bit0 anti-debug, bit1 anti-vm, bit2 timing,
#                             bit3 dr, bit4 license, bit5 vm, bit6 integrity,
#                             bit7 mutation
#   +12  u32 anti_debug_level
#   +16  u32 anti_vm_level
#   +20  u32 reserved
#   +24  u64 timing_threshold
#   +32  u64 expected_mutation_hash
#   +40  u64 expected_license_hash
#   +48  u32 license_blob_off
#   +52  u32 license_blob_len
#   +56  u32 license_key
#   +60  u32 vm_bytecode_off
#   +64  u32 vm_bytecode_len
#   +68  u32 vm_reverse_off
#   +72  u32 integrity_off
#   +76  u32 integrity_count
#   +80  u64 machine_bind_expected
#   +88  u64 reserved2
#   +96  payload area (8 byte aligned)
# =====================================================================

np_prot_start:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x600
    mov r15, rsp

    # frame layout (r15 relative)
    #   +0x000 regfile[20]
    #   +0x0A0 image base
    #   +0x0A8 payload header
    #   +0x0B0 data blob
    #   +0x0B8 mutation kernel
    #   +0x0C0 bytecode base
    #   +0x0C8 bytecode len
    #   +0x0D0 NtQueryInformationProcess
    #   +0x0D8 GetThreadContext
    #   +0x0E0 flags
    #   +0x0E8 scratch
    #   +0x0F0 scratch
    #   +0x100 NtQueryInformationProcess out buffer
    #   +0x110 CONTEXT buffer (0x4D0)
    mov qword ptr [r15+0xA0], rcx
    mov qword ptr [r15+0xA8], rdx
    mov qword ptr [r15+0xB0], r8
    mov qword ptr [r15+0xB8], r9

    xor eax, eax
    mov ecx, 20
np_pr_zero:
    mov qword ptr [r15+rcx*8-8], rax
    dec ecx
    jnz np_pr_zero

    test r8, r8
    jz np_pr_ok
    mov rbp, r8
    cmp dword ptr [rbp], 0x3150504E
    jne np_pr_ok
    cmp dword ptr [rbp+4], 1
    jne np_pr_ok

    mov eax, dword ptr [rbp+8]
    mov dword ptr [r15+0xE0], eax
    test eax, eax
    jz np_pr_ok

    # ---- resolve the two ntdll/kernel32 entry points we may need -----
    lea rsi, [rip+np_str_ntdll]
    call np_module_by_name
    test rax, rax
    jz np_pr_no_ntdll
    mov rcx, rax
    lea rsi, [rip+np_str_ntquery]
    call np_export_by_name
    mov qword ptr [r15+0xD0], rax
np_pr_no_ntdll:
    lea rsi, [rip+np_str_kernel32]
    call np_module_by_name
    test rax, rax
    jz np_pr_no_k32
    mov rcx, rax
    lea rsi, [rip+np_str_getctx]
    call np_export_by_name
    mov qword ptr [r15+0xD8], rax
np_pr_no_k32:

    mov r14d, dword ptr [r15+0xE0]

    # ---------------- anti debug (ids 1..5) ---------------------------
    test r14d, 1
    jz np_pr_timing
    call np_chk_peb
    test eax, eax
    jnz np_pr_fail1
    call np_chk_ntglobal
    test eax, eax
    jnz np_pr_fail2
    call np_chk_heap
    test eax, eax
    jnz np_pr_fail3
    cmp qword ptr [r15+0xD0], 0
    je np_pr_no_qip
    call np_chk_ntquery
    test eax, eax
    jnz np_pr_fail4
np_pr_no_qip:
    cmp qword ptr [r15+0xD8], 0
    je np_pr_timing
    call np_chk_dr
    test eax, eax
    jnz np_pr_fail5

    # ---------------- timing / single step (id 6) ---------------------
np_pr_timing:
    test r14d, 4
    jz np_pr_antivm
    call np_chk_timing
    test eax, eax
    jnz np_pr_fail6

    # ---------------- anti virtual machine (id 7) ---------------------
np_pr_antivm:
    test r14d, 2
    jz np_pr_mutation
    call np_chk_cpuid
    test eax, eax
    jnz np_pr_fail7

    # ---------------- mutation kernel verification (id 8) -------------
np_pr_mutation:
    test r14d, 0x80
    jz np_pr_license
    call np_chk_mutation
    test eax, eax
    jnz np_pr_fail8

    # ---------------- license / VM (id 9) -----------------------------
np_pr_license:
    test r14d, 0x20
    jz np_pr_integrity
    call np_chk_license
    test eax, eax
    jnz np_pr_fail9

    # ---------------- image integrity (id 10) -------------------------
np_pr_integrity:
    test r14d, 0x40
    jz np_pr_ok
    call np_chk_integrity
    test eax, eax
    jnz np_pr_fail10

np_pr_ok:
    xor eax, eax
    jmp np_pr_epilogue

np_pr_fail1:
    mov eax, 1
    jmp np_pr_epilogue
np_pr_fail2:
    mov eax, 2
    jmp np_pr_epilogue
np_pr_fail3:
    mov eax, 3
    jmp np_pr_epilogue
np_pr_fail4:
    mov eax, 4
    jmp np_pr_epilogue
np_pr_fail5:
    mov eax, 5
    jmp np_pr_epilogue
np_pr_fail6:
    mov eax, 6
    jmp np_pr_epilogue
np_pr_fail7:
    mov eax, 7
    jmp np_pr_epilogue
np_pr_fail8:
    mov eax, 8
    jmp np_pr_epilogue
np_pr_fail9:
    mov eax, 9
    jmp np_pr_epilogue
np_pr_fail10:
    mov eax, 10

np_pr_epilogue:
    add rsp, 0x600
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

# ---------------------------------------------------------------
# PEB.BeingDebugged
# ---------------------------------------------------------------
np_chk_peb:
    mov rax, qword ptr gs:[0x60]
    test rax, rax
    jz np_ck_ok
    movzx eax, byte ptr [rax+0x02]
    test eax, eax
    jnz np_ck_bad
np_ck_ok:
    xor eax, eax
    ret
np_ck_bad:
    mov eax, 1
    ret

# ---------------------------------------------------------------
# PEB.NtGlobalFlag & 0x70
# ---------------------------------------------------------------
np_chk_ntglobal:
    mov rax, qword ptr gs:[0x60]
    test rax, rax
    jz np_ck_ok
    mov eax, dword ptr [rax+0xBC]
    and eax, 0x70
    cmp eax, 0x70
    je np_ck_bad
    xor eax, eax
    ret

# ---------------------------------------------------------------
# Heap Flags / ForceFlags
# ---------------------------------------------------------------
np_chk_heap:
    mov rax, qword ptr gs:[0x60]
    test rax, rax
    jz np_ck_ok
    mov rax, qword ptr [rax+0x30]
    test rax, rax
    jz np_ck_ok
    mov ecx, dword ptr [rax+0x70]
    test ecx, ecx
    jnz np_ck_bad
    mov ecx, dword ptr [rax+0x74]
    test ecx, ecx
    jnz np_ck_bad
    xor eax, eax
    ret

# ---------------------------------------------------------------
# NtQueryInformationProcess based checks
# ---------------------------------------------------------------
np_chk_ntquery:
    push rbx
    mov rbx, qword ptr [r15+0xD0]
    test rbx, rbx
    jz np_nq_ok
    sub rsp, 0x40
    mov qword ptr [rsp+0x20], 0

    # ProcessDebugPort (7)
    mov rcx, -1
    mov rdx, 7
    lea r8, [r15+0x100]
    mov r9d, 8
    mov qword ptr [r15+0x100], 0
    call rbx
    cmp qword ptr [r15+0x100], 0
    jne np_nq_bad

    # ProcessDebugFlags (0x1F) : 0 means a debugger is present
    mov rcx, -1
    mov rdx, 0x1F
    lea r8, [r15+0x100]
    mov r9d, 4
    mov qword ptr [r15+0x100], 1
    call rbx
    cmp dword ptr [r15+0x100], 0
    je np_nq_bad

    # ProcessDebugObjectHandle (0x1E)
    mov rcx, -1
    mov rdx, 0x1E
    lea r8, [r15+0x100]
    mov r9d, 8
    mov qword ptr [r15+0x100], 0
    call rbx
    cmp qword ptr [r15+0x100], 0
    jne np_nq_bad

    add rsp, 0x40
    xor eax, eax
    pop rbx
    ret
np_nq_bad:
    add rsp, 0x40
    mov eax, 1
    pop rbx
    ret
np_nq_ok:
    xor eax, eax
    pop rbx
    ret

# ---------------------------------------------------------------
# Hardware breakpoint registers via GetThreadContext
# ---------------------------------------------------------------
np_chk_dr:
    push rbx
    mov rbx, qword ptr [r15+0xD8]
    test rbx, rbx
    jz np_dr_ok
    sub rsp, 0x40
    mov qword ptr [rsp+0x20], 0
    lea rsi, [r15+0x110]
    # zero the CONTEXT and set ContextFlags = CONTEXT_DEBUG_REGISTERS
    xor eax, eax
    mov ecx, 0x4D0
    mov rdi, rsi
np_dr_zero:
    mov byte ptr [rdi], 0
    inc rdi
    dec ecx
    jnz np_dr_zero
    mov dword ptr [rsi+0x30], 0x00100000
    mov rcx, -2                 # GetCurrentThread() pseudo handle
    mov rdx, rsi
    call rbx
    test eax, eax
    jz np_dr_skip
    mov rax, qword ptr [rsi+0x48]   # Dr0
    or  rax, qword ptr [rsi+0x50]   # Dr1
    or  rax, qword ptr [rsi+0x58]   # Dr2
    or  rax, qword ptr [rsi+0x60]   # Dr3
    test rax, rax
    jnz np_dr_bad
np_dr_skip:
    add rsp, 0x40
    xor eax, eax
    pop rbx
    ret
np_dr_bad:
    add rsp, 0x40
    mov eax, 1
    pop rbx
    ret
np_dr_ok:
    xor eax, eax
    pop rbx
    ret