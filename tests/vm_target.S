.intel_syntax noprefix
# NovaProtect VM virtualization test fixture.
# The marked region is a register-only straight-line block that the packer
# translates into wire bytecode. It is deliberately longer than the generated
# trampoline so the trampoline can be installed in place.
.text
.globl np_vm_demo
np_vm_demo:
    mov  r8, rcx
    mov  r9, rdx
    .byte 0x48,0x8D,0x0D,0x00,0x00,0x00,0x00
    .rept 20
    nop
    .endr
    mov  rax, r8
    mov  rcx, r9
    add  rax, rcx
    xor  rax, rcx
    add  rax, 0x1234
    shl  rax, 3
    sub  rax, rcx
    or   rax, rcx
    and  rax, 0x00FFFF00
    inc  rax
    dec  rax
    not  rax
    neg  rax
    lea  rax, [rax+0x40]
    add  rax, rcx
    xor  rax, r8
    sub  rax, 0x77
    shl  rax, 5
    shr  rax, 2
    or   rax, 0x0101
    and  rax, 0x7FFFFFFF
    add  rax, rcx
    xor  rax, r9
    not  rax
    neg  rax
    add  rax, 0x1111
    sub  rax, 0x2222
    shl  rax, 1
    or   rax, r8
    and  rax, 0x0F0F0F0F
    inc  rax
    xor  rax, rcx
    add  rax, r9
    lea  rax, [rax+0x100]
    sub  rax, 0x33
    shr  rax, 4
    or   rax, 0x2020
    and  rax, 0x00FF00FF
    add  rax, r8
    xor  rax, r9
    inc  rax
    dec  rax
    not  rax
    neg  rax
    add  rax, 0x7
    sub  rax, 0x9
    shl  rax, 2
    or   rax, rcx
    and  rax, 0x0000FFFF
    add  rax, r9
    xor  rax, r8
    lea  rax, [rax+0x20]
    add  rax, 0x5555
    sub  rax, 0x111
    .rept 20
    nop
    .endr
    ret