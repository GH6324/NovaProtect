.intel_syntax noprefix
.code64
# NovaProtect generated mutation kernel (x64, position independent).
#   rcx = buffer, rdx = length -> rax = hash
# Four per-build constants are patched by the packer:
#   BASIS  = 0x1122334455667788
#   PRIME  = 0x8877665544332211
#   SEEDX  = 0x0F1E2D3C4B5A6978
#   PRIME2 = 0xA1B2C3D4E5F60718
.global np_mut_kernel
np_mut_kernel:
    movabs rax, 0x1122334455667788
    xor r8d, r8d
np_mk_loop:
    cmp r8, rdx
    jae np_mk_done
    movzx r9d, byte ptr [rcx+r8]
    xor rax, r9
    movabs r10, 0x8877665544332211
    imul rax, r10
    inc r8
    jmp np_mk_loop
np_mk_done:
    movabs r10, 0x0F1E2D3C4B5A6978
    xor rax, r10
    rol rax, 17
    movabs r10, 0xA1B2C3D4E5F60718
    imul rax, r10
    ret
