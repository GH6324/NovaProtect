    .text
    .globl np_call_native
// u64 np_call_native(void* fn, u64* regs)
np_call_native:
    push %rbp
    push %rbx
    push %rsi
    push %rdi
    push %r12
    push %r13
    push %r14
    push %r15

    mov  %rsp, np_g_hrsp(%rip)
    mov  %rcx, np_g_fn(%rip)
    mov  %rdx, np_g_regs(%rip)
    mov  %rdx, %r11

    // stash guest r10/r11/rax first (registers we need as scratch)
    mov  80(%r11), %rax
    mov  %rax, np_g_r10(%rip)
    mov  88(%r11), %rax
    mov  %rax, np_g_g11(%rip)
    mov  0(%r11),  %rax
    mov  %rax, np_g_rax(%rip)
    mov  32(%r11), %rax
    mov  %rax, np_g_rsp(%rip)

    // load the remaining guest registers
    mov  8(%r11),   %rcx
    mov  16(%r11),  %rdx
    mov  24(%r11),  %rbx
    mov  40(%r11),  %rbp
    mov  48(%r11),  %rsi
    mov  56(%r11),  %rdi
    mov  64(%r11),  %r8
    mov  72(%r11),  %r9
    mov  96(%r11),  %r12
    mov  104(%r11), %r13
    mov  112(%r11), %r14
    mov  120(%r11), %r15

    // finally load the scratch ones and the guest stack
    mov  np_g_r10(%rip), %r10
    mov  np_g_g11(%rip), %r11
    mov  np_g_rax(%rip), %rax
    mov  np_g_rsp(%rip), %rsp

    call *np_g_fn(%rip)

    mov  np_g_hrsp(%rip), %rsp
    mov  np_g_regs(%rip), %r11
    mov  %rax, 0(%r11)
    mov  %rcx, 8(%r11)
    mov  %rdx, 16(%r11)
    mov  %rbx, 24(%r11)
    mov  %rbp, 40(%r11)
    mov  %rsi, 48(%r11)
    mov  %rdi, 56(%r11)
    mov  %r8,  64(%r11)
    mov  %r9,  72(%r11)
    mov  %r10, 80(%r11)
    mov  %r12, 96(%r11)
    mov  %r13, 104(%r11)
    mov  %r14, 112(%r11)
    mov  %r15, 120(%r11)

    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rdi
    pop  %rsi
    pop  %rbx
    pop  %rbp
    ret

    .data
    .align 8
np_g_hrsp: .quad 0
np_g_fn:   .quad 0
np_g_regs: .quad 0
np_g_g11:  .quad 0
np_g_r10:  .quad 0
np_g_rax:  .quad 0
np_g_rsp:  .quad 0