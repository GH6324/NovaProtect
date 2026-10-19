.intel_syntax noprefix
.code64
# NovaProtect x64 protection runtime entry trampoline.
# Linked as the very first object so the blob entry always sits at offset 0;
# the loader stub simply calls blob_base + 0.
.section .np_entry,"x"
.global np_blob_entry
np_blob_entry:
    jmp np_prot_start