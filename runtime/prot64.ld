/* NovaProtect x64 protection runtime - flat layout.
 *
 * Sections are packed at 16 byte granularity and placed contiguously in the
 * virtual address space so every PC relative reference between them stays
 * valid after the whole image is extracted with objcopy.
 *
 * The .np_entry trampoline is forced first so blob offset 0 is always a valid
 * entry point (np_prot_start is reached through a single rel32 jmp). */
ENTRY(np_blob_entry)
SECTIONS
{
  . = 0x200001000;
  .np_text : {
    KEEP(*(.np_entry))
    *(.text) *(.text.*)
  }
  . = ALIGN(16);
  .np_rdata : { *(.rdata) *(.rdata.*) *(.rodata) *(.rodata.*) }
  . = ALIGN(16);
  .np_data : { *(.data) *(.data.*) }
  /DISCARD/ : {
    *(.comment) *(.pdata) *(.xdata) *(.eh_frame) *(.bss)
    *(.idata) *(.reloc) *(.debug*) *(.edata) *(.tls)
  }
}