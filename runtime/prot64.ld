/* NovaProtect x64 protection runtime - flat layout.
 *
 * Sections are packed at 16 byte granularity and placed contiguously in the
 * virtual address space so every PC relative reference between them stays
 * valid after the whole image is extracted with objcopy.
 *
 * The invariant the packer relies on:
 *
 *     section_VMA - 0x200001000 == offset_of_section_in_prot64.bin
 *     .np_bss VMA - 0x200001000 == length of prot64.bin
 *
 * objcopy -O binary lays the sections out at their relative VMAs and keeps
 * the alignment gaps, so the ALIGN(16) directives below are correct as
 * written: the extracted image is a byte-for-byte copy of the VMA space.
 * (Padding inside a section does NOT work - ld reports the content size and
 * the gap would still be emitted between sections.)
 *
 * The .np_entry trampoline is forced first so blob offset 0 is always a valid
 * entry point (np_prot_start is reached through a single rel32 jmp).
 *
 * .np_bss (NOLOAD) is not extracted at all; it only advances the location
 * counter so the writable statics sit directly behind the blob image. The
 * packer deploys a zeroed region of exactly this size there
 * (kProtBlob64BssSize). */
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
  . = ALIGN(16);
  /* Writable zero-initialized statics (np_snap_buf, registry probe buffer).
   * NOLOAD keeps them out of the extracted binary but still advances the
   * location counter, so every PC-relative reference from the code points
   * just past the blob image. The packer deploys a zeroed region of the
   * link-time size behind the code (kProtBlob64BssSize). */
  .np_bss (NOLOAD) : { *(.bss) *(.bss.*) }
  /DISCARD/ : {
    *(.comment) *(.pdata) *(.xdata) *(.eh_frame)
    *(.idata) *(.reloc) *(.debug*) *(.edata) *(.tls)
  }
}
