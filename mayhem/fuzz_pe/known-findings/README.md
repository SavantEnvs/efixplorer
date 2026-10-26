# fuzz_pe known finding: relocation block size is trusted (hang)

Reproducer: `reloc-block-size-hang.efi` (`./fuzz_pe-standalone reloc-block-size-hang.efi`; does not finish in any
reasonable time, libFuzzer reports `timeout`).

Cause: `loader/pe.cc`, `PE::preprocess()`, base-relocation loop. `block_size` is read straight from the image
(here `0x3000000c`) and drives `block_reloc_count = (block_size - 8) / 2` (~400 million iterations of `get_word` +
`add_qword`/`add_dword`) even though the relocation directory declares only 12 bytes. `relocs_va < relocs_va_end` is only
checked between blocks, never inside a block.

Impact: a crafted PE/UEFI module makes IDA spin (denial of service) while loading.

Fix: clamp the block to the directory (`block_size <= relocs_va_end - relocs_va`) before computing the count.
