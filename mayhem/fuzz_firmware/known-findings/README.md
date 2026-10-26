# fuzz_firmware known finding: same relocation hang, reached through a firmware volume

Reproducer: `embedded-pe-reloc-block-size-hang.fd` — a UEFI firmware volume whose PE32+ module carries the
oversized relocation block described in `../../fuzz_pe/known-findings/README.md` (libFuzzer `timeout`).
