# fuzz_te known finding: signed integer overflow computing a TE section file offset

Reproducer: `section-vaddr-signed-overflow.te` (`./fuzz_te-standalone section-vaddr-signed-overflow.te`).

Cause: `loader/te.cc`, `TE::process()`, line `int32_t file_off = sec.s_scnptr - _adjust;`. `s_scnptr` comes straight from the
section table and `_adjust` is `stripped_size - 40`, both attacker-controlled; with `s_scnptr == 0x80000000` the
subtraction is evaluated in `int` and overflows (UBSan: `-2147483648 - 432 cannot be represented in type 'int'`).

Impact: undefined behavior on crafted TE headers.

Fix: do the arithmetic in a wide type (`int64_t`) and reject offsets outside the image. `file_off` is not used afterwards,
so dropping it is also enough.
