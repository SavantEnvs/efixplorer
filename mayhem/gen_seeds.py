#!/usr/bin/env python3
"""Regenerates the committed seeds and mayhem/oracle/expected.txt (known input -> known output).

The expected values are derived here from the layout each image is built with, independently of the
loader, so mayhem/test.sh checks the loader's behavior rather than its own previous output.
Run:  python3 mayhem/gen_seeds.py   (outputs are committed; the build never needs Python)
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

PEST_EXEC, PEST_WRITE = 0x20000000, 0x80000000
SEG_READ, SEG_WRITE, SEG_EXEC = 4, 2, 1

AMD64, I386, ARM64 = 0x8664, 0x014C, 0xAA64


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def section_header(name, vsize, rva, rawsize, rawptr, flags):
    return struct.pack("<8sIIIIIIHHI", name, vsize, rva, rawsize, rawptr, 0, 0, 0, 0, flags)


def build_pe(machine, image_base, relocs):
    """One .text + one .data section; a base-relocation table lives inside .data."""
    is64 = machine in (AMD64, ARM64)
    hdr_size = 0x200
    text_rva, data_rva = 0x1000, 0x2000
    text = bytearray(0x200)
    text[0:8] = b"\x90" * 7 + b"\xc3"
    data = bytearray(0x200)

    # relocation targets live at data_rva+0x10..; table at data_rva+0x100
    block = bytearray()
    entries = []
    exp_mem = []
    delta = (0 - image_base) & 0xFFFFFFFFFFFFFFFF  # IDA base 0 for the first image
    off = 0x10
    for typ, width in relocs:
        orig = (image_base + 0x1000 + off) & ((1 << (8 * width)) - 1)
        data[off:off + width] = orig.to_bytes(width, "little")
        entries.append((typ << 12) | (data_rva + off - 0x2000))
        mask = (1 << (8 * width)) - 1
        exp_mem.append((data_rva + off, width, (orig + (delta & mask)) & mask))
        off += 8
    if len(entries) % 2:
        entries.append(0)  # padding entry (ABSOLUTE) keeps the block 4-byte sized
    size = 8 + 2 * len(entries)
    block += struct.pack("<II", data_rva, size)
    for e in entries:
        block += struct.pack("<H", e)
    reloc_off = 0x100
    data[reloc_off:reloc_off + len(block)] = block

    if is64:
        opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, 0x200, 0x200, 0, text_rva, text_rva,
                          image_base, 0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0x3000, hdr_size, 0, 10, 0,
                          0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, 0x200, 0x200, 0, text_rva, text_rva,
                          data_rva, image_base, 0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0x3000, hdr_size, 0, 10, 0,
                          0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    assert len(opt) == (112 if is64 else 96), len(opt)
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 5 * 8, data_rva + reloc_off, len(block))
    opt += bytes(dirs)
    coff = struct.pack("<HHIIIHH", machine, 2, 0x5F000000, 0, 0, len(opt), 0x2022)
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    img = bytearray(dos) + b"PE\0\0" + coff + opt
    img += section_header(b".text", 0x80, text_rva, 0x200, 0x200, 0x60000020)
    img += section_header(b".data", 0x200, data_rva, 0x200, 0x400, 0xC0000040)
    img = img.ljust(hdr_size, b"\0") + bytes(text) + bytes(data)
    return bytes(img), exp_mem


def pe_expect(name, img, machine, exp_mem):
    out = [f"pe {name} machine={machine:#x}"]
    out.append("seg image.efi_HEADER 0x0 0x200")
    out.append(f"seg image.efi_.text 0x1000 0x1200 {SEG_READ | SEG_EXEC}")
    out.append(f"seg image.efi_.data 0x2000 0x2200 {SEG_READ | SEG_WRITE}")
    out.append(f"entry 0x1000 image.efi_entry_{zlib.crc32(img) & 0xFFFFFFFF:08X}")
    out.append("mem 0x1000 1 0x90")
    out.append("mem 0x1007 1 0xc3")
    for ea, width, val in exp_mem:
        out.append(f"mem {ea:#x} {width} {val:#x}")
    return out


def build_te(machine, x_text, x_data):
    nsec, A = 2, 0x1B0  # adjust = stripped_size - 40
    stripped = A + 40
    secs = bytearray()
    raw_start = 40 + 40 * nsec
    t_scn, d_scn = raw_start + A, raw_start + 0x40 + A
    secs += section_header(b".text", 0x40, 0x1000, 0x40, t_scn, 0x60000020)
    secs += section_header(b".data", 0x40, 0x2000, 0x40, d_scn, 0xC0000040)
    hdr = struct.pack("<HHBBHIIQIIII", 0x5A56, machine, nsec, 10, stripped, 0x1000, 0x1000, 0x140000000 if machine != I386 else 0x400000,
                      0, 0, 0, 0)
    assert len(hdr) == 40
    code = (b"\x55\x48\x89\xe5\x5d\xc3" + b"\xcc" * 0x3A)[:0x40]
    dat = bytes(range(0x40))
    img = hdr + bytes(secs) + code + dat
    return img


def te_expect(name, img, machine):
    A = 0x1B0
    t_start, d_start = 0x1000 - A, 0x2000 - A
    out = [f"te {name} machine={machine:#x}"]
    out.append(f"seg image.te_HEADER 0x0 {40 + 80:#x}")
    out.append(f"seg image.te_.text {t_start:#x} {t_start + 0x40:#x} {SEG_READ | SEG_EXEC}")
    out.append(f"seg image.te_.data {d_start:#x} {d_start + 0x40:#x} {SEG_READ | SEG_WRITE}")
    out.append(f"entry {0x1000 - A:#x} image.te_entry_{zlib.crc32(img) & 0xFFFFFFFF:08X}")
    out.append("mem 0x0 2 0x5a56")
    out.append("mem 0x78 1 0x55")
    out.append("mem 0xb8 1 0x0")
    out.append("mem 0xbb 1 0x3")
    return out


# ---- firmware volume -------------------------------------------------------------------------
def guid_bytes(s):
    p = s.split("-")
    return struct.pack("<IHH", int(p[0], 16), int(p[1], 16), int(p[2], 16)) + bytes.fromhex(p[3] + p[4])


def section(typ, body):
    n = 4 + len(body)
    return struct.pack("<I", n)[:3] + bytes([typ]) + body


def pad4(b):
    return b + b"\0" * (-len(b) % 4)


def ffs_file(guid, ftype, sections):
    body = b""
    for s in sections:
        body = pad4(body) + s
    size = 24 + len(body)
    hdr = bytearray(guid_bytes(guid) + bytes([0, 0xAA, ftype, 0]) + struct.pack("<I", size)[:3] + bytes([0xF8]))
    hsum = (sum(hdr[:16]) + sum(hdr[18:23])) & 0xFF
    hdr[16] = (0x100 - hsum) & 0xFF
    return bytes(hdr) + body


def fv(files, length):
    body = b""
    for f in files:
        body = body + b"\xff" * (-(0x48 + len(body)) % 8) + f
    hdr = bytearray(0x48)
    hdr[16:32] = guid_bytes("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
    struct.pack_into("<Q", hdr, 32, length)
    hdr[40:44] = b"_FVH"
    struct.pack_into("<I", hdr, 44, 0x0004FEFF)
    struct.pack_into("<H", hdr, 48, 0x48)
    hdr[55] = 2
    struct.pack_into("<II", hdr, 56, length // 0x1000, 0x1000)
    csum = sum(struct.unpack("<36H", bytes(hdr))) & 0xFFFF
    struct.pack_into("<H", hdr, 50, (0x10000 - csum) & 0xFFFF)
    img = bytes(hdr) + body
    return img.ljust(length, b"\xff")


def utf16z(s):
    return s.encode("utf-16le") + b"\0\0"


def build_firmware(pe_img, te_img):
    g_drv = "A1B2C3D4-0102-0304-0506-0708090A0B0C"
    g_pei = "11223344-5566-7788-99AA-BBCCDDEEFF00"
    g_apr = "FC510EE7-FFDC-11D4-BD41-0080C73C8881"
    depex = bytes([0x02]) + guid_bytes("5B1B31A1-9562-11D2-8E3F-00A0C969723B") + bytes([0x08])
    drv = ffs_file(g_drv, 0x07, [section(0x10, pe_img), section(0x15, utf16z("TestDxe")), section(0x13, depex)])
    pei = ffs_file(g_pei, 0x06, [section(0x12, te_img), section(0x15, utf16z("TestPei"))])
    apr = ffs_file(g_apr, 0x01, [section(0x19, guid_bytes(g_drv))])
    image = fv([apr, drv, pei], 0x3000)
    return image, (g_drv, g_pei)


def main():
    seeds = {
        "fuzz_pe": [],
        "fuzz_te": [],
        "fuzz_firmware": [],
    }
    expected = []

    pe64, mem64 = build_pe(AMD64, 0x10000000, [(10, 8), (10, 8)])
    pe32, mem32 = build_pe(I386, 0x00400000, [(3, 4), (3, 4)])
    pearm, memarm = build_pe(ARM64, 0x20000000, [(10, 8)])
    for name, img, machine, mem in (("amd64.efi", pe64, AMD64, mem64), ("i386.efi", pe32, I386, mem32),
                                     ("arm64.efi", pearm, ARM64, memarm)):
        seeds["fuzz_pe"].append((name, img))
        expected += pe_expect(f"fuzz_pe/testsuite/{name}", img, machine, mem) + ["end"]

    te64 = build_te(AMD64, 0, 0)
    te32 = build_te(I386, 0, 0)
    for name, img, machine in (("amd64.te", te64, AMD64), ("i386.te", te32, I386)):
        seeds["fuzz_te"].append((name, img))
        expected += te_expect(f"fuzz_te/testsuite/{name}", img, machine) + ["end"]

    fw, (g_drv, g_pei) = build_firmware(pe64, te64)
    seeds["fuzz_firmware"].append(("amd64_fv.fd", fw))
    expected += [f"fw fuzz_firmware/testsuite/amd64_fv.fd", "machine 0x8664", "nfiles 2",
                 f"file {g_drv} TestDxe pe", f"file {g_pei} TestPei te",
                 f"dump TestDxe {len(pe64)}", "end"]

    for target, items in seeds.items():
        d = os.path.join(HERE, target, "testsuite")
        os.makedirs(d, exist_ok=True)
        for name, data in items:
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
    os.makedirs(os.path.join(HERE, "oracle"), exist_ok=True)
    with open(os.path.join(HERE, "oracle", "expected.txt"), "w") as f:
        f.write("\n".join(expected) + "\n")


if __name__ == "__main__":
    main()
