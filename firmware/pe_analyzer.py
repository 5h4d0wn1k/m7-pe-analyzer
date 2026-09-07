#!/usr/bin/env python3
"""M7 - PE File Analyzer

PE header parsing, import table, section analysis, entropy.
Uses struct, hashlib, os only.
"""

import struct
import hashlib
import os
import sys
import math
import json
import tempfile
import shutil
import argparse


IMAGE_DOS_SIGNATURE = 0x5A4D  # 'MZ'
IMAGE_NT_SIGNATURE = 0x00004550  # 'PE\0\0'

MACHINE_TYPES = {
    0x014c: "I386",
    0x8664: "AMD64",
    0x01c0: "ARM",
    0xaa64: "ARM64",
    0x0200: "IA64",
    0x01f0: "POWERPC",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
}

CHARACTERISTICS = {
    0x0002: "EXECUTABLE_IMAGE",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x1000: "SYSTEM",
    0x2000: "DLL",
}

SECTION_FLAGS = {
    0x00000020: "CODE",
    0x40000040: "INITIALIZED_DATA",
    0x80000000: "UNINITIALIZED_DATA",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
    0x00000004: "NOT_PAGED",
    0x02000000: "DISCARDABLE",
    0x10000000: "SHARED",
    0x08000000: "MEM_NOT_CACHED",
}


def read_ascii(data, offset, maxlen=256):
    """Read a null-terminated ASCII string from data at offset."""
    end = data.find(b"\x00", offset)
    if end == -1 or end - offset > maxlen:
        end = offset + maxlen
    return data[offset:end].decode("ascii", errors="replace")


def entropy(data):
    """Compute Shannon entropy of a byte buffer in bits per byte."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


class PEAnalyzer:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.size = len(self.data)
        self.dos = None
        self.nt = None
        self.file_header = None
        self.optional = None
        self.sections = []
        self.imports = []
        self.checksums = {}

    def parse(self):
        self.checksums["md5"] = hashlib.md5(self.data).hexdigest()
        self.checksums["sha1"] = hashlib.sha1(self.data).hexdigest()
        self.checksums["sha256"] = hashlib.sha256(self.data).hexdigest()

        if self.size < 64:
            raise ValueError("File too small to be a PE")

        self._parse_dos()
        self._parse_nt()
        self._parse_sections()
        self._parse_imports()

    def _parse_dos(self):
        sig = struct.unpack_from("<H", self.data, 0)[0]
        if sig != IMAGE_DOS_SIGNATURE:
            raise ValueError("Not a valid PE file (bad DOS signature)")
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        self.dos = {
            "e_magic": hex(sig),
            "e_lfanew": e_lfanew,
        }
        self.nt_offset = e_lfanew

    def _parse_nt(self):
        if self.nt_offset + 24 > self.size:
            raise ValueError("NT header offset out of range")
        sig = struct.unpack_from("<I", self.data, self.nt_offset)[0]
        if sig != IMAGE_NT_SIGNATURE:
            raise ValueError("Invalid PE signature")
        # IMAGE_FILE_HEADER at nt_offset+4 (20 bytes)
        coff = self.nt_offset + 4
        machine, n_sections, timestamp, ptr_sym, n_sym, opt_size, chars = \
            struct.unpack_from("<HHIIIHH", self.data, coff)
        self.file_header = {
            "machine": machine,
            "machine_name": MACHINE_TYPES.get(machine, "UNKNOWN"),
            "number_of_sections": n_sections,
            "timestamp": timestamp,
            "pointer_to_symbol_table": ptr_sym,
            "number_of_symbols": n_sym,
            "size_of_optional_header": opt_size,
            "characteristics": chars,
            "characteristic_flags": [v for k, v in CHARACTERISTICS.items() if chars & k],
        }
        self.optional_offset = coff + 20
        self._parse_optional()

    def _parse_optional(self):
        o = self.optional_offset
        magic = struct.unpack_from("<H", self.data, o)[0]
        if magic == 0x10B:  # PE32
            fmt = "<HBBIIIIIIIIIIHHIIIIHHIIIIIIII"
            vals = struct.unpack_from(fmt, self.data, o)
            self.arch = "PE32"
            self.optional = self._map_optional(vals)
            self.optional["image_base"] = vals[9]
        elif magic == 0x20B:  # PE32+
            fmt = "<HBBIIIIIIIIIIHHIIIIQHIIIIIIII"
            vals = struct.unpack_from(fmt, self.data, o)
            self.arch = "PE32+"
            self.optional = self._map_optional(vals)
            self.optional["image_base"] = vals[8]
        else:
            raise ValueError("Unknown optional header magic: %s" % hex(magic))

    def _map_optional(self, v):
        # v layout: magic, majlink, minlink, sizes(3), entry, base, section offs
        return {
            "magic": hex(v[0]),
            "major_linker": v[1],
            "minor_linker": v[2],
            "size_of_code": v[3],
            "size_of_initialized_data": v[4],
            "size_of_uninitialized_data": v[5],
            "address_of_entry_point": hex(v[6]),
            "base_of_code": hex(v[7]),
            "section_alignment": v[10],
            "file_alignment": v[11],
            "major_os_version": v[12],
            "minor_os_version": v[13],
            "major_image_version": v[14],
            "minor_image_version": v[15],
            "major_subsystem_version": v[16],
            "minor_subsystem_version": v[17],
            "size_of_image": v[18],
            "size_of_headers": v[19],
            "checksum": hex(v[20]),
            "subsystem": v[21],
            "number_of_rva_and_sizes": v[22],
        }

    def _parse_sections(self):
        n = self.file_header["number_of_sections"]
        sec_off = self.optional_offset + self.file_header["size_of_optional_header"]
        for i in range(n):
            off = sec_off + i * 40
            if off + 40 > self.size:
                break
            name = read_ascii(self.data, off, 8).rstrip("\x00").strip()
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", self.data, off + 8)
            relocptr, linenum, nreloc, nlinenum = struct.unpack_from("<IIHH", self.data, off + 24)
            chars = struct.unpack_from("<I", self.data, off + 36)[0]
            raw = self.data[rawptr:rawptr + rawsize]
            self.sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": hex(vaddr),
                "raw_size": rawsize,
                "raw_offset": hex(rawptr),
                "characteristics": chars,
                "flags": [v for k, v in SECTION_FLAGS.items() if chars & k],
                "entropy": round(entropy(raw), 4),
                "md5": hashlib.md5(raw).hexdigest(),
            })

    def _parse_imports(self):
        # Data directory index 1 = import table
        dd = self.optional_offset + 96  # start of data directories (32-bit)
        if self.arch == "PE32+":
            dd = self.optional_offset + 112
        if dd + 8 > self.size:
            return
        import_rva, import_size = struct.unpack_from("<II", self.data, dd)
        if not import_rva:
            return
        # RVA -> file offset requires mapping through sections
        self.import_rva = import_rva
        self.import_size = import_size
        self._emit_imports(import_rva)

    def _rva_to_offset(self, rva):
        for s in self.sections:
            va = int(s["virtual_address"], 16)
            if va <= rva < va + s["virtual_size"]:
                return s["raw_offset"] + (rva - va)
        return None

    def _emit_imports(self, import_rva):
        off = self._rva_to_offset(import_rva)
        if off is None:
            return
        max_descriptors = 1000
        for _ in range(max_descriptors):
            if off + 20 > self.size:
                break
            olt, time, fwd, name_rva, iat = struct.unpack_from("<IIIII", self.data, off)
            if olt == 0 and name_rva == 0:
                break
            name_off = self._rva_to_offset(name_rva)
            if name_off is None:
                break
            dll = read_ascii(self.data, name_off)
            funcs = self._read_import_functions(olt)
            self.imports.append({"dll": dll, "functions": funcs})
            off += 20

    def _read_import_functions(self, thunk_rva):
        off = self._rva_to_offset(thunk_rva)
        if off is None:
            return []
        funcs = []
        for _ in range(5000):
            if self.arch == "PE32+":
                val = struct.unpack_from("<Q", self.data, off)[0]
                step = 8
            else:
                val = struct.unpack_from("<I", self.data, off)[0]
                step = 4
            if val == 0:
                break
            if val & 0x8000000000000000 if self.arch == "PE32+" else val & 0x80000000:
                funcs.append("ord_%d" % (val & 0xFFFF if self.arch == "PE32+" else val & 0xFFFF))
            else:
                hint_off = self._rva_to_offset(val if self.arch == "PE32+" else val & 0x7FFFFFFF)
                if hint_off is not None and hint_off + 2 <= self.size:
                    name = read_ascii(self.data, hint_off + 2)
                    funcs.append(name) if name else None
            off += step
        return funcs

    def report(self):
        lines = []
        lines.append("=== M7 - PE File Analyzer ===")
        lines.append("File: %s" % self.path)
        lines.append("Size: %d bytes" % self.size)

        lines.append("\n-- Hashes --")
        for algo, h in self.checksums.items():
            lines.append("  %s: %s" % (algo.upper(), h))

        lines.append("\n-- DOS Header --")
        lines.append("  e_magic:  %s" % self.dos["e_magic"])
        lines.append("  e_lfanew: 0x%x" % self.dos["e_lfanew"])

        lines.append("\n-- File Header --")
        lines.append("  Machine:         %s (%s)" % (self.file_header["machine_name"],
                                                     hex(self.file_header["machine"])))
        lines.append("  Sections:        %d" % self.file_header["number_of_sections"])
        lines.append("  Timestamp:       %d" % self.file_header["timestamp"])
        lines.append("  Characteristics: 0x%x" % self.file_header["characteristics"])
        for f in self.file_header["characteristic_flags"]:
            lines.append("    - %s" % f)

        lines.append("\n-- Optional Header --")
        lines.append("  Magic:         %s" % self.optional["magic"])
        lines.append("  Architecture:  %s" % self.arch)
        lines.append("  Image base:    0x%x" % self.optional["image_base"])
        lines.append("  Entry point:   %s" % self.optional["address_of_entry_point"])
        lines.append("  Subsystem:     %d" % self.optional["subsystem"])

        lines.append("\n-- Sections --")
        for s in self.sections:
            lines.append("  %-10s VA=%-10s VS=%d RS=%d Entropy=%.4f %s"
                         % (s["name"], s["virtual_address"], s["virtual_size"],
                            s["raw_size"], s["entropy"], ",".join(s["flags"] or ["?"])))

        lines.append("\n-- Imports --")
        if not self.imports:
            lines.append("  (none)")
        for imp in self.imports:
            lines.append("  DLL: %s (%d functions)" % (imp["dll"], len(imp["functions"])))
            for f in imp["functions"][:20]:
                lines.append("      %s" % f)
            if len(imp["functions"]) > 20:
                lines.append("      ... (%d more)" % (len(imp["functions"]) - 20))

        return "\n".join(lines)

    def to_dict(self):
        return {
            "path": self.path,
            "size": self.size,
            "checksums": self.checksums,
            "dos": self.dos,
            "file_header": self.file_header,
            "optional": self.optional,
            "arch": self.arch,
            "sections": self.sections,
            "imports": self.imports,
        }


def build_sample_pe() -> bytes:
    """Hand-build a minimal but valid PE32 that PEAnalyzer must fully parse.

    Layout is a single RWX ``.text`` section (raw_offset 0x200 maps to
    virtual_address 0x1000) containing code, two import descriptors
    (KERNEL32.ExitProcess, USER32.MessageBoxW), ILT/IAT arrays and
    hint/name entries. Fully offline and deterministic.
    """
    def align(v, a):
        return (v + a - 1) & ~(a - 1)

    FILE_ALIGN = 0x200
    SECT_ALIGN = 0x1000
    VA = 0x1000
    RAW = 0x200

    def rva(off):
        return VA + (off - RAW)

    raw = bytearray()
    code_off = 0
    cursor = RAW

    def add(blob):
        nonlocal cursor
        while cursor % 16:
            cursor += 1
            raw.append(0)
        off = cursor
        raw.extend(blob)
        cursor += len(blob)
        return off

    add(b"\xb8\x01\x00\x00\x00\xc3" + b"\x90" * 8)          # mov eax,1; ret ; nops
    add(b"Minimal PE32 test image (M7) - do not run\0")

    desc_size = 20
    null_desc = b"\x00" * desc_size
    dll_k = b"KERNEL32.dll\0"
    dll_u = b"USER32.dll\0"
    hn_exit = b"\x00\x00ExitProcess\0"
    hn_msg = b"\x00\x00MessageBoxW\0"

    # reserve descriptor area size: 3*20 = 60
    desc_area = add(b"\x00" * (desc_size * 3))
    ilt1_off = add(struct.pack("<II", 0, 0))
    iat1_off = add(struct.pack("<II", 0, 0))
    ilt2_off = add(struct.pack("<II", 0, 0))
    iat2_off = add(struct.pack("<II", 0, 0))
    k_off = add(dll_k)
    u_off = add(dll_u)
    hn1_off = add(hn_exit)
    hn2_off = add(hn_msg)

    # patch ILT/IAT
    struct.pack_into("<II", raw, ilt1_off - RAW, rva(hn1_off), 0)
    struct.pack_into("<II", raw, iat1_off - RAW, rva(hn1_off), 0)
    struct.pack_into("<II", raw, ilt2_off - RAW, rva(hn2_off), 0)
    struct.pack_into("<II", raw, iat2_off - RAW, rva(hn2_off), 0)

    # patch descriptors: OLT, TimeDateStamp, Forwarder, Name, IAT
    struct.pack_into("<IIIII", raw, desc_area - RAW,
                     rva(ilt1_off), 0, 0, rva(k_off), rva(iat1_off))
    struct.pack_into("<IIIII", raw, desc_area - RAW + desc_size,
                     rva(ilt2_off), 0, 0, rva(u_off), rva(iat2_off))

    section_size = align(len(raw), FILE_ALIGN)
    raw += b"\x00" * (section_size - len(raw))

    image_base = 0x00400000
    entry_rva = rva(code_off)
    size_of_code = section_size
    size_of_image = align(VA + section_size, SECT_ALIGN)

    # ---- DOS header (64 bytes) ----
    pe = bytearray()
    pe += b"MZ" + b"\x90" * 62
    struct.pack_into("<I", pe, 0x3C, 0x80)          # e_lfanew -> PE header

    # ---- PE signature + COFF file header (20 bytes) ----
    pe += b"PE\x00\x00"
    # machine(0x14c) nsec(1) timestamp ptr_sym nsym optsz chars
    pe += struct.pack("<HHIIIHH", 0x14C, 1, 0x5F123456, 0, 0, 0xE0, 0x0102)

    # ---- Optional header PE32 (0xE0) ----
    opt = bytearray()
    opt += struct.pack("<HBB", 0x10B, 14, 0)        # magic, linker
opt += struct.pack("<IIIIIII",                 # code, init, uninit, entry,
                       size_of_code, 0, 0, entry_rva, rva(code_off), 0,
                       image_base)                 # base_of_code, base_of_data, image_base
    opt += struct.pack("<IIHHHHHHII",               # section_align, file_align,
                       0x1000, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, 0)
    opt += struct.pack("<IIIIHHII",                 # size_of_image, size_of_headers,
                       size_of_image, 0x200, 0, 2, 0x0100, 0,
                       0x00100000, 0x1000)          # stack, heap
    opt += struct.pack("<IIII", 0x00100000, 0x1000, 0, 16)  # heap, loader, numdirs
    dirs = [0] * 16
    dirs[1] = rva(desc_area)                       # import table
    for d in dirs:
        opt += struct.pack("<II", d, 28 if d else 0)
    assert len(opt) == 0xE0, len(opt)
    pe += opt

    # ---- Section header (.text) ----
    pe += b".text\x00\x00\x00"
    pe += struct.pack("<IIII", section_size + 0x100, VA, section_size, RAW)
    pe += struct.pack("<IIHH", 0, 0, 0, 0)
    pe += struct.pack("<I", 0x60000020)            # CODE | EXECUTE | READ
    assert len(pe) <= RAW, len(pe)
    pe += b"\x00" * (RAW - len(pe))
    pe += raw
    return bytes(pe)


def build_sample_pe_file(path: str) -> str:
    with open(path, "wb") as f:
        f.write(build_sample_pe())
    return path


def cmd_demo(args):
    print("=" * 66)
    print("  M7 - PE File Analyzer - offline demo")
    print("=" * 66)
    tmp = tempfile.mkdtemp(prefix="m7_demo_")
    pe_path = os.path.join(tmp, "sample.exe")
    build_sample_pe_file(pe_path)
    pa = PEAnalyzer(pe_path)
    pa.parse()
    print("  Architecture    :", pa.arch)
    print("  Machine         :", pa.file_header["machine_name"])
    print("  Entry point     : %s" % pa.optional["address_of_entry_point"])
    print("  Image base      : 0x%x" % pa.optional["image_base"])
    print("  Sections        : %d" % len(pa.sections))
    for s in pa.sections:
        print("    %-8s entropy=%.4f %s"
              % (s["name"], s["entropy"], ",".join(s["flags"] or ["?"])))
    print("  Imports         : %d DLL(s)" % len(pa.imports))
    for imp in pa.imports:
        print("    %s -> %s" % (imp["dll"], ", ".join(imp["functions"])))
    os.makedirs(args.output_dir, exist_ok=True)
    report_path = os.path.join(args.output_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(pa.to_dict(), f, indent=2, default=str)
    shutil.rmtree(tmp, ignore_errors=True)
    print("  report          : %s" % report_path)
    print("  exit=0")
    return 0


def cmd_analyze(args):
    if not os.path.isfile(args.file):
        print("Error: %s not found" % args.file)
        return 1
    try:
        pa = PEAnalyzer(args.file)
        pa.parse()
        print(pa.report())
        if args.json:
            os.makedirs(args.json, exist_ok=True)
            with open(os.path.join(args.json, "report.json"), "w") as f:
                json.dump(pa.to_dict(), f, indent=2, default=str)
        return 0
    except Exception as e:
        print("Error: %s" % e)
        return 1


def main():
    p = argparse.ArgumentParser(
        prog="pe_analyzer.py",
        description="M7 - PE file analyzer (headers, sections, entropy, imports)")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("demo", help="offline demo on a hand-built PE32 (exits 0)") \
        .set_defaults(func=cmd_demo)

    p_an = sub.add_parser("analyze", help="analyze a PE file")
    p_an.add_argument("file")
    p_an.add_argument("--json", metavar="DIR",
                      help="also write report.json under DIR")
    p_an.set_defaults(func=cmd_analyze)

    p.add_argument("-o", "--output-dir", default="reports",
                   help="directory for demo reports (default: reports)")

    args = p.parse_args()
    if not getattr(args, "cmd", None):
        p.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
