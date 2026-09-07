#!/usr/bin/env python3
"""M7 - PE File Analyzer: hand-written Portable Executable parser."""

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from typing import Any, Dict, List, Optional


class PEParser:
    """Parse a Portable Executable file from raw bytes."""

    DOS_MAGIC = b'MZ'

    SECTION_NAME_MAP = {
        '.text': 'CODE', '.rdata': 'INITIALIZED_DATA', '.data': 'UNINITIALIZED_DATA',
        '.rsrc': 'RESOURCE', '.reloc': 'RELOCATIONS', '.idata': 'IMPORT',
        '.edata': 'EXPORT', '.bss': 'BSS', '.pdata': 'EXCEPTION',
    }

    IMAGE_FILE_MACHINE = {
        0x014c: 'i386', 0x8664: 'AMD64', 0x01c0: 'ARM',
        0xaa64: 'ARM64', 0x0200: 'IA64',
    }

    IMAGE_DIRECTORY_ENTRY = {
        0: 'EXPORT', 1: 'IMPORT', 2: 'RESOURCE', 3: 'EXCEPTION',
        4: 'SECURITY', 5: 'BASERELOC', 6: 'DEBUG', 7: 'ARCHITECTURE',
        8: 'GLOBALPTR', 9: 'TLS', 10: 'LOAD_CONFIG',
        11: 'BOUND_IMPORT', 12: 'IAT', 13: 'DELAY_IMPORT',
        14: 'COM_DESCRIPTOR', 15: 'RESERVED',
    }

    def __init__(self, data: bytes):
        self.data = data
        self.dos_header: Dict[str, Any] = {}
        self.coff_header: Dict[str, Any] = {}
        self.optional_header: Dict[str, Any] = {}
        self.sections: List[Dict[str, Any]] = []
        self.imports: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
        self.resources: List[Dict[str, Any]] = []
        self.entry_point_rva = 0
        self.image_base = 0
        self.is_pe64 = False
        self._parse()

    def _parse(self):
        self._parse_dos_header()
        pe_offset = self.dos_header.get('e_lfanew', 0)
        coff_offset = pe_offset + 4
        if pe_offset + 4 > len(self.data) or self.data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        self._parse_coff_header(coff_offset)
        opt_offset = coff_offset + 20
        self._parse_optional_header(opt_offset)
        sec_offset = opt_offset + self.coff_header['SizeOfOptionalHeader']
        self._parse_sections(sec_offset)
        self._parse_imports()
        self._parse_exports()
        self._parse_resources()

    def _parse_dos_header(self):
        if len(self.data) < 64:
            raise ValueError("File too small for DOS header")
        magic = self.data[0:2]
        if magic != self.DOS_MAGIC:
            raise ValueError(f"Not a PE file: bad DOS magic {magic!r}")
        self.dos_header = {
            'e_magic': magic.hex(),
            'e_lfanew': struct.unpack_from('<I', self.data, 60)[0],
        }

    def _parse_coff_header(self, offset: int):
        if offset + 24 > len(self.data):
            raise ValueError("File truncated at COFF header")
        machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from(
            '<HHIIIHH', self.data, offset
        )
        self.coff_header = {
            'Machine': machine,
            'MachineName': self.IMAGE_FILE_MACHINE.get(machine, f'0x{machine:04x}'),
            'NumberOfSections': num_sections,
            'TimeDateStamp': struct.unpack_from('<I', self.data, offset + 4)[0],
            'PointerToSymbolTable': struct.unpack_from('<I', self.data, offset + 8)[0],
            'NumberOfSymbols': struct.unpack_from('<I', self.data, offset + 12)[0],
            'SizeOfOptionalHeader': opt_size,
            'Characteristics': struct.unpack_from('<H', self.data, offset + 16)[0],
        }

    def _parse_optional_header(self, offset: int):
        if offset + 2 > len(self.data):
            return
        magic = struct.unpack_from('<H', self.data, offset)[0]
        self.is_pe64 = (magic == 0x20b)
        if magic not in (0x10b, 0x20b):
            return
        if self.is_pe64:
            self._parse_optional_header_pe64(offset)
        else:
            self._parse_optional_header_pe32(offset)

    def _parse_optional_header_pe32(self, offset: int):
        if offset + 96 > len(self.data):
            return
        magic = struct.unpack_from('<H', self.data, offset)[0]
        linker_major, linker_minor = struct.unpack_from('<BB', self.data, offset + 2)
        size_code = struct.unpack_from('<I', self.data, offset + 4)[0]
        size_idata = struct.unpack_from('<I', self.data, offset + 8)[0]
        size_udata = struct.unpack_from('<I', self.data, offset + 12)[0]
        entry_rva = struct.unpack_from('<I', self.data, offset + 16)[0]
        base_of_code = struct.unpack_from('<I', self.data, offset + 20)[0]
        base_of_data = struct.unpack_from('<I', self.data, offset + 24)[0]
        image_base = struct.unpack_from('<I', self.data, offset + 28)[0]
        section_align = struct.unpack_from('<I', self.data, offset + 32)[0]
        file_align = struct.unpack_from('<I', self.data, offset + 36)[0]
        os_major, os_minor = struct.unpack_from('<HH', self.data, offset + 40)
        size_image = struct.unpack_from('<I', self.data, offset + 56)[0]
        size_headers = struct.unpack_from('<I', self.data, offset + 60)[0]
        checksum = struct.unpack_from('<I', self.data, offset + 64)[0]
        dll_chars = struct.unpack_from('<H', self.data, offset + 70)[0]
        self.entry_point_rva = entry_rva
        self.image_base = image_base
        directories = {}
        for i in range(16):
            d_off = offset + 96 + i * 8
            if d_off + 8 <= len(self.data):
                rva, size = struct.unpack_from('<II', self.data, d_off)
                name = self.IMAGE_DIRECTORY_ENTRY.get(i, f'DIR_{i}')
                if rva or size:
                    directories[name] = {'RVA': f'0x{rva:x}', 'Size': size}
        self.optional_header = {
            'Magic': 'PE32', 'LinkerVersion': f'{linker_major}.{linker_minor}',
            'SizeOfCode': size_code, 'SizeOfInitializedData': size_idata,
            'SizeOfUninitializedData': size_udata,
            'AddressOfEntryPoint': f'0x{entry_rva:x}',
            'BaseOfCode': f'0x{base_of_code:x}',
            'ImageBase': f'0x{image_base:x}',
            'SectionAlignment': section_align, 'FileAlignment': file_align,
            'SizeOfImage': size_image, 'SizeOfHeaders': size_headers,
            'Checksum': f'0x{checksum:08x}',
            'DllCharacteristics': f'0x{dll_chars:04x}',
            'DataDirectories': directories,
        }

    def _parse_optional_header_pe64(self, offset: int):
        if offset + 112 > len(self.data):
            return
        fields = struct.unpack_from('<HBBIIIIQQIIIIHHHHHHIIIIHH', self.data, offset)
        (linker_major, linker_minor, size_code, size_idata, size_udata,
         entry_rva, base_of_code,
         image_base, section_align, file_align,
         os_major, os_minor, _, _, _,
         size_image, size_headers, checksum,
         dll_chars) = fields
        self.entry_point_rva = entry_rva
        self.image_base = image_base
        dirs_offset = offset + 112
        num_dirs = min(16, struct.unpack_from('<I', self.data, dirs_offset)[0]) if dirs_offset + 4 <= len(self.data) else 0
        directories = {}
        for i in range(num_dirs):
            d_off = dirs_offset + 4 + i * 8
            if d_off + 8 <= len(self.data):
                rva, size = struct.unpack_from('<II', self.data, d_off)
                name = self.IMAGE_DIRECTORY_ENTRY.get(i, f'DIR_{i}')
                if rva or size:
                    directories[name] = {'RVA': f'0x{rva:x}', 'Size': size}
        self.optional_header = {
            'Magic': 'PE32+', 'LinkerVersion': f'{linker_major}.{linker_minor}',
            'SizeOfCode': size_code, 'SizeOfInitializedData': size_idata,
            'SizeOfUninitializedData': size_udata,
            'AddressOfEntryPoint': f'0x{entry_rva:x}',
            'ImageBase': f'0x{image_base:x}',
            'SectionAlignment': section_align, 'FileAlignment': file_align,
            'SizeOfImage': size_image, 'SizeOfHeaders': size_headers,
            'Checksum': f'0x{checksum:08x}',
            'DllCharacteristics': f'0x{dll_chars:04x}',
            'DataDirectories': directories,
        }

    def _parse_sections(self, offset: int):
        num = self.coff_header.get('NumberOfSections', 0)
        for i in range(num):
            s_off = offset + i * 40
            if s_off + 40 > len(self.data):
                break
            name_raw = self.data[s_off:s_off + 8]
            name = name_raw.split(b'\x00')[0].decode('ascii', errors='replace')
            virtual_size, virtual_addr, raw_size, raw_addr = struct.unpack_from(
                '<IIII', self.data, s_off + 8
            )
            characteristics = struct.unpack_from('<I', self.data, s_off + 36)[0]
            section_data = b''
            if raw_addr and raw_size and raw_addr + raw_size <= len(self.data):
                section_data = self.data[raw_addr:raw_addr + raw_size]
            entropy = self._shannon_entropy(section_data) if section_data else 0.0
            self.sections.append({
                'Name': name,
                'VirtualSize': virtual_size,
                'VirtualAddress': f'0x{virtual_addr:x}',
                'SizeOfRawData': raw_size,
                'PointerToRawData': f'0x{raw_addr:x}',
                'Characteristics': f'0x{characteristics:08x}',
                'Flags': self._section_flags(characteristics),
                'Entropy': round(entropy, 4),
            })

    def _section_flags(self, chars: int) -> List[str]:
        flags = []
        flag_bits = [
            (0x00000020, 'CODE'), (0x00000040, 'INITIALIZED_DATA'),
            (0x00000080, 'UNINITIALIZED_DATA'), (0x20000000, 'EXECUTE'),
            (0x40000000, 'READ'), (0x80000000, 'WRITE'),
        ]
        for bit, name in flag_bits:
            if chars & bit:
                flags.append(name)
        return flags

    def _rva_to_offset(self, rva: int) -> Optional[int]:
        for sec in self.sections:
            va = int(sec['VirtualAddress'], 16)
            raw = int(sec['PointerToRawData'], 16)
            if va <= rva < va + sec['SizeOfRawData']:
                return raw + (rva - va)
        return None

    def _parse_imports(self):
        dirs = self.optional_header.get('DataDirectories', {})
        imp_dir = dirs.get('IMPORT')
        if not imp_dir:
            return
        rva = int(imp_dir['RVA'], 16)
        offset = self._rva_to_offset(rva)
        if offset is None:
            return
        ptr_size = 4 if not self.is_pe64 else 8
        fmt = '<I' if not self.is_pe64 else '<Q'
        while offset + 20 <= len(self.data):
            orig_first_rva, _, _, name_rva, first_rva = struct.unpack_from(
                '<IIIII', self.data, offset
            )
            offset += 20
            if name_rva == 0:
                break
            name_off = self._rva_to_offset(name_rva)
            if name_off is None:
                continue
            dll_name = self._read_cstring(name_off)
            functions = []
            iat_off = self._rva_to_offset(first_rva)
            if iat_off is not None:
                while iat_off + ptr_size <= len(self.data):
                    entry = struct.unpack_from(fmt, self.data, iat_off)[0]
                    iat_off += ptr_size
                    if entry == 0:
                        break
                    if self.is_pe64 and entry & (1 << 63):
                        ord_num = entry & 0xFFFF
                        functions.append({'name': f'ordinal_{ord_num}', 'by_ordinal': True})
                    elif not self.is_pe64 and entry & (1 << 31):
                        ord_num = entry & 0xFFFF
                        functions.append({'name': f'ordinal_{ord_num}', 'by_ordinal': True})
                    else:
                        hint_rva = entry & 0x7FFFFFFF
                        hint_off = self._rva_to_offset(hint_rva)
                        if hint_off and hint_off + 2 < len(self.data):
                            hint = struct.unpack_from('<H', self.data, hint_off)[0]
                            func_name = self._read_cstring(hint_off + 2)
                            functions.append({'name': func_name, 'hint': hint})
            self.imports.append({'DLL': dll_name, 'Functions': functions})

    def _parse_exports(self):
        dirs = self.optional_header.get('DataDirectories', {})
        exp_dir = dirs.get('EXPORT')
        if not exp_dir:
            return
        rva = int(exp_dir['RVA'], 16)
        offset = self._rva_to_offset(rva)
        if offset is None or offset + 40 > len(self.data):
            return
        _, _, _, name_rva, ordinal_base, num_funcs, num_names = struct.unpack_from(
            '<IIIIIIII', self.data, offset
        )
        addr_table_rva = struct.unpack_from('<I', self.data, offset + 28)[0]
        name_ptr_rva = struct.unpack_from('<I', self.data, offset + 32)[0]
        ordinal_table_rva = struct.unpack_from('<I', self.data, offset + 36)[0]
        fmt = '<I' if not self.is_pe64 else '<Q'
        ptr_size = 4 if not self.is_pe64 else 8
        for i in range(min(num_funcs, 1000)):
            func_rva_off = self._rva_to_offset(addr_table_rva + i * ptr_size)
            if func_rva_off is None or func_rva_off + ptr_size > len(self.data):
                break
            func_rva = struct.unpack_from(fmt, self.data, func_rva_off)[0]
            ordinal = ordinal_base + i
            name_str = f'ordinal_{ordinal}'
            if name_ptr_rva and i < num_names:
                np_off = self._rva_to_offset(name_ptr_rva + i * ptr_size)
                if np_off and np_off + ptr_size <= len(self.data):
                    fn_rva = struct.unpack_from(fmt, self.data, np_off)[0]
                    fn_off = self._rva_to_offset(fn_rva)
                    if fn_off:
                        name_str = self._read_cstring(fn_off)
            self.exports.append({
                'Name': name_str, 'Ordinal': ordinal, 'RVA': f'0x{func_rva:x}'
            })

    def _parse_resources(self):
        dirs = self.optional_header.get('DataDirectories', {})
        res_dir = dirs.get('RESOURCE')
        if not res_dir:
            return
        rva = int(res_dir['RVA'], 16)
        offset = self._rva_to_offset(rva)
        if offset is None or offset + 16 > len(self.data):
            return
        characteristics, timedate, major_ver, minor_ver = struct.unpack_from(
            '<IIHH', self.data, offset
        )
        num_named = struct.unpack_from('<H', self.data, offset + 12)[0]
        num_id = struct.unpack_from('<H', self.data, offset + 14)[0]
        self.resources.append({
            'Type': 'RESOURCE_DIRECTORY', 'NamedEntries': num_named,
            'IdEntries': num_id, 'TimeDateStamp': timedate,
        })

    def _read_cstring(self, offset: int, max_len: int = 256) -> str:
        end = self.data.find(b'\x00', offset, offset + max_len)
        if end == -1:
            end = offset + max_len
        return self.data[offset:end].decode('ascii', errors='replace')

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def compute_hashes(self) -> Dict[str, str]:
        return {
            'MD5': hashlib.md5(self.data).hexdigest(),
            'SHA1': hashlib.sha1(self.data).hexdigest(),
            'SHA256': hashlib.sha256(self.data).hexdigest(),
        }

    def compute_import_hash(self) -> str:
        """Fuzzy import hash: normalized DLL+func names -> SHA256."""
        parts = []
        for imp in sorted(self.imports, key=lambda x: x['DLL'].lower()):
            dll = imp['DLL'].lower()
            funcs = sorted(f['name'].lower() for f in imp['Functions'])
            parts.append(dll + ':' + ','.join(funcs))
        combined = '|'.join(parts)
        return hashlib.sha256(combined.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'DOS Header': self.dos_header,
            'COFF Header': self.coff_header,
            'Optional Header': self.optional_header,
            'EntryPoint': f'0x{self.entry_point_rva:x}',
            'Sections': self.sections,
            'Imports': self.imports,
            'Exports': self.exports,
            'Resources': self.resources,
            'Hashes': self.compute_hashes(),
            'ImportHash': self.compute_import_hash(),
        }


def build_minimal_pe(name: str = b'TEST', machine: int = 0x014c) -> bytes:
    """Build a minimal valid PE file for testing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 60, 64)
    pe_sig = b'PE\x00\x00'
    coff = bytearray(20)
    struct.pack_into('<HH', coff, 0, machine, 1)
    struct.pack_into('<HH', coff, 16, 224, 0xe0)
    opt32 = bytearray(224)
    struct.pack_into('<H', opt32, 0, 0x10b)
    struct.pack_into('<I', opt32, 16, 0x1000)
    struct.pack_into('<I', opt32, 28, 0x00400000)
    struct.pack_into('<I', opt32, 32, 0x1000)
    struct.pack_into('<I', opt32, 36, 0x200)
    struct.pack_into('<I', opt32, 56, 0x10000)
    struct.pack_into('<I', opt32, 60, 0x200)
    struct.pack_into('<I', opt32, 92, 16)
    section = bytearray(40)
    section[0:6] = b'.text\x00'
    struct.pack_into('<II', section, 8, 0x100, 0x1000)
    struct.pack_into('<II', section, 16, 0x200, 0x200)
    struct.pack_into('<I', section, 36, 0x60000020)
    code = bytes(0x100)
    return bytes(dos_header + pe_sig + coff + opt32 + section + code)


def main():
    parser = argparse.ArgumentParser(
        description='M7 - PE File Analyzer',
        epilog='Educational tool for studying Portable Executable file format.'
    )
    parser.add_argument('pe_file', nargs='?', help='Path to PE file to analyze')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--output', '-o', help='Write JSON report to file')
    parser.add_argument('--demo', action='store_true', help='Run offline demo with crafted PE fixture')
    args = parser.parse_args()

    if args.demo:
        print("=== M7 - PE File Analyzer (Demo Mode) ===")
        pe_data = build_minimal_pe()
        p = PEParser(pe_data)
        result = p.to_dict()
        print(f"  Machine: {result['COFF Header']['MachineName']}")
        print(f"  Sections: {len(result['Sections'])}")
        for sec in result['Sections']:
            print(f"    {sec['Name']:10s} VA={sec['VirtualAddress']} VS={sec['VirtualSize']} "
                  f"Entropy={sec['Entropy']} Flags={'|'.join(sec['Flags'])}")
        print(f"  Imports: {len(result['Imports'])} DLLs")
        for imp in result['Imports']:
            print(f"    {imp['DLL']}: {len(imp['Functions'])} functions")
        print(f"  Exports: {len(result['Exports'])}")
        print(f"  Entry: {result['EntryPoint']}")
        print(f"  Hashes: {result['Hashes']['SHA256'][:32]}...")
        print(f"  ImportHash: {result['ImportHash'][:32]}...")
        if args.json or args.output:
            report = {'tool': 'm7-pe-analyzer', 'demo': True, 'analysis': result}
            if args.output:
                os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\nReport written to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        print("\nDemo complete. Exit 0.")
        return 0

    if not args.pe_file:
        parser.print_help()
        return 1

    path = args.pe_file
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    with open(path, 'rb') as f:
        data = f.read()

    try:
        p = PEParser(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    result = p.to_dict()
    if args.json or args.output:
        report = {'tool': 'm7-pe-analyzer', 'file': path, 'size': len(data), 'analysis': result}
        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report written to {args.output}")
        else:
            print(json.dumps(report, indent=2))
    else:
        print(f"=== M7 - PE File Analyzer ===")
        print(f"File: {path} ({len(data)} bytes)")
        print(f"Machine: {result['COFF Header']['MachineName']}")
        print(f"Sections:")
        for sec in result['Sections']:
            print(f"  {sec['Name']:10s} VA={sec['VirtualAddress']} VS={sec['VirtualSize']} "
                  f"RS={sec['SizeOfRawData']} Entropy={sec['Entropy']} "
                  f"Flags={'|'.join(sec['Flags'])}")
        print(f"Imports: {len(result['Imports'])} DLLs")
        for imp in result['Imports']:
            print(f"  {imp['DLL']}: {len(imp['Functions'])} functions")
        print(f"Exports: {len(result['Exports'])}")
        print(f"Entry: {result['EntryPoint']}")
        print(f"MD5:    {result['Hashes']['MD5']}")
        print(f"SHA1:   {result['Hashes']['SHA1']}")
        print(f"SHA256: {result['Hashes']['SHA256']}")
        print(f"ImportHash: {result['ImportHash']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
