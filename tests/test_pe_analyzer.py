#!/usr/bin/env python3
"""Tests for M7 - PE File Analyzer."""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pe_analyzer import PEParser, build_minimal_pe


class TestBuildMinimalPE(unittest.TestCase):
    def test_builds_valid_size(self):
        pe = build_minimal_pe()
        self.assertGreaterEqual(len(pe), 64 + 4 + 20 + 224 + 40)

    def test_dos_magic(self):
        pe = build_minimal_pe()
        self.assertEqual(pe[0:2], b'MZ')

    def test_pe_signature(self):
        pe = build_minimal_pe()
        lfanew = struct.unpack_from('<I', pe, 60)[0]
        self.assertEqual(pe[lfanew:lfanew + 4], b'PE\x00\x00')


class TestPEParser(unittest.TestCase):
    def setUp(self):
        self.pe_data = build_minimal_pe()
        self.parser = PEParser(self.pe_data)

    def test_dos_header_parsed(self):
        self.assertEqual(self.parser.dos_header['e_magic'], '4d5a')

    def test_coff_header_machine(self):
        self.assertEqual(self.parser.coff_header['MachineName'], 'i386')

    def test_coff_num_sections(self):
        self.assertEqual(self.parser.coff_header['NumberOfSections'], 1)

    def test_optional_header_magic(self):
        self.assertEqual(self.parser.optional_header['Magic'], 'PE32')

    def test_entry_point(self):
        self.assertEqual(self.parser.entry_point_rva, 0x1000)

    def test_sections_parsed(self):
        self.assertEqual(len(self.parser.sections), 1)

    def test_section_name(self):
        self.assertEqual(self.parser.sections[0]['Name'], '.text')

    def test_section_entropy(self):
        ent = self.parser.sections[0]['Entropy']
        self.assertEqual(ent, 0.0)

    def test_section_flags(self):
        flags = self.parser.sections[0]['Flags']
        self.assertIn('CODE', flags)
        self.assertIn('EXECUTE', flags)
        self.assertIn('READ', flags)

    def test_imports_empty(self):
        self.assertEqual(len(self.parser.imports), 0)

    def test_exports_empty(self):
        self.assertEqual(len(self.parser.exports), 0)

    def test_compute_hashes(self):
        hashes = self.parser.compute_hashes()
        self.assertEqual(hashes['MD5'], hashlib.md5(self.pe_data).hexdigest())
        self.assertEqual(hashes['SHA256'], hashlib.sha256(self.pe_data).hexdigest())

    def test_import_hash_deterministic(self):
        h1 = self.parser.compute_import_hash()
        h2 = PEParser(self.pe_data).compute_import_hash()
        self.assertEqual(h1, h2)

    def test_import_hash_format(self):
        h = self.parser.compute_import_hash()
        self.assertEqual(len(h), 64)
        int(h, 16)

    def test_to_dict_keys(self):
        d = self.parser.to_dict()
        for key in ['DOS Header', 'COFF Header', 'Optional Header',
                     'Sections', 'Imports', 'Exports', 'Hashes', 'ImportHash']:
            self.assertIn(key, d)


class TestPEParserInvalid(unittest.TestCase):
    def test_too_small(self):
        with self.assertRaises(ValueError):
            PEParser(b'\x00' * 10)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            PEParser(b'XX' + b'\x00' * 62 + struct.pack('<I', 64) + b'\x00' * 64)


class TestPEParserDemo(unittest.TestCase):
    def test_demo_mode_exits_cleanly(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), 'pe_analyzer.py'), '--demo'],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn('Demo complete', result.stdout)


if __name__ == '__main__':
    unittest.main()
