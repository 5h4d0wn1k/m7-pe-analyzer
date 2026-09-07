# M7 — PE File Analyzer

A hand-written Portable Executable (PE) file parser for malware research and forensics education.

## Overview

This project implements a PE file parser from scratch using only the Python standard library. It parses DOS/COFF/PE32/PE32+ headers, sections, imports, exports, resources, and computes fuzzy import hashes for similarity detection.

## Features

- **Header parsing**: DOS stub, COFF file header, optional header (PE32 and PE32+)
- **Section analysis**: virtual/raw addresses, sizes, characteristics, Shannon entropy
- **Import table**: DLL names, function names with hints, ordinal imports
- **Export table**: function names, ordinals, RVAs
- **Resource directory**: directory entry counts and metadata
- **Hashing**: MD5, SHA1, SHA256 of the full file
- **Fuzzy import hash**: normalized DLL+function names -> SHA256 for similarity detection
- **Minimal PE builder**: create crafted PE fixtures for testing

## Usage

```bash
# Analyze a PE file
python3 pe_analyzer.py sample.exe

# JSON output
python3 pe_analyzer.py sample.exe --json

# Save report
python3 pe_analyzer.py sample.exe -o reports/analysis.json

# Offline demo with crafted fixture
python3 pe_analyzer.py --demo
python3 pe_analyzer.py --demo --json
```

## Example Output

```
=== M7 - PE File Analyzer ===
File: sample.exe (204800 bytes)
Machine: i386
Sections:
  .text      VA=0x1000 VS=18240 RS=18432 Entropy=6.5211 Flags=CODE|EXECUTE|READ
Imports: 3 DLLs
  KERNEL32.dll: 12 functions
  USER32.dll: 5 functions
  MSVCRT.dll: 8 functions
Exports: 0
Entry: 0x1000
MD5:    5d41402abc4b2a76b9719d911017c592
SHA256: a948904f2f0f479b8f8564e9d718d8a7...
ImportHash: e3b0c44298fc1c149afbf4c8996fb924...
```

## Tests

```bash
python -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `--demo` offline and verify exit code 0
2. Parse a known PE32 binary and verify header field values
3. Parse a known PE32+ binary and verify 64-bit parsing
4. Verify import hash is deterministic across runs
5. Verify entropy is 0.0 for all-zero section data
6. Verify hashes match `sha256sum` / `md5sum` on the same file

## Metrics

- Hand-written parser: ~300 lines, zero external dependencies
- Supports PE32 and PE32+ formats
- Parses imports (by name and ordinal), exports, and resource directories
- Shannon entropy computed per section
- Fuzzy import hash for binary similarity detection
- Minimal PE fixture builder for deterministic testing

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Analysis of binaries you do not own or have authorization to test may be illegal
- This tool should ONLY be used on files you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Digital Millennium Copyright Act (DMCA)**: Circumvention of technological protection measures may be illegal
- **State Laws**: Many states have additional computer crime statutes

### Acceptable Use
- Malware research in controlled lab environments
- Reverse engineering for authorized security assessments
- Academic research and education
- CTF competitions and challenges
- Forensic analysis of your own systems

### Prohibited Use
- Analyzing binaries belonging to others without authorization
- Using findings to gain unauthorized access
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
