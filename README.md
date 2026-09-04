# M7 — PE File Analyzer

A portable executable (PE) file analysis tool for malware/forensics research.

## Overview

This project implements a PE file parser that:
- Parses the DOS and NT headers
- Dumps file/optional header fields
- Extracts and analyzes PE sections
- Parses the import table (DLLs and functions)
- Computes hashes (MD5/SHA1/SHA256)
- Computes per-section Shannon entropy

## Features

- **Header parsing**: DOS, COFF file header, optional header (PE32/PE32+)
- **Import table**: DLL names and imported functions
- **Section analysis**: virtual/raw size, flags, entropy
- **Entropy**: detects packed/encrypted sections (high entropy)
- **Hashing**: MD5, SHA1, SHA256

## Usage

```bash
python3 pe_analyzer.py sample.exe
```

## Example Output

```
=== M7 - PE File Analyzer ===
File: sample.exe
Size: 204800 bytes

-- Hashes --
  MD5: 5d41402abc4b2a76b9719d911017c592
  ...

-- Sections --
  .text      VA=0x1000      VS=18240 RS=18432 Entropy=6.5211 CODE
  .rdata     VA=0x6000      VS=2048  RS=2048  Entropy=5.0012 INITIALIZED_DATA
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
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
