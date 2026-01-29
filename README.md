# DocSeal — Secure Academic Document Signing & Verification

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)](#)

Comprehensive cryptographic solution for secure signing, encryption, and verification of academic documents. Production-ready GUI (PyQt6) and CLI with full-featured CA system. See [pyproject.toml](pyproject.toml) for current version.

**Quick Links**: [Installation](#installation) | [GUI Guide](#gui-guide) | [CLI Commands](#cli-reference) | [Python API](#python-api) | [Security](#security) | [Architecture](#architecture)

---

## Features

**Core**: RSA-PSS-SHA256 signing | AES-256-GCM encryption | Two-layer operations (sign+encrypt/decrypt+verify) | Tamper detection | Full CA system with revocation | Audit logging | X.509 certificates

**Interfaces**: 
- **GUI** (PyQt6): 6 operation tabs (Sign, Verify, Encrypt, Decrypt, Sign+Encrypt, Decrypt+Verify), CA management with dark/light themes
- **CLI**: 10+ commands with argparse, batch automation support
- **Python API**: DocSealService for programmatic use

**Format**: `.dseal` (ZIP-based with JSON metadata, plaintext/ciphertext payload, signatures, certificates)

**Security**: RSA-2048, AES-256-GCM, PBKDF2 key derivation, certificate validation, CRL checking, audit trails

---

## Installation

**Requirements**: Python 3.11+ | OpenSSL dev headers | Linux/macOS/Windows

```bash
# Clone & setup
git clone <repo-url> && cd docseal
python3 -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Optional: dev dependencies
pip install -r requirements-dev.txt

# Install package
pip install -e .

# Verify
docseal --help && docseal-gui
```

---

## Quick Start

### GUI (Recommended)
```bash
docseal-gui
```
Navigate: **CA Tab** → Init CA → Issue Certificate → Use Sign/Verify/Encrypt/Decrypt tabs. All intuitive with real-time feedback, dark/light theme support.

### CLI
```bash
docseal ca init                                              # Initialize CA (prompts for password)
docseal ca issue --name "Alice" --role "Registrar"          # Issue certificate
docseal sign --input doc.pdf --cert alice.p12 --output doc.dseal    # Sign
docseal verify --envelope doc.dseal --verbose               # Verify
docseal encrypt --input secret.pdf --cert recipient.pem --output secret.dseal
docseal decrypt --envelope secret.dseal --key recipient_key.pem
docseal ca list                                              # Show revoked certs
docseal ca revoke --serial <num> --reason "compromised"     # Revoke cert
```

### Python API
```python
from docseal.core.service import DocSealService
from docseal.core.envelope import DsealEnvelope
from cryptography import x509
from cryptography.hazmat.primitives import serialization

service = DocSealService()

# Load keys/certs
with open('key.pem', 'rb') as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
with open('cert.pem', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read())

# Sign
envelope = service.sign(b"document content", key, cert, description="Transcript")
with open('out.dseal', 'wb') as f:
    f.write(envelope.to_bytes())

# Verify
loaded = DsealEnvelope.from_bytes(open('out.dseal', 'rb').read())
result = service.verify(loaded, [cert])
print(f"Valid: {result.is_valid}, Signer: {result.signer_name}")

# Encrypt
encrypted = service.encrypt(b"confidential", recipient_cert, "Enrollment")

# Decrypt+Verify (two-layer)
signed_encrypted = service.sign_encrypt(b"doc", key, cert, recipient_cert)
decrypted, verify_result = service.decrypt_and_verify(signed_encrypted, recipient_key, [cert])
```

---

## GUI Guide

| Tab | Purpose | Steps |
|-----|---------|-------|
| **Sign** | Create signatures | Select doc → Choose cert (.p12) → Enter password → Click Sign → Save .dseal |
| **Verify** | Check authenticity | Select .dseal → Optionally add signer cert → Click Verify → View results (signer, timestamp, validity) |
| **Encrypt** | Secure sharing | Select doc → Choose recipient cert → Click Encrypt → Save .dseal |
| **Decrypt** | Unlock encrypted docs | Select .dseal → Choose your private cert → Enter password → Click Decrypt → Save plaintext |
| **Sign+Encrypt** | Confidential + authenticated | Doc → Your cert (sign) → Recipient cert (encrypt) → Click Sign & Encrypt |
| **Decrypt+Verify** | One-step auth + decrypt | .dseal → Your private cert → Signer cert → Click Decrypt & Verify → View results + plaintext |

**CA Sub-tabs**: 
- **Init CA**: Set CA password (8+ chars) → Creates keypair/self-signed cert
- **Issue Cert**: Name → Role → Validity days → Password → Generates .p12
- **Revoke**: Select from dropdown → View details → Reason → Confirm
- **List**: View all revoked certificates (serial, date, reason)
- **CA Info**: Display CA certificate details and counts

**Themes**: Menu → Toggle Light/Dark (default: Light)

---

## CLI Reference

```bash
# Certificate Authority
docseal ca init                                    # Initialize new CA
docseal ca issue --name NAME --role ROLE --valid-days DAYS    # Issue cert
docseal ca revoke --serial SERIAL --reason REASON # Revoke cert
docseal ca list                                    # List revoked certs
docseal ca info                                    # CA information

# Document Operations  
docseal sign --input FILE --cert CERT.p12 [--output FILE.dseal]        # Sign
docseal verify --envelope FILE.dseal [--cert CERT.pem] [--verbose]     # Verify
docseal encrypt --input FILE --cert RECIPIENT.pem [--output FILE.dseal] # Encrypt
docseal decrypt --envelope FILE.dseal --key KEY.pem [--output FILE]    # Decrypt
docseal sign-encrypt --input FILE --signer-cert SIGNER.p12 --recipient-cert RECIPIENT.pem
docseal decrypt-verify --envelope FILE.dseal --key KEY.pem --signer-cert SIGNER.pem

# Options
--verbose                   # Detailed output
--no-revocation-check       # Skip CRL check (verify only)
--help, --version           # Show help/version
```

---

## Python API

**Service Methods**:
- `sign(document: bytes, key, cert, description: str) → DsealEnvelope`
- `verify(envelope: DsealEnvelope, trusted_certs: list) → VerificationResult`
- `encrypt(document: bytes, recipient_cert, description: str) → DsealEnvelope`
- `decrypt(envelope: DsealEnvelope, key) → bytes`
- `sign_encrypt(document, signer_key, signer_cert, recipient_cert, desc) → DsealEnvelope`
- `decrypt_and_verify(envelope, recipient_key, trusted_certs) → (bytes, VerificationResult)`

**Envelope**: Serialize with `envelope.to_bytes()` | Deserialize with `DsealEnvelope.from_bytes(data)`

**Full Example**:
```python
from docseal.core.service import DocSealService
from docseal.core.envelope import DsealEnvelope
from cryptography import x509
from cryptography.hazmat.primitives import serialization

service = DocSealService()

# Two-layer secure transfer
signer_key = serialization.load_pem_private_key(open('signer_key.pem', 'rb').read(), None)
signer_cert = x509.load_pem_x509_certificate(open('signer_cert.pem', 'rb').read())
recipient_cert = x509.load_pem_x509_certificate(open('recipient_cert.pem', 'rb').read())

envelope = service.sign_encrypt(open('sensitive.pdf', 'rb').read(), signer_key, signer_cert, recipient_cert)
with open('secure.dseal', 'wb') as f:
    f.write(envelope.to_bytes())

# Recipient side
recipient_key = serialization.load_pem_private_key(open('recipient_key.pem', 'rb').read(), None)
loaded = DsealEnvelope.from_bytes(open('secure.dseal', 'rb').read())
document, result = service.decrypt_and_verify(loaded, recipient_key, [signer_cert])

if result.is_valid:
    print(f"✓ Verified from {result.signer_name} at {result.signature_timestamp}")
    with open('decrypted.pdf', 'wb') as f:
        f.write(document)
```

---

## File Format (.dseal)

ZIP archive structure:
```
metadata.json          # {"version": "1.0", "payload_encrypted": false/true, "signer_name": "...", 
                       #  "signature_timestamp": "...", "algorithms": {...}, ...}
payload.bin            # Original document or AES-256-GCM ciphertext
signature.bin          # RSA-PSS-SHA256 signature (optional)
signer_cert.pem        # Signer's X.509 certificate (if signed)
recipient_cert.pem     # Recipient's certificate (if encrypted)
encrypted_key.bin      # RSA-OAEP wrapped AES key (if encrypted)
```

---

## Certificate Authority System

**Overview**: Full X.509 CA for issuing/revoking certificates with forensic audit logging.

**How It Works**: 
1. Init CA → RSA-2048 keypair + self-signed cert stored in `~/.docseal/ca/`
2. Issue certs → CA signs certificates with subject/issuer in separate X.509 extensions
3. Maintain CRL → Track revoked certs in `crl.json`
4. Verify against CRL → All signature verifications check revocation status

**Files** (in `~/.docseal/ca/`):
- `ca.pem` - CA certificate (PEM)
- `ca_key.pem` - CA private key (encrypted)
- `crl.json` - Certificate revocation list
- `audit.log` - Forensic audit trail

**Revocation Workflow**:
```bash
docseal ca revoke --serial 123456789 --reason "key-compromise"
# Updates crl.json with {serial, date_revoked, reason}
# Future verifications with that cert will fail
```

---

## Architecture

**Layer Model**:
```
┌─────────────────────────────────────┐
│  GUI (PyQt6)    │    CLI (argparse) │
│  6 op tabs      │    10+ commands   │
│  CA mgmt        │    Batch support  │
│  Dark/light     │                   │
└────────┬────────────────┬───────────┘
         │                │
    ┌────▼────────────────▼────┐
    │   Service Layer           │
    │  (DocSealService)         │
    │  sign, verify, encrypt,   │
    │  decrypt, sign_encrypt,   │
    │  decrypt_verify, CRL check│
    └────┬─────────────────────┘
         │
    ┌────▼──────────────────────┐
    │ Core Cryptographic Ops    │
    │ signing.py (RSA-PSS)      │
    │ verification.py (sig+CRL) │
    │ encryption.py (AES-GCM)   │
    │ decryption.py (AES-GCM)   │
    │ envelope.py (ZIP format)  │
    └────┬─────────────────────┘
         │
    ┌────▼──────────────────────┐
    │  cryptography lib (v42+)  │
    │  RSA, AES, X.509, PBKDF2  │
    └──────────────────────────┘
```

**Module Map** (src/docseal/):
```
core/              # Cryptographic operations
├── service.py        (DocSealService API)
├── envelope.py       (.dseal ZIP format)
├── signing.py        (RSA-PSS creation)
├── verification.py   (RSA verification + CRL)
├── encryption.py     (AES-256-GCM + RSA wrap)
└── decryption.py     (AES-256-GCM operations)

ca/                # Certificate Authority
├── authority.py      (CertificateAuthority)
├── certificates.py   (X.509 generation/validation)
├── revocation.py     (CRL management)
└── exceptions.py     (CA errors)

cli/               # Command-line interface
├── main.py          (Entry point, command routing)
├── sign.py, verify.py, encrypt.py, decrypt.py, ca.py
└── colors.py        (Color output)

gui/               # Graphical interface
├── app.py           (Entry point)
├── main_window.py   (Main window frame)
├── tabs.py          (Operation tabs: Sign, Verify, Encrypt, Decrypt, etc.)
├── ca_tabs.py       (CA tabs: Init, Issue, Revoke, List, Info)
├── ca_manager.py    (CA GUI controller)
├── service_wrapper.py (GUI service wrapper with file I/O)
├── themes.py        (Light/dark themes)
└── styles.py        (CSS styling)

audit/             # Audit logging
└── logger.py        (Forensic logging)

utils/             # Utilities
└── validation.py    (Input validation)
```

---

## Testing

```bash
# Run tests
pip install -r requirements-dev.txt
pytest tests/ -v                                    # All tests
pytest tests/test_integration_*.py -v              # Integration only
pytest tests/test_cli_*.py -v                      # CLI only
pytest tests/test_ca_*.py -v                       # CA only
pytest tests/ --cov=src/docseal --cov-report=html # With coverage

# Generate test certificates (RSA-2048, X.509)
python scripts/generate_test_keys.py
# Creates: registrar, lecturers, students, employer with keys/certs

# Test scenarios: signing, encryption, tamper detection, multi-signer, 
# revocation, certificate validation, CLI parsing, GUI interaction
```

---

## File Locations

**CA Storage** (`~/.docseal/ca/`): `ca.pem`, `ca_key.pem`, `crl.json`, `audit.log`

**Working Files**: Documents/certificates anywhere; `.dseal` output to input dir or `--output` location

**Config**: Linux/macOS: `~/.docseal/` | Windows: `%USERPROFILE%\.docseal\`

---

## Security

**Algorithms**:
| Operation | Algorithm | Standard |
|-----------|-----------|----------|
| Signing | RSA-PSS-SHA256 | PKCS#1 v2.1 |
| Encryption | AES-256-GCM | NIST |
| Key Wrapping | RSA-OAEP | PKCS#1 v2.1 |
| Key Derivation | PBKDF2-SHA256 | PKCS#5 |
| Asym Keys | RSA-2048 | NIST |

**Threat Model**:
- ✓ **Signature tampering**: Detected (RSA-PSS verification fails)
- ✓ **Encrypted payload tampering**: Detected (GCM auth fails)
- ✓ **Wrong key decryption**: Fails (GCM auth fails)
- ✓ **Revoked cert use**: Detected (CRL check)
- ✓ **Timestamp authenticity**: TSA integration for certified timestamps (v2.0)
- ✓ **Multi-recipient**: Full multi-recipient encryption support (v2.0)
- ✓ **HSM support**: Hardware Security Module integration (v2.0)

**Best Practices**: Strong passwords (8+ chars, mixed case/numbers/symbols) | Protect private keys | Verify external documents | Always enable CRL checks | Review audit logs | Backup CA | Renew certs before expiry | Keep software updated

**Assumptions**: Trusted environment for key storage | Secure cert distribution | No external timestamp authority (v0.9) | No HSM (v0.9)

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| CA not initialized | `docseal ca init` or GUI CA → Init CA |
| Document/file not found | Check path exists, use absolute paths, verify filename |
| Invalid certificate/password | Re-enter password (case-sensitive), re-issue if forgotten |
| Certificate revoked | `docseal ca list` to check, use different cert |
| SIGNATURE INVALID | Document modified after signing, wrong cert, expired cert, corrupted file |
| Permission denied | Check `~/.docseal/ca/` permissions with `ls -la`, fix if needed |
| Out of memory | Close other apps, increase RAM, split large documents |
| GUI won't start | `pip install -e '.[gui]'`, check X11/Wayland (Linux) |
| CLI commands not found | `pip install -e .` again, or use `python -m docseal.cli.main` |

---

## Development

**Code Quality**:
```bash
mypy src/docseal --strict          # Type checking
ruff check src/                     # Linting
bandit -r src/docseal/             # Security audit
pytest tests/ --cov=src/docseal    # Coverage
```

**Contributing**: Fork → Feature branch → Add tests → Pass CI → PR

**Known v2.0 Limits**: Local-only CRL (no OCSP) | No WebUI yet

**v3.0 Roadmap**: OCSP integration | WebUI dashboard | Batch operations API | Blockchain notarization

---

## License

MIT - See [LICENSE](LICENSE)

**Support**: Open GitHub issues | Check existing issues | Review docs above

