# DocSeal CLI Quick Reference

## Installation & Setup

### Option 1: Direct execution (recommended for development)
```bash
# Make the script executable
chmod +x ./docseal

# Run commands
./docseal --help
```

### Option 2: Install as package
```bash
pip install -e .
docseal --help
```

### Option 3: Using Python module
```bash
PYTHONPATH=./src python -m docseal.cli.main --help
```

---

## Commands Overview

### Certificate Authority (CA) Commands

#### 1. Initialize CA
```bash
./docseal ca init
# Or with password flag:
./docseal ca init --password "strongpassword123"

# Force overwrite existing CA:
./docseal ca init --force
```

**What it does:**
- Creates self-signed root CA certificate
- Saves to `~/.docseal/ca/ca.p12` (PKCS#12)
- Exports PEM to `~/.docseal/ca/ca.pem`

---

#### 2. Issue Certificate
```bash
./docseal ca issue --name "John Doe" --role "Registrar"

# With custom validity:
./docseal ca issue --name "Jane Smith" --role "Dean" --validity 730

# Specify output path:
./docseal ca issue --name "Admin" --role "IT" --out admin.p12
```

**What it does:**
- Issues certificate signed by CA
- Requires CA password
- Saves as PKCS#12 bundle with private key

---

#### 3. Revoke Certificate
```bash
./docseal ca revoke --serial 123456789
# With reason:
./docseal ca revoke --serial 123456789 --reason "key-compromise"
```

**What it does:**
- Adds serial to revocation list
- Saves to `~/.docseal/ca/crl.json`

---

#### 4. List Revoked Certificates
```bash
./docseal ca list
```

---

#### 5. Show CA Information
```bash
./docseal ca info
```

---

### Signing Commands

#### Sign a Document
```bash
./docseal sign --doc transcript.pdf --cert john_doe.p12 --out transcript.sig

# With password flag:
./docseal sign --doc transcript.pdf --cert john_doe.p12 --out transcript.sig --password "certpass"
```

**What it does:**
- Creates detached signature
- Includes document hash, timestamp, signer certificate
- Outputs JSON signature file

---

### Verification Commands

#### Verify a Signature
```bash
./docseal verify --doc transcript.pdf --sig transcript.sig

# Specify CA certificate:
./docseal verify --doc transcript.pdf --sig transcript.sig --ca /path/to/ca.pem

# Verbose output:
./docseal verify --doc transcript.pdf --sig transcript.sig --verbose

# Skip revocation check:
./docseal verify --doc transcript.pdf --sig transcript.sig --no-revocation-check

# Skip audit logging:
./docseal verify --doc transcript.pdf --sig transcript.sig --no-audit
```

**What it does:**
- Verifies certificate chain
- Checks certificate expiry
- Checks revocation status
- Verifies document hash
- Verifies cryptographic signature
- Logs to `~/.docseal/ca/audit.log`

---

## Complete Workflow Example

```bash
# 1. Initialize CA
./docseal ca init
# Enter password: strongpass123

# 2. Issue certificate for registrar
./docseal ca issue --name "Alice Registrar" --role "Registrar"
# CA password: strongpass123
# Certificate password: alicepass

# 3. Create test document
echo "Student: John Doe, Grade: A" > transcript.txt

# 4. Sign document
./docseal sign --doc transcript.txt --cert alice_registrar.p12 --out transcript.sig
# Certificate password: alicepass

# 5. Verify signature
./docseal verify --doc transcript.txt --sig transcript.sig --verbose

# 6. Get CA info
./docseal ca info

# 7. (Optional) Revoke certificate
./docseal ca revoke --serial 123456789 --reason "terminated"

# 8. Check revoked certificates
./docseal ca list
```

---

## File Locations

- **CA Directory**: `~/.docseal/ca/`
- **CA PKCS#12**: `~/.docseal/ca/ca.p12`
- **CA PEM**: `~/.docseal/ca/ca.pem`
- **Revocation List**: `~/.docseal/ca/crl.json`
- **Audit Log**: `~/.docseal/ca/audit.log`

---

## Testing

```bash
# Run CLI tests
PYTHONPATH=./src pytest tests/test_cli.py -v

# Run all tests
PYTHONPATH=./src pytest -v

# Run with coverage
PYTHONPATH=./src pytest --cov=docseal --cov-report=term-missing
```

---

## Troubleshooting

### "CA not initialized"
Run `./docseal ca init` first.

### "Document not found"
Check file path is correct.

### "Invalid certificate or password"
Verify password is correct.

### "Certificate revoked"
Certificate has been revoked. Check `./docseal ca list`.

### "SIGNATURE INVALID"
Document may have been modified, certificate expired, or signature is corrupted.
