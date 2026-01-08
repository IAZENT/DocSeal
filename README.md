# DocSeal

DocSeal is a secure academic document signing and verification system built with Python. It provides a complete PKI infrastructure including Certificate Authority (CA) management, certificate issuance, revocation handling, and cryptographic document signing with full chain validation.

**Key capabilities**: Certificate issuance, document signing, signature verification, revocation management, and audit logging.

## Features

- **Certificate Authority**: Create and manage a self-signed root CA and issue end-entity certificates
- **Document Signing**: Create detached cryptographic signatures with embedded certificates
- **Signature Verification**: Validate signatures with full certificate chain verification
- **Revocation Management**: Mark certificates as revoked and maintain a revocation list
- **Audit Logging**: Forensic-ready logging of all verification attempts
- **CLI Interface**: Unix-like command-line interface for all operations
- **Test Coverage**: Comprehensive pytest-based test suite

## Requirements

- Python 3.11+
- cryptography >= 42.0
- pytest (for development)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/docseal.git
cd docseal
```

### 2. Set Up Environment

#### Option A: Using Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

#### Option B: System-wide Installation

```bash
pip install -r requirements.txt
```

### 3. Run DocSeal CLI

#### Option A: Direct Execution (Recommended)

**Linux/macOS:**
```bash
# Make script executable
chmod +x ./docseal

# Run commands
./docseal --help
```

**Windows:**
```cmd
# Run commands directly
docseal.bat --help

# Or simply (if .bat is in PATH)
docseal --help

# PowerShell users can use:
.\docseal.ps1 --help
```

#### Option B: Install as Package

```bash
pip install -e .
docseal --help
```

#### Option C: Using Python Module

```bash
PYTHONPATH=./src python -m docseal.cli.main --help
```

## Usage Examples

**Note:** Use `./docseal` on Linux/macOS, or `docseal` (or `docseal.bat`) on Windows.

### Initialize Certificate Authority

```bash
./docseal ca init          # Linux/macOS
docseal ca init            # Windows
# Enter a strong password when prompted
```

### Issue a Certificate

```bash
./docseal ca issue --name "Alice Registrar" --role "Registrar"
# Enter CA password, then certificate password
```

### Sign a Document

```bash
./docseal sign --doc transcript.pdf --cert alice_registrar.p12 --out transcript.sig
# Enter certificate password
```

### Verify a Signature

```bash
./docseal verify --doc transcript.pdf --sig transcript.sig --verbose
```

### Revoke a Certificate

```bash
./docseal ca revoke --serial 123456789 --reason "key-compromise"
```

### View CA Information

```bash
./docseal ca info
```

### List Revoked Certificates

```bash
./docseal ca list
```

## Complete Workflow Example

```bash
# Linux/macOS: use ./docseal
# Windows: use docseal or docseal.bat

# 1. Initialize CA
./docseal ca init

# 2. Issue certificate for registrar
./docseal ca issue --name "Alice Registrar" --role "Registrar"

# 3. Create a test document
echo "Student: John Doe\nGrade: A\nDate: 2026-01-08" > transcript.txt

# 4. Sign the document
./docseal sign --doc transcript.txt --cert alice_registrar.p12 --out transcript.sig

# 5. Verify the signature
./docseal verify --doc transcript.txt --sig transcript.sig --verbose

# 6. View CA details
./docseal ca info

# 7. (Optional) Revoke certificate if needed
./docseal ca revoke --serial <serial_number> --reason "terminated"
```

## Development

### Running Tests

```bash
# Run all tests
PYTHONPATH=./src pytest -v

# Run specific test file
PYTHONPATH=./src pytest tests/test_cli.py -v

# Run with coverage
PYTHONPATH=./src pytest --cov=docseal --cov-report=term-missing
```

### Code Quality Checks

```bash
# Format code with black
black .

# Check formatting
black --check .

# Lint with ruff
ruff check src/ tests/

# Type checking with mypy
mypy src/

# Security audit
pip-audit
bandit -r src/
```

### Project Structure

```
DocSeal/
├── src/docseal/
│   ├── audit/           # Audit logging
│   ├── ca/              # Certificate Authority
│   ├── cli/             # Command-line interface
│   ├── crypto/          # Signing and verification
│   └── utils/           # Validation utilities
├── tests/               # Test suite
├── docseal              # CLI wrapper (Linux/macOS)
├── docseal.bat          # CLI wrapper (Windows cmd)
├── docseal.ps1          # CLI wrapper (Windows PowerShell)
├── pyproject.toml       # Project configuration
├── requirements.txt     # Runtime dependencies
└── requirements-dev.txt # Development dependencies
```

## File Locations

DocSeal stores CA artifacts in your home directory:

- **CA Directory**: `~/.docseal/ca/`
- **CA Certificate (PKCS#12)**: `~/.docseal/ca/ca.p12`
- **CA Certificate (PEM)**: `~/.docseal/ca/ca.pem`
- **Revocation List**: `~/.docseal/ca/crl.json`
- **Audit Log**: `~/.docseal/ca/audit.log`

## CLI Commands Reference

### Certificate Authority Commands

| Command | Description |
|---------|-------------|
| `docseal ca init` | Initialize a new Certificate Authority |
| `docseal ca issue` | Issue a new certificate |
| `docseal ca revoke` | Revoke a certificate |
| `docseal ca list` | List all revoked certificates |
| `docseal ca info` | Display CA information |

### Document Commands

| Command | Description |
|---------|-------------|
| `docseal sign` | Sign a document |
| `docseal verify` | Verify a document signature |

### Common Options

- `--help`: Show help message
- `--version`: Show version information
- `--verbose`: Show detailed output (verify command)
- `--no-revocation-check`: Skip revocation checking (verify command)
- `--no-audit`: Skip audit logging (verify command)

## Security Considerations

- **Password Security**: Use strong passwords for CA and certificates (minimum 8 characters)
- **Key Storage**: Private keys are stored encrypted in PKCS#12 format
- **Audit Trail**: All verification attempts are logged to `audit.log`
- **Revocation**: Always check certificate revocation status during verification
- **File Permissions**: Ensure CA files have appropriate permissions (600 recommended)

## Troubleshooting

### "CA not initialized"
**Solution**: Run `./docseal ca init` first

### "Document not found"
**Solution**: Check that the file path is correct

### "Invalid certificate or password"
**Solution**: Verify the password is correct

### "Certificate revoked"
**Solution**: Certificate has been revoked, check with `./docseal ca list`

### "SIGNATURE INVALID"
**Solution**: Document may have been modified, certificate expired, or signature corrupted

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repo.
2. Create a feature branch.
3. Add tests for your change.
4. Open a pull request with a clear description.

## License

See the project `LICENSE` file.

## Contact

Open an issue in this repository for questions or feature requests.

