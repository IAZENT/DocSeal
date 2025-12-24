# DocSeal

DocSeal is a small, educational Python project demonstrating a minimal Certificate Authority (CA), certificate management, revocation handling, a keystore, and document sealing (signing/verification) utilities. It is intended as a coursework sandbox for learning PKI concepts and applied cryptography in Python.

Key ideas: issuance, signing, verification, revocation, and safe key storage.

## Features

- CA: create and manage root and intermediate certificates, sign CSRs.
- Keystore: persistent storage for private keys and certificates.
- Revocation: mark certificates as revoked and list revoked entries.
- Crypto helpers: signing and verification utilities for documents.
- CLI/GUI entrypoints: simple runnable interfaces in the source tree.

## Requirements

- Python 3.10+
- See `pyproject.toml` for declared dependencies.

## Quick Start

1. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
# or install in editable/packaged form
pip install .
```

3. Run the CLI entrypoint (if present):

```bash
python -m docseal
# or
python src/docseal/main.py
```

4. Run tests:

```bash
pytest -q
```

## Example Usage (illustrative)

- Create a root CA (example command — check `src/docseal/main.py` for exact flags):

```bash
docseal ca create-root --name "DocSeal Root" --out root.pem
```

- Issue a leaf certificate:

```bash
docseal ca issue --subject "user@example.com" --ca root.pem --out user.crt
```

- Sign a document:

```bash
docseal sign --key user.key --in report.pdf --out report.sig
```

- Verify a signature:

```bash
docseal verify --cert user.crt --in report.pdf --sig report.sig
```

Replace the above sample commands with the actual CLI flags implemented in `src/docseal/main.py`.

## Project Layout

- Code: [src/docseal](src/docseal)
- CA module: [src/docseal/ca](src/docseal/ca)
- Keystore: [src/docseal/keystore](src/docseal/keystore)
- GUI: [src/docseal/gui](src/docseal/gui)
- Tests: [tests](tests)

## Development

- Run tests:

```bash
pytest -q
```

- Formatting and linting (if configured):

```bash
ruff check .
ruff format .
mypy src  # if type-checking configured
```

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

