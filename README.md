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

