# DocSeal

DocSeal is a small, educational Python project demonstrating a minimal in-memory Certificate Authority (CA), certificate issuance, revocation handling, certificate validation utilities, and detached document signing. It is intended as a coursework sandbox for learning PKI concepts and applied cryptography in Python.

Key ideas: issuance, signing, verification, revocation, and safe key storage.

## Features

- CA: create and manage a self-signed root certificate and issue end-entity certificates.
- Revocation: mark certificates as revoked and generate a signed CRL.
- Crypto helpers: certificate chain validation and detached document signing.
- Tests: pytest-based unit tests for CA initialization, issuance, revocation, validation, and document signing.

## Requirements

- Python 3.11+
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

