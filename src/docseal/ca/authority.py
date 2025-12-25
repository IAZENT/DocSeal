"""Certificate Authority utilities for DocSeal.

Contains CertificateAuthority which can initialize a self-signed
root CA and export it as PKCS#12.
"""

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# PKCS12 serializer lives in a submodule in some cryptography versions.
serialize_key_and_certificates: Optional[Callable[..., bytes]] = None
try:
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )
except Exception:
    serialize_key_and_certificates = None

# When running the module directly, relative imports may fail. Try the
# package-relative import first and fall back to adding ``src/`` to
# sys.path and importing absolutely.
try:
    from .exceptions import CAAlreadyInitialized, CAInitializationError
except Exception:
    import os
    import sys

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    from docseal.ca.exceptions import CAAlreadyInitialized, CAInitializationError


class CertificateAuthority:
    """Simple in-memory Certificate Authority for tests and tooling."""

    def __init__(self) -> None:
        # Use Optional types so static checkers know these may be None at
        # construction and later hold concrete values.
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._certificate: Optional[x509.Certificate] = None

    def initialize(self, password: str) -> None:
        """Create a new self-signed CA certificate and private key."""
        if self._private_key is not None:
            raise CAAlreadyInitialized("CA already initialized")

        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal University"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "DocSeal Root CA"),
                ]
            )

            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(private_key, hashes.SHA256())
            )

            self._private_key = private_key
            self._certificate = certificate

        except Exception as exc:
            raise CAInitializationError(str(exc)) from exc

    def export_pkcs12(self, password: str) -> bytes:
        """Export the CA as a PKCS#12 archive protected by ``password``."""
        if not self._private_key or not self._certificate:
            raise CAInitializationError("CA not initialized")

        if serialize_key_and_certificates is None:
            raise CAInitializationError(
                "PKCS12 serialization is not supported by the installed "
                "cryptography package"
            )

        return serialize_key_and_certificates(
            name=b"docseal-root-ca",
            key=self._private_key,
            cert=self._certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            ),
        )


__all__ = ["CertificateAuthority"]


if __name__ == "__main__":
    # Helper for local manual testing: prefer a password from the environment
    # or generate a short token.
    import os
    import secrets
    import sys

    password = os.environ.get("DOCSEAL_TEST_PASSWORD") or secrets.token_urlsafe(16)

    ca = CertificateAuthority()
    try:
        ca.initialize(password=password)
    except CAAlreadyInitialized:
        pass

    try:
        data = ca.export_pkcs12(password=password)
    except CAInitializationError as exc:
        print("Error exporting PKCS12:", exc, file=sys.stderr)
        sys.exit(1)

    out_path = "docseal-root-ca.p12"
    with open(out_path, "wb") as f:
        f.write(data)

    print(f"Wrote PKCS#12 to {out_path}")
