from datetime import datetime, timezone
from typing import Any, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def _utc_property(cert: x509.Certificate, name: str) -> datetime:
    """Return a timezone-aware UTC datetime for a certificate validity property.

    Uses the newer <name>_utc attribute if available, otherwise falls back to
    the older property and converts to UTC.
    """
    utc_name = f"{name}_utc"
    if hasattr(cert, utc_name):
        return cast(datetime, getattr(cert, utc_name))

    val = cast(datetime, getattr(cert, name))
    # Some cryptography versions return naive datetimes; ensure timezone-aware
    if val.tzinfo is None:
        return val.replace(tzinfo=timezone.utc)
    return val.astimezone(timezone.utc)


def validate_certificate_chain(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
) -> bool:
    """
    Verify that `cert` was issued and signed by `ca_cert`.

    Supports common CA key types (RSA, ECDSA, DSA, Ed25519/Ed448).
    """
    try:
        # Signature verification is sufficient — don't require strict issuer
        # object equality which can be brittle across name encodings.
        public_key: Any = ca_cert.public_key()

        alg = cert.signature_hash_algorithm

        # RSA: requires padding + hash algorithm
        if isinstance(public_key, RSAPublicKey):
            if alg is None:
                return False
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                alg,
            )

        # ECDSA
        elif isinstance(public_key, EllipticCurvePublicKey):
            if alg is None:
                return False
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(alg),
            )

        # DSA
        elif isinstance(public_key, DSAPublicKey):
            if alg is None:
                return False  # pragma: no cover - defensive guard
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                alg,
            )

        # EdDSA (no separate hash algorithm)
        elif isinstance(public_key, (Ed25519PublicKey, Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)

        else:
            return False  # Unsupported CA key type

        # Issuer check: compare RFC4514 strings to be robust across encodings
        if cert.issuer.rfc4514_string() != ca_cert.subject.rfc4514_string():
            return False

        # Validity window check (use UTC-aware properties)
        now = datetime.now(timezone.utc)
        not_before = _utc_property(cert, "not_valid_before")
        not_after = _utc_property(cert, "not_valid_after")
        if now < not_before or now > not_after:
            return False

        return True

    except InvalidSignature:
        return False
    except Exception:
        return False


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    is_revoked: bool,
) -> bool:
    """Validate a single certificate against a CA cert and revocation status.

    Returns False if the certificate is revoked or signature/validity checks fail.
    """
    if is_revoked:
        return False

    # Reuse the existing chain validation for signature/issuer/validity checks.
    return validate_certificate_chain(cert, ca_cert)
