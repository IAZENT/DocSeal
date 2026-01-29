"""Signature verification for envelopes."""

from dataclasses import dataclass
from typing import Iterable, Optional, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .envelope import DsealEnvelope


@dataclass
class VerificationResult:
    """Result of signature verification."""

    is_valid: bool
    signer_name: Optional[str] = None
    signer_email: Optional[str] = None
    signature_timestamp: Optional[str] = None
    is_encrypted: bool = False
    error_message: Optional[str] = None


def verify_envelope(
    envelope: DsealEnvelope,
    trusted_certs: Optional[list[x509.Certificate]] = None,
) -> VerificationResult:
    """Verify signature on envelope.

    Supports verification of:
    - Signatures on plaintext payload
    - Signatures on encrypted payload (envelope verification)

    Args:
        envelope: Envelope to verify
        trusted_certs: List of trusted certificates for validation

    Returns:
        VerificationResult with verification status
    """
    if envelope.signature is None:
        return VerificationResult(
            is_valid=False,
            error_message="No signature found in envelope",
            is_encrypted=envelope.metadata.payload_encrypted,
        )

    if envelope.signer_cert is None:
        return VerificationResult(
            is_valid=False,
            error_message="No signer certificate found in envelope",
            is_encrypted=envelope.metadata.payload_encrypted,
        )

    try:
        # Load signer certificate from PEM bytes
        if isinstance(envelope.signer_cert, bytes):
            signer_cert = x509.load_pem_x509_certificate(envelope.signer_cert)
        else:
            signer_cert = envelope.signer_cert

        # Get signer's public key from certificate
        public_key = signer_cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Unsupported public key type; RSA required")

        # Verify signature on payload
        if envelope.payload is None:
            raise ValueError("No payload to verify")

        public_key.verify(
            envelope.signature,
            envelope.payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Extract signer information
        signer_name = None
        signer_email = None

        # Try to get Common Name
        try:
            cn_attrs = signer_cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            if cn_attrs:
                signer_name = str(cn_attrs[0].value)
        except Exception:  # noqa: S110
            pass

        # Try to get email
        try:
            san = signer_cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_value = cast(Iterable[x509.GeneralName], san.value)
            for name in san_value:
                if isinstance(name, x509.RFC822Name):
                    signer_email = name.value
                    break
        except x509.ExtensionNotFound:
            pass

        # Optionally validate cert chain
        if trusted_certs:
            # Simple validation: signer cert must be explicitly trusted.
            cert_valid = any(signer_cert == trusted for trusted in trusted_certs)

            if not cert_valid:
                return VerificationResult(
                    is_valid=False,
                    signer_name=signer_name,
                    signer_email=signer_email,
                    error_message="Signer certificate not trusted",
                    is_encrypted=envelope.metadata.payload_encrypted,
                )

        return VerificationResult(
            is_valid=True,
            signer_name=signer_name,
            signer_email=signer_email,
            signature_timestamp=str(envelope.metadata.signature_timestamp),
            is_encrypted=envelope.metadata.payload_encrypted,
        )

    except InvalidSignature:
        return VerificationResult(
            is_valid=False,
            error_message="Signature verification failed - signature is invalid",
            is_encrypted=envelope.metadata.payload_encrypted,
        )
    except Exception as e:
        return VerificationResult(
            is_valid=False,
            error_message=f"Verification error: {str(e)}",
            is_encrypted=envelope.metadata.payload_encrypted,
        )
