"""Signing operations for documents."""

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .envelope import DsealEnvelope, EnvelopeMetadata


def sign_document(
    payload: bytes,
    signer_key: rsa.RSAPrivateKey,
    signer_cert: x509.Certificate,
    description: str = "",
) -> DsealEnvelope:
    """Sign a document using RSA-PSS with SHA256.

    Args:
        payload: Document bytes to sign
        signer_key: RSA private key for signing
        signer_cert: X.509 certificate of signer
        description: Optional description of signature

    Returns:
        DsealEnvelope with signature and plaintext payload
    """
    # Create signature
    signature = signer_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Create envelope metadata
    metadata = EnvelopeMetadata(
        version="0.9",
        payload_encrypted=False,
        signer_name=_extract_signer_name(signer_cert),
        signature_timestamp=datetime.now(timezone.utc),
        description=description,
        format_version="1.0",
    )

    # Create envelope
    envelope = DsealEnvelope()
    envelope.metadata = metadata
    envelope.payload = payload
    envelope.signature = signature
    # Store certificate as PEM bytes
    envelope.signer_cert = signer_cert.public_bytes(serialization.Encoding.PEM)

    return envelope


def _extract_signer_name(cert: x509.Certificate) -> str:
    """Extract human-readable name from certificate."""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass

    return "Unknown Signer"
