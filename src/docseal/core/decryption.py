"""Decryption operations for encrypted envelopes."""

from cryptography.hazmat.primitives.asymmetric import rsa

from .encryption import decrypt_payload
from .envelope import DsealEnvelope


def decrypt_envelope(
    envelope: DsealEnvelope, recipient_key: rsa.RSAPrivateKey
) -> DsealEnvelope:
    """Decrypt envelope, return new envelope with plaintext payload."""
    if not envelope.metadata.payload_encrypted:
        raise ValueError("Envelope is not encrypted")

    if envelope.payload is None:
        raise ValueError("No payload to decrypt")

    plaintext = decrypt_payload(envelope.payload, recipient_key)

    # Create new envelope with decrypted content
    decrypted_envelope = DsealEnvelope()
    decrypted_envelope.metadata = envelope.metadata
    decrypted_envelope.metadata.payload_encrypted = False
    decrypted_envelope.payload = plaintext
    decrypted_envelope.signature = envelope.signature
    decrypted_envelope.signer_cert = envelope.signer_cert

    return decrypted_envelope
