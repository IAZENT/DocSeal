"""High-level service layer for DocSeal operations.

Orchestrates signing, encryption, verification, and decryption operations.
All cryptographic logic is delegated to lower-level modules.
This is the primary interface for CLI and GUI.
"""

from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .decryption import decrypt_envelope
from .encryption import encrypt_document
from .envelope import DsealEnvelope
from .signing import sign_document
from .verification import VerificationResult, verify_envelope


@dataclass
class DocSealService:
    """Orchestrates all DocSeal operations."""

    def sign(
        self,
        payload: bytes,
        signer_key: rsa.RSAPrivateKey,
        signer_cert: x509.Certificate,
        description: str = "",
    ) -> DsealEnvelope:
        """
        Sign a document.

        Args:
            payload: Document bytes to sign
            signer_key: RSA private key for signing
            signer_cert: X.509 certificate of signer
            description: Optional description of signature

        Returns:
            DsealEnvelope with signed payload
        """
        return sign_document(payload, signer_key, signer_cert, description)

    def encrypt(
        self,
        payload: bytes,
        recipient_cert: x509.Certificate,
    ) -> DsealEnvelope:
        """
        Encrypt a document.

        Args:
            payload: Document bytes to encrypt
            recipient_cert: X.509 certificate of recipient

        Returns:
            DsealEnvelope with encrypted payload
        """
        return encrypt_document(payload, recipient_cert)

    def sign_encrypt(
        self,
        payload: bytes,
        signer_key: rsa.RSAPrivateKey,
        signer_cert: x509.Certificate,
        recipient_cert: x509.Certificate,
        description: str = "",
    ) -> DsealEnvelope:
        """
        Sign then encrypt a document (two-layer envelope).

        Args:
            payload: Document bytes to sign and encrypt
            signer_key: RSA private key for signing
            signer_cert: X.509 certificate of signer
            recipient_cert: X.509 certificate of recipient
            description: Optional description of signature

        Returns:
            DsealEnvelope with signed-encrypted payload
        """
        # Step 1: Sign plaintext
        signed_envelope = self.sign(payload, signer_key, signer_cert, description)

        # Step 2: Encrypt the signed envelope (as bytes)
        signed_bytes = signed_envelope.to_bytes()
        encrypted_envelope = self.encrypt(signed_bytes, recipient_cert)

        # Copy signature info to encrypted envelope
        encrypted_envelope.metadata.signer_name = signed_envelope.metadata.signer_name
        encrypted_envelope.metadata.signature_timestamp = (
            signed_envelope.metadata.signature_timestamp
        )
        encrypted_envelope.metadata.description = signed_envelope.metadata.description

        return encrypted_envelope

    def verify(
        self,
        envelope: DsealEnvelope,
        trusted_certs: Optional[list[x509.Certificate]] = None,
    ) -> VerificationResult:
        """
        Verify a signed envelope.

        Args:
            envelope: Envelope to verify
            trusted_certs: Optional list of trusted CA certificates for
                cert chain validation

        Returns:
            VerificationResult with verification status
        """
        return verify_envelope(envelope, trusted_certs)

    def decrypt(
        self,
        envelope: DsealEnvelope,
        recipient_key: rsa.RSAPrivateKey,
    ) -> DsealEnvelope:
        """
        Decrypt an encrypted envelope.

        Args:
            envelope: Envelope to decrypt
            recipient_key: RSA private key of recipient

        Returns:
            DsealEnvelope with decrypted payload
        """
        return decrypt_envelope(envelope, recipient_key)

    def decrypt_and_verify(
        self,
        envelope: DsealEnvelope,
        recipient_key: rsa.RSAPrivateKey,
        trusted_certs: Optional[list[x509.Certificate]] = None,
    ) -> tuple[DsealEnvelope, VerificationResult]:
        """
        Decrypt then verify a signed-encrypted envelope.

        Args:
            envelope: Envelope to decrypt and verify
            recipient_key: RSA private key of recipient
            trusted_certs: Optional list of trusted CA certificates

        Returns:
            Tuple of (decrypted_envelope, verification_result)
        """
        # Step 1: Decrypt envelope
        decrypted = self.decrypt(envelope, recipient_key)

        # Step 2: Check if decrypted payload is itself a serialized envelope
        # (sign_encrypt scenario: encrypted the serialized signed envelope)
        try:
            if decrypted.payload is None:
                raise ValueError("Decrypted payload is empty")
            inner_envelope = DsealEnvelope.from_bytes(decrypted.payload)
            # This is a nested signed-encrypted envelope
            result = self.verify(inner_envelope, trusted_certs)
            return inner_envelope, result
        except Exception:
            # Not a nested envelope, just verify the decrypted one
            result = self.verify(decrypted, trusted_certs)
            return decrypted, result
