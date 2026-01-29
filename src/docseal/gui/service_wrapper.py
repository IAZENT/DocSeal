"""GUI-specific service wrapper that handles file I/O and certificate loading.

This module provides a wrapper around DocSealService that:
- Handles file I/O operations
- Provides proper error handling
- Integrates with CA management
- Converts paths to/from strings
"""

from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..core.envelope import DsealEnvelope
from ..core.service import DocSealService
from ..core.verification import VerificationResult


class GUIDocSealService:
    """GUI service wrapper that handles file I/O and provides error handling."""

    def __init__(self):
        """Initialize the GUI service.

        Raises:
            RuntimeError: If core service initialization fails
        """
        try:
            self.core_service = DocSealService()
        except Exception as e:
            raise RuntimeError(f"Failed to initialize service: {str(e)}") from e

    def _load_document(self, path: Path) -> bytes:
        """Load a document from disk.

        Args:
            path: Path to document file

        Returns:
            Document content as bytes

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        if not isinstance(path, Path):
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Document not found: {path}")

        if not path.is_file():
            raise IOError(f"Not a file: {path}")

        try:
            return path.read_bytes()
        except Exception as e:
            raise IOError(f"Failed to read document: {str(e)}") from e

    def _load_private_key(self, path: Path):
        """Load a private key from disk.

        Args:
            path: Path to private key file (PEM format)

        Returns:
            Private key object

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If key format is invalid
        """
        if not isinstance(path, Path):
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")

        try:
            key_pem = path.read_bytes()
            return serialization.load_pem_private_key(key_pem, password=None)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {str(e)}") from e

    def _load_certificate(self, path: Path) -> x509.Certificate:
        """Load a certificate from disk.

        Args:
            path: Path to certificate file (PEM format)

        Returns:
            X.509 certificate object

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If certificate format is invalid
        """
        if not isinstance(path, Path):
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Certificate not found: {path}")

        try:
            cert_pem = path.read_bytes()
            return x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise ValueError(f"Failed to load certificate: {str(e)}") from e

    def _load_envelope(self, path: Path) -> DsealEnvelope:
        """Load an envelope from disk.

        Args:
            path: Path to envelope file

        Returns:
            Deserialized DsealEnvelope object

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If envelope format is invalid
        """
        if not isinstance(path, Path):
            path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Envelope not found: {path}")

        try:
            envelope_bytes = path.read_bytes()
            return DsealEnvelope.from_bytes(envelope_bytes)
        except Exception as e:
            raise ValueError(f"Failed to load envelope: {str(e)}") from e

    def _save_envelope(self, envelope: DsealEnvelope, path: Path) -> None:
        """Save an envelope to disk.

        Args:
            envelope: DsealEnvelope object to save
            path: Output path

        Raises:
            IOError: If file cannot be written
        """
        if not isinstance(path, Path):
            path = Path(path)

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(envelope.to_bytes())
        except Exception as e:
            raise IOError(f"Failed to save envelope: {str(e)}") from e

    def _save_document(self, data: bytes, path: Path) -> None:
        """Save document data to disk.

        Args:
            data: Document content as bytes
            path: Output path

        Raises:
            IOError: If file cannot be written
        """
        if not isinstance(path, Path):
            path = Path(path)

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except Exception as e:
            raise IOError(f"Failed to save document: {str(e)}") from e

    def sign(
        self,
        document_path: Path,
        key_path: Path,
        cert_path: Path,
        output_path: Path,
        description: str = "",
    ) -> None:
        """Sign a document.

        Args:
            document_path: Path to document to sign
            key_path: Path to private key
            cert_path: Path to certificate
            output_path: Path to save envelope
            description: Optional signature description
        """
        # Load files
        document = self._load_document(document_path)
        private_key = self._load_private_key(key_path)
        certificate = self._load_certificate(cert_path)

        # Perform operation
        envelope = self.core_service.sign(
            document, private_key, certificate, description
        )

        # Save result
        self._save_envelope(envelope, output_path)

    def verify(
        self,
        envelope_path: Path,
        output_path: Optional[Path] = None,
        trusted_cert_path: Optional[Path] = None,
    ) -> VerificationResult:
        """Verify a signed envelope.

        Args:
            envelope_path: Path to envelope to verify
            output_path: Optional path to save extracted document
            trusted_cert_path: Optional path to trusted CA certificate

        Returns:
            VerificationResult
        """
        # Load envelope
        envelope = self._load_envelope(envelope_path)

        # Load trusted certs if provided
        trusted_certs = None
        if trusted_cert_path:
            trusted_certs = [self._load_certificate(trusted_cert_path)]

        # Perform verification
        result = self.core_service.verify(envelope, trusted_certs)

        # Save extracted document if output path provided
        if output_path:
            self._save_document(envelope.payload, output_path)

        return result

    def encrypt(
        self,
        document_path: Path,
        recipient_cert_path: Path,
        output_path: Path,
    ) -> None:
        """Encrypt a document.

        Args:
            document_path: Path to document to encrypt
            recipient_cert_path: Path to recipient's certificate
            output_path: Path to save envelope
        """
        # Load files
        document = self._load_document(document_path)
        recipient_cert = self._load_certificate(recipient_cert_path)

        # Perform operation
        envelope = self.core_service.encrypt(document, recipient_cert)

        # Save result
        self._save_envelope(envelope, output_path)

    def decrypt(
        self,
        envelope_path: Path,
        key_path: Path,
        output_path: Path,
    ) -> None:
        """Decrypt an envelope.

        Args:
            envelope_path: Path to encrypted envelope
            key_path: Path to private key
            output_path: Path to save decrypted document
        """
        # Load files
        envelope = self._load_envelope(envelope_path)
        private_key = self._load_private_key(key_path)

        # Perform operation
        decrypted_envelope = self.core_service.decrypt(envelope, private_key)

        # Save result
        self._save_document(decrypted_envelope.payload, output_path)

    def sign_encrypt(
        self,
        document_path: Path,
        key_path: Path,
        cert_path: Path,
        recipient_cert_path: Path,
        output_path: Path,
        description: str = "",
    ) -> None:
        """Sign and encrypt a document (two-layer envelope).

        Args:
            document_path: Path to document to sign and encrypt
            key_path: Path to signer's private key
            cert_path: Path to signer's certificate
            recipient_cert_path: Path to recipient's certificate
            output_path: Path to save envelope
            description: Optional signature description
        """
        # Load files
        document = self._load_document(document_path)
        signer_key = self._load_private_key(key_path)
        signer_cert = self._load_certificate(cert_path)
        recipient_cert = self._load_certificate(recipient_cert_path)

        # Perform operation
        envelope = self.core_service.sign_encrypt(
            document, signer_key, signer_cert, recipient_cert, description
        )

        # Save result
        self._save_envelope(envelope, output_path)

    def decrypt_and_verify(
        self,
        envelope_path: Path,
        key_path: Path,
        output_path: Path,
        trusted_cert_path: Optional[Path] = None,
    ) -> tuple[VerificationResult, DsealEnvelope]:
        """Decrypt and verify a signed-encrypted envelope.

        Args:
            envelope_path: Path to encrypted envelope
            key_path: Path to recipient's private key
            output_path: Path to save decrypted document
            trusted_cert_path: Optional path to trusted CA certificate

        Returns:
            Tuple of (VerificationResult, decrypted_envelope)
        """
        # Load files
        envelope = self._load_envelope(envelope_path)
        private_key = self._load_private_key(key_path)

        # Load trusted certs if provided
        trusted_certs = None
        if trusted_cert_path:
            trusted_certs = [self._load_certificate(trusted_cert_path)]

        # Perform operation
        decrypted_envelope, verification_result = self.core_service.decrypt_and_verify(
            envelope, private_key, trusted_certs
        )

        # Save result
        self._save_document(decrypted_envelope.payload, output_path)

        return verification_result, decrypted_envelope
