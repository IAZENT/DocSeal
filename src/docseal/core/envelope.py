"""Unified .dseal envelope format for signed/encrypted documents."""

import json
import zipfile
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from uuid import uuid4


@dataclass
class EnvelopeMetadata:
    """Metadata for a .dseal envelope."""

    version: str = "1.0"
    original_filename: Optional[str] = None
    payload_encrypted: bool = False
    algorithms: Dict[str, str] = field(
        default_factory=lambda: {"signing": "RSA-PSS", "encryption": "AES-256-GCM"}
    )
    timestamp: Optional[str] = None
    doc_id: Optional[str] = None
    signer_fingerprint: Optional[str] = None
    signer_name: Optional[str] = None
    signature_timestamp: Optional[Any] = None  # Can be datetime or str
    description: Optional[str] = None
    format_version: Optional[str] = None

    def __post_init__(self):
        """Initialize default values."""
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.doc_id is None:
            self.doc_id = str(uuid4())
        if self.format_version is None:
            self.format_version = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dict."""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        if self.signature_timestamp and hasattr(self.signature_timestamp, "isoformat"):
            data["signature_timestamp"] = self.signature_timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnvelopeMetadata":
        """Create from dict."""
        return cls(**data)


class DsealEnvelope:
    """Container for signed/encrypted documents."""

    def __init__(self, metadata: Optional[EnvelopeMetadata] = None):
        """Initialize envelope."""
        self.metadata = metadata or EnvelopeMetadata()
        self.payload: Optional[bytes] = None  # plaintext or ciphertext
        self.signature: Optional[bytes] = None  # RSA signature
        self.signer_cert: Optional[bytes] = None  # PEM format
        self.recipient_cert: Optional[bytes] = None  # PEM format, if encrypted

    def to_bytes(self) -> bytes:
        """Serialize to .dseal format (zip-based)."""
        import io

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write metadata
            metadata_json = json.dumps(self.metadata.to_dict(), indent=2)
            zf.writestr("metadata.json", metadata_json)

            # Write binary content
            if self.payload:
                zf.writestr("payload.bin", self.payload)
            if self.signature:
                zf.writestr("signature.bin", self.signature)
            if self.signer_cert:
                zf.writestr("signer_cert.pem", self.signer_cert)
            if self.recipient_cert:
                zf.writestr("recipient_cert.pem", self.recipient_cert)

        return zip_buffer.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> "DsealEnvelope":
        """Deserialize from .dseal format."""
        import io

        envelope = cls()
        zip_buffer = io.BytesIO(data)

        with zipfile.ZipFile(zip_buffer, "r") as zf:
            # Read metadata
            metadata_json = zf.read("metadata.json").decode("utf-8")
            metadata_dict = json.loads(metadata_json)
            envelope.metadata = EnvelopeMetadata.from_dict(metadata_dict)

            # Read binary content
            if "payload.bin" in zf.namelist():
                envelope.payload = zf.read("payload.bin")
            if "signature.bin" in zf.namelist():
                envelope.signature = zf.read("signature.bin")
            if "signer_cert.pem" in zf.namelist():
                envelope.signer_cert = zf.read("signer_cert.pem")
            if "recipient_cert.pem" in zf.namelist():
                envelope.recipient_cert = zf.read("recipient_cert.pem")

        return envelope

    def save(self, path: Path) -> None:
        """Save envelope to .dseal file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.to_bytes())

    @classmethod
    def load(cls, path: Path) -> "DsealEnvelope":
        """Load envelope from .dseal file."""
        return cls.from_bytes(Path(path).read_bytes())

    def extract_payload(self, output_path: Path) -> None:
        """Extract payload (plaintext only) to file."""
        if self.metadata.payload_encrypted:
            raise ValueError("Cannot extract encrypted payload. Decrypt first.")
        if self.payload is None:
            raise ValueError("No payload in envelope.")
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(self.payload)
