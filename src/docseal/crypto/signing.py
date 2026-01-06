import base64
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign_document(
    document_path: Path,
    private_key: rsa.RSAPrivateKey,
    signer_certificate: x509.Certificate,
) -> Dict[str, Any]:
    """Sign a document with a detached signature and metadata.

    The signed payload is:

        SHA256(document bytes) || document_id || timestamp
    """

    # 1. Read document
    data = document_path.read_bytes()

    # 2. Hash document
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    document_hash = digest.finalize()

    # 3. Metadata
    document_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    payload = document_hash + document_id.encode("utf-8") + timestamp.encode("utf-8")

    # 4. Sign
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 5. Build signature object
    signature_data: Dict[str, Any] = {
        "document_id": document_id,
        "timestamp": timestamp,
        "hash_algorithm": "SHA256",
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signer_certificate": base64.b64encode(
            signer_certificate.public_bytes(encoding=serialization.Encoding.DER)
        ).decode("utf-8"),
    }

    return signature_data


def save_signature(signature_data: Dict[str, Any], output_path: Path) -> None:
    """Persist a JSON-formatted signature file to ``output_path``."""

    output_path.write_text(json.dumps(signature_data, indent=2))
