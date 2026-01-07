import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID


def verify_document_signature(
    document_path: Path,
    signature_path: Path,
    trusted_ca_cert: x509.Certificate,
    revocation_registry: Optional[Any] = None,
    audit_logger: Optional[Any] = None,
) -> Dict[str, Any]:
    """Verify a detached document signature.

    The verification process performs:

    1. Certificate trust verification (signer certificate signed by the CA)
    2. Certificate expiry enforcement (not yet valid or expired)
    3. Certificate revocation check (if revocation_registry provided)
    4. Document hashing (SHA256 over the current document bytes)
    5. Payload reconstruction: ``SHA256(document) || document_id || timestamp``
    6. Cryptographic signature verification using the signer certificate
    7. Audit logging (if audit_logger provided)
    """

    # Load signature file
    sig_data = json.loads(signature_path.read_text())

    document_id = sig_data["document_id"]
    timestamp = sig_data["timestamp"]

    signature = base64.b64decode(sig_data["signature"])
    signer_cert_bytes = base64.b64decode(sig_data["signer_certificate"])

    signer_cert = x509.load_der_x509_certificate(signer_cert_bytes)

    try:
        # 1. Certificate expiry enforcement
        now = datetime.now(timezone.utc)

        if signer_cert.not_valid_before_utc > now:
            raise ValueError("Certificate not yet valid")

        if signer_cert.not_valid_after_utc < now:
            raise ValueError("Certificate expired")

        # 2. Certificate revocation check
        if revocation_registry:
            if revocation_registry.is_revoked(signer_cert.serial_number):
                raise ValueError("Certificate revoked")

        # 3. Verify certificate is signed by trusted CA
        ca_public_key = cast(RSAPublicKey, trusted_ca_cert.public_key())
        ca_public_key.verify(
            signer_cert.signature,
            signer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cast(hashes.HashAlgorithm, signer_cert.signature_hash_algorithm),
        )

        # 4. Hash document
        data = document_path.read_bytes()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        document_hash = digest.finalize()

        # 5. Rebuild payload
        payload = (
            document_hash
            + document_id.encode("utf-8")
            + timestamp.encode("utf-8")
        )

        # 6. Verify signature
        signer_public_key = cast(RSAPublicKey, signer_cert.public_key())
        signer_public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # 7. Extract identity info
        subject = signer_cert.subject
        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        result = {
            "valid": True,
            "signer": common_name,
            "document_id": document_id,
            "timestamp": timestamp,
        }

        # 8. Audit logging - success
        if audit_logger:
            audit_logger.log(
                {
                    "document_id": document_id,
                    "signer": signer_cert.subject.rfc4514_string(),
                    "result": "VALID",
                }
            )

        return result

    except Exception as e:
        # Audit logging - failure
        if audit_logger:
            audit_logger.log(
                {
                    "document_id": sig_data.get("document_id"),
                    "result": "INVALID",
                    "reason": str(e),
                }
            )
        raise
