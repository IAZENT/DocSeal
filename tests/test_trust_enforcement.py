import pytest
from pathlib import Path

from docseal.ca.authority import CertificateAuthority
from docseal.ca.revocation import RevocationRegistry
from docseal.crypto.signing import sign_document, save_signature
from docseal.crypto.verification import verify_document_signature


def test_revoked_certificate_is_rejected(tmp_path: Path) -> None:
    """Test that revoked certificates are rejected during verification."""
    ca = CertificateAuthority()
    ca.initialize(password="strongpass")

    key, cert = ca.issue_certificate("Registrar", "staff")

    registry = RevocationRegistry(tmp_path / "crl.json")
    registry.revoke(cert.serial_number)

    doc = tmp_path / "doc.txt"
    doc.write_text("Official Transcript")

    sig = sign_document(doc, key, cert)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig, sig_path)

    with pytest.raises(ValueError, match="Certificate revoked"):
        verify_document_signature(
            doc,
            sig_path,
            ca.certificate,
            revocation_registry=registry,
        )


def test_expired_certificate_is_rejected(tmp_path: Path) -> None:
    """Test that expired certificates are rejected during verification.

    Note: This test would require creating an expired certificate,
    which is not straightforward with the current CA implementation.
    This is a placeholder for future implementation.
    """
    # TODO: Implement with test CA that can issue expired certificates
    pass


def test_not_yet_valid_certificate_is_rejected(tmp_path: Path) -> None:
    """Test that future-dated certificates are rejected during verification.

    Note: This test would require creating a future-dated certificate,
    which is not straightforward with the current CA implementation.
    This is a placeholder for future implementation.
    """
    # TODO: Implement with test CA that can issue future-dated certificates
    pass
