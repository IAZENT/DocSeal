import secrets
from pathlib import Path

from docseal.ca.authority import CertificateAuthority
from docseal.crypto.signing import sign_document


def test_document_signing(tmp_path: Path) -> None:
    # Prepare CA and signer
    ca = CertificateAuthority()
    password = secrets.token_urlsafe(16)
    ca.initialize(password=password)

    key, cert = ca.issue_certificate(
        common_name="Lecturer One",
        role="lecturer",
    )

    # Create test document
    doc = tmp_path / "test.txt"
    doc.write_text("Official transcript data")

    signature = sign_document(doc, key, cert)

    assert "signature" in signature
    assert "document_id" in signature
    assert "timestamp" in signature
    assert "signer_certificate" in signature
