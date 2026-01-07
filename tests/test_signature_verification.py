import secrets
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from docseal.ca.authority import CertificateAuthority
from docseal.crypto.signing import save_signature, sign_document
from docseal.crypto.verification import verify_document_signature


def test_valid_signature(tmp_path: Path) -> None:
    ca = CertificateAuthority()
    password = secrets.token_urlsafe(16)
    ca.initialize(password=password)

    key, cert = ca.issue_certificate(
        common_name="Registrar",
        role="admin",
    )

    doc = tmp_path / "doc.txt"
    doc.write_text("Official marksheet")

    sig = sign_document(doc, key, cert)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig, sig_path)

    result = verify_document_signature(doc, sig_path, ca.certificate)  # type: ignore[arg-type]

    assert result["valid"] is True
    assert result["signer"] == "Registrar"


def test_tampered_document_fails(tmp_path: Path) -> None:
    ca = CertificateAuthority()
    password = secrets.token_urlsafe(16)
    ca.initialize(password=password)

    key, cert = ca.issue_certificate(
        common_name="Registrar",
        role="admin",
    )

    doc = tmp_path / "doc.txt"
    doc.write_text("Original content")

    sig = sign_document(doc, key, cert)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig, sig_path)

    # Tamper document after signing
    doc.write_text("Modified content")

    with pytest.raises(InvalidSignature):
        verify_document_signature(doc, sig_path, ca.certificate)  # type: ignore[arg-type]
