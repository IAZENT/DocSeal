import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from docseal.ca.authority import CertificateAuthority
from docseal.crypto.signing import save_signature, sign_document
from docseal.crypto.verification import verify_document_signature


def _make_signed_pair(tmp_path: Path, ca: CertificateAuthority):
    ca.initialize(password=secrets.token_urlsafe(12))
    priv, cert = ca.issue_certificate("Signer", "Role")

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("content")

    sig = sign_document(doc_path, priv, cert)
    sig_path = tmp_path / "sig.json"
    save_signature(sig, sig_path)

    return doc_path, sig_path, cert


def test_verify_not_yet_valid(tmp_path):
    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(12))
    assert ca.certificate is not None
    assert ca.private_key is not None

    # Create a signer cert that starts in the future
    future_start = datetime.now(timezone.utc) + timedelta(days=10)
    future_end = future_start + timedelta(days=365)

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Future User"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(future_start)
        .not_valid_after(future_end)
    )

    signer_cert = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA256())  # type: ignore

    sig_content = {
        "document_id": "docid",
        "timestamp": "ts",
        "signature": base64.b64encode(b"sigbytes").decode("utf-8"),
        "signer_certificate": base64.b64encode(
            signer_cert.public_bytes(serialization.Encoding.DER)
        ).decode("utf-8"),
    }

    sig_path = tmp_path / "sig.json"
    sig_path.write_text(json.dumps(sig_content))

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("hi")

    with pytest.raises(ValueError) as exc:
        verify_document_signature(doc_path, sig_path, ca.certificate, None, None)  # type: ignore
    assert "not yet valid" in str(exc.value)


def test_verify_expired(tmp_path):
    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(12))
    assert ca.certificate is not None
    assert ca.private_key is not None

    past_start = datetime.now(timezone.utc) - timedelta(days=10)
    past_end = datetime.now(timezone.utc) - timedelta(days=1)

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Expired User"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past_start)
        .not_valid_after(past_end)
    )

    signer_cert = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA256())  # type: ignore

    sig_content = {
        "document_id": "docid",
        "timestamp": "ts",
        "signature": base64.b64encode(b"sigbytes").decode("utf-8"),
        "signer_certificate": base64.b64encode(
            signer_cert.public_bytes(serialization.Encoding.DER)
        ).decode("utf-8"),
    }

    sig_path = tmp_path / "sig.json"
    sig_path.write_text(json.dumps(sig_content))

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("hi")

    with pytest.raises(ValueError) as exc:
        verify_document_signature(doc_path, sig_path, ca.certificate, None, None)  # type: ignore
    assert "expired" in str(exc.value)


def test_verify_revoked_and_audit(tmp_path):
    ca = CertificateAuthority()
    doc_path, sig_path, cert = _make_signed_pair(tmp_path, ca)
    assert ca.certificate is not None

    class FakeRegistry:
        def __init__(self, serial):
            self.serial = serial

        def is_revoked(self, serial):
            return True

    logs = []

    class FakeAudit:
        def log(self, entry):
            logs.append(entry)

    with pytest.raises(ValueError):
        verify_document_signature(
            doc_path,
            sig_path,
            ca.certificate,
            FakeRegistry(cert.serial_number),
            FakeAudit(),  # type: ignore
        )

    assert logs and logs[0]["result"] == "INVALID"


def test_verify_signature_and_audit_success(tmp_path):
    ca = CertificateAuthority()
    doc_path, sig_path, cert = _make_signed_pair(tmp_path, ca)

    logs = []

    class FakeAudit:
        def log(self, entry):
            logs.append(entry)

    result = verify_document_signature(
        doc_path, sig_path, ca.certificate, None, FakeAudit()  # type: ignore
    )
    assert result["valid"] is True
    assert logs and logs[0]["result"] == "VALID"


def test_verify_signature_missing_hash_algo(tmp_path, monkeypatch):
    ca = CertificateAuthority()
    doc_path, sig_path, cert = _make_signed_pair(tmp_path, ca)

    # Patch the loader to return a fake cert with no signature_hash_algorithm
    import docseal.crypto.verification as verification_mod

    def fake_loader(_):
        class FakeCert:
            not_valid_before = datetime.now(timezone.utc) - timedelta(days=1)
            not_valid_after = datetime.now(timezone.utc) + timedelta(days=1)
            signature_hash_algorithm = None

        return FakeCert()

    monkeypatch.setattr(verification_mod.x509, "load_der_x509_certificate", fake_loader)

    with pytest.raises(ValueError) as exc:
        verify_document_signature(doc_path, sig_path, ca.certificate, None, None)  # type: ignore
    assert "no signature hash" in str(exc.value).lower()
