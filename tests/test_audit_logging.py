import json
from pathlib import Path

from docseal.audit.logger import AuditLogger
from docseal.ca.authority import CertificateAuthority
from docseal.ca.revocation import RevocationRegistry
from docseal.crypto.signing import save_signature, sign_document
from docseal.crypto.verification import verify_document_signature


def test_audit_logger_logs_successful_verification(tmp_path: Path) -> None:
    """Test that successful verification is logged."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)

    ca = CertificateAuthority()
    ca.initialize(password="testpass")  # noqa: S106

    key, cert = ca.issue_certificate("Tester", "staff")

    doc = tmp_path / "doc.txt"
    doc.write_text("Test Document")

    sig = sign_document(doc, key, cert)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig, sig_path)

    result = verify_document_signature(
        doc, sig_path, ca.certificate, audit_logger=logger
    )

    assert result["valid"] is True
    assert log_file.exists()

    logs = log_file.read_text().strip().split("\n")
    assert len(logs) == 1

    log_entry = json.loads(logs[0])
    assert log_entry["result"] == "VALID"
    assert "timestamp" in log_entry


def test_audit_logger_logs_failed_verification(tmp_path: Path) -> None:
    """Test that failed verification is logged."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)

    ca = CertificateAuthority()
    ca.initialize(password="testpass")  # noqa: S106

    key, cert = ca.issue_certificate("Tester", "staff")

    registry = RevocationRegistry(tmp_path / "crl.json")
    registry.revoke(cert.serial_number)

    doc = tmp_path / "doc.txt"
    doc.write_text("Test Document")

    sig = sign_document(doc, key, cert)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig, sig_path)

    try:
        verify_document_signature(
            doc, sig_path, ca.certificate, registry, audit_logger=logger
        )
    except ValueError:
        pass

    assert log_file.exists()

    logs = log_file.read_text().strip().split("\n")
    assert len(logs) == 1

    log_entry = json.loads(logs[0])
    assert log_entry["result"] == "INVALID"
    assert log_entry["reason"] == "Certificate revoked"
    assert "timestamp" in log_entry
