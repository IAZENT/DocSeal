"""Direct tests for CLI command functions to increase coverage."""

import secrets
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from docseal.ca.authority import CertificateAuthority
from docseal.cli.ca import (
    cmd_ca_info,
    cmd_ca_init,
    cmd_ca_issue,
    cmd_ca_list_revoked,
    cmd_ca_revoke,
)
from docseal.cli.main import main
from docseal.cli.sign import cmd_sign
from docseal.cli.verify import cmd_verify


@pytest.fixture
def setup_ca():
    """Setup CA for testing."""
    ca_dir = Path.home() / ".docseal" / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)

    ca = CertificateAuthority()
    ca.initialize(password="testpass123")  # noqa: S106

    pkcs12 = ca.export_pkcs12(password="testpass123")  # noqa: S106
    (ca_dir / "ca.p12").write_bytes(pkcs12)

    if ca.certificate:
        from cryptography.hazmat.primitives import serialization

        pem = ca.certificate.public_bytes(encoding=serialization.Encoding.PEM)
        (ca_dir / "ca.pem").write_bytes(pem)

    yield ca
    # Cleanup handled by other tests


def test_cmd_ca_init_with_force(capsys):
    """Test CA init with force flag."""
    args = Mock()
    args.password = secrets.token_urlsafe(12)
    args.force = True

    cmd_ca_init(args)  # Should succeed or handle existing CA
    captured = capsys.readouterr()
    assert "initialized" in captured.out.lower() or "exists" in captured.err.lower()


def test_cmd_ca_init_short_password(capsys):
    """Test CA init with short password."""
    import shutil

    ca_dir = Path.home() / ".docseal" / "ca"
    if ca_dir.exists():
        shutil.rmtree(ca_dir)

    args = Mock()
    args.password = "short"  # noqa: S105
    args.force = False

    with pytest.raises(SystemExit) as exc_info:
        cmd_ca_init(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "at least 8 characters" in captured.err


def test_cmd_ca_issue_no_ca(capsys):
    """Test issuing cert without CA."""
    import shutil

    ca_dir = Path.home() / ".docseal" / "ca"
    if ca_dir.exists():
        shutil.rmtree(ca_dir)

    args = Mock()
    args.name = "Test"
    args.role = "Tester"
    args.validity = 365
    args.out = None
    args.password = "certpass"  # noqa: S105

    with pytest.raises(SystemExit) as exc_info:
        cmd_ca_issue(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "not initialized" in captured.err


def test_cmd_ca_revoke(setup_ca):
    """Test certificate revocation."""
    args = Mock()
    args.serial = 123456789
    args.reason = "test"

    cmd_ca_revoke(args)  # Should complete without error


def test_cmd_ca_list_empty(capsys):
    """Test listing when no revocations."""
    args = Mock()

    cmd_ca_list_revoked(args)  # Should complete
    captured = capsys.readouterr()
    assert "revoked" in captured.out.lower() or len(captured.out) > 0


def test_cmd_ca_info(setup_ca, capsys):
    """Test CA info command."""
    args = Mock()

    cmd_ca_info(args)  # Should display info
    captured = capsys.readouterr()
    assert "Certificate Authority" in captured.out


def test_cmd_sign_no_doc(capsys):
    """Test sign with non-existent document."""
    args = Mock()
    args.doc = "/nonexistent/file.txt"
    args.cert = "cert.p12"
    args.out = "out.sig"
    args.password = None

    with pytest.raises(SystemExit) as exc_info:
        cmd_sign(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_cmd_sign_directory(capsys, tmp_path):
    """Test sign with directory instead of file."""
    args = Mock()
    args.doc = str(tmp_path)
    args.cert = "cert.p12"
    args.out = "out.sig"
    args.password = None

    with pytest.raises(SystemExit) as exc_info:
        cmd_sign(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "not a file" in captured.err.lower()


def test_cmd_verify_no_doc(capsys):
    """Test verify with non-existent document."""
    args = Mock()
    args.doc = "/nonexistent/file.txt"
    args.sig = "sig.json"
    args.ca = None
    args.no_revocation_check = False
    args.no_audit = True
    args.verbose = False

    with pytest.raises(SystemExit) as exc_info:
        cmd_verify(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_cmd_verify_directory(capsys, tmp_path):
    """Test verify with directory instead of file."""
    args = Mock()
    args.doc = str(tmp_path)
    args.sig = "sig.json"
    args.ca = None
    args.no_revocation_check = False
    args.no_audit = True
    args.verbose = False

    with pytest.raises(SystemExit) as exc_info:
        cmd_verify(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "not a file" in captured.err.lower()


def test_main_no_args():
    """Test main with no arguments."""
    with patch.object(sys, "argv", ["docseal"]):
        with pytest.raises(SystemExit):
            main()


def test_main_help():
    """Test main with help."""
    with patch.object(sys, "argv", ["docseal", "--help"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0


def test_cmd_sign_success(setup_ca, tmp_path, capsys):
    """Test successful document signing."""
    # Issue certificate
    private_key, certificate = setup_ca.issue_certificate("Signer", "Tester", 30)

    # Export as PKCS#12
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )

    cert_p12 = serialize_key_and_certificates(
        name=b"signer",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"certpass"),
    )

    cert_path = tmp_path / "signer.p12"
    cert_path.write_bytes(cert_p12)

    # Create document
    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Test content")

    # Sign
    args = Mock()
    args.doc = str(doc_path)
    args.cert = str(cert_path)
    args.out = str(tmp_path / "doc.sig")
    args.password = "certpass"  # noqa: S105

    cmd_sign(args)
    captured = capsys.readouterr()
    assert "signed successfully" in captured.out.lower()


def test_cmd_verify_success(setup_ca, tmp_path, capsys):
    """Test successful signature verification."""
    # Issue certificate and sign
    private_key, certificate = setup_ca.issue_certificate("Signer", "Tester", 30)

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Test content")

    # Sign document
    from docseal.crypto.signing import save_signature, sign_document

    sig_data = sign_document(doc_path, private_key, certificate)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig_data, sig_path)

    # Verify
    args = Mock()
    args.doc = str(doc_path)
    args.sig = str(sig_path)
    args.ca = None
    args.no_revocation_check = True
    args.no_audit = True
    args.verbose = False

    cmd_verify(args)
    captured = capsys.readouterr()
    assert "VALID" in captured.out


def test_cmd_verify_missing_ca(capsys):
    """Test verify with missing CA certificate."""
    args = Mock()
    args.doc = "doc.txt"
    args.sig = "sig.json"
    args.ca = "/nonexistent/ca.pem"
    args.no_revocation_check = False
    args.no_audit = False
    args.verbose = False

    with pytest.raises(SystemExit) as exc_info:
        cmd_verify(args)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_cmd_verify_with_verbose(setup_ca, tmp_path, capsys):
    """Test verify with verbose output."""
    # Issue certificate and sign
    private_key, certificate = setup_ca.issue_certificate("Signer", "Tester", 30)

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Test content")

    # Sign document
    from docseal.crypto.signing import save_signature, sign_document

    sig_data = sign_document(doc_path, private_key, certificate)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig_data, sig_path)

    # Verify with verbose
    args = Mock()
    args.doc = str(doc_path)
    args.sig = str(sig_path)
    args.ca = None
    args.no_revocation_check = True
    args.no_audit = True
    args.verbose = True

    cmd_verify(args)
    captured = capsys.readouterr()
    assert "Verifying signature" in captured.out


def test_cmd_ca_issue_with_password_flag(setup_ca, tmp_path, capsys):
    """Test issuing cert with password flag."""
    args = Mock()
    args.name = "Test User"
    args.role = "Tester"
    args.validity = 365
    args.out = str(tmp_path / "test.p12")
    args.password = "certpass"  # noqa: S105  # noqa: S105

    # Mock getpass to return CA password
    with patch("docseal.cli.ca.getpass", return_value="testpass123"):
        cmd_ca_issue(args)

    captured = capsys.readouterr()
    assert "issued successfully" in captured.out.lower()


def test_cmd_sign_with_password_flag(tmp_path, setup_ca, capsys):
    """Test signing with password flag."""
    # Create certificate
    private_key, certificate = setup_ca.issue_certificate("Signer", "Tester", 30)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )

    cert_p12 = serialize_key_and_certificates(
        name=b"signer",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"certpass"),
    )

    cert_path = tmp_path / "signer.p12"
    cert_path.write_bytes(cert_p12)

    # Create document
    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Test content")

    # Sign
    args = Mock()
    args.doc = str(doc_path)
    args.cert = str(cert_path)
    args.out = str(tmp_path / "doc.sig")
    args.password = "certpass"  # noqa: S105

    with patch("docseal.cli.sign.getpass", return_value="testpass123"):  # CA password
        cmd_sign(args)

    captured = capsys.readouterr()
    assert "signed successfully" in captured.out.lower()


def test_cmd_verify_with_no_revocation_check(setup_ca, tmp_path, capsys):
    """Test verify with no revocation check."""
    # Issue certificate and sign
    private_key, certificate = setup_ca.issue_certificate("Signer", "Tester", 30)

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Test content")

    # Sign document
    from docseal.crypto.signing import save_signature, sign_document

    sig_data = sign_document(doc_path, private_key, certificate)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig_data, sig_path)

    # Verify with no revocation check
    args = Mock()
    args.doc = str(doc_path)
    args.sig = str(sig_path)
    args.ca = None
    args.no_revocation_check = True
    args.no_audit = True
    args.verbose = False

    cmd_verify(args)
    captured = capsys.readouterr()
    assert "VALID" in captured.out
