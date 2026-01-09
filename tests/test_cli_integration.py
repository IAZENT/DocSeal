"""Integration tests for CLI commands with actual execution."""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from docseal.ca.authority import CertificateAuthority


def run_cli_module(*args: str, input_text: str = "") -> subprocess.CompletedProcess:
    """Run CLI as Python module."""
    cmd = [sys.executable, "-m", "docseal.cli.main", *args]
    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        input=input_text,
    )


@pytest.fixture
def temp_dir():
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def test_ca_init_with_password(temp_dir: Path):
    """Test CA initialization with password flag."""
    result = run_cli_module("ca", "init", "--password", "test12345", "--force")
    assert result.returncode == 0 or "already exists" in result.stderr


def test_ca_info_no_init():
    """Test CA info when not initialized."""
    # Clear CA first
    import shutil

    ca_dir = Path.home() / ".docseal" / "ca"
    if ca_dir.exists():
        shutil.rmtree(ca_dir)

    result = run_cli_module("ca", "info")
    assert result.returncode != 0
    assert "not initialized" in result.stderr.lower()


def test_ca_list_empty():
    """Test listing revoked certs when none exist."""
    result = run_cli_module("ca", "list")
    # Should work even if no revocation list
    assert "No revoked" in result.stdout or result.returncode == 0


def test_sign_with_nonexistent_cert(temp_dir: Path):
    """Test signing with non-existent certificate."""
    doc = temp_dir / "test.txt"
    doc.write_text("Test document")

    result = run_cli_module(
        "sign",
        "--doc",
        str(doc),
        "--cert",
        str(temp_dir / "nonexistent.p12"),
        "--out",
        str(temp_dir / "test.sig"),
    )
    assert result.returncode != 0
    assert "not found" in result.stderr.lower()


def test_verify_with_nonexistent_sig(temp_dir: Path):
    """Test verification with non-existent signature."""
    doc = temp_dir / "test.txt"
    doc.write_text("Test document")

    result = run_cli_module(
        "verify",
        "--doc",
        str(doc),
        "--sig",
        str(temp_dir / "nonexistent.sig"),
    )
    assert result.returncode != 0
    assert "not found" in result.stderr.lower()


def test_main_keyboard_interrupt():
    """Test CLI handles KeyboardInterrupt gracefully."""
    # This tests the exception handler in main()
    # We can't easily trigger KeyboardInterrupt, but we can test error handling
    result = run_cli_module("invalid_command")
    assert result.returncode != 0


def test_colors_module():
    """Test color utilities."""
    from docseal.cli.colors import Colors

    # Test color methods
    assert Colors.success("test") != ""
    assert Colors.error("test") != ""
    assert Colors.warning("test") != ""
    assert Colors.info("test") != ""
    assert Colors.bold("test") != ""


def test_cli_main_entry():
    """Test main entry point can be imported."""
    from docseal.cli.main import create_parser

    parser = create_parser()
    assert parser is not None
    assert parser.prog == "docseal"


def test_full_ca_workflow(temp_dir: Path):
    """Test complete CA workflow: init, issue, info."""
    ca_dir = Path.home() / ".docseal" / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)

    # Initialize CA
    ca = CertificateAuthority()
    ca.initialize(password="testpass123")  # noqa: S106

    # Export CA
    pkcs12 = ca.export_pkcs12(password="testpass123")  # noqa: S106
    ca_p12_path = ca_dir / "ca.p12"
    ca_p12_path.write_bytes(pkcs12)

    if ca.certificate:
        from cryptography.hazmat.primitives import serialization

        pem_data = ca.certificate.public_bytes(encoding=serialization.Encoding.PEM)
        ca_pem_path = ca_dir / "ca.pem"
        ca_pem_path.write_bytes(pem_data)

    # Test CA info command
    result = run_cli_module("ca", "info")
    assert result.returncode == 0
    assert "Certificate Authority" in result.stdout


def test_sign_and_verify_workflow(temp_dir: Path):
    """Test full sign and verify workflow."""
    ca_dir = Path.home() / ".docseal" / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)

    # Initialize CA
    ca = CertificateAuthority()
    ca.initialize(password="testpass123")  # noqa: S106

    # Export CA certificate
    if ca.certificate:
        from cryptography.hazmat.primitives import serialization

        pem_data = ca.certificate.public_bytes(encoding=serialization.Encoding.PEM)
        ca_pem_path = ca_dir / "ca.pem"
        ca_pem_path.write_bytes(pem_data)

    # Issue certificate
    private_key, certificate = ca.issue_certificate(
        common_name="Test User", role="Tester", validity_days=30
    )

    # Export certificate as PKCS#12
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )

    cert_pkcs12 = serialize_key_and_certificates(
        name=b"test-user",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"certpass"),
    )

    cert_path = temp_dir / "test.p12"
    cert_path.write_bytes(cert_pkcs12)

    # Create test document
    doc_path = temp_dir / "test.txt"
    doc_path.write_text("Test document content")

    # Sign document
    sig_path = temp_dir / "test.sig"
    result = run_cli_module(
        "sign",
        "--doc",
        str(doc_path),
        "--cert",
        str(cert_path),
        "--out",
        str(sig_path),
        "--password",
        "certpass",
    )
    assert result.returncode == 0
    assert sig_path.exists()

    # Verify signature
    result = run_cli_module(
        "verify",
        "--doc",
        str(doc_path),
        "--sig",
        str(sig_path),
        "--verbose",
    )
    assert result.returncode == 0
    assert "VALID" in result.stdout
