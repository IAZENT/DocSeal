"""Integration tests for DocSeal CLI."""

import subprocess
import sys
from pathlib import Path

import pytest


def run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the docseal CLI with the given arguments."""
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "docseal.cli.main", *args],
        capture_output=True,
        text=True,
    )


def test_cli_help():
    """Test that CLI help works."""
    result = run_cli("--help")
    assert result.returncode == 0
    assert "DocSeal" in result.stdout
    assert "Secure Academic Document Signing" in result.stdout


def test_cli_version():
    """Test that CLI version works."""
    result = run_cli("--version")
    assert result.returncode == 0
    assert "docseal" in result.stdout


def test_cli_no_args():
    """Test that CLI without args shows error."""
    result = run_cli()
    assert result.returncode != 0


def test_ca_help():
    """Test CA subcommand help."""
    result = run_cli("ca", "--help")
    assert result.returncode == 0
    assert "Certificate Authority" in result.stdout


def test_ca_init_help():
    """Test CA init help."""
    result = run_cli("ca", "init", "--help")
    assert result.returncode == 0
    assert "Certificate Authority" in result.stdout


def test_ca_issue_help():
    """Test CA issue help."""
    result = run_cli("ca", "issue", "--help")
    assert result.returncode == 0
    assert "Issue a certificate" in result.stdout
    assert "--name" in result.stdout
    assert "--role" in result.stdout


def test_ca_revoke_help():
    """Test CA revoke help."""
    result = run_cli("ca", "revoke", "--help")
    assert result.returncode == 0
    assert "revocation" in result.stdout
    assert "--serial" in result.stdout


def test_ca_list_help():
    """Test CA list help."""
    result = run_cli("ca", "list", "--help")
    assert result.returncode == 0


def test_ca_info_help():
    """Test CA info help."""
    result = run_cli("ca", "info", "--help")
    assert result.returncode == 0


def test_sign_help():
    """Test sign command help."""
    result = run_cli("sign", "--help")
    assert result.returncode == 0
    assert "signature" in result.stdout
    assert "--doc" in result.stdout
    assert "--cert" in result.stdout
    assert "--out" in result.stdout


def test_verify_help():
    """Test verify command help."""
    result = run_cli("verify", "--help")
    assert result.returncode == 0
    assert "Verify" in result.stdout
    assert "--doc" in result.stdout
    assert "--sig" in result.stdout


def test_sign_missing_doc():
    """Test sign command with missing document."""
    result = run_cli(
        "sign",
        "--doc",
        "nonexistent.pdf",
        "--cert",
        "cert.p12",
        "--out",
        "sig.json",
    )
    assert result.returncode != 0
    assert result.stderr  # parser error is acceptable


def test_verify_missing_doc():
    """Test verify command with missing document."""
    result = run_cli(
        "verify",
        "--doc",
        "nonexistent.pdf",
        "--sig",
        "sig.json",
    )
    assert result.returncode != 0
    assert result.stderr  # parser error is acceptable


@pytest.mark.skipif(
    not Path.home().joinpath(".docseal", "ca", "ca.pem").exists(),
    reason="CA not initialized",
)
def test_ca_info_with_initialized_ca():
    """Test CA info when CA is initialized."""
    result = run_cli("ca", "info")
    # Should work if CA exists, otherwise will fail with helpful message
    if result.returncode == 0:
        assert "Certificate Authority Information" in result.stdout
    else:
        assert "not initialized" in result.stderr.lower()
