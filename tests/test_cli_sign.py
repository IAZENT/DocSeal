import secrets
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from docseal.ca.authority import CertificateAuthority
from docseal.cli.sign import cmd_sign


def _write_dummy_file(tmp_path: Path, content: bytes = b"dummy") -> Path:
    p = tmp_path / "cert.p12"
    p.write_bytes(content)
    return p


def test_cmd_sign_no_private_key(tmp_path, capsys, monkeypatch):
    # Create a dummy p12 file
    cert_path = _write_dummy_file(tmp_path)

    # Make load_key_and_certificates return (None, cert, None)
    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(8))
    _, cert = ca.issue_certificate("User", "Role")

    monkeypatch.setattr(
        "docseal.cli.sign.load_key_and_certificates",
        lambda data, pw: (None, cert, None),
    )

    args = SimpleNamespace(
        doc=__file__,
        cert=str(cert_path),
        out=str(tmp_path / "out.sig"),
        password=secrets.token_urlsafe(8),
    )

    with pytest.raises(SystemExit) as exc:
        cmd_sign(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "No private key" in captured.err


def test_cmd_sign_no_certificate(tmp_path, capsys, monkeypatch):
    cert_path = _write_dummy_file(tmp_path)

    # Return private key but no certificate
    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(8))
    priv, _ = ca.issue_certificate("User", "Role")

    monkeypatch.setattr(
        "docseal.cli.sign.load_key_and_certificates",
        lambda data, pw: (priv, None, None),
    )

    args = SimpleNamespace(
        doc=__file__,
        cert=str(cert_path),
        out=str(tmp_path / "out.sig"),
        password=secrets.token_urlsafe(8),
    )

    with pytest.raises(SystemExit) as exc:
        cmd_sign(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "No certificate" in captured.err


def test_cmd_sign_non_rsa_key(tmp_path, capsys, monkeypatch):
    cert_path = _write_dummy_file(tmp_path)

    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(8))
    _, cert = ca.issue_certificate("User", "Role")

    # Use an EC private key to simulate unsupported key type
    ec_key = ec.generate_private_key(ec.SECP384R1())

    monkeypatch.setattr(
        "docseal.cli.sign.load_key_and_certificates",
        lambda data, pw: (ec_key, cert, None),
    )

    args = SimpleNamespace(
        doc=__file__,
        cert=str(cert_path),
        out=str(tmp_path / "out.sig"),
        password=secrets.token_urlsafe(8),
    )

    with pytest.raises(SystemExit) as exc:
        cmd_sign(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Only RSA keys" in captured.err


def test_cmd_sign_invalid_password_raises_valueerror(tmp_path, capsys, monkeypatch):
    cert_path = _write_dummy_file(tmp_path)

    def _raise(data, pw):
        raise ValueError("invalid password")

    monkeypatch.setattr("docseal.cli.sign.load_key_and_certificates", _raise)

    args = SimpleNamespace(
        doc=__file__,
        cert=str(cert_path),
        out=str(tmp_path / "out.sig"),
        password=secrets.token_urlsafe(8),
    )

    with pytest.raises(SystemExit) as exc:
        cmd_sign(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Invalid certificate or password" in captured.err


def test_cmd_sign_general_exception(tmp_path, capsys, monkeypatch):
    cert_path = _write_dummy_file(tmp_path)

    def _raise(data, pw):
        raise RuntimeError("boom")

    monkeypatch.setattr("docseal.cli.sign.load_key_and_certificates", _raise)

    args = SimpleNamespace(
        doc=__file__,
        cert=str(cert_path),
        out=str(tmp_path / "out.sig"),
        password=secrets.token_urlsafe(8),
    )

    with pytest.raises(SystemExit) as exc:
        cmd_sign(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Signing failed" in captured.err
