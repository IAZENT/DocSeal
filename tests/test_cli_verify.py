import secrets
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from docseal.ca.authority import CertificateAuthority
from docseal.cli.verify import cmd_verify
from docseal.crypto.signing import save_signature, sign_document


def _make_signed_doc(tmp_path: Path):
    ca = CertificateAuthority()
    pwd = secrets.token_urlsafe(8)
    ca.initialize(password=pwd)

    priv, cert = ca.issue_certificate("Signer", "Role")

    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Hello")

    sig = sign_document(doc_path, priv, cert)
    sig_path = tmp_path / "doc.sig"
    save_signature(sig, sig_path)

    # write CA pem

    pem = ca.certificate.public_bytes(encoding=serialization.Encoding.PEM)
    ca_pem = tmp_path / "ca.pem"
    ca_pem.write_bytes(pem)

    return doc_path, sig_path, ca_pem


def test_cmd_verify_fails_to_load_ca(tmp_path, capsys):
    # Create a doc and signature pair to satisfy file checks
    doc_path = tmp_path / "doc.txt"
    doc_path.write_text("Hello")
    sig_path = tmp_path / "doc.sig"
    sig_path.write_text("not a real sig")

    # Create an invalid CA file
    ca_pem = tmp_path / "ca.pem"
    ca_pem.write_bytes(b"not a pem")

    args = SimpleNamespace(
        doc=str(doc_path),
        sig=str(sig_path),
        ca=str(ca_pem),
        no_revocation_check=True,
        no_audit=True,
        verbose=False,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_verify(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Failed to load CA certificate" in captured.err


def test_cmd_verify_no_revocation_list_verbose(tmp_path, capsys):
    doc_path, sig_path, ca_pem = _make_signed_doc(tmp_path)

    args = SimpleNamespace(
        doc=str(doc_path),
        sig=str(sig_path),
        ca=str(ca_pem),
        no_revocation_check=False,
        no_audit=True,
        verbose=True,
    )

    cmd_verify(args)
    captured = capsys.readouterr()
    assert "No revocation list found" in captured.out


def test_cmd_verify_success_with_audit(tmp_path, capsys):
    doc_path, sig_path, ca_pem = _make_signed_doc(tmp_path)

    args = SimpleNamespace(
        doc=str(doc_path),
        sig=str(sig_path),
        ca=str(ca_pem),
        no_revocation_check=True,
        no_audit=False,
        verbose=False,
    )

    cmd_verify(args)
    captured = capsys.readouterr()
    assert "SIGNATURE VALID" in captured.out
    assert "Audit log" in captured.out


def test_cmd_verify_value_error_raises_invalid(monkeypatch, tmp_path, capsys):
    doc_path, sig_path, ca_pem = _make_signed_doc(tmp_path)

    def _raise(*args, **kwargs):
        raise ValueError("bad sig")

    monkeypatch.setattr("docseal.cli.verify.verify_document_signature", _raise)

    args = SimpleNamespace(
        doc=str(doc_path),
        sig=str(sig_path),
        ca=str(ca_pem),
        no_revocation_check=True,
        no_audit=False,
        verbose=False,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_verify(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "SIGNATURE INVALID" in captured.err
    assert "Audit log" in captured.err


def test_cmd_verify_generic_exception(monkeypatch, tmp_path, capsys):
    doc_path, sig_path, ca_pem = _make_signed_doc(tmp_path)

    def _raise(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("docseal.cli.verify.verify_document_signature", _raise)

    args = SimpleNamespace(
        doc=str(doc_path),
        sig=str(sig_path),
        ca=str(ca_pem),
        no_revocation_check=True,
        no_audit=True,
        verbose=False,
    )

    with pytest.raises(SystemExit) as exc:
        cmd_verify(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Verification error" in captured.err
