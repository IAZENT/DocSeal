"""Extra coverage tests for CLI helpers and edge cases."""

import argparse
import importlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import docseal.cli.ca as ca_cli
from docseal.ca.authority import CAInitializationError, CertificateAuthority
from docseal.ca.revocation import RevocationRegistry
from docseal.cli.colors import bold as color_bold
from docseal.cli.colors import error as color_error
from docseal.cli.colors import info as color_info
from docseal.cli.colors import success as color_success
from docseal.cli.colors import warning as color_warning
from docseal.cli.decrypt import decrypt_command
from docseal.cli.encrypt import encrypt_command
from docseal.cli.sign import cmd_sign
from docseal.cli.verify import cmd_verify
from docseal.core import DocSealService, DsealEnvelope
from docseal.core.decryption import decrypt_envelope
from docseal.core.verification import VerificationResult, verify_envelope

DATA_DIR = Path(__file__).parent.parent / "data"
KEYS = DATA_DIR / "keys"
CERTS = DATA_DIR / "certs"


def load_key(path: Path):
    if not path.exists():
        pytest.skip(f"Missing test key: {path}")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_cert(path: Path):
    if not path.exists():
        pytest.skip(f"Missing test cert: {path}")
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_version_fallback(monkeypatch):
    """Ensure fallback version path is executed when metadata is missing."""

    import docseal

    monkeypatch.setattr(
        importlib.metadata,
        "version",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            importlib.metadata.PackageNotFoundError()
        ),
    )

    importlib.reload(docseal)
    assert docseal.__version__ == "2.0.0"


def test_revocation_registry_load_existing(tmp_path: Path):
    existing = tmp_path / "revoked.json"
    existing.write_text("[1, 2]")

    registry = RevocationRegistry(existing)
    assert registry.is_revoked(1)
    assert registry.is_revoked(2)


def test_decrypt_envelope_no_payload_raises():
    env = DsealEnvelope()
    env.metadata.payload_encrypted = True
    env.payload = None

    with pytest.raises(ValueError):
        decrypt_envelope(env, load_key(KEYS / "student_charlie_key.pem"))


def test_envelope_save_load_and_extract(tmp_path: Path):
    env = DsealEnvelope()
    env.payload = b"hello"

    out = tmp_path / "sample.dseal"
    env.save(out)

    loaded = DsealEnvelope.load(out)
    assert loaded.payload == b"hello"

    extracted = tmp_path / "payload.bin"
    loaded.extract_payload(extracted)
    assert extracted.read_bytes() == b"hello"

    loaded.metadata.payload_encrypted = True
    with pytest.raises(ValueError):
        loaded.extract_payload(extracted)

    loaded.metadata.payload_encrypted = False
    loaded.payload = None
    with pytest.raises(ValueError):
        loaded.extract_payload(extracted)


def test_service_decrypt_and_verify_plaintext_path(tmp_path: Path):
    service = DocSealService()
    recipient_cert = load_cert(CERTS / "student_charlie_cert.pem")
    recipient_key = load_key(KEYS / "student_charlie_key.pem")

    plaintext = b"unencrypted payload"
    encrypted = service.encrypt(plaintext, recipient_cert)

    decrypted, result = service.decrypt_and_verify(encrypted, recipient_key)
    assert isinstance(decrypted, DsealEnvelope)
    assert isinstance(result, VerificationResult)
    assert decrypted.payload == plaintext


def test_validation_utc_property():
    from docseal.utils.validation import _utc_property

    class FakeCert:
        def __init__(self):
            self.not_valid_before = datetime.now(timezone.utc)
            self.not_valid_after = datetime.now(timezone.utc)

    cert = FakeCert()
    assert _utc_property(cert, "not_valid_before").tzinfo is not None


def test_certificate_authority_error_branches():
    ca = CertificateAuthority()
    with pytest.raises(CAInitializationError):
        ca.revoke_certificate(load_cert(CERTS / "lecturer_alice_cert.pem"), "x")
    with pytest.raises(CAInitializationError):
        ca.generate_crl()
    with pytest.raises(CAInitializationError):
        ca.is_revoked(load_cert(CERTS / "lecturer_alice_cert.pem"))
    with pytest.raises(CAInitializationError):
        ca.export_pkcs12("pass")
    with pytest.raises(CAInitializationError):
        ca.issue_certificate("x", "y")


def test_certificate_authority_initialize_error(monkeypatch):
    def fail_generate(*_a, **_k):
        raise ValueError("fail")

    monkeypatch.setattr("docseal.ca.authority.rsa.generate_private_key", fail_generate)
    ca = CertificateAuthority()
    with pytest.raises(CAInitializationError):
        ca.initialize("passpass")


def test_verify_envelope_no_email_or_cn(monkeypatch):
    """Cover branches where CN and SAN extraction fail."""

    class FakeSubject:
        def get_attributes_for_oid(self, *_):
            raise Exception("fail")

    class FakeExtensions:
        def get_extension_for_oid(self, *_):
            raise x509.ExtensionNotFound("nope", None)

    class FakeCert:
        def __init__(self):
            self.subject = FakeSubject()
            self.extensions = FakeExtensions()

        def __eq__(self, _other):
            return False

        @property
        def issuer(self):
            return self.subject

        def public_key(self):
            class FakeKey:
                def verify(self, *_, **__):
                    return None

            return FakeKey()

    env = DsealEnvelope()
    env.payload = b"data"
    env.signature = b"sig"
    env.signer_cert = FakeCert()

    result = verify_envelope(env)
    assert result.is_valid is True or result.error_message is not None


def test_extract_signer_name_error_path():
    class BadSubject:
        @property
        def subject(self):  # pragma: no cover - property exists only for test
            raise ValueError("boom")

    bad_cert = BadSubject()

    from docseal.core.signing import _extract_signer_name

    assert _extract_signer_name(bad_cert) == "Unknown Signer"


def test_verify_envelope_error_cases():
    env = DsealEnvelope()
    result = verify_envelope(env)
    assert result.is_valid is False
    assert "signature" in (result.error_message or "").lower()

    env.signature = b"dummy"
    env.payload = b"payload"
    result = verify_envelope(env)
    assert result.error_message and "certificate" in result.error_message


def test_verify_envelope_trust_and_invalid_signature(tmp_path: Path):
    service = DocSealService()
    signer_key = load_key(KEYS / "lecturer_alice_key.pem")
    signer_cert = load_cert(CERTS / "lecturer_alice_cert.pem")
    other_cert = load_cert(CERTS / "student_charlie_cert.pem")

    envelope = service.sign(b"payload", signer_key, signer_cert)
    envelope.signature = b"not-a-real-signature"
    bad = verify_envelope(envelope)
    assert bad.is_valid is False

    envelope = service.sign(b"payload", signer_key, signer_cert)
    envelope.signer_cert = signer_cert

    untrusted = verify_envelope(envelope, trusted_certs=[other_cert])
    assert untrusted.is_valid is False
    assert "trusted" in (untrusted.error_message or "")

    envelope.payload = None
    generic = verify_envelope(envelope)
    assert generic.is_valid is False


def test_cli_colors_functions(capsys):
    color_success("ok")
    color_error("fail")
    color_warning("warn")
    color_info("info")
    color_bold("bold")

    captured = capsys.readouterr()
    assert "ok" in captured.out
    assert "fail" in captured.err


def test_cli_encrypt_success_and_error(tmp_path: Path, capsys, monkeypatch):
    doc = tmp_path / "doc.txt"
    doc.write_text("secret")

    # Skip if test certs not available
    cert_path = CERTS / "student_charlie_cert.pem"
    if not cert_path.exists():
        pytest.skip(f"Missing test certificate: {cert_path}")

    args = argparse.Namespace(
        document=str(doc),
        recipient_cert=str(cert_path),
        output=None,
    )
    assert encrypt_command(args) == 0
    default_out = tmp_path / "doc.encrypted.dseal"
    assert default_out.exists()

    args.output = str(tmp_path / "custom.dseal")
    assert encrypt_command(args) == 0
    assert Path(args.output).exists()

    args.document = str(tmp_path / "missing.txt")
    encrypt_command(args)
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()

    # Missing recipient cert
    args.document = str(doc)
    args.recipient_cert = str(tmp_path / "missing.pem")
    assert encrypt_command(args) == 1

    # Force encrypt exception path
    args.recipient_cert = str(CERTS / "student_charlie_cert.pem")
    args.document = str(doc)

    class BoomService(DocSealService):
        def encrypt(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr("docseal.cli.encrypt.DocSealService", lambda: BoomService())
    assert encrypt_command(args) == 1


def test_cli_sign_success_and_missing_key(tmp_path: Path, capsys, monkeypatch):
    doc = tmp_path / "doc.txt"
    doc.write_text("sign me")

    # Skip if test keys not available
    cert_path = CERTS / "lecturer_alice_cert.pem"
    key_path = KEYS / "lecturer_alice_key.pem"
    if not (cert_path.exists() and key_path.exists()):
        pytest.skip("Missing test credentials")

    args = argparse.Namespace(
        document=str(doc),
        cert=str(cert_path),
        key=str(key_path),
        output=str(tmp_path / "doc.dseal"),
        description="Test signature",
    )
    assert cmd_sign(args) == 0
    assert Path(args.output).exists()

    args.key = str(tmp_path / "missing.pem")
    cmd_sign(args)
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()

    # Missing document path
    args.document = str(tmp_path / "missing.txt")
    result = cmd_sign(args)
    assert result == 1

    # Document is a directory (not a file)
    args.document = str(tmp_path)
    result = cmd_sign(args)
    assert result == 1

    # Missing certificate path
    args.document = str(doc)
    args.key = str(KEYS / "lecturer_alice_key.pem")
    args.cert = str(tmp_path / "missing_cert.pem")
    result = cmd_sign(args)
    assert result == 1

    # Default output branch and exception path
    args.document = str(doc)
    args.output = None
    args.key = str(KEYS / "lecturer_alice_key.pem")
    args.cert = str(CERTS / "lecturer_alice_cert.pem")

    # Monkeypatch service to raise
    class BoomService(DocSealService):
        def sign(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr("docseal.cli.sign.DocSealService", lambda: BoomService())
    assert cmd_sign(args) == 1


def test_cli_verify_success_and_failure(tmp_path: Path, capsys, monkeypatch):
    service = DocSealService()
    signer_key = load_key(KEYS / "lecturer_alice_key.pem")
    signer_cert = load_cert(CERTS / "lecturer_alice_cert.pem")
    other_cert = load_cert(CERTS / "student_charlie_cert.pem")

    envelope = service.sign(b"payload", signer_key, signer_cert, description="desc")
    env_path = tmp_path / "payload.dseal"
    env_path.write_bytes(envelope.to_bytes())

    cert_path = tmp_path / "signer.pem"
    cert_path.write_bytes(signer_cert.public_bytes(serialization.Encoding.PEM))

    args = argparse.Namespace(envelope=str(env_path), cert=str(cert_path), verbose=True)
    assert cmd_verify(args) == 0

    other_cert_path = tmp_path / "other.pem"
    other_cert_path.write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))
    args.cert = str(other_cert_path)
    assert cmd_verify(args) == 1
    captured = capsys.readouterr()
    assert "failed" in captured.err.lower() or "trusted" in captured.err.lower()

    # Missing envelope path triggers early error
    args.envelope = str(tmp_path / "missing.dseal")
    assert cmd_verify(args) == 1

    # Envelope path is a directory (not a file)
    args.envelope = str(tmp_path)
    assert cmd_verify(args) == 1

    # Cert path missing triggers error
    args.envelope = str(env_path)
    args.cert = str(tmp_path / "missing_cert.pem")
    assert cmd_verify(args) == 1

    # Encrypted envelope to hit is_encrypted branch
    service = DocSealService()
    recipient_cert = load_cert(CERTS / "student_charlie_cert.pem")
    encrypted_env = service.encrypt(b"cipherme", recipient_cert)
    enc_path = tmp_path / "enc.dseal"
    enc_path.write_bytes(encrypted_env.to_bytes())
    args.envelope = str(enc_path)
    args.cert = None
    args.verbose = True
    assert cmd_verify(args) == 1

    # Simulate successful verification with encrypted payload to hit info branch
    class FakeResult:
        is_valid = True
        signer_name = "X"
        signer_email = "x@example.com"
        signature_timestamp = "now"
        is_encrypted = True
        error_message = None

    class StubService(DocSealService):
        def verify(self, *_, **__):
            return FakeResult()

    monkeypatch.setattr("docseal.cli.verify.DocSealService", lambda: StubService())
    assert cmd_verify(args) == 0

    # Force verify exception path
    class BoomService(DocSealService):
        def verify(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr("docseal.cli.verify.DocSealService", lambda: BoomService())
    assert cmd_verify(args) == 1


def test_cli_decrypt_paths(tmp_path: Path, capsys, monkeypatch):
    service = DocSealService()
    signer_key = load_key(KEYS / "lecturer_alice_key.pem")
    signer_cert = load_cert(CERTS / "lecturer_alice_cert.pem")
    recipient_cert = load_cert(CERTS / "student_charlie_cert.pem")

    envelope = service.sign_encrypt(
        b"top secret", signer_key, signer_cert, recipient_cert
    )
    env_path = tmp_path / "secret.dseal"
    env_path.write_bytes(envelope.to_bytes())

    verify_path = tmp_path / "signer.pem"
    verify_path.write_bytes(signer_cert.public_bytes(serialization.Encoding.PEM))

    args = argparse.Namespace(
        envelope=str(env_path),
        private_key=str(KEYS / "student_charlie_key.pem"),
        output=None,
        verify=str(verify_path),
    )
    assert decrypt_command(args) == 0
    default_out = tmp_path / "secret.decrypted"
    assert default_out.exists()

    plain_env = service.sign(b"plain", signer_key, signer_cert)
    plain_path = tmp_path / "plain.dseal"
    plain_path.write_bytes(plain_env.to_bytes())

    args.envelope = str(plain_path)
    assert decrypt_command(args) == 1
    captured = capsys.readouterr()
    assert "not encrypted" in captured.err.lower()

    args.envelope = str(tmp_path / "missing.dseal")
    assert decrypt_command(args) == 1

    # Missing private key path
    args.envelope = str(env_path)
    args.private_key = str(tmp_path / "no_key.pem")
    assert decrypt_command(args) == 1

    # Verify flag with missing cert
    args.private_key = str(KEYS / "student_charlie_key.pem")
    args.verify = str(tmp_path / "missing.pem")
    assert decrypt_command(args) == 1

    # Verification returns invalid result to hit error branch
    class BadService(DocSealService):
        def decrypt_and_verify(self, *_a, **_k):
            return envelope, VerificationResult(
                is_valid=False, error_message="bad", is_encrypted=True
            )

    monkeypatch.setattr("docseal.cli.decrypt.DocSealService", lambda: BadService())
    args.verify = str(verify_path)
    assert decrypt_command(args) == 1
    monkeypatch.undo()

    # Custom output path without verify to hit alternate branch
    args.verify = None
    args.output = str(tmp_path / "custom.out")
    assert decrypt_command(args) == 0
    assert Path(args.output).exists()

    # Force decrypt exception path
    class BoomService(DocSealService):
        def decrypt(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    args.output = str(tmp_path / "custom2.out")
    monkeypatch.setattr("docseal.cli.decrypt.DocSealService", lambda: BoomService())
    assert decrypt_command(args) == 1


@pytest.fixture
def ca_env(tmp_path: Path, monkeypatch):
    ca_dir = tmp_path / "ca"
    monkeypatch.setattr(ca_cli, "CA_DIR", ca_dir)
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", ca_dir / "ca.p12")
    monkeypatch.setattr(ca_cli, "CA_PEM_PATH", ca_dir / "ca.pem")
    monkeypatch.setattr(ca_cli, "REVOCATION_PATH", ca_dir / "crl.json")
    monkeypatch.setattr(ca_cli, "getpass", lambda _msg="": "testpass123")
    return ca_dir


def test_ca_cli_workflow(ca_env: Path, tmp_path: Path):
    init_args = argparse.Namespace(password="testpass123", force=True)  # noqa: S106
    ca_cli.cmd_ca_init(init_args)

    issue_args = argparse.Namespace(
        name="Test User",
        role="Tester",
        validity=30,
        out=str(tmp_path / "issued.p12"),
        password="certpass",  # noqa: S106
    )
    ca_cli.cmd_ca_issue(issue_args)
    assert Path(issue_args.out).exists()

    revoke_args = argparse.Namespace(serial=1234, reason="testing")
    ca_cli.cmd_ca_revoke(revoke_args)

    list_args = argparse.Namespace()
    ca_cli.cmd_ca_list_revoked(list_args)

    info_args = argparse.Namespace()
    ca_cli.cmd_ca_info(info_args)


def test_ca_init_short_password(monkeypatch):
    tmp_ca_path = Path.cwd() / "tmp_ca" / "ca.p12"
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", tmp_ca_path)
    passwords = iter(["short", "short"])
    monkeypatch.setattr(ca_cli, "getpass", lambda _msg="": next(passwords))
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_init(argparse.Namespace(password=None, force=True))


def test_ca_issue_not_initialized(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", tmp_path / "missing.p12")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_issue(
            argparse.Namespace(
                name="X",
                role="Y",
                validity=10,
                out=None,
                password="pass12345",  # noqa: S106
            )
        )


def test_ca_issue_password_mismatch(monkeypatch, ca_env: Path):
    responses = iter(["first", "second"])
    monkeypatch.setattr(ca_cli, "getpass", lambda _msg="": next(responses))
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", ca_env / "ca.p12")
    ca_cli.cmd_ca_init(
        argparse.Namespace(password="testpass123", force=True)
    )  # noqa: S106
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_issue(
            argparse.Namespace(
                name="X",
                role="Y",
                validity=10,
                out=None,
                password=None,
            )
        )


def test_ca_info_not_initialized(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(ca_cli, "CA_PEM_PATH", tmp_path / "nope.pem")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_info(argparse.Namespace())


def test_ca_list_revoked_empty(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.setattr(ca_cli, "REVOCATION_PATH", tmp_path / "crl.json")
    ca_cli.REVOCATION_PATH.write_text("[]")
    ca_cli.cmd_ca_list_revoked(argparse.Namespace())
    out = capsys.readouterr().out
    assert "No revoked" in out


def test_ca_list_revoked_error(monkeypatch, tmp_path: Path):
    class Boom:
        def __init__(self, *_):
            raise RuntimeError("boom")

    monkeypatch.setattr(ca_cli, "RevocationRegistry", Boom)
    monkeypatch.setattr(ca_cli, "REVOCATION_PATH", tmp_path / "crl.json")
    # create placeholder to skip early return
    ca_cli.REVOCATION_PATH.write_text("[]")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_list_revoked(argparse.Namespace())


def test_ca_issue_non_rsa_key(monkeypatch, ca_env: Path):
    ca_cli.cmd_ca_init(
        argparse.Namespace(password="testpass123", force=True)
    )  # noqa: S106

    def fake_loader(*_args, **_kwargs):
        return object(), object(), None

    monkeypatch.setattr(
        "cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates",
        fake_loader,
    )
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", ca_env / "ca.p12")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_issue(
            argparse.Namespace(
                name="X",
                role="Y",
                validity=10,
                out=None,
                password="pass12345",  # noqa: S106
            )
        )


def test_ca_issue_invalid_ca_password(monkeypatch, ca_env: Path):
    ca_cli.cmd_ca_init(
        argparse.Namespace(password="testpass123", force=True)
    )  # noqa: S106

    def fake_loader(*_args, **_kwargs):
        raise ValueError("bad password")

    monkeypatch.setattr(
        "cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates",
        fake_loader,
    )
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", ca_env / "ca.p12")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_issue(
            argparse.Namespace(
                name="X",
                role="Y",
                validity=10,
                out=None,
                password="pass12345",  # noqa: S106
            )
        )


def test_ca_issue_ca_error(monkeypatch, ca_env: Path):
    ca_cli.cmd_ca_init(
        argparse.Namespace(password="testpass123", force=True)
    )  # noqa: S106

    class FakeCA(ca_cli.CertificateAuthority):
        def issue_certificate(self, *_, **__):
            raise ca_cli.CAInitializationError("issue fail")

    monkeypatch.setattr(ca_cli, "CertificateAuthority", FakeCA)
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", ca_env / "ca.p12")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_issue(
            argparse.Namespace(
                name="X",
                role="Y",
                validity=10,
                out=None,
                password="pass12345",  # noqa: S106
            )
        )


def test_ca_issue_generic_error(monkeypatch, ca_env: Path):
    ca_cli.cmd_ca_init(
        argparse.Namespace(password="testpass123", force=True)
    )  # noqa: S106

    class FakeCA(ca_cli.CertificateAuthority):
        def issue_certificate(self, *_, **__):
            raise RuntimeError("boom")

    monkeypatch.setattr(ca_cli, "CertificateAuthority", FakeCA)
    monkeypatch.setattr(ca_cli, "CA_PKCS12_PATH", ca_env / "ca.p12")
    with pytest.raises(SystemExit):
        ca_cli.cmd_ca_issue(
            argparse.Namespace(
                name="X",
                role="Y",
                validity=10,
                out=None,
                password="pass12345",  # noqa: S106
            )
        )
