from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from docseal.utils.validation import _utc_property, validate_certificate_chain


def _build_self_signed_ca(key_type: str = "rsa", common_name: str = "Test CA"):
    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError("unsupported key type in test helper")

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    return private_key, cert


def _issue_cert_signed_by(
    ca_private_key,
    ca_cert,
    common_name: str = "end-entity",
    *,
    not_before=None,
    not_after=None,
):
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.now(timezone.utc)
    nb = not_before or now
    na = not_after or (now + timedelta(days=365))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )

    cert = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    return user_key, cert


def test__utc_property_prefers_utc_attr():
    class DummyCert:
        not_valid_before_utc = datetime(2020, 1, 1, tzinfo=timezone.utc)

    cert = DummyCert()
    assert _utc_property(cert, "not_valid_before") == cert.not_valid_before_utc


def test__utc_property_handles_naive_datetime():
    class DummyCert:
        not_valid_before = datetime(2020, 1, 1)

    cert = DummyCert()
    val = _utc_property(cert, "not_valid_before")
    assert val.tzinfo is not None
    assert val.tzinfo.utcoffset(val) == timezone.utc.utcoffset(val)


def test_validate_certificate_chain_success_rsa():
    ca_key, ca_cert = _build_self_signed_ca("rsa")
    _, cert = _issue_cert_signed_by(ca_key, ca_cert)

    assert validate_certificate_chain(cert, ca_cert) is True


def test_validate_certificate_chain_invalid_signature():
    # Signed by a different CA
    ca1_key, ca1_cert = _build_self_signed_ca("rsa", "CA One")
    ca2_key, ca2_cert = _build_self_signed_ca("rsa", "CA Two")

    _, cert = _issue_cert_signed_by(ca1_key, ca1_cert)

    # Validation against ca2 should fail due to signature mismatch
    assert validate_certificate_chain(cert, ca2_cert) is False


def test_validate_certificate_chain_issuer_mismatch():
    ca_key, ca_cert = _build_self_signed_ca("rsa", "Original CA")
    _, cert = _issue_cert_signed_by(ca_key, ca_cert)

    # Create a CA certificate with the same public key but a different subject
    subject2 = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Other Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Different CA"),
        ]
    )

    now = datetime.now(timezone.utc)
    ca2 = (
        x509.CertificateBuilder()
        .subject_name(subject2)
        .issuer_name(subject2)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Signature verification will pass (same key) but issuer name differs
    assert validate_certificate_chain(cert, ca2) is False


def test_validate_certificate_chain_not_yet_valid():
    ca_key, ca_cert = _build_self_signed_ca("rsa")
    future_start = datetime.now(timezone.utc) + timedelta(days=10)
    _, cert = _issue_cert_signed_by(ca_key, ca_cert, not_before=future_start)

    assert validate_certificate_chain(cert, ca_cert) is False


def test_validate_certificate_chain_expired():
    ca_key, ca_cert = _build_self_signed_ca("rsa")
    past_start = datetime.now(timezone.utc) - timedelta(days=10)
    past_end = datetime.now(timezone.utc) - timedelta(days=1)
    _, cert = _issue_cert_signed_by(
        ca_key, ca_cert, not_before=past_start, not_after=past_end
    )

    assert validate_certificate_chain(cert, ca_cert) is False


def test_validate_certificate_chain_unsupported_ca_key_type():
    # Create a dummy CA-like object with an unsupported public key type
    class DummyCA:
        def public_key(self):
            return object()

    ca_key, ca_cert = _build_self_signed_ca("rsa")
    _, cert = _issue_cert_signed_by(ca_key, ca_cert)

    assert validate_certificate_chain(cert, DummyCA()) is False


def test_validate_certificate_chain_verify_raises_generic_exception(monkeypatch):
    # Force public_key.verify to raise a non-InvalidSignature exception by
    # providing a dummy object with a verify that raises and monkeypatching
    # the module's RSAPublicKey so isinstance checks succeed.

    class DummyPub:
        def verify(self, *args, **kwargs):
            raise ValueError("boom")

    dummy_pub = DummyPub()

    class FakeCA:
        def public_key(self):
            return dummy_pub

    # Monkeypatch the module's RSAPublicKey symbol so isinstance works
    import docseal.utils.validation as validation_mod

    monkeypatch.setattr(validation_mod, "RSAPublicKey", DummyPub, raising=False)

    ca_key, ca_cert = _build_self_signed_ca("rsa")
    _, cert = _issue_cert_signed_by(ca_key, ca_cert)

    assert validate_certificate_chain(cert, FakeCA()) is False


def test_validate_certificate_chain_ec_success():
    ca_key, ca_cert = _build_self_signed_ca("ec")
    _, cert = _issue_cert_signed_by(ca_key, ca_cert)
    assert validate_certificate_chain(cert, ca_cert) is True


def test_validate_certificate_chain_dsa_success():
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.x509.oid import NameOID

    private_key = dsa.generate_private_key(key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DSA CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "DSA User"),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
    )

    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    assert validate_certificate_chain(cert, ca_cert) is True


def test_validate_certificate_chain_ed25519_success():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Ed CA"),
        ]
    )
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, None)
    )

    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DocSeal Tests"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Ed User"),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
    )

    cert = builder.sign(private_key=private_key, algorithm=None)
    assert validate_certificate_chain(cert, ca_cert) is True


def test_validate_certificate_chain_alg_none_for_rsa_and_ec():
    # Fake cert with signature_hash_algorithm = None should return False
    class FakeCert:
        signature_hash_algorithm = None

    ca_key, ca_cert = _build_self_signed_ca("rsa")
    assert validate_certificate_chain(FakeCert(), ca_cert) is False

    ca_key_ec, ca_cert_ec = _build_self_signed_ca("ec")
    assert validate_certificate_chain(FakeCert(), ca_cert_ec) is False
