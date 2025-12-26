import os
import secrets

from docseal.ca.authority import CertificateAuthority
from docseal.utils.validation import validate_certificate_chain


def _init_ca() -> CertificateAuthority:
    ca = CertificateAuthority()
    password = os.environ.get("DOCSEAL_TEST_PASSWORD") or secrets.token_urlsafe(16)
    ca.initialize(password=password)
    return ca


def test_issue_staff_certificate():
    ca = _init_ca()

    key, cert = ca.issue_certificate(
        common_name="Lecturer One",
        role="lecturer",
    )

    assert key is not None
    assert cert is not None
    assert "CN=Lecturer One" in cert.subject.rfc4514_string()


def test_certificate_chain_validation():
    ca = _init_ca()

    _, cert = ca.issue_certificate(
        common_name="Student A",
        role="student",
    )

    assert validate_certificate_chain(
        cert,
        ca.certificate,
    )
