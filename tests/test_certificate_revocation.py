import secrets

from docseal.ca.authority import CertificateAuthority
from docseal.utils.validation import validate_certificate


def test_certificate_revocation():
    ca = CertificateAuthority()
    pwd = secrets.token_urlsafe(16)
    ca.initialize(password=pwd)

    _, cert = ca.issue_certificate(common_name="Lecturer Two", role="lecturer")

    # Initially valid
    assert validate_certificate(cert, ca._certificate, ca.is_revoked(cert)) is True

    # Revoke
    ca.revoke_certificate(cert, reason="Key compromised")

    # Should now fail
    assert validate_certificate(cert, ca._certificate, ca.is_revoked(cert)) is False


def test_crl_generation():
    ca = CertificateAuthority()
    pwd = secrets.token_urlsafe(16)
    ca.initialize(password=pwd)

    _, cert = ca.issue_certificate(common_name="Student B", role="student")

    ca.revoke_certificate(cert, reason="Left university")

    crl = ca.generate_crl()
    assert crl is not None
    assert len(list(crl)) == 1
