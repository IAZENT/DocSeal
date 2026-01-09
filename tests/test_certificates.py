import secrets

import pytest

from docseal.ca.authority import CertificateAuthority
from docseal.ca.certificates import CertificateIssuer


def test_issue_certificate_requires_common_name():
    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(12))

    issuer = CertificateIssuer(ca.private_key, ca.certificate)

    with pytest.raises(ValueError):
        issuer.issue_certificate(common_name="", role="role")


def test_issue_certificate_validity_positive():
    ca = CertificateAuthority()
    ca.initialize(password=secrets.token_urlsafe(12))

    issuer = CertificateIssuer(ca.private_key, ca.certificate)

    with pytest.raises(ValueError):
        issuer.issue_certificate(common_name="Name", role="role", validity_days=0)
