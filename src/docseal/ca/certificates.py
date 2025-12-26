from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

# Private OID for DocSeal role extension (example enterprise OID)
DOCSEAL_ROLE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")


class CertificateIssuer:
    """Issues end-entity certificates signed by a CA."""

    def __init__(
        self,
        ca_private_key: rsa.RSAPrivateKey,
        ca_certificate: x509.Certificate,
        *,
        country: str = "NP",
        organization: str = "DocSeal University",
    ):
        self._ca_key = ca_private_key
        self._ca_cert = ca_certificate
        self._country = country
        self._organization = organization

    def issue_certificate(
        self,
        common_name: str,
        role: str,
        validity_days: int = 365,
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        if not common_name:
            raise ValueError("common_name must not be empty")
        if validity_days <= 0:
            raise ValueError("validity_days must be positive")

        # 1. Generate key
        user_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )

        # 2. Subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self._country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.now(timezone.utc)

        # 3. Certificate builder
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
        )

        # 4. Required extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=False,
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_key.public_key()),
            critical=False,
        )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._ca_key.public_key()
            ),
            critical=False,
        )

        # 5. Role extension (clean, explicit, extensible)
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                DOCSEAL_ROLE_OID,
                role.encode("utf-8"),
            ),
            critical=False,
        )

        # 6. Sign
        cert = builder.sign(
            private_key=self._ca_key,
            algorithm=hashes.SHA256(),
        )

        return user_key, cert
