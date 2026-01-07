import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class RevocationRegistry:
    """Persistent revocation registry for certificate revocation.

    Stores revoked certificate serial numbers in a JSON file.
    Simple, persistent, and serializable.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            self.revoked = set(json.loads(self.path.read_text()))
        else:
            self.revoked = set()

    def revoke(self, serial_number: int) -> None:
        self.revoked.add(serial_number)
        self._save()

    def is_revoked(self, serial_number: int) -> bool:
        return serial_number in self.revoked

    def _save(self) -> None:
        self.path.write_text(json.dumps(sorted(self.revoked)))


class RevocationManager:
    """In-memory revocation manager used by the test CA.

    Stores revoked serial numbers and reasons and can produce a signed CRL.
    """

    def __init__(
        self,
        ca_private_key: RSAPrivateKey,
        ca_certificate: x509.Certificate,
    ) -> None:
        self._ca_key = ca_private_key
        self._ca_cert = ca_certificate
        # Map serial_number -> (revocation_date, reason)
        self._revoked_serials: Dict[int, tuple[datetime, str]] = {}

    def revoke(self, serial_number: int, reason: str) -> None:
        self._revoked_serials[serial_number] = (datetime.now(timezone.utc), reason)

    def is_revoked(self, serial_number: int) -> bool:
        return serial_number in self._revoked_serials

    def generate_crl(self) -> x509.CertificateRevocationList:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._ca_cert.subject)
            .last_update(datetime.now(timezone.utc))
            .next_update(datetime.now(timezone.utc) + timedelta(days=7))
        )

        for serial, (revocation_date, _reason) in self._revoked_serials.items():
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revocation_date)
                .add_extension(
                    # Use a generic CRLReason extension; the exact reason enum
                    # can be mapped from the provided string if needed. For
                    # tests we use unspecified.
                    x509.CRLReason(x509.ReasonFlags.unspecified),
                    critical=False,
                )
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        return builder.sign(private_key=self._ca_key, algorithm=hashes.SHA256())
