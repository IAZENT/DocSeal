"""CA (Certificate Authority) management for DocSeal GUI."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID


@dataclass
class CAInfo:
    """Information about a Certificate Authority."""

    name: str
    organization: str
    country: str
    state: str
    city: str
    email: str
    key_size: int = 2048
    valid_days: int = 3650


class CertificateAuthority:
    """Manages Certificate Authority operations."""

    def __init__(self, ca_dir: Path):
        """
        Initialize the CA manager.

        Args:
            ca_dir: Directory for CA keys and certificates
        """
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.ca_dir / "ca_key.pem"
        self.ca_cert_path = self.ca_dir / "ca_cert.pem"
        self.serial_number = self.ca_dir / "serial"

    def ca_exists(self) -> bool:
        """Check if a CA already exists."""
        return self.ca_key_path.exists() and self.ca_cert_path.exists()

    def initialize_ca(self, ca_info: CAInfo) -> tuple[bool, str]:
        """
        Initialize a new Certificate Authority.

        Args:
            ca_info: CA information

        Returns:
            Tuple of (success, message)
        """
        if self.ca_exists():
            return False, "CA already exists"

        # Validate country code (must be exactly 2 characters)
        if not ca_info.country or len(ca_info.country) != 2:
            return False, "Country code must be exactly 2 characters (e.g., 'NP', 'US')"

        # Validate other required fields
        if not ca_info.state or len(ca_info.state) < 1:
            return False, "State/Province is required"
        if not ca_info.city or len(ca_info.city) < 1:
            return False, "City/Locality is required"
        if not ca_info.organization or len(ca_info.organization) < 1:
            return False, "Organization is required"
        if not ca_info.name or len(ca_info.name) < 1:
            return False, "CA name/Common name is required"

        try:
            # Generate CA private key
            ca_key = rsa.generate_private_key(
                public_exponent=65537, key_size=ca_info.key_size
            )

            # Create CA certificate
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, ca_info.country),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca_info.state),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, ca_info.city),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_info.organization),
                    x509.NameAttribute(NameOID.COMMON_NAME, ca_info.name),
                ]
            )

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=ca_info.valid_days))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        key_encipherment=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.RFC822Name(ca_info.email)]),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            # Save CA key
            with open(self.ca_key_path, "wb") as f:
                f.write(
                    ca_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption(),
                    )
                )

            # Save CA certificate
            with open(self.ca_cert_path, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))

            # Initialize serial number file
            self._initialize_serial()

            return True, "CA initialized successfully"

        except Exception as e:
            return False, f"Error initializing CA: {str(e)}"

    def issue_certificate(
        self, common_name: str, organization: str, email: str, valid_days: int = 365
    ) -> tuple[bool, str, Optional[Path]]:
        """
        Issue a certificate signed by the CA.

        Args:
            common_name: Certificate common name
            organization: Organization name
            email: Email address
            valid_days: Certificate validity in days

        Returns:
            Tuple of (success, message, certificate_path)
        """
        if not self.ca_exists():
            return False, "CA does not exist", None

        try:
            # Load CA key and certificate
            with open(self.ca_key_path, "rb") as f:
                ca_key = load_pem_private_key(f.read(), password=None)

            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            # Generate subject key
            subject_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Create certificate request
            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ]
            )

            # Issue certificate
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.issuer)
                .public_key(subject_key.public_key())
                .serial_number(self._get_next_serial())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
                .add_extension(
                    x509.SubjectAlternativeName([x509.RFC822Name(email)]),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=False,
                        crl_sign=False,
                        key_encipherment=True,
                        content_commitment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(ca_key, hashes.SHA256())
            )

            # Save certificate
            cert_filename = f"{common_name.replace(' ', '_')}_cert.pem"
            cert_path = self.ca_dir / cert_filename
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))

            # Save private key
            key_filename = f"{common_name.replace(' ', '_')}_key.pem"
            key_path = self.ca_dir / key_filename
            with open(key_path, "wb") as f:
                f.write(
                    subject_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption(),
                    )
                )

            return True, f"Certificate issued for {common_name}", cert_path

        except Exception as e:
            return False, f"Error issuing certificate: {str(e)}", None

    def revoke_certificate(self, cert_path: Path) -> tuple[bool, str]:
        """
        Revoke a certificate.

        Args:
            cert_path: Path to certificate file

        Returns:
            Tuple of (success, message)
        """
        try:
            revoked_dir = self.ca_dir / "revoked"
            revoked_dir.mkdir(exist_ok=True)

            # Move to revoked directory
            revoked_path = revoked_dir / cert_path.name
            cert_path.rename(revoked_path)

            return True, f"Certificate revoked: {cert_path.name}"

        except Exception as e:
            return False, f"Error revoking certificate: {str(e)}"

    def _initialize_serial(self) -> None:
        """Initialize the serial number file."""
        if not self.serial_number.exists():
            with open(self.serial_number, "w") as f:
                f.write("1")

    def _get_next_serial(self) -> int:
        """Get the next serial number for a certificate."""
        self._initialize_serial()

        with open(self.serial_number, "r") as f:
            serial = int(f.read().strip())

        with open(self.serial_number, "w") as f:
            f.write(str(serial + 1))

        return serial

    def get_ca_info(self) -> Optional[str]:
        """Get CA information as a formatted string."""
        if not self.ca_exists():
            return None

        try:
            with open(self.ca_cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            # Use UTC versions of datetime to avoid deprecation warnings
            valid_from = (
                cert.not_valid_before_utc
                if hasattr(cert, "not_valid_before_utc")
                else cert.not_valid_before
            )
            valid_until = (
                cert.not_valid_after_utc
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after
            )

            info = f"""
            CA Information:
            ===============
            Subject: {cert.subject.rfc4514_string()}
            Issuer: {cert.issuer.rfc4514_string()}
            Valid From: {valid_from}
            Valid Until: {valid_until}
            Serial Number: {cert.serial_number}
            """
            return info

        except Exception as e:
            return f"Error reading CA info: {str(e)}"

    def list_certificates(self) -> list[str]:
        """List all issued certificates."""
        certs = []
        for cert_file in self.ca_dir.glob("*_cert.pem"):
            if cert_file.name != "ca_cert.pem":
                certs.append(cert_file.stem.replace("_cert", ""))
        return sorted(certs)

    def get_certificate_info(self, cert_name: str) -> str:
        """Get details about a specific certificate."""
        cert_path = self.ca_dir / f"{cert_name}_cert.pem"
        if not cert_path.exists():
            return f"Certificate not found: {cert_name}"

        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            valid_from = (
                cert.not_valid_before_utc
                if hasattr(cert, "not_valid_before_utc")
                else cert.not_valid_before
            )
            valid_until = (
                cert.not_valid_after_utc
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after
            )

            info = f"""
Certificate: {cert_name}
Subject: {cert.subject.rfc4514_string()}
Valid From: {valid_from.strftime('%Y-%m-%d %H:%M:%S UTC')}
Valid Until: {valid_until.strftime('%Y-%m-%d %H:%M:%S UTC')}
Serial Number: {cert.serial_number}
            """
            return info
        except Exception as e:
            return f"Error reading certificate: {str(e)}"

    def get_ca_key(self):
        """Load and return the CA private key."""
        if not self.ca_exists():
            raise ValueError("CA does not exist. Please initialize it first.")
        with open(self.ca_key_path, "rb") as f:
            return load_pem_private_key(f.read(), password=None)

    def get_ca_cert(self) -> x509.Certificate:
        """Load and return the CA certificate."""
        if not self.ca_exists():
            raise ValueError("CA does not exist. Please initialize it first.")
        with open(self.ca_cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
