"""Generate test keys and certificates for DocSeal integration tests."""

import os
from datetime import datetime, timedelta, timezone

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_test_keys_and_certs():
    """Generate RSA-2048 keys and X.509 certificates for all test users."""
    # Load test users configuration
    with open("tests/users.yaml", "r") as f:
        config = yaml.safe_load(f)

    users = config["users"]
    key_size = config["crypto"]["key_size"]
    validity_days = config["certificates"]["validity_days"]

    # Create directories if they don't exist
    os.makedirs("data/keys", exist_ok=True)
    os.makedirs("data/certs", exist_ok=True)

    print(f"Generating test keys and certificates (RSA-{key_size})...")
    print()

    for user_id, user_config in users.items():
        print(f"  Generating keys for {user_config['name']}...")

        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Save private key
        key_path = user_config["key_file"]
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        print(f"    ✓ Private key: {key_path}")

        # Generate X.509 certificate
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "England"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "London"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, user_config["name"]),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, user_config["email"]),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # Self-signed for testing
            .public_key(private_key.public_key())
            .serial_number(
                users[user_id].get("serial", hash(user_config["name"]) % 10000000)
            )
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(user_config["email"])]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Save certificate
        cert_path = user_config["cert_file"]
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"    ✓ Certificate: {cert_path}")

    print()
    print("✓ All test keys and certificates generated successfully!")
    print()
    print("Summary:")
    print(f"  Users: {len(users)}")
    print(f"  Key size: RSA-{key_size}")
    print(f"  Certificate validity: {validity_days} days")
    print("  Location: data/keys/ and data/certs/")


if __name__ == "__main__":
    generate_test_keys_and_certs()
