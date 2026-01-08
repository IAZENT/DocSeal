"""Certificate Authority CLI commands."""

from __future__ import annotations

import argparse
import sys
from getpass import getpass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import Any, cast

from docseal.ca.authority import CertificateAuthority
from docseal.ca.exceptions import CAAlreadyInitialized, CAInitializationError
from docseal.ca.revocation import RevocationRegistry

# Default paths for CA artifacts
CA_DIR = Path.home() / ".docseal" / "ca"
CA_PKCS12_PATH = CA_DIR / "ca.p12"
CA_PEM_PATH = CA_DIR / "ca.pem"
REVOCATION_PATH = CA_DIR / "crl.json"


def register_ca_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register CA subcommands."""
    ca_parser = subparsers.add_parser(
        "ca",
        help="Certificate Authority operations",
        description="Manage the DocSeal Certificate Authority",
    )

    ca_subparsers = ca_parser.add_subparsers(
        dest="ca_command",
        required=True,
        help="CA operations",
    )

    # ca init
    init_parser = ca_subparsers.add_parser(
        "init",
        help="Initialize a new CA",
        description="Create a new Certificate Authority with self-signed root",
    )
    init_parser.add_argument(
        "--password",
        help="CA password (will prompt if not provided)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing CA if present",
    )
    init_parser.set_defaults(func=cmd_ca_init)

    # ca issue
    issue_parser = ca_subparsers.add_parser(
        "issue",
        help="Issue a new certificate",
        description="Issue a certificate for staff members signed by the CA",
    )
    issue_parser.add_argument(
        "--name",
        required=True,
        help="Common name for the certificate (e.g., 'John Doe')",
    )
    issue_parser.add_argument(
        "--role",
        required=True,
        help="Role of the certificate holder (e.g., 'Registrar', 'Dean')",
    )
    issue_parser.add_argument(
        "--validity",
        type=int,
        default=365,
        help="Certificate validity in days (default: 365)",
    )
    issue_parser.add_argument(
        "--out",
        help="Output path for certificate bundle (default: <name>.p12)",
    )
    issue_parser.add_argument(
        "--password",
        help="Password for certificate protection (will prompt if not provided)",
    )
    issue_parser.set_defaults(func=cmd_ca_issue)

    # ca revoke
    revoke_parser = ca_subparsers.add_parser(
        "revoke",
        help="Revoke a certificate",
        description="Add a certificate to the revocation list",
    )
    revoke_parser.add_argument(
        "--serial",
        type=int,
        required=True,
        help="Serial number of the certificate to revoke",
    )
    revoke_parser.add_argument(
        "--reason",
        default="unspecified",
        help="Revocation reason (default: unspecified)",
    )
    revoke_parser.set_defaults(func=cmd_ca_revoke)

    # ca list
    list_parser = ca_subparsers.add_parser(
        "list",
        help="List revoked certificates",
        description="Display all revoked certificate serial numbers",
    )
    list_parser.set_defaults(func=cmd_ca_list_revoked)

    # ca info
    info_parser = ca_subparsers.add_parser(
        "info",
        help="Display CA information",
        description="Show Certificate Authority details",
    )
    info_parser.set_defaults(func=cmd_ca_info)


def cmd_ca_init(args: argparse.Namespace) -> None:
    """Initialize a new Certificate Authority."""
    # Check if CA already exists
    if CA_PKCS12_PATH.exists() and not args.force:
        print(
            f"[!] CA already exists at {CA_PKCS12_PATH}",
            file=sys.stderr,
        )
        print("    Use --force to overwrite", file=sys.stderr)
        sys.exit(1)

    # Get password
    password = args.password
    if not password:
        password = getpass("Enter CA password: ")
        password_confirm = getpass("Confirm CA password: ")
        if password != password_confirm:
            print("[!] Passwords do not match", file=sys.stderr)
            sys.exit(1)

    if len(password) < 8:
        print("[!] Password must be at least 8 characters", file=sys.stderr)
        sys.exit(1)

    try:
        # Create CA directory
        CA_DIR.mkdir(parents=True, exist_ok=True)

        # Initialize CA
        ca = CertificateAuthority()
        ca.initialize(password=password)

        # Export PKCS#12
        pkcs12_data = ca.export_pkcs12(password=password)
        CA_PKCS12_PATH.write_bytes(pkcs12_data)

        # Export CA certificate in PEM format for verification
        if ca.certificate:
            pem_data = ca.certificate.public_bytes(encoding=serialization.Encoding.PEM)
            CA_PEM_PATH.write_bytes(pem_data)

        print("✓ CA initialized successfully")
        print(f"  PKCS#12: {CA_PKCS12_PATH}")
        print(f"  PEM:     {CA_PEM_PATH}")
        print(f"  Serial:  {ca.certificate.serial_number if ca.certificate else 'N/A'}")

    except (CAAlreadyInitialized, CAInitializationError) as e:
        print(f"[!] CA initialization failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_ca_issue(args: argparse.Namespace) -> None:
    """Issue a new certificate signed by the CA."""
    # Check if CA exists
    if not CA_PKCS12_PATH.exists():
        print(
            "[!] CA not initialized. Run 'docseal ca init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    # Get password for certificate protection
    cert_password = args.password
    if not cert_password:
        cert_password = getpass("Enter password for certificate: ")
        cert_password_confirm = getpass("Confirm password: ")
        if cert_password != cert_password_confirm:
            print("[!] Passwords do not match", file=sys.stderr)
            sys.exit(1)

    try:
        # Load existing CA from PKCS#12
        ca_password = getpass("Enter CA password: ")
        ca_pkcs12 = CA_PKCS12_PATH.read_bytes()

        from cryptography.hazmat.primitives.serialization.pkcs12 import (
            load_key_and_certificates,
        )

        ca_key, ca_cert, _ = load_key_and_certificates(
            ca_pkcs12, ca_password.encode("utf-8")
        )

        if not ca_key or not ca_cert:
            print("[!] Failed to load CA certificate", file=sys.stderr)
            sys.exit(1)

        # Type check: ensure we have RSA key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        if not isinstance(ca_key, RSAPrivateKey):
            print("[!] CA key is not RSA", file=sys.stderr)
            sys.exit(1)

        # Use loaded CA to issue certificate
        ca = CertificateAuthority()
        ca._private_key = ca_key
        ca._certificate = ca_cert

        # Issue certificate
        private_key, certificate = ca.issue_certificate(
            common_name=args.name,
            role=args.role,
            validity_days=args.validity,
        )

        # Determine output path
        output_path = (
            Path(args.out)
            if args.out
            else Path(f"{args.name.replace(' ', '_').lower()}.p12")
        )

        # Export as PKCS#12
        from cryptography.hazmat.primitives.serialization.pkcs12 import (
            serialize_key_and_certificates,
        )

        pkcs12_data = serialize_key_and_certificates(
            name=args.name.encode("utf-8"),
            key=cast(Any, private_key),
            cert=certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(
                cert_password.encode("utf-8")
            ),
        )

        output_path.write_bytes(pkcs12_data)

        print("✓ Certificate issued successfully")
        print(f"  Name:    {args.name}")
        print(f"  Role:    {args.role}")
        print(f"  Serial:  {certificate.serial_number}")
        print(f"  Valid:   {args.validity} days")
        print(f"  Output:  {output_path}")

    except ValueError as e:
        print(f"[!] Invalid CA password: {e}", file=sys.stderr)
        sys.exit(1)
    except CAInitializationError as e:
        print(f"[!] Failed to issue certificate: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_ca_revoke(args: argparse.Namespace) -> None:
    """Revoke a certificate."""
    try:
        # Ensure revocation registry exists
        REVOCATION_PATH.parent.mkdir(parents=True, exist_ok=True)

        registry = RevocationRegistry(REVOCATION_PATH)
        registry.revoke(args.serial)

        print("✓ Certificate revoked successfully")
        print(f"  Serial: {args.serial}")
        print(f"  Reason: {args.reason}")

    except Exception as e:
        print(f"[!] Failed to revoke certificate: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_ca_list_revoked(args: argparse.Namespace) -> None:
    """List all revoked certificates."""
    if not REVOCATION_PATH.exists():
        print("No revoked certificates")
        return

    try:
        registry = RevocationRegistry(REVOCATION_PATH)
        if not registry.revoked:
            print("No revoked certificates")
            return

        print(f"Revoked certificates ({len(registry.revoked)}):")
        for serial in sorted(registry.revoked):
            print(f"  - Serial: {serial}")

    except Exception as e:
        print(f"[!] Failed to list revoked certificates: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_ca_info(args: argparse.Namespace) -> None:
    """Display CA information."""
    if not CA_PEM_PATH.exists():
        print(
            "[!] CA not initialized. Run 'docseal ca init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        # Load CA certificate
        cert_pem = CA_PEM_PATH.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Extract info
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        serial = cert.serial_number

        # Handle both old and new cryptography APIs
        from datetime import timezone

        if hasattr(cert, "not_valid_before_utc"):
            not_before = getattr(cert, "not_valid_before_utc")
            not_after = getattr(cert, "not_valid_after_utc")
        else:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        print("Certificate Authority Information:")
        print(f"  Subject:     {subject}")
        print(f"  Issuer:      {issuer}")
        print(f"  Serial:      {serial}")
        print(f"  Valid from:  {not_before}")
        print(f"  Valid until: {not_after}")
        print(f"  PKCS#12:     {CA_PKCS12_PATH}")
        print(f"  PEM:         {CA_PEM_PATH}")

    except Exception as e:
        print(f"[!] Failed to read CA info: {e}", file=sys.stderr)
        sys.exit(1)
