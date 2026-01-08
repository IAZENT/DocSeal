"""Document signing CLI command."""

from __future__ import annotations

import argparse
import sys
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)

from docseal.crypto.signing import save_signature, sign_document


def register_sign_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the sign command."""
    sign_parser = subparsers.add_parser(
        "sign",
        help="Sign a document",
        description="Create a detached cryptographic signature for a document",
    )

    sign_parser.add_argument(
        "--doc",
        required=True,
        help="Path to document to sign",
    )
    sign_parser.add_argument(
        "--cert",
        required=True,
        help="Path to PKCS#12 certificate bundle (.p12)",
    )
    sign_parser.add_argument(
        "--out",
        required=True,
        help="Output path for signature file (.sig)",
    )
    sign_parser.add_argument(
        "--password",
        help="Certificate password (will prompt if not provided)",
    )

    sign_parser.set_defaults(func=cmd_sign)


def cmd_sign(args: argparse.Namespace) -> None:
    """Sign a document with a certificate."""
    # Validate input file
    doc_path = Path(args.doc)
    if not doc_path.exists():
        print(f"[!] Document not found: {doc_path}", file=sys.stderr)
        sys.exit(1)

    if not doc_path.is_file():
        print(f"[!] Not a file: {doc_path}", file=sys.stderr)
        sys.exit(1)

    # Validate certificate file
    cert_path = Path(args.cert)
    if not cert_path.exists():
        print(f"[!] Certificate not found: {cert_path}", file=sys.stderr)
        sys.exit(1)

    # Get password
    password = args.password
    if not password:
        password = getpass("Enter certificate password: ")

    try:
        # Load PKCS#12 certificate
        pkcs12_data = cert_path.read_bytes()
        private_key, certificate, _additional_certs = load_key_and_certificates(
            pkcs12_data, password.encode("utf-8")
        )

        if not private_key:
            print("[!] No private key found in certificate", file=sys.stderr)
            sys.exit(1)

        if not certificate:
            print("[!] No certificate found in bundle", file=sys.stderr)
            sys.exit(1)

        # Type check: ensure we have RSA key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        if not isinstance(private_key, RSAPrivateKey):
            print("[!] Only RSA keys are supported", file=sys.stderr)
            sys.exit(1)

        # Sign document
        print(f"Signing document: {doc_path}")
        signature_data = sign_document(doc_path, private_key, certificate)

        # Save signature
        output_path = Path(args.out)
        save_signature(signature_data, output_path)

        # Display info
        print("✓ Document signed successfully")
        print(f"  Document:    {doc_path}")
        print(f"  Signature:   {output_path}")
        print(f"  Document ID: {signature_data['document_id']}")
        print(f"  Timestamp:   {signature_data['timestamp']}")
        print(f"  Signer:      {certificate.subject.rfc4514_string()}")

    except ValueError as e:
        print(f"[!] Invalid certificate or password: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Signing failed: {e}", file=sys.stderr)
        sys.exit(1)
