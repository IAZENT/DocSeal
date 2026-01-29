"""Document signing CLI command."""

import argparse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from docseal.cli.colors import error, info, success
from docseal.core import DocSealService


def register_sign_command(
    subparsers: argparse._SubParsersAction,  # type: ignore
) -> None:
    """Register the sign command."""
    sign_parser = subparsers.add_parser(
        "sign",
        help="Sign a document",
        description="Sign a document and create a .dseal envelope",
    )

    sign_parser.add_argument(
        "--document",
        "-d",
        required=True,
        help="Path to document to sign",
    )
    sign_parser.add_argument(
        "--cert",
        "-c",
        required=True,
        help="Path to signer's X.509 certificate (PEM format)",
    )
    sign_parser.add_argument(
        "--key",
        "-k",
        required=True,
        help="Path to signer's private key (PEM format)",
    )
    sign_parser.add_argument(
        "--output",
        "-o",
        help="Output path for .dseal file (default: <document>.dseal)",
    )
    sign_parser.add_argument(
        "--description",
        help="Optional description of the signature",
    )

    sign_parser.set_defaults(func=cmd_sign)


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a document with a certificate."""
    try:
        # Validate input file
        doc_path = Path(args.document)
        if not doc_path.exists():
            error(f"Document not found: {doc_path}")
            return 1

        if not doc_path.is_file():
            error(f"Not a file: {doc_path}")
            return 1

        # Validate key file
        key_path = Path(args.key)
        if not key_path.exists():
            error(f"Private key not found: {key_path}")
            return 1

        # Validate cert file
        cert_path = Path(args.cert)
        if not cert_path.exists():
            error(f"Certificate not found: {cert_path}")
            return 1

        # Determine output path
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = doc_path.parent / f"{doc_path.stem}.dseal"

        # Load document
        document_bytes = doc_path.read_bytes()
        info(f"Loaded document: {len(document_bytes)} bytes")

        # Load private key
        key_pem = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            error("Private key must be RSA")
            return 1

        # Load certificate
        cert_pem = cert_path.read_bytes()
        certificate = x509.load_pem_x509_certificate(cert_pem)
        info("Loaded signer certificate")

        # Sign document
        service = DocSealService()
        envelope = service.sign(
            document_bytes,
            private_key,
            certificate,
            description=args.description or "",
        )

        # Save
        output_path.write_bytes(envelope.to_bytes())
        success(f"Document signed and saved to: {output_path}")

        return 0

    except Exception as e:
        error(f"Signing failed: {e}")
        return 1
