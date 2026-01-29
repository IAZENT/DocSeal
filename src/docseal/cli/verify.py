"""Document verification CLI command."""

import argparse
import sys
from pathlib import Path

from cryptography import x509

from docseal.core import DsealEnvelope, DocSealService
from docseal.cli.colors import error, success, info, warning


def register_verify_command(
    subparsers: argparse._SubParsersAction,  # type: ignore
) -> None:
    """Register the verify command."""
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a document signature",
        description="Verify the cryptographic signature in a .dseal envelope",
    )

    verify_parser.add_argument(
        "--envelope",
        "-e",
        required=True,
        help="Path to .dseal envelope file",
    )
    verify_parser.add_argument(
        "--cert",
        "-c",
        help="Path to signer's X.509 certificate (PEM format) for trust validation",
    )
    verify_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed verification information",
    )

    verify_parser.set_defaults(func=cmd_verify)


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a document signature."""
    try:
        # Validate input file
        envelope_path = Path(args.envelope)
        if not envelope_path.exists():
            error(f"Envelope file not found: {envelope_path}")
            return 1

        if not envelope_path.is_file():
            error(f"Not a file: {envelope_path}")
            return 1

        # Load envelope
        envelope_bytes = envelope_path.read_bytes()
        envelope = DsealEnvelope.from_bytes(envelope_bytes)
        info(f"Loaded envelope from: {envelope_path}")

        # Load trusted certificate if provided
        trusted_certs = None
        if args.cert:
            cert_path = Path(args.cert)
            if not cert_path.exists():
                error(f"Certificate not found: {cert_path}")
                return 1
            cert_pem = cert_path.read_bytes()
            trusted_cert = x509.load_pem_x509_certificate(cert_pem)
            trusted_certs = [trusted_cert]

        # Verify signature
        service = DocSealService()
        result = service.verify(envelope, trusted_certs)

        # Display results
        if result.is_valid:
            success("✓ Signature is valid")
        else:
            warning("✗ Signature verification failed")
            if result.error_message:
                error(f"  Error: {result.error_message}")
            return 1

        # Display detailed information
        if args.verbose or args.cert:
            print()
            if result.signer_name:
                info(f"Signer: {result.signer_name}")
            if result.signer_email:
                info(f"Email: {result.signer_email}")
            if result.signature_timestamp:
                info(f"Timestamp: {result.signature_timestamp}")
            if envelope.metadata.description:
                info(f"Description: {envelope.metadata.description}")
            if result.is_encrypted:
                warning("Payload is encrypted")
            else:
                success("Payload is plaintext")

        return 0

    except Exception as e:
        error(f"Verification failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
