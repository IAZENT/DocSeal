"""Document verification CLI command."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography import x509

from docseal.audit.logger import AuditLogger
from docseal.ca.revocation import RevocationRegistry
from docseal.crypto.verification import verify_document_signature

# Default paths
CA_DIR = Path.home() / ".docseal" / "ca"
CA_PEM_PATH = CA_DIR / "ca.pem"
REVOCATION_PATH = CA_DIR / "crl.json"
AUDIT_LOG_PATH = CA_DIR / "audit.log"


def register_verify_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the verify command."""
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a document signature",
        description="Verify the cryptographic signature of a document",
    )

    verify_parser.add_argument(
        "--doc",
        required=True,
        help="Path to document to verify",
    )
    verify_parser.add_argument(
        "--sig",
        required=True,
        help="Path to signature file (.sig)",
    )
    verify_parser.add_argument(
        "--ca",
        help=f"Path to CA certificate (default: {CA_PEM_PATH})",
    )
    verify_parser.add_argument(
        "--no-revocation-check",
        action="store_true",
        help="Skip certificate revocation checking",
    )
    verify_parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Skip audit logging",
    )
    verify_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed verification information",
    )

    verify_parser.set_defaults(func=cmd_verify)


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a document signature."""
    # Validate input files
    doc_path = Path(args.doc)
    if not doc_path.exists():
        print(f"[!] Document not found: {doc_path}", file=sys.stderr)
        sys.exit(1)

    if not doc_path.is_file():
        print(f"[!] Not a file: {doc_path}", file=sys.stderr)
        sys.exit(1)

    sig_path = Path(args.sig)
    if not sig_path.exists():
        print(f"[!] Signature not found: {sig_path}", file=sys.stderr)
        sys.exit(1)

    # Load CA certificate
    ca_path = Path(args.ca) if args.ca else CA_PEM_PATH
    if not ca_path.exists():
        print(
            f"[!] CA certificate not found: {ca_path}",
            file=sys.stderr,
        )
        print("    Run 'docseal ca init' first or specify --ca", file=sys.stderr)
        sys.exit(1)

    try:
        ca_cert_pem = ca_path.read_bytes()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    except Exception as e:
        print(f"[!] Failed to load CA certificate: {e}", file=sys.stderr)
        sys.exit(1)

    # Setup revocation checking
    revocation_registry = None
    if not args.no_revocation_check:
        if REVOCATION_PATH.exists():
            revocation_registry = RevocationRegistry(REVOCATION_PATH)
        elif args.verbose:
            print("[i] No revocation list found, skipping revocation check")

    # Setup audit logging
    audit_logger = None
    if not args.no_audit:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = AuditLogger(AUDIT_LOG_PATH)

    # Verify signature
    try:
        if args.verbose:
            print("Verifying signature...")
            print(f"  Document:  {doc_path}")
            print(f"  Signature: {sig_path}")
            print(f"  CA:        {ca_path}")

        result = verify_document_signature(
            document_path=doc_path,
            signature_path=sig_path,
            trusted_ca_cert=ca_cert,
            revocation_registry=revocation_registry,
            audit_logger=audit_logger,
        )

        # Success output
        print("\nSIGNATURE VALID")
        print(f"  Signer:      {result['signer']}")
        print(f"  Document ID: {result['document_id']}")
        print(f"  Timestamp:   {result['timestamp']}")

        if audit_logger and not args.no_audit:
            print(f"  Audit log:   {AUDIT_LOG_PATH}")

        if args.verbose:
            print("\n[i] All verification checks passed:")
            print("    - Certificate trust chain")
            print("    - Certificate validity period")
            if not args.no_revocation_check:
                print("    - Certificate revocation status")
            print("    - Document hash integrity")
            print("    - Cryptographic signature")

    except ValueError as e:
        # Verification failed
        print("\nSIGNATURE INVALID", file=sys.stderr)
        print(f"  Reason: {e}", file=sys.stderr)

        if audit_logger and not args.no_audit:
            print(f"  Audit log: {AUDIT_LOG_PATH}", file=sys.stderr)

        sys.exit(1)

    except Exception as e:
        print(f"[!] Verification error: {e}", file=sys.stderr)
        sys.exit(1)
