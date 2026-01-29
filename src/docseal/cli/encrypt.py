"""CLI command for encrypting documents."""

import argparse
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from docseal.core import DsealEnvelope, DocSealService
from docseal.cli.colors import error, success, info


def encrypt_command(args: argparse.Namespace) -> int:
    """Encrypt a document for a recipient.
    
    Creates a .dseal envelope with encrypted payload.
    """
    try:
        # Validate inputs
        doc_path = Path(args.document)
        if not doc_path.exists():
            error(f"Document not found: {doc_path}")
            return 1
        
        recipient_cert_path = Path(args.recipient_cert)
        if not recipient_cert_path.exists():
            error(f"Recipient certificate not found: {recipient_cert_path}")
            return 1
        
        # Determine output path
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = doc_path.parent / f"{doc_path.stem}.encrypted.dseal"
        
        # Load document
        document_bytes = doc_path.read_bytes()
        info(f"Loaded document: {len(document_bytes)} bytes")
        
        # Load recipient certificate
        cert_pem = recipient_cert_path.read_bytes()
        recipient_cert = x509.load_pem_x509_certificate(cert_pem)
        info(f"Loaded recipient certificate")
        
        # Encrypt
        service = DocSealService()
        envelope = service.encrypt(document_bytes, recipient_cert)
        
        # Save
        output_path.write_bytes(envelope.to_bytes())
        success(f"Document encrypted and saved to: {output_path}")
        
        return 0
        
    except Exception as e:
        error(f"Encryption failed: {e}")
        return 1


def register_encrypt_command(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
    """Register the encrypt command."""
    parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a document for a recipient",
        description="Encrypt a document using AES-256-GCM for a recipient.",
    )
    
    parser.add_argument(
        "--document",
        "-d",
        required=True,
        help="Path to document to encrypt",
    )
    
    parser.add_argument(
        "--recipient-cert",
        "-r",
        required=True,
        help="Path to recipient's X.509 certificate (PEM format)",
    )
    
    parser.add_argument(
        "--output",
        "-o",
        help="Output path for encrypted .dseal file (default: <document>.encrypted.dseal)",
    )
    
    parser.set_defaults(func=encrypt_command)
