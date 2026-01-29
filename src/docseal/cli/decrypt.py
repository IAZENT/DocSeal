"""CLI command for decrypting documents."""

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from docseal.core import DsealEnvelope, DocSealService
from docseal.cli.colors import error, success, info


def decrypt_command(args: argparse.Namespace) -> int:
    """Decrypt an encrypted .dseal document.
    
    Returns the decrypted payload and verifies signature if present.
    """
    try:
        # Validate inputs
        envelope_path = Path(args.envelope)
        if not envelope_path.exists():
            error(f"Envelope file not found: {envelope_path}")
            return 1
        
        key_path = Path(args.private_key)
        if not key_path.exists():
            error(f"Private key not found: {key_path}")
            return 1
        
        # Determine output path
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = envelope_path.parent / f"{envelope_path.stem}.decrypted"
        
        # Load envelope
        envelope_bytes = envelope_path.read_bytes()
        envelope = DsealEnvelope.from_bytes(envelope_bytes)
        
        if not envelope.metadata.payload_encrypted:
            error("Envelope is not encrypted")
            return 1
        
        info(f"Loaded encrypted envelope")
        
        # Load private key
        key_pem = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        
        # Decrypt
        service = DocSealService()
        
        if args.verify:
            # Try to verify signature after decryption
            trusted_certs_path = Path(args.verify)
            if trusted_certs_path.exists():
                trusted_cert_pem = trusted_certs_path.read_bytes()
                from cryptography import x509
                trusted_cert = x509.load_pem_x509_certificate(trusted_cert_pem)
                decrypted, result = service.decrypt_and_verify(
                    envelope,
                    private_key,
                    [trusted_cert],
                )
                
                if result.is_valid:
                    success(f"Signature verified from: {result.signer_name}")
                else:
                    error(f"Signature verification failed: {result.error_message}")
                    return 1
            else:
                error(f"Trusted certificate not found: {trusted_certs_path}")
                return 1
        else:
            decrypted = service.decrypt(envelope, private_key)
        
        # Save decrypted payload
        output_path.write_bytes(decrypted.payload)
        success(f"Document decrypted and saved to: {output_path}")
        success(f"Payload size: {len(decrypted.payload)} bytes")
        
        return 0
        
    except Exception as e:
        error(f"Decryption failed: {e}")
        return 1


def register_decrypt_command(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
    """Register the decrypt command."""
    parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt an encrypted .dseal document",
        description="Decrypt a document using recipient's private key.",
    )
    
    parser.add_argument(
        "--envelope",
        "-e",
        required=True,
        help="Path to encrypted .dseal file",
    )
    
    parser.add_argument(
        "--private-key",
        "-k",
        required=True,
        help="Path to recipient's private key (PEM format)",
    )
    
    parser.add_argument(
        "--output",
        "-o",
        help="Output path for decrypted document (default: <envelope>.decrypted)",
    )
    
    parser.add_argument(
        "--verify",
        "-v",
        help="Path to signer's certificate to verify signature after decryption",
    )
    
    parser.set_defaults(func=decrypt_command)
