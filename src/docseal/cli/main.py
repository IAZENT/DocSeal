"""DocSeal CLI main entry point."""

import argparse
import sys

from docseal.cli.ca import register_ca_commands
from docseal.cli.decrypt import register_decrypt_command
from docseal.cli.encrypt import register_encrypt_command
from docseal.cli.sign import register_sign_command
from docseal.cli.verify import register_verify_command


def create_parser() -> argparse.ArgumentParser:
    """Create the main CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="docseal",
        description="DocSeal — Secure Academic Document Signing & Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign a document
  docseal sign --document transcript.pdf --cert signer.pem --key signer_key.pem

  # Verify a signature
  docseal verify --envelope transcript.dseal --cert signer.pem

  # Encrypt a document for a recipient
  docseal encrypt --document data.pdf --recipient-cert recipient.pem

  # Decrypt and verify
  docseal decrypt --envelope data.dseal --private-key recipient_key.pem \\
    --verify signer.pem

For more information, visit: https://github.com/yourusername/docseal
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.9.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available commands",
    )

    # Register subcommands
    register_ca_commands(subparsers)
    register_sign_command(subparsers)
    register_verify_command(subparsers)
    register_encrypt_command(subparsers)
    register_decrypt_command(subparsers)

    return parser


def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        # Execute the command function associated with the subparser
        exit_code = args.func(args)
        return exit_code if exit_code is not None else 0
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
