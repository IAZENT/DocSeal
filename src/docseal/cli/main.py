"""DocSeal CLI main entry point."""

import argparse
import sys
from typing import NoReturn

from docseal.cli.ca import register_ca_commands
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
  # Initialize CA
  docseal ca init

  # Issue a certificate
  docseal ca issue --name "John Doe" --role "Registrar"

  # Sign a document
  docseal sign --doc transcript.pdf --cert signer.p12 --out transcript.sig

  # Verify a signature
  docseal verify --doc transcript.pdf --sig transcript.sig --ca ca.pem

For more information, visit: https://github.com/yourusername/docseal
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
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

    return parser


def main() -> NoReturn:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        # Execute the command function associated with the subparser
        args.func(args)
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
