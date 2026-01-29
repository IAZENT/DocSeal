"""DocSeal - Secure document signing, encryption, and verification."""

import importlib.metadata

try:
    __version__ = importlib.metadata.version("docseal")
except importlib.metadata.PackageNotFoundError:
    __version__ = "2.0.0"  # Fallback version during development

__all__ = ["__version__"]
