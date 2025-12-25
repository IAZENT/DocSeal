import pytest

# Allow running this test module directly (python path/to/test_ca_initialization.py)
# by adding the project's `src/` directory to sys.path if imports fail.
try:
    from docseal.ca.authority import CertificateAuthority
    from docseal.ca.exceptions import CAAlreadyInitialized
except ModuleNotFoundError:
    import os
    import sys

    ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    SRC = os.path.join(ROOT, "src")
    if SRC not in sys.path:
        sys.path.insert(0, SRC)

    from docseal.ca.authority import CertificateAuthority
    from docseal.ca.exceptions import CAAlreadyInitialized


STRONG_PASSWORD = "".join(["strong", "password"])
ANOTHER_PASSWORD = "".join(["another", "password"])


def test_ca_initialization_success():
    ca = CertificateAuthority()
    ca.initialize(password=STRONG_PASSWORD)


def test_ca_double_initialization_fails():
    ca = CertificateAuthority()
    ca.initialize(password=STRONG_PASSWORD)

    with pytest.raises(CAAlreadyInitialized):
        ca.initialize(password=ANOTHER_PASSWORD)


def test_pkcs12_export():
    ca = CertificateAuthority()
    ca.initialize(password=STRONG_PASSWORD)

    data = ca.export_pkcs12(password=STRONG_PASSWORD)
    assert isinstance(data, bytes)
    assert len(data) > 0
