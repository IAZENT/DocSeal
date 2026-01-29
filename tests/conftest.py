import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Ensure the project's `src` directory is on sys.path so tests can import the package
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


@dataclass
class TestUser:
    """Test user with loaded keys and certificates."""

    user_id: str
    name: str
    email: str
    role: str
    key_file: str
    cert_file: str
    description: str
    private_key: any = None
    certificate: x509.Certificate = None

    def load_key(self):
        """Load private key from file."""
        if not os.path.exists(self.key_file):
            raise FileNotFoundError(f"Key file not found: {self.key_file}")

        with open(self.key_file, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), None)

    def load_cert(self):
        """Load certificate from file."""
        if not os.path.exists(self.cert_file):
            raise FileNotFoundError(f"Cert file not found: {self.cert_file}")

        with open(self.cert_file, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())

    def ensure_loaded(self):
        """Ensure both key and certificate are loaded."""
        if self.private_key is None:
            self.load_key()
        if self.certificate is None:
            self.load_cert()


@pytest.fixture(scope="session")
def test_users_config():
    """Load test users configuration from users.yaml."""
    config_path = Path(__file__).parent / "users.yaml"

    if not config_path.exists():
        pytest.skip(f"Test users config not found at {config_path}")

    with open(config_path, "r") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def test_users(test_users_config):
    """Create TestUser objects from configuration."""
    users = {}
    for user_id, config in test_users_config["users"].items():
        user = TestUser(
            user_id=user_id,
            name=config["name"],
            email=config["email"],
            role=config["role"],
            key_file=config["key_file"],
            cert_file=config["cert_file"],
            description=config.get("description", ""),
        )
        # Try to load keys/certs, skip test if they don't exist
        try:
            user.ensure_loaded()
        except FileNotFoundError:
            pytest.skip(
                "Test keys/certs not generated yet. "
                "Run: python scripts/generate_test_keys.py"
            )
        users[user_id] = user

    return users


@pytest.fixture
def registrar(test_users):
    """Get the registrar test user."""
    return test_users["registrar"]


@pytest.fixture
def lecturer_alice(test_users):
    """Get lecturer Alice test user."""
    return test_users["lecturer_alice"]


@pytest.fixture
def lecturer_bob(test_users):
    """Get lecturer Bob test user."""
    return test_users["lecturer_bob"]


@pytest.fixture
def student_charlie(test_users):
    """Get student Charlie test user."""
    return test_users["student_charlie"]


@pytest.fixture
def student_diana(test_users):
    """Get student Diana test user."""
    return test_users["student_diana"]


@pytest.fixture
def employer_eve(test_users):
    """Get employer Eve test user."""
    return test_users["employer_eve"]


# Mark test collection
def pytest_collection_modifyitems(config, items):
    """Add markers to tests based on file name."""
    for item in items:
        if "test_crypto" in item.nodeid:
            item.add_marker(pytest.mark.crypto)
        if "test_cli" in item.nodeid:
            item.add_marker(pytest.mark.cli)
        if "test_integration" in item.nodeid or "test_scenario" in item.nodeid:
            item.add_marker(pytest.mark.integration)
