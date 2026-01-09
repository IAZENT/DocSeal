import json
import secrets
from types import SimpleNamespace

import pytest

from docseal.cli import ca as ca_mod


def _patch_paths(tmp_path, monkeypatch):
    ca_dir = tmp_path / "ca"
    monkeypatch.setattr(ca_mod, "CA_DIR", ca_dir)
    monkeypatch.setattr(ca_mod, "CA_PKCS12_PATH", ca_dir / "ca.p12")
    monkeypatch.setattr(ca_mod, "CA_PEM_PATH", ca_dir / "ca.pem")
    monkeypatch.setattr(ca_mod, "REVOCATION_PATH", ca_dir / "crl.json")
    return ca_dir


def test_cmd_ca_init_ca_exists_no_force(tmp_path, capsys, monkeypatch):
    ca_dir = _patch_paths(tmp_path, monkeypatch)
    ca_dir.mkdir(parents=True)
    (ca_dir / "ca.p12").write_bytes(b"x")

    args = SimpleNamespace(password=secrets.token_urlsafe(8), force=False)
    with pytest.raises(SystemExit) as exc:
        ca_mod.cmd_ca_init(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "CA already exists" in captured.err


def test_cmd_ca_init_password_mismatch(tmp_path, capsys, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)

    calls = ["a", "b"]

    def fake_getpass(prompt):
        return calls.pop(0)

    monkeypatch.setattr(ca_mod, "getpass", fake_getpass)

    args = SimpleNamespace(password=None, force=False)
    with pytest.raises(SystemExit) as exc:
        ca_mod.cmd_ca_init(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Passwords do not match" in captured.err


def test_cmd_ca_init_export_failure_due_to_pkcs12_not_supported(
    tmp_path, capsys, monkeypatch
):
    _patch_paths(tmp_path, monkeypatch)

    # Force authority serialize to be unavailable
    import docseal.ca.authority as auth_mod

    monkeypatch.setattr(auth_mod, "serialize_key_and_certificates", None)

    args = SimpleNamespace(password=secrets.token_urlsafe(12), force=True)

    with pytest.raises(SystemExit) as exc:
        ca_mod.cmd_ca_init(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "CA initialization failed" in captured.err


def test_cmd_ca_issue_failed_to_load_ca(tmp_path, capsys, monkeypatch):
    ca_dir = _patch_paths(tmp_path, monkeypatch)
    ca_dir.mkdir(parents=True)
    (ca_dir / "ca.p12").write_bytes(b"not a pkcs12")

    # Patch getpass for CA password
    monkeypatch.setattr(ca_mod, "getpass", lambda prompt: secrets.token_urlsafe(8))

    # Patch load_key_and_certificates to simulate failure (imported locally in function)
    monkeypatch.setattr(
        "cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates",
        lambda data, pw: (None, None, None),
    )

    args = SimpleNamespace(
        name="Name",
        role="Role",
        validity=365,
        out=None,
        password=secrets.token_urlsafe(12),
    )

    with pytest.raises(SystemExit) as exc:
        ca_mod.cmd_ca_issue(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Failed to load CA certificate" in captured.err


def test_cmd_ca_list_revoked_empty_and_nonempty(tmp_path, capsys, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)

    # Empty revoked
    class EmptyRegistry:
        def __init__(self, path):
            self.revoked = []

    monkeypatch.setattr(ca_mod, "RevocationRegistry", EmptyRegistry)

    args = SimpleNamespace()
    ca_mod.cmd_ca_list_revoked(args)
    captured = capsys.readouterr()
    assert "No revoked certificates" in captured.out

    # Non-empty
    class SomeRegistry:
        def __init__(self, path):
            self.revoked = [123, 456]

    monkeypatch.setattr(ca_mod, "RevocationRegistry", SomeRegistry)
    # Ensure the revocation path file exists so the function proceeds
    ca_mod.REVOCATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    ca_mod.REVOCATION_PATH.write_text(json.dumps([]))
    ca_mod.cmd_ca_list_revoked(args)
    captured = capsys.readouterr()
    assert "Revoked certificates" in captured.out


def test_cmd_ca_info_fails_to_read_ca(tmp_path, capsys, monkeypatch):
    ca_dir = _patch_paths(tmp_path, monkeypatch)
    ca_dir.mkdir(parents=True)
    (ca_dir / "ca.pem").write_bytes(b"not pem")

    args = SimpleNamespace()
    with pytest.raises(SystemExit) as exc:
        ca_mod.cmd_ca_info(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Failed to read CA info" in captured.err


def test_cmd_ca_revoke_failure(monkeypatch, tmp_path, capsys):
    _patch_paths(tmp_path, monkeypatch)

    class BadRegistry:
        def __init__(self, path):
            pass

        def revoke(self, serial):
            raise RuntimeError("boom")

    monkeypatch.setattr(ca_mod, "RevocationRegistry", BadRegistry)

    args = SimpleNamespace(serial=1, reason="x")
    with pytest.raises(SystemExit) as exc:
        ca_mod.cmd_ca_revoke(args)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Failed to revoke certificate" in captured.err
