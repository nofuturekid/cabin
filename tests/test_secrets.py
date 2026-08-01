"""Tests for cabin.secrets: SecretStore seal/unseal and master-key management."""

import base64
import json
import os
import stat
from pathlib import Path

import pytest

from cabin.secrets import SecretsError, SecretStore, _create_keyfile


def test_open_creates_keyfile_mode_600_kdf_none(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path, None)

    key_path = tmp_path / "secret.key"
    assert key_path.exists()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    doc = json.loads(key_path.read_text())
    assert doc["kdf"] == "none"

    token = store.seal(b"hello world")
    assert store.unseal(token) == b"hello world"


def test_seal_unseal_roundtrip(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path, None)
    plaintext = b"a very secret CA private key"
    token = store.seal(plaintext)
    assert isinstance(token, str)
    assert store.unseal(token) == plaintext


def test_unseal_rejects_tampered_and_truncated(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path, None)
    token = store.seal(b"secret data")

    raw = bytearray(base64.urlsafe_b64decode(token))
    raw[-1] ^= 0xFF
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(SecretsError):
        store.unseal(tampered)

    truncated = token[:-8]
    with pytest.raises(SecretsError):
        store.unseal(truncated)


def test_passphrase_wraps_key_scrypt(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path, "hunter2")

    doc = json.loads((tmp_path / "secret.key").read_text())
    assert doc["kdf"] == "scrypt"
    assert "salt" in doc
    assert "wrapped" in doc

    token = store.seal(b"payload")

    reopened = SecretStore.open(tmp_path, "hunter2")
    assert reopened.unseal(token) == b"payload"


def test_wrong_passphrase_rejected(tmp_path: Path) -> None:
    SecretStore.open(tmp_path, "hunter2")

    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, "wrong-passphrase")


def test_kdf_mismatch_rejected_both_directions(tmp_path: Path) -> None:
    none_dir = tmp_path / "none"
    none_dir.mkdir()
    SecretStore.open(none_dir, None)
    with pytest.raises(SecretsError):
        SecretStore.open(none_dir, "some-passphrase")

    scrypt_dir = tmp_path / "scrypt"
    scrypt_dir.mkdir()
    SecretStore.open(scrypt_dir, "some-passphrase")
    with pytest.raises(SecretsError):
        SecretStore.open(scrypt_dir, None)


def test_seal_uses_fresh_nonce(tmp_path: Path) -> None:
    store = SecretStore.open(tmp_path, None)
    token1 = store.seal(b"same plaintext")
    token2 = store.seal(b"same plaintext")
    assert token1 != token2


def test_create_keyfile_reuses_existing_on_race(tmp_path: Path) -> None:
    """FR-3: if secret.key already exists when we try to link ours in, keep the winner's."""
    existing_doc = {
        "v": 1,
        "kdf": "none",
        "key": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
    }
    key_path = tmp_path / "secret.key"
    key_path.write_text(json.dumps(existing_doc))
    key_path.chmod(0o600)

    result = _create_keyfile(tmp_path, key_path, None)

    assert result == existing_doc
    assert json.loads(key_path.read_text()) == existing_doc


def test_open_rejects_non_json_keyfile(tmp_path: Path) -> None:
    (tmp_path / "secret.key").write_text("not json{{{")
    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, None)


def test_open_rejects_keyfile_missing_key_field(tmp_path: Path) -> None:
    doc = {"v": 1, "kdf": "none"}  # missing "key"
    (tmp_path / "secret.key").write_text(json.dumps(doc))
    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, None)


def test_open_rejects_unknown_version(tmp_path: Path) -> None:
    doc = {
        "v": 2,
        "kdf": "none",
        "key": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
    }
    (tmp_path / "secret.key").write_text(json.dumps(doc))
    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, None)


def test_open_rejects_unknown_kdf(tmp_path: Path) -> None:
    doc = {
        "v": 1,
        "kdf": "argon2",
        "key": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
    }
    (tmp_path / "secret.key").write_text(json.dumps(doc))
    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, None)


def test_open_rejects_null_key_field(tmp_path: Path) -> None:
    doc = {"v": 1, "kdf": "none", "key": None}
    (tmp_path / "secret.key").write_text(json.dumps(doc))
    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, None)


def test_open_rejects_master_key_wrong_length(tmp_path: Path) -> None:
    doc = {
        "v": 1,
        "kdf": "none",
        "key": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii"),
    }
    (tmp_path / "secret.key").write_text(json.dumps(doc))
    with pytest.raises(SecretsError):
        SecretStore.open(tmp_path, None)
