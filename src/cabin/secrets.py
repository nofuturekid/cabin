"""Encryption at rest: master key management and AES-256-GCM sealing.

The master key lives in ``data_dir/secret.key``, auto-generated on first
start. Optionally, ``CABIN_MASTER_PASSPHRASE`` wraps it with a scrypt-derived
key-encryption-key (KEK), so the key file alone is useless without it.
"""

import base64
import contextlib
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_FILE_NAME = "secret.key"
_NONCE_LEN = 12  # 96-bit GCM nonce
_KEY_LEN = 32  # 256-bit key
_SALT_LEN = 16
_SCRYPT_N = 32768
_SCRYPT_R = 8
_SCRYPT_P = 1


class SecretsError(Exception):
    """Secrets layer failure: bad token, wrong passphrase, or key-file mismatch."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _read_keyfile(key_path: Path) -> dict[str, Any]:
    """Read and JSON-parse ``key_path``, raising ``SecretsError`` if it's corrupt."""
    try:
        doc = json.loads(key_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretsError(f"secret.key is corrupt or unreadable: {exc}") from exc
    if not isinstance(doc, dict):
        raise SecretsError("secret.key is corrupt or unreadable: not a JSON object")
    return doc


def _scrypt(passphrase: bytes, *, salt: bytes, n: int, r: int, p: int) -> bytes:
    """hashlib.scrypt with an explicit memory cap (default cap is exactly 128*N*r)."""
    return hashlib.scrypt(
        passphrase, salt=salt, n=n, r=r, p=p, dklen=_KEY_LEN, maxmem=128 * n * r * p * 2
    )


class SecretStore:
    """Seals and unseals secrets with AES-256-GCM under a master key."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def seal(self, plaintext: bytes) -> str:
        """Encrypt ``plaintext``, returning a base64url token with a fresh nonce."""
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, None)
        return _b64(nonce + ciphertext)

    def unseal(self, token: str) -> bytes:
        """Decrypt a token produced by :meth:`seal`.

        Raises ``SecretsError`` if the token is malformed, truncated, or
        fails GCM authentication (tampered or wrong key).
        """
        try:
            raw = _unb64(token)
        except Exception as exc:
            raise SecretsError("invalid token: not valid base64url") from exc
        if len(raw) < _NONCE_LEN:
            raise SecretsError("invalid token: truncated")
        nonce, ciphertext = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise SecretsError("invalid token: failed authentication (tampered)") from exc

    @classmethod
    def open(cls, data_dir: Path, passphrase: str | None) -> "SecretStore":
        """Load ``data_dir/secret.key``, creating it on first use."""
        key_path = data_dir / _KEY_FILE_NAME
        if key_path.exists():
            doc = _read_keyfile(key_path)
        else:
            doc = _create_keyfile(data_dir, key_path, passphrase)
        return cls(key=_load_key(doc, passphrase))


def _create_keyfile(data_dir: Path, key_path: Path, passphrase: str | None) -> dict[str, Any]:
    """Atomically create ``key_path``, or read it if another process won the race."""
    master_key = os.urandom(_KEY_LEN)
    doc: dict[str, Any]
    if passphrase is None:
        doc = {"v": 1, "kdf": "none", "key": _b64(master_key)}
    else:
        salt = os.urandom(_SALT_LEN)
        kek = _scrypt(passphrase.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
        nonce = os.urandom(_NONCE_LEN)
        wrapped = AESGCM(kek).encrypt(nonce, master_key, None)
        doc = {
            "v": 1,
            "kdf": "scrypt",
            "salt": _b64(salt),
            "n": _SCRYPT_N,
            "r": _SCRYPT_R,
            "p": _SCRYPT_P,
            "wrapped": _b64(nonce + wrapped),
        }

    fd, tmp_name = tempfile.mkstemp(dir=data_dir, prefix=".secret.key.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, 0o600)
        # another process may have created it first; fall through to re-read below
        with contextlib.suppress(FileExistsError):
            os.link(tmp_name, key_path)
        dir_fd = os.open(data_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.unlink(tmp_name)

    return _read_keyfile(key_path)


def _load_key(doc: dict[str, Any], passphrase: str | None) -> bytes:
    version = doc.get("v")
    kdf = doc.get("kdf")
    if version != 1 or kdf not in ("none", "scrypt"):
        raise SecretsError(f"secret.key: unsupported version/kdf (v={version!r}, kdf={kdf!r})")

    if kdf == "none":
        if passphrase is not None:
            raise SecretsError(
                "secret.key was created without a passphrase (kdf=none) but "
                "CABIN_MASTER_PASSPHRASE is set; unset it or delete secret.key to start fresh"
            )
        try:
            key = _unb64(doc["key"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise SecretsError(f"secret.key is corrupt or unreadable: {exc}") from exc
        if len(key) != _KEY_LEN:
            raise SecretsError("secret.key: master key is not 32 bytes")
        return key

    # kdf == "scrypt"
    if passphrase is None:
        raise SecretsError(
            "secret.key was created with a passphrase (kdf=scrypt) but "
            "CABIN_MASTER_PASSPHRASE is not set"
        )
    try:
        kek = _scrypt(
            passphrase.encode("utf-8"),
            salt=_unb64(doc["salt"]),
            n=doc["n"],
            r=doc["r"],
            p=doc["p"],
        )
        raw = _unb64(doc["wrapped"])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SecretsError(f"secret.key is corrupt or unreadable: {exc}") from exc
    nonce, wrapped_ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    try:
        return AESGCM(kek).decrypt(nonce, wrapped_ct, None)
    except InvalidTag as exc:
        raise SecretsError("wrong CABIN_MASTER_PASSPHRASE: could not unwrap master key") from exc
