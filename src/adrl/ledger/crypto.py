"""AES-GCM and keyed hashing primitives for prompt-class data. Primary: ADRL-MEM-010.

Secondary: ADRL-MEM-005 (keyed instruction hashes).
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12


def new_key() -> bytes:
    return os.urandom(KEY_BYTES)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext) under AES-256-GCM."""
    nonce = os.urandom(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def keyed_hash(secret: bytes, text: str) -> str:
    """HMAC-SHA256 pseudonym of an instruction; differs per host secret (ADRL-MEM-005 clause 3)."""
    return hmac.new(secret, text.encode("utf-8"), hashlib.sha256).hexdigest()


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]
