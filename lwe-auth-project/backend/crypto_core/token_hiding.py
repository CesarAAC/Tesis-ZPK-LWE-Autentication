"""Designated-verifier token hiding: ML-KEM-768 encapsulation plus AES-256-GCM.

    tok1 = ML-KEM-768 ciphertext (1088 bytes), K = the encapsulated 32-byte secret
    tok2 = nonce (12 bytes) || AES-256-GCM_K(payload, associated data)

Only the holder of the ML-KEM private key recovers K and therefore the payload.
Both ends can keep K (``seal_with_secret``, ``open_token_with_secret``) to protect
later messages of the same session with ``seal_symmetric`` / ``open_symmetric``.

The thesis writes tok1 = Kyber.Enc(vpk, K) for a key K chosen by the client.
A standard KEM does not take the key as input: encapsulation returns it. K is
therefore the encapsulated secret, which is uniformly random and, unlike the
bare Kyber public-key encryption, protected against chosen-ciphertext attacks.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_core.exceptions import InvalidProtocolDataError

PUBLIC_KEY_BYTES = 1184
CIPHERTEXT_BYTES = 1088
PRIVATE_SEED_BYTES = 64
NONCE_BYTES = 12
TAG_BYTES = 16


def generate_verifier_keypair() -> tuple[bytes, bytes]:
    """Return (vpk, private seed); the 64-byte seed is the whole private key."""
    private_key = mlkem.MLKEM768PrivateKey.generate()
    return private_key.public_key().public_bytes_raw(), private_key.private_bytes_raw()


def load_private_key(private_seed: bytes) -> mlkem.MLKEM768PrivateKey:
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(private_seed)


def sealed_length(payload_length: int) -> int:
    """Length of tok2 for a payload of ``payload_length`` bytes."""
    return NONCE_BYTES + payload_length + TAG_BYTES


def seal(public_key: bytes, payload: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    """Encrypt ``payload`` for the verifier; returns (tok1, tok2)."""
    tok1, tok2, _ = seal_with_secret(public_key, payload, associated_data)
    return tok1, tok2


def seal_with_secret(
    public_key: bytes,
    payload: bytes,
    associated_data: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Like ``seal``, and also return the encapsulated secret K (tok1, tok2, K)."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise InvalidProtocolDataError(
            f"La clave pública del verificador debe tener {PUBLIC_KEY_BYTES} bytes."
        )
    try:
        verifier_key = mlkem.MLKEM768PublicKey.from_public_bytes(public_key)
    except ValueError as exc:
        raise InvalidProtocolDataError(
            "La clave pública del verificador no es una clave ML-KEM-768 válida."
        ) from exc
    shared_secret, ciphertext = verifier_key.encapsulate()
    return ciphertext, seal_symmetric(shared_secret, payload, associated_data), shared_secret


def open_token(
    private_key: mlkem.MLKEM768PrivateKey,
    tok1: bytes,
    tok2: bytes,
    associated_data: bytes,
) -> bytes | None:
    """Return the payload, or None when the token was not sealed for this key.

    A modified tok1 decapsulates to an unrelated secret (ML-KEM implicit
    rejection), so every forgery or corruption ends in a failed GCM tag.
    """
    opened = open_token_with_secret(private_key, tok1, tok2, associated_data)
    return None if opened is None else opened[0]


def open_token_with_secret(
    private_key: mlkem.MLKEM768PrivateKey,
    tok1: bytes,
    tok2: bytes,
    associated_data: bytes,
) -> tuple[bytes, bytes] | None:
    """Like ``open_token``, and also return the decapsulated secret: (payload, K)."""
    if len(tok1) != CIPHERTEXT_BYTES:
        raise InvalidProtocolDataError(f"'tok1' debe tener {CIPHERTEXT_BYTES} bytes.")
    shared_secret = private_key.decapsulate(tok1)
    payload = open_symmetric(shared_secret, tok2, associated_data)
    return None if payload is None else (payload, shared_secret)


def seal_symmetric(key: bytes, payload: bytes, associated_data: bytes) -> bytes:
    """nonce (12 bytes, fresh) || AES-256-GCM_key(payload, associated data)."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, payload, associated_data)


def open_symmetric(key: bytes, sealed: bytes, associated_data: bytes) -> bytes | None:
    """Inverse of ``seal_symmetric``; None when the tag does not verify."""
    if len(sealed) < NONCE_BYTES + TAG_BYTES:
        raise InvalidProtocolDataError("El mensaje cifrado es demasiado corto.")
    try:
        return AESGCM(key).decrypt(sealed[:NONCE_BYTES], sealed[NONCE_BYTES:], associated_data)
    except InvalidTag:
        return None
