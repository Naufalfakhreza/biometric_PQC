"""
Post-Quantum Cryptographic Engine (PQC Engine).

Implements NIST FIPS 203 (ML-KEM-768) key encapsulation mechanisms and
NIST FIPS 204 (ML-DSA-65) digital signature schemes for zero-knowledge
biometric authentication and session token issuance.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

# Standard byte lengths for NIST FIPS 203 ML-KEM-768
EK_SIZE: int = 1184   # Encapsulation key (public key) size in bytes
DK_SIZE: int = 2400   # Decapsulation key (private key) size in bytes
CT_SIZE: int = 1088   # Ciphertext size in bytes


def generate_ml_kem_keypair() -> tuple[bytes, bytes]:
    """
    Generates an ML-KEM-768 key pair (FIPS 203).

    Returns:
        tuple[bytes, bytes]: A tuple of (encapsulation_key_ek, decapsulation_key_dk).
    """
    return ML_KEM_768.keygen()


def encapsulate_challenge(ek: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulates a shared secret using the client's ML-KEM-768 encapsulation key.

    Args:
        ek (bytes): The 1184-byte ML-KEM-768 public encapsulation key.

    Returns:
        tuple[bytes, bytes]: A tuple of (shared_secret_k, ciphertext_c).

    Raises:
        ValueError: If the encapsulation key is not 1184 bytes.
    """
    if len(ek) != EK_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 public key length: expected {EK_SIZE} bytes, got {len(ek)} bytes."
        )
    return ML_KEM_768.encaps(ek)


def decapsulate_challenge(dk: bytes, ciphertext_c: bytes) -> bytes:
    """
    Decapsulates the shared secret from a ciphertext using the ML-KEM-768 private key.

    Args:
        dk (bytes): The 2400-byte ML-KEM-768 decapsulation key.
        ciphertext_c (bytes): The 1088-byte ciphertext challenge.

    Returns:
        bytes: The 32-byte shared secret K.

    Raises:
        ValueError: If key or ciphertext length does not match ML-KEM-768 specifications.
    """
    if len(dk) != DK_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 private key length: expected {DK_SIZE} bytes, got {len(dk)} bytes."
        )
    if len(ciphertext_c) != CT_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 ciphertext length: expected {CT_SIZE} bytes, got {len(ciphertext_c)} bytes."
        )
    return ML_KEM_768.decaps(dk, ciphertext_c)


def compute_proof_hmac(shared_secret_k: bytes, user_id: str, ciphertext_c: bytes) -> str:
    """
    Computes a transcript-bound HMAC-SHA3-256 proof keyed by the shared secret K.

    The proof binds the authenticated user identity and the challenge ciphertext:
        Proof = HMAC-SHA3-256(Key = K, Data = user_id || ciphertext_c)

    Args:
        shared_secret_k (bytes): The shared secret derived from ML-KEM.
        user_id (str): The unique identifier of the authenticating user.
        ciphertext_c (bytes): The challenge ciphertext from the server.

    Returns:
        str: Hex-encoded HMAC digest representing cryptographic proof of identity.
    """
    mac = hmac.new(key=shared_secret_k, digestmod=hashlib.sha3_256)
    mac.update(user_id.encode("utf-8"))
    mac.update(ciphertext_c)
    return mac.hexdigest()


def generate_ml_dsa_keypair() -> tuple[bytes, bytes]:
    """
    Generates an ML-DSA-65 digital signature key pair (FIPS 204).

    Returns:
        tuple[bytes, bytes]: A tuple of (public_key_pk, secret_key_sk).
    """
    return ML_DSA_65.keygen()


def issue_pqc_token(server_sk: bytes, user_id: str, ttl_seconds: int = 3600) -> str:
    """
    Issues a quantum-safe bearer token signed with NIST FIPS 204 ML-DSA-65.

    Args:
        server_sk (bytes): The server's ML-DSA private signing key.
        user_id (str): The subject identifier for the token.
        ttl_seconds (int): Time-to-live for the token in seconds. Defaults to 3600 (1 hour).

    Returns:
        str: URL-safe Base64-encoded token in format `<payload_b64>.<signature_b64>`.
    """
    now = int(time.time())
    payload = {
        "sub": user_id,
        "alg": "ML-DSA-65",
        "auth": "local_arcface_ml_kem_768",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")

    signature = ML_DSA_65.sign(server_sk, payload_bytes)
    sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8")

    return f"{payload_b64}.{sig_b64}"


def verify_pqc_token(server_pk: bytes, token: str) -> dict[str, Any]:
    """
    Verifies an ML-DSA-65 signed bearer token and validates expiration.

    Args:
        server_pk (bytes): The server's ML-DSA public verification key.
        token (str): The dot-separated token `<payload_b64>.<signature_b64>`.

    Returns:
        dict[str, Any]: Verified token claims dictionary.

    Raises:
        ValueError: If token format is invalid, signature verification fails, or token expired.
    """
    try:
        payload_b64, sig_b64 = token.split(".")
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
    except Exception as exc:
        raise ValueError("Malformed PQC token format.") from exc

    if not ML_DSA_65.verify(server_pk, payload_bytes, signature):
        raise ValueError("Invalid ML-DSA-65 token signature.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Malformed token payload JSON.") from exc

    if time.time() > payload.get("exp", 0):
        raise ValueError("PQC token has expired.")

    return payload
