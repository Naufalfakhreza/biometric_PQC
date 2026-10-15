import hashlib
from kyber_py.ml_kem import ML_KEM_768

# NIST FIPS 203 ML-KEM-768 byte length constants
EK_SIZE = 1184  # Public Encapsulation Key (pk_user)
DK_SIZE = 2400  # Private Decapsulation Key (sk_user)
CT_SIZE = 1088  # Ciphertext Challenge (C)


def generate_ml_kem_keypair() -> tuple[bytes, bytes]:
    """Generates an ML-KEM-768 (encapsulation_key, decapsulation_key) pair."""
    ek, dk = ML_KEM_768.keygen()
    return ek, dk


def encapsulate_challenge(ek: bytes) -> tuple[bytes, bytes]:
    """
    Server-side: Uses user's public encapsulation key (ek) to generate
    a 32-byte shared secret (K) and 1088-byte ciphertext (C).
    """
    if len(ek) != EK_SIZE:
        raise ValueError(f"Invalid ML-KEM-768 public key length: expected {EK_SIZE}, got {len(ek)}")
    shared_secret_k, ciphertext_c = ML_KEM_768.encaps(ek)
    return shared_secret_k, ciphertext_c


def decapsulate_challenge(dk: bytes, ciphertext_c: bytes) -> bytes:
    """
    Client-side: Uses private decapsulation key (dk) to recover the 32-byte
    shared secret (K) from ciphertext (C). Implements FIPS 203 implicit rejection.
    """
    if len(dk) != DK_SIZE:
        raise ValueError("Invalid ML-KEM-768 private key length.")
    if len(ciphertext_c) != CT_SIZE:
        raise ValueError("Invalid ML-KEM-768 ciphertext length.")
    return ML_KEM_768.decaps(dk, ciphertext_c)


def compute_proof_hash(shared_secret_k: bytes, user_id: str) -> str:
    """Binds the shared secret K to the user_id via SHA3-256 to create H(K)."""
    hasher = hashlib.sha3_256()
    hasher.update(shared_secret_k)
    hasher.update(user_id.encode("utf-8"))
    return hasher.hexdigest()