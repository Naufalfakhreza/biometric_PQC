import base64
import hashlib
import hmac
import json
import time
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65


EK_SIZE = 1184  
DK_SIZE = 2400  
CT_SIZE = 1088  


#Generates an ML-KEM-768 key pair.
def generate_ml_kem_keypair() -> tuple[bytes, bytes]:
    return ML_KEM_768.keygen()


#Generates shared secret and ciphertext.
def encapsulate_challenge(ek: bytes) -> tuple[bytes, bytes]:
    if len(ek) != EK_SIZE:
        raise ValueError(f"Invalid ML-KEM-768 public key length: expected {EK_SIZE}, got {len(ek)}")
    return ML_KEM_768.encaps(ek)


#Recovers shared secret from ciphertext.
def decapsulate_challenge(dk: bytes, ciphertext_c: bytes) -> bytes:
    if len(dk) != DK_SIZE:
        raise ValueError("Invalid ML-KEM-768 private key length.")
    if len(ciphertext_c) != CT_SIZE:
        raise ValueError("Invalid ML-KEM-768 ciphertext length.")
    return ML_KEM_768.decaps(dk, ciphertext_c)


#Computes transcript-bound HMAC-SHA3-256 keyed with shared secret K over (user_id || ciphertext_c).
def compute_proof_hmac(shared_secret_k: bytes, user_id: str, ciphertext_c: bytes) -> str:
    mac = hmac.new(key=shared_secret_k, digestmod=hashlib.sha3_256)
    mac.update(user_id.encode("utf-8"))
    mac.update(ciphertext_c)
    return mac.hexdigest()


#Generates an ML-DSA pair for token signing.
def generate_ml_dsa_keypair() -> tuple[bytes, bytes]:
    return ML_DSA_65.keygen()


#Signs a JSON token payload using NIST FIPS 204 ML-DSA.
def issue_pqc_token(server_sk: bytes, user_id: str, ttl_seconds: int = 3600) -> str:
    payload = {
        "sub": user_id,
        "alg": "ML-DSA-65",
        "auth": "local_arcface_ml_kem_768",
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")

    signature = ML_DSA_65.sign(server_sk, payload_bytes)
    sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8")

    return f"{payload_b64}.{sig_b64}"


#Verifies an ML-DSA signed token and checks its expiration timestamp.
def verify_pqc_token(server_pk: bytes, token: str) -> dict:
    try:
        payload_b64, sig_b64 = token.split(".")
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
    except Exception:
        raise ValueError("Malformed PQC token format.")

    if not ML_DSA_65.verify(server_pk, payload_bytes, signature):
        raise ValueError("Invalid ML-DSA-65 token signature.")

    payload = json.loads(payload_bytes.decode("utf-8"))
    if time.time() > payload.get("exp", 0):
        raise ValueError("PQC token has expired.")

    return payload