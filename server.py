import base64
import time
import secrets
import jwt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pqc_engine import (
    EK_SIZE,
    encapsulate_challenge,
    compute_proof_hash,
)

app = FastAPI(title="Post-Quantum ML-KEM Face Auth Server")

JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
CHALLENGE_TTL_SECONDS = 60

# In-memory stores (Replace with PostgreSQL + Redis in production)
USER_DB: dict[str, bytes] = {}               # user_id -> ek (bytes)
ACTIVE_CHALLENGES: dict[str, dict] = {}      # user_id -> {"expected_hash": str, "expires_at": float}


class RegisterRequest(BaseModel):
    user_id: str
    public_key_b64: str


class ChallengeRequest(BaseModel):
    user_id: str


class VerifyRequest(BaseModel):
    user_id: str
    proof_hash: str


@app.post("/register", status_code=201)
def register_user(req: RegisterRequest):
    try:
        ek_bytes = base64.b64decode(req.public_key_b64)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid Base64 encoding.")

    if len(ek_bytes) != EK_SIZE:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid ML-KEM-768 public key size. Expected {EK_SIZE} bytes.",
        )

    USER_DB[req.user_id] = ek_bytes
    return {"status": "registered", "user_id": req.user_id}


@app.post("/login/challenge")
def create_login_challenge(req: ChallengeRequest):
    ek_bytes = USER_DB.get(req.user_id)
    if not ek_bytes:
        raise HTTPException(status_code=404, detail="User not registered.")

    # FIPS 203 Encapsulation: generates (K, C)
    shared_secret_k, ciphertext_c = encapsulate_challenge(ek_bytes)
    expected_proof = compute_proof_hash(shared_secret_k, req.user_id)

    ACTIVE_CHALLENGES[req.user_id] = {
        "expected_hash": expected_proof,
        "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
    }

    return {
        "user_id": req.user_id,
        "ciphertext_b64": base64.b64encode(ciphertext_c).decode("utf-8"),
        "ttl_seconds": CHALLENGE_TTL_SECONDS,
    }


@app.post("/login/verify")
def verify_login_proof(req: VerifyRequest):
    # Pop challenge immediately on first attempt to block replay attacks (QA-09)
    challenge = ACTIVE_CHALLENGES.pop(req.user_id, None)
    if not challenge:
        raise HTTPException(status_code=401, detail="No active challenge found or already used.")

    if time.time() > challenge["expires_at"]:
        raise HTTPException(status_code=401, detail="Challenge expired (QA-10).")

    # Constant-time string comparison against timing attacks
    if not secrets.compare_digest(req.proof_hash, challenge["expected_hash"]):
        raise HTTPException(status_code=401, detail="Invalid cryptographic proof.")

    token_payload = {
        "sub": req.user_id,
        "auth_method": "local_face_ml_kem_768",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    access_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {"status": "authenticated", "access_token": access_token}