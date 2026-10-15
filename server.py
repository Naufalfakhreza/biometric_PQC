import base64
import time
import secrets
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from pqc_engine import (
    EK_SIZE,
    encapsulate_challenge,
    compute_proof_hmac,
    generate_ml_dsa_keypair,
    issue_pqc_token,
    verify_pqc_token,
)

app = FastAPI(title="Post-Quantum ML-KEM & ML-DSA Face Auth Server")

SERVER_DSA_PK, SERVER_DSA_SK = generate_ml_dsa_keypair()
CHALLENGE_TTL_SECONDS = 60

USER_DB: dict[str, bytes] = {}               
ACTIVE_CHALLENGES: dict[str, dict] = {}      


class RegisterRequest(BaseModel):
    user_id: str
    public_key_b64: str


class ChallengeRequest(BaseModel):
    user_id: str


class VerifyRequest(BaseModel):
    user_id: str
    proof_hmac: str


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

    shared_secret_k, ciphertext_c = encapsulate_challenge(ek_bytes)
    expected_hmac = compute_proof_hmac(shared_secret_k, req.user_id, ciphertext_c)

    ACTIVE_CHALLENGES[req.user_id] = {
        "expected_hmac": expected_hmac,
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

    if not secrets.compare_digest(req.proof_hmac, challenge["expected_hmac"]):
        raise HTTPException(status_code=401, detail="Invalid cryptographic proof.")

    pqc_token = issue_pqc_token(SERVER_DSA_SK, req.user_id)

    return {
        "status": "authenticated",
        "token_type": "ML-DSA-65",
        "access_token": pqc_token,
    }


@app.get("/me")
def get_authenticated_user(authorization: str = Header(...)):
    """Protected route that verifies the ML-DSA-65 Post-Quantum signature."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token.")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = verify_pqc_token(SERVER_DSA_PK, token)
        return {"verified_claims": claims}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))