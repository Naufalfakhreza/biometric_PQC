"""
Post-Quantum Biometric Authentication Server.

Implements NIST FIPS 203 (ML-KEM-768) challenge-response authentication and
NIST FIPS 204 (ML-DSA-65) token issuance using FastAPI.
"""

import base64
import secrets
import time
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

import config
from pqc_engine import (
    EK_SIZE,
    compute_proof_hmac,
    encapsulate_challenge,
    generate_ml_dsa_keypair,
    issue_pqc_token,
    verify_pqc_token,
)

app = FastAPI(
    title="Post-Quantum Face Authentication Server",
    description="Zero-knowledge biometric authentication server backed by NIST FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65.",
    version="1.0.0",
)

# Server Post-Quantum Identity Keys (ML-DSA-65)
SERVER_DSA_PK, SERVER_DSA_SK = generate_ml_dsa_keypair()
CHALLENGE_TTL_SECONDS: int = config.CHALLENGE_TTL_SECONDS

HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY)
USER_DB: dict[str, bytes] = {}
ACTIVE_CHALLENGES: dict[str, dict[str, Any]] = {}


def verify_api_key(x_api_key: str | None = Header(None, alias="X-API-Key")) -> None:
    """
    Validates the optional system API Key if configured in the environment.
    If no API_KEY is set in config/.env, authentication bypass is permitted for open local development.
    """
    if config.API_KEY:
        if not x_api_key or not secrets.compare_digest(x_api_key, config.API_KEY):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing API key in X-API-Key header.",
            )


# ==============================================================================
# Request Models
# ==============================================================================
class RegisterRequest(BaseModel):
    user_id: str = Field(..., description="Unique user identifier")
    public_key_b64: str = Field(..., description="Base64-encoded ML-KEM-768 public key (1184 bytes)")


class ChallengeRequest(BaseModel):
    user_id: str = Field(..., description="Unique user identifier requesting challenge")


class VerifyRequest(BaseModel):
    user_id: str = Field(..., description="Unique user identifier")
    proof_hmac: str = Field(..., description="Hex-encoded HMAC-SHA3-256 proof of decapsulation")


# ==============================================================================
# Endpoints
# ==============================================================================
@app.get("/", tags=["Health"])
def health_check():
    """Returns server status and supported post-quantum cryptography standards."""
    return {
        "status": "online",
        "service": "Post-Quantum Face Authentication Server",
        "standards": ["NIST FIPS 203 (ML-KEM-768)", "NIST FIPS 204 (ML-DSA-65)"],
        "api_key_required": bool(config.API_KEY),
    }


@app.post("/register", status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register_user(req: RegisterRequest, _: None = Depends(verify_api_key)):
    """
    Registers a user's post-quantum ML-KEM-768 public encapsulation key.
    Raw biometrics are never accepted or stored.
    """
    try:
        ek_bytes = base64.b64decode(req.public_key_b64)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTP_422,
            detail="Invalid Base64 encoding for public key.",
        ) from exc

    if len(ek_bytes) != EK_SIZE:
        raise HTTPException(
            status_code=HTTP_422,
            detail=f"Invalid ML-KEM-768 public key size. Expected {EK_SIZE} bytes, got {len(ek_bytes)}.",
        )

    USER_DB[req.user_id] = ek_bytes
    return {"status": "registered", "user_id": req.user_id}


@app.post("/login/challenge", tags=["Authentication"])
def create_login_challenge(req: ChallengeRequest, _: None = Depends(verify_api_key)):
    """
    Generates a post-quantum cryptographic challenge for a registered user.
    Encapsulates a shared secret K and returns ciphertext C.
    """
    ek_bytes = USER_DB.get(req.user_id)
    if not ek_bytes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not registered.",
        )

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


@app.post("/login/verify", tags=["Authentication"])
def verify_login_proof(req: VerifyRequest, _: None = Depends(verify_api_key)):
    """
    Verifies the zero-knowledge HMAC-SHA3-256 proof against the active challenge.
    Single-use challenge consumption prevents replay attacks.
    On success, issues a NIST FIPS 204 ML-DSA-65 signed session token.
    """
    # Pop challenge immediately to eliminate replay attack windows
    challenge = ACTIVE_CHALLENGES.pop(req.user_id, None)
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active challenge found or challenge already consumed.",
        )

    if time.time() > challenge["expires_at"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Challenge expired.",
        )

    if not secrets.compare_digest(req.proof_hmac, challenge["expected_hmac"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cryptographic proof.",
        )

    pqc_token = issue_pqc_token(SERVER_DSA_SK, req.user_id, ttl_seconds=config.TOKEN_TTL_SECONDS)

    return {
        "status": "authenticated",
        "token_type": "ML-DSA-65",
        "access_token": pqc_token,
    }


@app.get("/me", tags=["Protected Resource"])
def get_authenticated_user(authorization: str = Header(...)):
    """
    Protected endpoint verifying ML-DSA-65 quantum-safe bearer signature and token validity.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token.",
        )

    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = verify_pqc_token(SERVER_DSA_PK, token)
        return {"verified_claims": claims}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host=config.SERVER_HOST, port=config.SERVER_PORT, reload=True)
