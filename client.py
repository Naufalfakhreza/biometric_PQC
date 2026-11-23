"""
Post-Quantum Biometric Client & Secure Enclave.

Manages RAM-only facial feature extraction using DeepFace (ArcFace),
OS Credential Manager (Keyring) chunked private key storage,
and NIST FIPS 203 ML-KEM-768 challenge decapsulation.
"""

import base64
import json
import os
import sys
import time
from typing import Any

import cv2
import httpx
import keyring
import numpy as np
from deepface import DeepFace

import config
from pqc_engine import (
    compute_proof_hmac,
    decapsulate_challenge,
    generate_ml_kem_keypair,
)

# Exported module-level configuration (loaded from config.py / .env)
SERVER_URL: str = config.SERVER_URL
KEYRING_SERVICE: str = config.KEYRING_SERVICE
ENCLAVE_DIR: str = config.ENCLAVE_DIR
CAMERA_INDEX: int = config.CAMERA_INDEX
DETECTOR_BACKEND: str = config.DETECTOR_BACKEND
ARCFACE_COSINE_THRESHOLD: float = config.ARCFACE_COSINE_THRESHOLD
ENABLE_ANTI_SPOOFING: bool = config.ENABLE_ANTI_SPOOFING
CHUNK_SIZE: int = config.CHUNK_SIZE
NUM_CHUNKS: int = config.NUM_CHUNKS

# Ensure local enclave directory exists
os.makedirs(ENCLAVE_DIR, exist_ok=True)


def _get_request_headers() -> dict[str, str]:
    """Generates standard HTTP request headers including API key if configured."""
    return config.get_client_headers()


def save_dk_to_keyring(user_id: str, dk_bytes: bytes) -> None:
    """
    Splits the 2400-byte ML-KEM-768 private key into 4 chunks and persists
    them into the OS Keyring (e.g. Windows Credential Manager).

    Args:
        user_id (str): The unique username.
        dk_bytes (bytes): The raw decapsulation key bytes.
    """
    dk_b64 = base64.b64encode(dk_bytes).decode("utf-8")
    chunks = [dk_b64[i : i + CHUNK_SIZE] for i in range(0, len(dk_b64), CHUNK_SIZE)]

    for idx, chunk in enumerate(chunks):
        keyring.set_password(KEYRING_SERVICE, f"{user_id}_part_{idx}", chunk)


def load_dk_from_keyring(user_id: str) -> bytes | None:
    """
    Reconstructs the ML-KEM-768 private key from OS Keyring chunks.

    Args:
        user_id (str): The unique username.

    Returns:
        bytes | None: Reassembled decapsulation key bytes or None if missing.
    """
    chunks: list[str] = []
    for idx in range(NUM_CHUNKS):
        part = keyring.get_password(KEYRING_SERVICE, f"{user_id}_part_{idx}")
        if part is None:
            return None
        chunks.append(part)

    dk_b64 = "".join(chunks)
    return base64.b64decode(dk_b64)


def capture_frame_in_memory(window_prompt: str) -> np.ndarray:
    """
    Captures a single webcam frame directly into memory (RAM).
    No raw image is ever written to disk.

    Args:
        window_prompt (str): Prompt instruction displayed to the user.

    Returns:
        np.ndarray: The captured OpenCV BGR frame.

    Raises:
        RuntimeError: If webcam cannot be opened or fails to yield frames.
    """
    input(f"\n[CAMERA] {window_prompt} - Look at the camera and press ENTER to capture...")

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        raise RuntimeError(f"Could not access webcam at index {CAMERA_INDEX}.")

    print("[CAMERA] Warming up sensor & adjusting auto-exposure in RAM...")
    time.sleep(0.5)

    frame: np.ndarray | None = None
    for _ in range(30):
        ret, temp_frame = cap.read()
        if ret and temp_frame is not None:
            frame = temp_frame

    cap.release()

    if frame is None:
        raise RuntimeError("Failed to read frames from webcam.")

    brightness = float(frame.mean())
    print(f"[CAMERA] Frame captured in RAM (Average Brightness: {brightness:.1f}/255).")
    if brightness < 5.0:
        print("[WARNING] Captured frame is nearly pitch black! Check camera cover or CAMERA_INDEX.")

    return frame


def extract_face_embedding(frame: np.ndarray) -> list[float]:
    """
    Extracts a 512-dimensional ArcFace vector directly from an in-memory frame.

    Args:
        frame (np.ndarray): The raw image frame in RAM.

    Returns:
        list[float]: 512-D floating point facial embedding vector.
    """
    representations = DeepFace.represent(
        img_path=frame,
        model_name="ArcFace",
        detector_backend=DETECTOR_BACKEND,
        enforce_detection=True,
        anti_spoofing=ENABLE_ANTI_SPOOFING,
    )
    return representations[0]["embedding"]


def verify_face_in_memory(user_id: str, live_frame: np.ndarray) -> bool:
    """
    Compares live facial embedding against stored template using Cosine Distance in RAM.

    Args:
        user_id (str): User identifier.
        live_frame (np.ndarray): Freshly captured live camera frame in RAM.

    Returns:
        bool: True if cosine distance is within threshold, False otherwise.
    """
    emb_path = os.path.join(ENCLAVE_DIR, f"{user_id}_embedding.json")
    if not os.path.exists(emb_path):
        print(f"[ERROR] No local biometric embedding found for '{user_id}'. Run 'enroll' first.")
        return False

    with open(emb_path, "r", encoding="utf-8") as f:
        ref_embedding = np.array(json.load(f), dtype=np.float64)

    try:
        live_embedding = np.array(extract_face_embedding(live_frame), dtype=np.float64)
    except Exception as exc:
        print(f"[BIOMETRIC TEE] Face/liveness verification failed: {exc}")
        return False

    # Cosine Distance = 1 - (A . B) / (||A|| * ||B||)
    dot_product = np.dot(live_embedding, ref_embedding)
    norm_product = np.linalg.norm(live_embedding) * np.linalg.norm(ref_embedding)
    cosine_distance = float(1.0 - (dot_product / norm_product))

    verified = cosine_distance <= ARCFACE_COSINE_THRESHOLD
    print(
        f"[BIOMETRIC TEE] Match Verified: {verified} "
        f"(Cosine Distance: {cosine_distance:.4f} / Threshold: {ARCFACE_COSINE_THRESHOLD})"
    )
    return verified


def enroll_user(user_id: str) -> None:
    """
    Enrolls a user:
      1. Captures facial frame in RAM.
      2. Extracts 512-D ArcFace template and writes template vector to enclave.
      3. Generates post-quantum ML-KEM-768 keypair.
      4. Secures decapsulation key (dk) in OS Keyring.
      5. Registers public encapsulation key (ek) with the server.

    Args:
        user_id (str): The username to register.
    """
    print(f"\n=== Enrolling User: {user_id} ===")
    frame = capture_frame_in_memory(f"Enroll Face for '{user_id}'")

    try:
        embedding = extract_face_embedding(frame)
    except Exception as exc:
        print(f"[ERROR] Enrollment aborted: No clear face detected ({exc}).")
        return
    finally:
        del frame

    os.makedirs(ENCLAVE_DIR, exist_ok=True)
    emb_path = os.path.join(ENCLAVE_DIR, f"{user_id}_embedding.json")
    with open(emb_path, "w", encoding="utf-8") as f:
        json.dump(embedding, f)
    print(f"[ENCLAVE] Saved 512-D facial vector to '{emb_path}' (zero raw photos stored).")

    # Clean legacy artifacts if any
    old_jpg = os.path.join(ENCLAVE_DIR, f"{user_id}_reference.jpg")
    if os.path.exists(old_jpg):
        os.remove(old_jpg)

    ek, dk = generate_ml_kem_keypair()
    save_dk_to_keyring(user_id, dk)
    print("[ENCLAVE] ML-KEM-768 Private Key (dk) locked inside OS Keyring.")

    ek_b64 = base64.b64encode(ek).decode("utf-8")
    headers = _get_request_headers()

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{SERVER_URL}/register",
                headers=headers,
                json={"user_id": user_id, "public_key_b64": ek_b64},
            )
            resp.raise_for_status()
            print(f"[SERVER] Registration Success: {resp.json()}")
    except httpx.HTTPStatusError as exc:
        print(f"[SERVER ERROR] Registration rejected ({exc.response.status_code}): {exc.response.text}")
    except Exception as exc:
        print(f"[NETWORK ERROR] Failed to connect to server at {SERVER_URL}: {exc}")


def authenticate_user(user_id: str) -> str | None:
    """
    Authenticates a user:
      1. Captures live facial frame in RAM and compares against local enclave template.
      2. If biometric match passes, retrieves ML-KEM-768 private key from OS Keyring.
      3. Requests challenge ciphertext from server.
      4. Decapsulates shared secret K and computes HMAC-SHA3-256 proof.
      5. Sends proof to server and receives NIST FIPS 204 ML-DSA-65 bearer token.
      6. Verifies token against protected /me endpoint.

    Args:
        user_id (str): The username to authenticate.

    Returns:
        str | None: Issued ML-DSA-65 bearer token on success, None on failure.
    """
    print(f"\n=== Authenticating User: {user_id} ===")

    live_frame = capture_frame_in_memory(f"Verify Face for '{user_id}'")
    is_matched = verify_face_in_memory(user_id, live_frame)
    del live_frame

    if not is_matched:
        print("[ACCESS DENIED] Biometric verification failed. Secure Enclave remains locked.")
        return None

    dk_bytes = load_dk_from_keyring(user_id)
    if not dk_bytes:
        print("[ERROR] Private key not found in OS Keyring. Please enroll first.")
        return None

    headers = _get_request_headers()

    try:
        with httpx.Client(timeout=10.0) as client:
            # 1. Request cryptographic challenge
            chal_resp = client.post(
                f"{SERVER_URL}/login/challenge",
                headers=headers,
                json={"user_id": user_id},
            )
            if chal_resp.status_code != 200:
                print(f"[SERVER ERROR] Challenge request failed ({chal_resp.status_code}): {chal_resp.text}")
                return None

            ciphertext_c = base64.b64decode(chal_resp.json()["ciphertext_b64"])

            # 2. Decapsulate challenge & compute transcript-bound HMAC proof
            shared_secret_k = decapsulate_challenge(dk_bytes, ciphertext_c)
            proof_hmac = compute_proof_hmac(shared_secret_k, user_id, ciphertext_c)

            # Scrub sensitive key material from memory
            del dk_bytes, shared_secret_k

            # 3. Submit proof to verify endpoint
            verify_resp = client.post(
                f"{SERVER_URL}/login/verify",
                headers=headers,
                json={"user_id": user_id, "proof_hmac": proof_hmac},
            )
            if verify_resp.status_code != 200:
                print(f"\n[LOGIN FAILED] Server rejected proof ({verify_resp.status_code}): {verify_resp.text}")
                return None

            data = verify_resp.json()
            pqc_token = data["access_token"]
            print("\n[LOGIN SUCCESS] Post-Quantum Handshake Verified!")
            print(f"Token Algorithm : {data['token_type']} (NIST FIPS 204 ML-DSA-65)")
            print(f"PQC Token (len) : {len(pqc_token)} chars ({pqc_token[:40]}...)")

            # 4. Access protected endpoint
            me_resp = client.get(
                f"{SERVER_URL}/me",
                headers={"Authorization": f"Bearer {pqc_token}"},
            )
            print(f"[PROTECTED API] /me response: {me_resp.json()}")
            return pqc_token

    except httpx.ConnectError:
        print(f"[NETWORK ERROR] Cannot connect to server at {SERVER_URL}. Is the server running?")
        return None
    except Exception as exc:
        print(f"[ERROR] Authentication pipeline failed: {exc}")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("enroll", "login"):
        print("Quantum-Safe Biometric Authentication Client")
        print("Usage:")
        print("  python client.py enroll <user_id>")
        print("  python client.py login <user_id>")
        sys.exit(1)

    action, user = sys.argv[1].lower(), sys.argv[2]
    if action == "enroll":
        enroll_user(user)
    elif action == "login":
        authenticate_user(user)
