import base64
import json
import os
import sys
import time
import cv2
import httpx
import keyring
import numpy as np
from deepface import DeepFace
from pqc_engine import (
    generate_ml_kem_keypair,
    decapsulate_challenge,
    compute_proof_hmac,
)

SERVER_URL = "http://127.0.0.1:8000"
KEYRING_SERVICE = "PQC_FaceAuth_Enclave"
ENCLAVE_DIR = "local_enclave"

CAMERA_INDEX = 0
DETECTOR_BACKEND = "retinaface"
ARCFACE_COSINE_THRESHOLD = 0.68  

ENABLE_ANTI_SPOOFING = False

CHUNK_SIZE = 800
NUM_CHUNKS = 4

os.makedirs(ENCLAVE_DIR, exist_ok=True)


#Splits the ML-KEM-768 key into 4 chunks for Windows Credential Manager.
def save_dk_to_keyring(user_id: str, dk_bytes: bytes):
    dk_b64 = base64.b64encode(dk_bytes).decode("utf-8")
    chunks = [dk_b64[i : i + CHUNK_SIZE] for i in range(0, len(dk_b64), CHUNK_SIZE)]

    for idx, chunk in enumerate(chunks):
        keyring.set_password(KEYRING_SERVICE, f"{user_id}_part_{idx}", chunk)


#Reassembles the ML-KEM private key chunks from Windows Credential Manager.
def load_dk_from_keyring(user_id: str) -> bytes | None:
    chunks = []
    for idx in range(NUM_CHUNKS):
        part = keyring.get_password(KEYRING_SERVICE, f"{user_id}_part_{idx}")
        if part is None:
            return None
        chunks.append(part)

    dk_b64 = "".join(chunks)
    return base64.b64decode(dk_b64)


#Captures a webcam frame directly into RAM without saving any raw photo to disk.
def capture_frame_in_memory(window_prompt: str) -> np.ndarray:
    input(f"\n[CAMERA] {window_prompt} - Look at the camera and press ENTER to capture...")

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        raise RuntimeError(f"Could not access webcam at index {CAMERA_INDEX}.")

    print("[CAMERA] Warming up sensor & adjusting auto-exposure in RAM...")
    time.sleep(0.5)

    frame = None
    for _ in range(30):
        ret, temp_frame = cap.read()
        if ret and temp_frame is not None:
            frame = temp_frame

    cap.release()

    if frame is None:
        raise RuntimeError("Failed to read frames from webcam.")

    brightness = frame.mean()
    print(f"[CAMERA] Frame captured in RAM (Average Brightness: {brightness:.1f}/255).")
    if brightness < 5.0:
        print("[WARNING] Captured frame is nearly pitch black! Check your camera cover or CAMERA_INDEX.")

    return frame


#Extracts the ArcFace vector directly from the RAM frame.
def extract_face_embedding(frame: np.ndarray) -> list[float]:
    representations = DeepFace.represent(
        img_path=frame,
        model_name="ArcFace",
        detector_backend=DETECTOR_BACKEND,
        enforce_detection=True,
        anti_spoofing=ENABLE_ANTI_SPOOFING,
    )
    return representations[0]["embedding"]


#Compares live facial embedding against stored vector using Cosine Distance in RAM.
def verify_face_in_memory(user_id: str, live_frame: np.ndarray) -> bool:
    emb_path = os.path.join(ENCLAVE_DIR, f"{user_id}_embedding.json")
    if not os.path.exists(emb_path):
        print("[ERROR] No local biometric embedding found for this user. Run `enroll` first.")
        return False

    with open(emb_path, "r") as f:
        ref_embedding = np.array(json.load(f), dtype=np.float64)

    try:
        live_embedding = np.array(extract_face_embedding(live_frame), dtype=np.float64)
    except ValueError as e:
        print(f"[BIOMETRIC TEE] Face/Liveness check failed: {e}")
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


#Extracts 512-D face vector in RAM, generates ML-KEM keys, and registers pk_user.
def enroll_user(user_id: str):
    
    print(f"=== Enrolling User: {user_id} ===")
    frame = capture_frame_in_memory(f"Enroll Face: {user_id}")

    try:
        embedding = extract_face_embedding(frame)
    except ValueError as e:
        print(f"[ERROR] Enrollment aborted: No clear/live face detected ({e}).")
        return
    finally:
        del frame 

    emb_path = os.path.join(ENCLAVE_DIR, f"{user_id}_embedding.json")
    with open(emb_path, "w") as f:
        json.dump(embedding, f)
    print(f"[ENCLAVE] Saved 512-D facial vector to '{emb_path}' (no photo saved to disk).")

    old_jpg = os.path.join(ENCLAVE_DIR, f"{user_id}_reference.jpg")
    if os.path.exists(old_jpg):
        os.remove(old_jpg)

    ek, dk = generate_ml_kem_keypair()
    save_dk_to_keyring(user_id, dk)
    print("[ENCLAVE] ML-KEM-768 Private Key (dk) locked in OS Keyring.")

    ek_b64 = base64.b64encode(ek).decode("utf-8")
    with httpx.Client() as client:
        resp = client.post(
            f"{SERVER_URL}/register",
            json={"user_id": user_id, "public_key_b64": ek_b64},
        )
        resp.raise_for_status()
        print(f"[SERVER] Registration Success: {resp.json()}")


#Verifies face vector in RAM -> Unlocks ML-KEM Key -> Receives ML-DSA PQC Token.
def authenticate_user(user_id: str):
    print(f"=== Authenticating User: {user_id} ===")

    live_frame = capture_frame_in_memory(f"Verify Face: {user_id}")
    is_matched = verify_face_in_memory(user_id, live_frame)
    del live_frame  

    if not is_matched:
        print("[ACCESS DENIED] Biometric verification failed. Secure Enclave remains locked.")
        return

    dk_bytes = load_dk_from_keyring(user_id)
    if not dk_bytes:
        print("[ERROR] Private key not found in OS Keyring.")
        return

    with httpx.Client() as client:
        chal_resp = client.post(f"{SERVER_URL}/login/challenge", json={"user_id": user_id})
        if chal_resp.status_code != 200:
            print(f"[SERVER ERROR] Challenge failed: {chal_resp.text}")
            return

        ciphertext_c = base64.b64decode(chal_resp.json()["ciphertext_b64"])

        shared_secret_k = decapsulate_challenge(dk_bytes, ciphertext_c)
        proof_hmac = compute_proof_hmac(shared_secret_k, user_id, ciphertext_c)

        del dk_bytes, shared_secret_k

        verify_resp = client.post(
            f"{SERVER_URL}/login/verify",
            json={"user_id": user_id, "proof_hmac": proof_hmac},
        )
        if verify_resp.status_code != 200:
            print(f"\n[LOGIN FAILED] Server rejected proof: {verify_resp.text}")
            return

        data = verify_resp.json()
        pqc_token = data["access_token"]
        print("\n[LOGIN SUCCESS] Post-Quantum Handshake Verified!")
        print(f"Token Algorithm : {data['token_type']} (NIST FIPS 204)")
        print(f"PQC Token (len) : {len(pqc_token)} chars ({pqc_token[:50]}...)")

        me_resp = client.get(
            f"{SERVER_URL}/me",
            headers={"Authorization": f"Bearer {pqc_token}"},
        )
        print(f"[PROTECTED API] /me verification result: {me_resp.json()}")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("enroll", "login"):
        print("Usage:")
        print("  python client.py enroll <user_id>")
        print("  python client.py login <user_id>")
        sys.exit(1)

    action, user = sys.argv[1], sys.argv[2]
    if action == "enroll":
        enroll_user(user)
    elif action == "login":
        authenticate_user(user)