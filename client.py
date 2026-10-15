import base64
import os
import sys
import time
import cv2
import httpx
import keyring
from deepface import DeepFace
from pqc_engine import (
    generate_ml_kem_keypair,
    decapsulate_challenge,
    compute_proof_hash,
)

SERVER_URL = "http://127.0.0.1:8000"
KEYRING_SERVICE = "PQC_FaceAuth_Enclave"
ENCLAVE_DIR = "local_enclave"

# Change CAMERA_INDEX to 1 or 2 if index 0 points to a virtual camera (e.g., OBS)
CAMERA_INDEX = 0
# Options: 'opencv', 'ssd', 'mtcnn', 'retinaface'
DETECTOR_BACKEND = "retinaface"

# Windows Credential Manager limit workaround (3,200 Base64 chars split into 4x800 chunks)
CHUNK_SIZE = 800
NUM_CHUNKS = 4

os.makedirs(ENCLAVE_DIR, exist_ok=True)


def save_dk_to_keyring(user_id: str, dk_bytes: bytes):
    """Splits the 3,200-char Base64 ML-KEM-768 key into 4 chunks for Windows Credential Manager."""
    dk_b64 = base64.b64encode(dk_bytes).decode("utf-8")
    chunks = [dk_b64[i : i + CHUNK_SIZE] for i in range(0, len(dk_b64), CHUNK_SIZE)]

    for idx, chunk in enumerate(chunks):
        keyring.set_password(KEYRING_SERVICE, f"{user_id}_part_{idx}", chunk)


def load_dk_from_keyring(user_id: str) -> bytes | None:
    """Reassembles the ML-KEM-768 private key chunks from Windows Credential Manager."""
    chunks = []
    for idx in range(NUM_CHUNKS):
        part = keyring.get_password(KEYRING_SERVICE, f"{user_id}_part_{idx}")
        if part is None:
            return None
        chunks.append(part)

    dk_b64 = "".join(chunks)
    return base64.b64decode(dk_b64)


def capture_webcam_frame(window_prompt: str) -> str:
    """Flushes the camera buffer via terminal prompt so auto-exposure adjusts before saving."""
    input(f"\n[CAMERA] {window_prompt} - Look at the camera and press ENTER to capture...")

    cap = cv2.VideoCapture(CAMERA_INDEX)
    if not cap.isOpened():
        raise RuntimeError(f"Could not access webcam at index {CAMERA_INDEX}.")

    print("[CAMERA] Warming up sensor & adjusting auto-exposure...")
    time.sleep(0.5)

    # Flush 30 frames (~1 second) so the webcam adjusts gain and clears dark initial frames
    frame = None
    for _ in range(30):
        ret, temp_frame = cap.read()
        if ret and temp_frame is not None:
            frame = temp_frame

    cap.release()

    if frame is None:
        raise RuntimeError("Failed to read frames from webcam.")

    brightness = frame.mean()
    print(f"[CAMERA] Frame captured (Average Brightness: {brightness:.1f}/255).")
    if brightness < 5.0:
        print("[WARNING] Captured frame is nearly pitch black! Check your camera cover or CAMERA_INDEX.")

    temp_path = os.path.join(ENCLAVE_DIR, "live_capture.jpg")
    cv2.imwrite(temp_path, frame)
    return temp_path


def verify_face_locally(user_id: str, live_img_path: str) -> bool:
    """Runs on-device ArcFace verification inside the local enclave."""
    ref_img_path = os.path.join(ENCLAVE_DIR, f"{user_id}_reference.jpg")
    if not os.path.exists(ref_img_path):
        print("[ERROR] No local biometric template found for this user.")
        return False

    try:
        result = DeepFace.verify(
            img1_path=live_img_path,
            img2_path=ref_img_path,
            model_name="ArcFace",
            detector_backend=DETECTOR_BACKEND,
            enforce_detection=True,
        )
        distance = result.get("distance", 1.0)
        verified = result.get("verified", False)
        print(f"[BIOMETRIC TEE] Match Verified: {verified} (Cosine Distance: {distance:.4f})")
        return verified
    except ValueError:
        debug_path = os.path.join(ENCLAVE_DIR, "debug_failed_capture.jpg")
        if os.path.exists(live_img_path):
            os.replace(live_img_path, debug_path)
        print(f"[BIOMETRIC TEE] Face detection failed. Saved image to '{debug_path}' for inspection.")
        return False


def enroll_user(user_id: str):
    """Captures reference face, generates ML-KEM-768 keys, and registers pk_user with server."""
    print(f"=== Enrolling User: {user_id} ===")
    captured_path = capture_webcam_frame(f"Enroll Face: {user_id}")

    try:
        DeepFace.extract_faces(
            img_path=captured_path,
            detector_backend=DETECTOR_BACKEND,
            enforce_detection=True,
        )
    except ValueError:
        debug_path = os.path.join(ENCLAVE_DIR, "debug_failed_capture.jpg")
        os.replace(captured_path, debug_path)
        print(f"[ERROR] No clear face detected. Open '{debug_path}' to check what your camera captured.")
        return

    ref_img_path = os.path.join(ENCLAVE_DIR, f"{user_id}_reference.jpg")
    os.replace(captured_path, ref_img_path)

    # Generate NIST ML-KEM-768 Keypair
    ek, dk = generate_ml_kem_keypair()

    # Store Private Key (dk) in OS Keyring across 4 safe-sized chunks
    save_dk_to_keyring(user_id, dk)
    print("[ENCLAVE] ML-KEM-768 Private Key (dk) locked in OS Keyring.")

    # Send Public Key (ek) to Authentication Server
    ek_b64 = base64.b64encode(ek).decode("utf-8")
    with httpx.Client() as client:
        resp = client.post(
            f"{SERVER_URL}/register",
            json={"user_id": user_id, "public_key_b64": ek_b64},
        )
        resp.raise_for_status()
        print(f"[SERVER] Registration Success: {resp.json()}")


def authenticate_user(user_id: str):
    """Executes On-Device Face Verification -> Unlocks ML-KEM Key -> Solves Server Challenge."""
    print(f"=== Authenticating User: {user_id} ===")

    # Step 1: Capture & Verify Face Locally (Biometric Gate)
    live_path = capture_webcam_frame(f"Verify Face: {user_id}")
    is_matched = verify_face_locally(user_id, live_path)
    if os.path.exists(live_path):
        os.remove(live_path)  # Immediately wipe live capture from disk

    if not is_matched:
        print("[ACCESS DENIED] Biometric verification failed. Secure Enclave remains locked.")
        return

    # Step 2: Unlock Private Key (dk) from OS Keyring
    dk_bytes = load_dk_from_keyring(user_id)
    if not dk_bytes:
        print("[ERROR] Private key not found in OS Keyring.")
        return

    with httpx.Client() as client:
        # Step 3: Request ML-KEM Challenge Ciphertext (C) from Server
        chal_resp = client.post(f"{SERVER_URL}/login/challenge", json={"user_id": user_id})
        if chal_resp.status_code != 200:
            print(f"[SERVER ERROR] Challenge failed: {chal_resp.text}")
            return

        ciphertext_c = base64.b64decode(chal_resp.json()["ciphertext_b64"])

        # Step 4: Decapsulate C -> K inside Client Enclave and Hash Proof H(K)
        shared_secret_k = decapsulate_challenge(dk_bytes, ciphertext_c)
        proof_hash = compute_proof_hash(shared_secret_k, user_id)

        # Step 5: Send Proof Hash H(K) to Server
        verify_resp = client.post(
            f"{SERVER_URL}/login/verify",
            json={"user_id": user_id, "proof_hash": proof_hash},
        )
        if verify_resp.status_code == 200:
            data = verify_resp.json()
            print("\n[LOGIN SUCCESS] Post-Quantum Handshake Verified!")
            print(f"JWT Access Token: {data['access_token'][:60]}...")
        else:
            print(f"\n[LOGIN FAILED] Server rejected proof: {verify_resp.text}")


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