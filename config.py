"""
Configuration Module for Post-Quantum Biometric Authentication.

Loads application settings and API credentials from environment variables or a .env file.
Provides centralized access to networking, biometric thresholds, and cryptographic parameters.
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    # Load environment variables from .env in the project root directory
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
except ImportError:
    pass

# ==============================================================================
# Server & Networking
# ==============================================================================
SERVER_HOST: str = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT: int = int(os.getenv("SERVER_PORT", "8000"))
SERVER_URL: str = os.getenv("SERVER_URL", f"http://{SERVER_HOST}:{SERVER_PORT}")

# ==============================================================================
# Security & API Credentials
# ==============================================================================
# Optional API Key used to protect client-server communication
API_KEY: str = os.getenv("API_KEY", "").strip()

# ==============================================================================
# Local Secure Enclave & Keyring
# ==============================================================================
KEYRING_SERVICE: str = os.getenv("KEYRING_SERVICE", "PQC_FaceAuth_Enclave")
ENCLAVE_DIR: str = os.getenv("ENCLAVE_DIR", "local_enclave")

# ==============================================================================
# Biometric & Camera Settings
# ==============================================================================
CAMERA_INDEX: int = int(os.getenv("CAMERA_INDEX", "0"))
DETECTOR_BACKEND: str = os.getenv("DETECTOR_BACKEND", "retinaface")
ARCFACE_COSINE_THRESHOLD: float = float(os.getenv("ARCFACE_COSINE_THRESHOLD", "0.68"))
ENABLE_ANTI_SPOOFING: bool = os.getenv("ENABLE_ANTI_SPOOFING", "false").lower() in (
    "true",
    "1",
    "yes",
)

# ==============================================================================
# Cryptographic Protocol Parameters (NIST FIPS 203 & 204)
# ==============================================================================
CHALLENGE_TTL_SECONDS: int = int(os.getenv("CHALLENGE_TTL_SECONDS", "60"))
TOKEN_TTL_SECONDS: int = int(os.getenv("TOKEN_TTL_SECONDS", "3600"))

# Chunking configuration for OS Keyring (e.g. Windows Credential Manager payload limits)
CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "800"))
NUM_CHUNKS: int = int(os.getenv("NUM_CHUNKS", "4"))


def get_client_headers() -> dict[str, str]:
    """
    Returns standard HTTP headers for client requests, including the API key if configured.
    """
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers
