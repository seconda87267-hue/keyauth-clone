import hashlib
import hmac
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ENCRYPTION_KEY


def _derive_aes_key() -> bytes:
    return hashlib.sha256(ENCRYPTION_KEY.encode()).digest()


def encrypt_data(data: dict) -> str:
    key = _derive_aes_key()
    iv = hashlib.md5(key[:16]).digest()
    plaintext = json.dumps(data, separators=(",", ":")).encode()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return b64encode(encrypted).decode()


def decrypt_data(encrypted_b64: str) -> dict | None:
    try:
        key = _derive_aes_key()
        iv = hashlib.md5(key[:16]).digest()
        encrypted = b64decode(encrypted_b64)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return json.loads(plaintext.decode())
    except Exception:
        return None


def sign_request(data: dict, secret: str = ENCRYPTION_KEY) -> str:
    msg = json.dumps(data, separators=(",", ":"), sort_keys=True)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def verify_signature(data: dict, signature: str, secret: str = ENCRYPTION_KEY) -> bool:
    expected = sign_request(data, secret)
    return hmac.compare_digest(expected, signature)
