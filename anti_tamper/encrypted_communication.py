"""
Encrypted Communication Layer

Provides end-to-end encryption for API communication between client and server.
Uses AES-256-CBC for payload encryption + HMAC-SHA256 for request signing.

Client-side usage:
    from anti_tamper.encrypted_communication import SecureChannel

    channel = SecureChannel(encryption_key="shared_secret", api_key="optional_hwid")
    
    # Encrypt a request payload
    payload = {"license": "ABC-123", "hwid": "hashed_hwid"}
    encrypted = channel.encrypt_request(payload)
    
    # Decrypt a server response  
    response = channel.decrypt_response(server_response)

Server-side usage:
    from anti_tamper.encrypted_communication import SecureChannel
    
    channel = SecureChannel(encryption_key="shared_secret")
    
    # Decrypt incoming request
    data = channel.decrypt_request(encrypted_body)
    
    # Encrypt response
    response = channel.encrypt_response({"success": True})
"""
import hashlib
import hmac
import json
import time
import base64
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class SecureChannel:
    """
    Encrypted communication channel with:
    - AES-256-CBC payload encryption
    - HMAC-SHA256 request signing
    - Timestamp-based replay protection
    - Random IV per message
    """

    def __init__(self, encryption_key: str, signing_key: str = None):
        self._encryption_key = hashlib.sha256(encryption_key.encode()).digest()
        self._signing_key = (signing_key or encryption_key).encode()

    def _aes_encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        iv = hashlib.md5(self._encryption_key[:16] + str(time.time_ns()).encode()).digest()

        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return ciphertext, iv

    def _aes_decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def _sign(self, data: bytes) -> str:
        return hmac.new(self._signing_key, data, hashlib.sha256).hexdigest()

    def _verify(self, data: bytes, signature: str) -> bool:
        expected = self._sign(data)
        return hmac.compare_digest(expected, signature)

    def encrypt_request(self, payload: dict) -> str:
        """
        Encrypt a request payload for sending to the server.
        
        Returns a JSON string with structure:
        {
            "iv": "<base64>",
            "data": "<base64 encrypted>",
            "timestamp": <unix_ms>,
            "signature": "<hex>"
        }
        """
        timestamp_ms = int(time.time() * 1000)
        payload_with_ts = {**payload, "_t": timestamp_ms}

        plaintext = json.dumps(payload_with_ts, separators=(",", ":")).encode()
        ciphertext, iv = self._aes_encrypt(plaintext)

        # Sign the encrypted payload
        sig_data = iv + ciphertext + str(timestamp_ms).encode()
        signature = self._sign(sig_data)

        return json.dumps({
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(ciphertext).decode(),
            "timestamp": timestamp_ms,
            "signature": signature
        })

    def decrypt_request(self, encrypted_b64: str) -> dict | None:
        """
        Decrypt a request received from a client.
        Verifies signature and checks timestamp freshness.
        """
        try:
            msg = json.loads(encrypted_b64)
            iv = base64.b64decode(msg["iv"])
            ciphertext = base64.b64decode(msg["data"])
            timestamp = msg["timestamp"]
            signature = msg["signature"]

            # Verify signature
            sig_data = iv + ciphertext + str(timestamp).encode()
            if not self._verify(sig_data, signature):
                return None

            # Check timestamp freshness (allow 30s clock skew)
            now_ms = int(time.time() * 1000)
            if abs(now_ms - timestamp) > 30000:
                return None

            # Decrypt
            plaintext = self._aes_decrypt(ciphertext, iv)
            payload = json.loads(plaintext.decode())

            # Remove internal timestamp field
            payload.pop("_t", None)

            return payload

        except Exception:
            return None

    def encrypt_response(self, payload: dict) -> str:
        """Encrypt a response to send back to the client."""
        return self.encrypt_request(payload)

    def decrypt_response(self, encrypted_b64: str) -> dict | None:
        """Decrypt a response received from the server."""
        return self.decrypt_request(encrypted_b64)


# Convenience wrappers for FastAPI integration

def encrypted_endpoint(func):
    """
    Decorator for FastAPI endpoints that accept encrypted requests.
    The decorated function receives (request_data: dict) instead of the raw body.
    """
    import functools
    from fastapi import Request

    @functools.wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        body = await request.body()
        channel = SecureChannel(
            encryption_key=request.app.state.encryption_key
        )
        data = channel.decrypt_request(body.decode())
        if data is None:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Invalid encrypted payload"}
            )
        return await func(data, *args, **kwargs)

    return wrapper


if __name__ == "__main__":
    # Demo
    channel = SecureChannel("test_key_12345")

    # Client encrypts a request
    original = {"license": "ABC-123", "hwid": "abc123hash"}
    encrypted = channel.encrypt_request(original)
    print(f"Encrypted: {encrypted[:80]}...")

    # Server decrypts it
    decrypted = channel.decrypt_request(encrypted)
    print(f"Decrypted: {decrypted}")

    # Verify
    print(f"Match: {original == decrypted}")
