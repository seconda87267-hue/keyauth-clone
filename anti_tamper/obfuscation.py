"""
String Obfuscation Utilities

Provides helpers to obfuscate strings at rest and deobfuscate at runtime
to make static analysis harder.

Usage:
    from anti_tamper.obfuscation import XORObfuscator

    obf = XORObfuscator()
    encrypted = obf.encrypt("sensitive_string")
    decrypted = obf.decrypt(encrypted)
"""
import base64
import hashlib
import random
import string


class XORObfuscator:
    """Simple XOR-based string obfuscation with random key per string"""

    def __init__(self, global_key: str = None):
        if global_key is None:
            global_key = hashlib.sha256(b"KeyAuth_Default_Obfuscation_Key_2024").hexdigest()[:32]
        self.global_key = global_key

    def _xor(self, data: bytes, key: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))[:len(data)]

    def encrypt(self, plaintext: str) -> str:
        """Encrypt/obfuscate a string. Returns base64-encoded result with embedded key hint."""
        key_seed = hashlib.md5(plaintext.encode()).hexdigest()[:8]
        local_key = hashlib.sha256((self.global_key + key_seed).encode()).digest()[:16]

        encrypted = self._xor(plaintext.encode(), local_key)
        combined = key_seed.encode() + encrypted

        return base64.b64encode(combined).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt a previously obfuscated string."""
        try:
            combined = base64.b64decode(ciphertext_b64)
            key_seed = combined[:8].decode()
            encrypted = combined[8:]

            local_key = hashlib.sha256((self.global_key + key_seed).encode()).digest()[:16]
            decrypted = self._xor(encrypted, local_key)

            return decrypted.decode()
        except Exception:
            return ""


class StringPool:
    """Manage a pool of obfuscated strings with runtime deobfuscation"""

    def __init__(self, key: str = None):
        self.obf = XORObfuscator(key)
        self._pool = {}

    def add(self, name: str, plaintext: str):
        """Add a string to the pool (obfuscated)"""
        self._pool[name] = self.obf.encrypt(plaintext)

    def get(self, name: str) -> str:
        """Retrieve and deobfuscate a string from the pool"""
        if name not in self._pool:
            return ""
        return self.obf.decrypt(self._pool[name])

    def add_bulk(self, strings: dict[str, str]):
        """Add multiple strings at once: {name: plaintext}"""
        for name, plaintext in strings.items():
            self.add(name, plaintext)

    def export_pool(self) -> dict[str, str]:
        """Export the obfuscated pool dict for embedding in code"""
        return {k: v for k, v in self._pool.items()}


class StringObfuscator:
    """
    Compile-time string obfuscation helper.
    Generates Python code with pre-obfuscated strings for embedding.
    """

    @staticmethod
    def generate_stub(strings: dict[str, str], key: str = None) -> str:
        """Generate Python source code with embedded obfuscated strings"""
        pool = StringPool(key)
        pool.add_bulk(strings)
        obfuscated = pool.export_pool()

        lines = [
            "import base64, hashlib",
            "",
            "class _ObfuscatedStringPool:",
            "    _key = " + repr(hashlib.sha256((key or "").encode()).hexdigest()[:32] if key else "KeyAuth_Default_Obfuscation_Key_2024"),
            "",
            "    @staticmethod",
            "    def _xor(data, key):",
            "        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))[:len(data)]",
            "",
            "    _pool = " + repr(obfuscated),
            "",
            "    @classmethod",
            "    def get(cls, name):",
            "        raw = base64.b64decode(cls._pool[name])",
            "        seed = raw[:8].decode()",
            "        encrypted = raw[8:]",
            "        local_key = hashlib.sha256((cls._key + seed).encode()).digest()[:16]",
            "        return cls._xor(encrypted, local_key).decode()",
            "",
            "# Generated obfuscated string accessors",
        ]

        for name in strings:
            lines.append(f"def get_{name}(): return _ObfuscatedStringPool.get({repr(name)})")

        return "\n".join(lines)


if __name__ == "__main__":
    # Demo
    obf = XORObfuscator()
    original = "supersecretapikey"
    encrypted = obf.encrypt(original)
    decrypted = obf.decrypt(encrypted)

    print(f"Original:  {original}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match:     {original == decrypted}")

    # Generate stub
    stub = StringObfuscator.generate_stub({
        "api_key": "sk-1234567890abcdef",
        "db_password": "s3cur3p@ss",
        "endpoint": "https://api.example.com"
    })
    print("\n--- Generated Stub ---")
    print(stub[:500])
