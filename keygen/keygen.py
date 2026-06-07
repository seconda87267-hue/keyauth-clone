"""
License Key Generator Library

Generates keys in format: XXXXXX-XXXXXX-XXXXXX
Each segment is 6 characters from A-Z, 0-9
"""
import secrets
import string
import json
from datetime import datetime, timedelta


def generate_key() -> str:
    """Generate a single license key: ABCDEF-GHIJKL-MNOPQR"""
    chars = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(chars) for _ in range(6))
        for _ in range(3)
    )


def generate_bulk(count: int = 10) -> list[str]:
    """Generate multiple unique keys"""
    keys = set()
    while len(keys) < count:
        keys.add(generate_key())
    return list(keys)


def generate_with_expiry(days: int = 30) -> dict:
    """Generate a key with expiry info"""
    key = generate_key()
    expiry = datetime.utcnow() + timedelta(days=days)
    return {
        "license_key": key,
        "expires": expiry.isoformat(),
        "expiry_days": days,
        "created": datetime.utcnow().isoformat()
    }


def generate_bulk_with_expiry(count: int, days: int = 30) -> list[dict]:
    return [generate_with_expiry(days) for _ in range(count)]


def export_json(keys: list, filename: str = "keys.json"):
    """Export keys to JSON file"""
    with open(filename, "w") as f:
        json.dump({"keys": keys, "generated": datetime.utcnow().isoformat()}, f, indent=2)
    print(f"Exported {len(keys)} keys to {filename}")


def export_txt(keys: list[str], filename: str = "keys.txt"):
    """Export keys to text file (one per line)"""
    with open(filename, "w") as f:
        for k in keys:
            f.write(k + "\n")
    print(f"Exported {len(keys)} keys to {filename}")


if __name__ == "__main__":
    keys = generate_bulk(10)
    for k in keys:
        print(k)
    export_txt(keys)
    export_json([{"license_key": k} for k in keys])
