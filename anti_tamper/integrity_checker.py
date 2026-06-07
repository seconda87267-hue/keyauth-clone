"""
Integrity Checker - Verifies file hashes to detect tampering

Usage:
    python integrity_checker.py check          # Check all monitored files
    python integrity_checker.py update          # Update stored hashes
    python integrity_checker.py status          # Show which files are monitored
"""
import hashlib
import json
import os
import sys
from pathlib import Path

HASH_FILE = "file_hashes.json"
MONITORED_PATTERNS = [
    "*.py", "*.exe", "*.dll", "*.so", "*.dylib",
    "*.bin", "*.sh", "*.bat", "*.ps1"
]
EXCLUDE_DIRS = {"__pycache__", ".git", "node_modules", "venv", ".venv", "build", "dist"}
BASE_DIR = Path(__file__).parent.parent


def compute_hash(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_monitored_files() -> list[Path]:
    files = []
    for pattern in MONITORED_PATTERNS:
        for f in BASE_DIR.rglob(pattern):
            if not any(excl in f.parts for excl in EXCLUDE_DIRS):
                files.append(f)
    return files


def load_hashes() -> dict:
    if not os.path.exists(HASH_FILE):
        return {}
    with open(HASH_FILE) as f:
        return json.load(f)


def save_hashes(hashes: dict):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=2, sort_keys=True)


def update_hashes():
    hashes = {}
    for fp in get_monitored_files():
        rel_path = str(fp.relative_to(BASE_DIR))
        hashes[rel_path] = compute_hash(fp)
    save_hashes(hashes)
    print(f"✓ Stored hashes for {len(hashes)} files")


def check_integrity() -> list[dict]:
    stored = load_hashes()
    if not stored:
        print("No stored hashes found. Run 'update' first.")
        return []

    violations = []
    for rel_path, stored_hash in stored.items():
        fp = BASE_DIR / rel_path
        if not fp.exists():
            violations.append({"file": rel_path, "status": "MISSING"})
            continue
        current_hash = compute_hash(fp)
        if current_hash != stored_hash:
            violations.append({
                "file": rel_path,
                "status": "MODIFIED",
                "stored": stored_hash[:16],
                "current": current_hash[:16]
            })
    return violations


def status():
    stored = load_hashes()
    if stored:
        print(f"Monitoring {len(stored)} files")
        for f in sorted(stored.keys()):
            print(f"  ✓ {f}")
    else:
        print("No hashes stored. Run 'update' first.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python integrity_checker.py [check|update|status]")
        return

    cmd = sys.argv[1].lower()
    if cmd == "update":
        update_hashes()
    elif cmd == "check":
        violations = check_integrity()
        if not violations:
            print("✓ All files intact")
        else:
            print(f"⚠ {len(violations)} integrity violation(s) found:")
            for v in violations:
                print(f"  [{v['status']}] {v['file']}")
                if v['status'] == 'MODIFIED':
                    print(f"    Stored: {v['stored']}...")
                    print(f"    Current: {v['current']}...")
    elif cmd == "status":
        status()
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
