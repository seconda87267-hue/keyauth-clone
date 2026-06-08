import requests, json, os, hashlib, time

TOKEN = "nfp_LuoW6q5eTkKCQTvdfY9xvygenDKRMPALa55a"
SITE_ID = "899bd44d-b804-4a33-b435-46eb6c452333"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

BASE = r"C:\Users\RAJAT ROY\Documents\panel 1\0.0.0.key\keyauth-clone\server"
FUNC_DIR = os.path.join(BASE, "netlify", "functions")

SKIP_SUFFIXES = (".db", ".db-shm", ".db-wal", ".pem", ".crt", ".key")
SKIP_PREFIXES = ("__pycache__",)
SKIP_FILES = {".env", "config.py"}

def sha256_file(path):
    s = hashlib.sha256()
    with open(path, "rb") as f:
        s.update(f.read())
    return s.hexdigest()

def collect_files(base_dir, prefix=""):
    fmap = {}
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", "venv", "__pycache__")]
        for fn in files:
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, base_dir).replace(os.sep, "/")
            if fn in SKIP_FILES or fn.endswith(SKIP_SUFFIXES) or rel.startswith(SKIP_PREFIXES):
                continue
            if prefix:
                rel = prefix + rel
            fmap[rel] = sha256_file(fp)
    return fmap

print("Scanning files...")
files = collect_files(BASE)
functions = collect_files(FUNC_DIR, prefix="")

print(f"Files: {len(files)}, Functions: {len(functions)}")

# Create deploy
print("Creating deploy...")
r = requests.post(
    f"https://api.netlify.com/api/v1/sites/{SITE_ID}/deploys",
    headers=HEADERS,
    json={"files": files, "functions": functions},
)
if r.status_code not in (200, 201):
    print(f"Create deploy failed: {r.status_code}")
    print(r.text[:500])
    exit(1)

deploy = r.json()
deploy_id = deploy["id"]
req_files = deploy.get("required", [])
req_funcs = deploy.get("required_functions", [])
print(f"Deploy ID: {deploy_id}")
print(f"Need to upload {len(req_files)} files + {len(req_funcs)} functions")

# Upload files
uploaded = 0
for fpath in req_files:
    local_path = os.path.join(BASE, fpath)
    if os.path.exists(local_path):
        with open(local_path, "rb") as fh:
            data = fh.read()
        r = requests.put(
            f"https://api.netlify.com/api/v1/deploys/{deploy_id}/files/{fpath}",
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/octet-stream"},
            data=data,
        )
        if r.status_code not in (200, 201):
            print(f"  FAILED: {fpath} - {r.status_code}")
        else:
            uploaded += 1
            print(f"  OK: {fpath}")

# Upload functions
for fpath in req_funcs:
    local_path = os.path.join(FUNC_DIR, fpath)
    if os.path.exists(local_path):
        with open(local_path, "rb") as fh:
            data = fh.read()
        r = requests.put(
            f"https://api.netlify.com/api/v1/deploys/{deploy_id}/functions/{fpath}",
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/octet-stream"},
            data=data,
        )
        if r.status_code not in (200, 201):
            print(f"  FUNC FAILED: {fpath} - {r.status_code} - {r.text[:200]}")
        else:
            uploaded += 1
            print(f"  FUNC OK: {fpath}")

print(f"\nUploaded {uploaded} items")

# Lock deploy
print("Locking deploy...")
r = requests.post(
    f"https://api.netlify.com/api/v1/deploys/{deploy_id}/lock",
    headers=HEADERS,
)
if r.status_code == 200:
    print("Deploy locked successfully!")
else:
    print(f"Lock failed: {r.status_code} - {r.text[:200]}")

print(f"\nDone! Site: https://{deploy_id}--rexykeyauth-yt.netlify.app")
print("Final URL after processing: https://rexykeyauth-yt.netlify.app")
