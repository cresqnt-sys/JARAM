import os, json, requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:7930"
PASSWORD = os.environ.get("RAM_API_PASSWORD", "")
GROUP = None          # Try None first
INCLUDE_COOKIES = True
OUTPUT_FILE = Path("users.json")

def fetch_accounts_json():
    params = {"Password": PASSWORD, "IncludeCookies": str(INCLUDE_COOKIES).lower()}
    if GROUP: params["Group"] = GROUP
    url = f"{BASE_URL}/GetAccountsJson"
    r = requests.get(url, params=params, timeout=15)

    print(f"[DEBUG] URL: {r.url}")
    print(f"[DEBUG] Status: {r.status_code}")
    print(f"[DEBUG] Body (first 300): {r.text[:300]}")
    r.raise_for_status()

    data = r.json()
    print(f"[DEBUG] Type: {type(data)} Length: {len(data) if isinstance(data, list) else 'N/A'}")
    return data

def transform(accounts):
    out = {}
    for acc in accounts:
        print("[DEBUG] Account keys:", list(acc.keys()))
        uid = acc.get("UserID")
        if uid is None:
            print("[WARN] Skipping account with no UserID:", acc)
            continue
        fields = acc.get("Fields") or {}
        out[str(uid)] = {
            "username": acc.get("Username") or f"User_{uid}",
            "cookie": acc.get("Cookie") or "",
            "private_server_link": fields.get("SavedJobId", ""),
            "place": fields.get("SavedPlaceId", "")
        }
    return out

def main():
    accounts = fetch_accounts_json()
    if not accounts:
        print("[WARN] No accounts returned. See earlier debug info.")
    transformed = transform(accounts)
    OUTPUT_FILE.write_text(json.dumps(transformed, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {len(transformed)} accounts to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
