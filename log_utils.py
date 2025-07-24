import os
import re
import time
from pathlib import Path
from typing import Optional

# Folder that Roblox writes its client logs to
ROBLOX_LOGS_DIR = os.path.join(os.getenv("LOCALAPPDATA"), "Roblox", "logs")

# User-name marker ― exactly the same pattern detection.py relies on
_PAT_LOAD_FAIL = re.compile(r"load failed in Players\.([^.]+)\.")

# Disconnect strings that trigger an immediate restart
R_DISC_REASON  = re.compile(r"\[FLog::Network\]\s+Disconnect reason received:\s*(\d+)", re.I)
R_DISC_NOTIFY  = re.compile(r"\[FLog::Network\]\s+Disconnection Notification\.\s*Reason:\s*(\d+)", re.I)
R_DISC_SENDING = re.compile(r"\[FLog::Network\]\s+Sending disconnect with reason:\s*(\d+)", re.I)
R_CONN_LOST    = re.compile(r"\[FLog::Network\]\s+Connection lost", re.I)

# How deep to read when searching for the username marker
# (1 MiB matches detection.py’s LOG_READ_SIZE and is plenty fast)
READ_BYTES    = 1_048_576        # 1 MB
_SCAN_WINDOW  = 2 * 3600         # look at logs ≤ 2 h old
_CACHE_TTL    = 60               # rebuild map once a minute

# Internal cache { "map": {username: log_path}, "expire_at": epoch }
_CACHE: dict[str, object] = {"map": {}, "expire_at": 0.0}


def _rebuild_cache() -> None:
    """Scan recent logs and build username → newest-log mapping."""
    mapping: dict[str, str] = {}
    now = time.time()

    for path in sorted(
        Path(ROBLOX_LOGS_DIR).glob("*.log*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        if now - path.stat().st_mtime > _SCAN_WINDOW:
            break                               # past the 2 h window

        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                head = f.read(READ_BYTES)       # read up to 1 MB
        except Exception:
            continue                            # unreadable → skip

        m = _PAT_LOAD_FAIL.search(head)
        if m:
            uname = m.group(1).lower()
            # keep only the NEWEST log we encounter for each user
            mapping.setdefault(uname, str(path))

    _CACHE["map"]       = mapping
    _CACHE["expire_at"] = now + _CACHE_TTL


def find_log_for_username(
    username: str,
    *,
    allow_fallback: bool = True,
) -> Optional[str]:
    """
    Return the newest Roblox log that contains
    “load failed in Players.<username>.”.

    • If *allow_fallback* is False and no match is found, returns **None**.  
    • If *allow_fallback* is True, falls back to the newest log in the folder.
    """
    if not username:
        return None

    if time.time() > _CACHE["expire_at"]:
        _rebuild_cache()

    path = _CACHE["map"].get(username.lower())
    if path or not allow_fallback:
        return path            # exact match –or– None when fallback disabled

    # optional fallback: simply return the newest file in the folder
    try:
        newest = max(
            Path(ROBLOX_LOGS_DIR).glob("*.log*"),
            key=lambda p: p.stat().st_mtime,
        )
        return str(newest)
    except ValueError:
        return None
