import psutil
import os
import time
import win32gui
import win32process
import random
import requests
import json
import shutil
from pathlib import Path
from collections import defaultdict

try:
    from gui import ConfigManager
except ImportError:


    
    def limit_strap_helpers(threshold: int = 50, *, kill_all: bool = False) -> None:
        """
        Trim *-strap.exe* helpers.

        • kill_all = False  ➜ keep the **oldest** helper and terminate any
        extras once the running count reaches or exceeds *threshold*.
        • kill_all = True   ➜ terminate **every** helper.

        Pass threshold=1 to “kill all but oldest” unconditionally.
        """
        helpers = [
            p for p in psutil.process_iter(['name', 'create_time'])
            if (n := p.info['name']) and n.lower().endswith('strap.exe')
        ]
        if not helpers:
            return

        if kill_all:
            for p in helpers:
                try:
                    p.kill()
                except Exception:
                    pass
            return

        if len(helpers) < threshold:
            return                                    # nothing to trim

        helpers.sort(key=lambda p: p.info['create_time'])  # oldest first
        for p in helpers[1:]:                         # keep index-0
            try:
                p.kill()
            except Exception:
                pass


    class ConfigManager:
        def __init__(self):
            self.app_name = "JARAM"
            self.config_dir = self._get_config_directory()
            self.users_file = self.config_dir / "users.json"
            self._ensure_directories()

        def _get_config_directory(self):
            if os.name == 'nt':
                appdata = os.environ.get('APPDATA')
                if appdata:
                    return Path(appdata) / self.app_name
            return Path.home() / f".{self.app_name.lower()}"

        def _ensure_directories(self):
            try:
                self.config_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                pass
        # ── new ─────────────────────────────────────────────
        def _deep_update(self, base: dict, updates: dict):
            """Recursive dict.update so nested keys survive partial files."""
            for k, v in updates.items():
                if isinstance(v, dict) and isinstance(base.get(k), dict):
                    base[k] = self._deep_update(base[k], v)
                else:
                    base[k] = v
            return base

        def load_settings(self):
            try:
                if self.settings_file.exists():
                    with open(self.settings_file, 'r', encoding='utf-8') as f:
                        loaded = json.load(f)

                    # start from defaults, then deep-merge file content
                    settings = json.loads(json.dumps(self.default_settings))  # deep copy
                    settings = self._deep_update(settings, loaded)
                    return settings
                else:
                    return json.loads(json.dumps(self.default_settings))
            except Exception:
                return json.loads(json.dumps(self.default_settings))

# ──────────────────────────────────────────────────────────────
# 1-A. RobloxManager – strip presence monitor & shorter loop
# ──────────────────────────────────────────────────────────────
class RobloxManager:
    def __init__(self, config_manager: "ConfigManager" = None):
        # use the GUI’s instance if one is provided
        self.config_manager = config_manager or ConfigManager()
        self.settings        = self._load_settings()
        self.process_tracker = ProcessTracker()
        self.auth_handler    = AuthenticationHandler()

        # ⬇ delete: self.presence_monitor = PresenceMonitor()

        app_settings = self._load_app_settings()
        self.target_place = "15532962292"
        self.window_limit = app_settings.get("window_limit", 1)

        # presence key removed, default tick every 2 s
        self.check_intervals = {
            'window'   : 3,
            'cleanup'  : 30,
            'main_tick': 2
        }

        timeouts = app_settings.get("timeouts", {})

        self.timeouts = {
            "relaunch"     : 20,
            "launch_delay" : timeouts.get("launch_delay", 4),
            "offline"      : timeouts.get("offline",      35),
            "initial_delay": timeouts.get("initial_delay",4)
        }

        self.excluded_pid = 0
        from timeout_monitor import TimeoutMonitor   # top-level import

        tm_cfg = app_settings.get("timeout_monitor", {})
        self.timeout_monitor = TimeoutMonitor(
            kill_timeout        = tm_cfg.get("kill_timeout", 1740),
            poll_interval       = tm_cfg.get("poll_interval", 10),
            webhook_url         = tm_cfg.get("webhook_url", ""),
            ping_message        = tm_cfg.get("ping_message", "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested")
        )


    def _load_settings(self):
        try:

            if hasattr(self.config_manager, 'get_users_for_manager'):
                return self.config_manager.get_users_for_manager()   # keep ALL users

            else:
                users = self.config_manager.load_users()

            if not users:
                return {}
            return users
        except Exception as error:
            return {}

    def _load_app_settings(self):
        try:
            if hasattr(self.config_manager, 'load_settings'):
                return self.config_manager.load_settings()
            else:

                return {
                    "window_limit": 1,
                    "timeouts": {
                        "offline": 35,
                        "launch_delay": 4
                    }
                }
        except Exception as error:
            return {
                "window_limit": 1,
                "timeouts": {
                    "offline": 35,
                    "launch_delay": 4
                }
            }

class ProcessTracker:
    def __init__(self):
        self.user_processes = defaultdict(list)
        self.process_owners = {}
        self.creation_timestamps = {}
        self.protection_period = 60  
        self.initialization_mode = False  

class AuthenticationHandler:
    def __init__(self):
        self.token_cache = {}

    def retrieve_csrf_token(self, cookie):
        if cookie in self.token_cache and self.token_cache[cookie]["expires"] > time.time():
            return self.token_cache[cookie]["token"]

        session = requests.Session()
        session.cookies[".ROBLOSECURITY"] = cookie
        session.headers.update({
            "Referer": "https://www.roblox.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        try:
            response = session.post("https://auth.roblox.com/v1/authentication-ticket", timeout=5)
            if response.status_code == 403 and "x-csrf-token" in response.headers:
                token = response.headers["x-csrf-token"]
                self.token_cache[cookie] = {
                    "token": token,
                    "expires": time.time() + 1800
                }
                return token
        except Exception as error:
            pass
        return None

    def obtain_auth_ticket(self, cookie):
        session = requests.Session()
        session.headers.update({
            "Cookie": f".ROBLOSECURITY={cookie}",
            "Referer": "https://www.roblox.com/",
            "User-Agent": "Roblox/WinInet"
        })

        try:
            response = session.post("https://auth.roblox.com/v1/authentication-ticket", timeout=5)
            if response.status_code == 403 and "x-csrf-token" in response.headers:
                csrf_token = response.headers["x-csrf-token"]
                session.headers.update({
                    "X-CSRF-TOKEN": csrf_token,
                    "Content-Type": "application/json"
                })
                second_response = session.post("https://auth.roblox.com/v1/authentication-ticket", timeout=5)
                ticket = second_response.headers.get("rbx-authentication-ticket")
                if ticket:
                    return ticket
        except Exception as error:
            pass
        return None

# ──────────────────────────────────────────────────────────────
# 1-B. presence monitor class – delete the whole class
#     (PresenceMonitor … end)
# ──────────────────────────────────────────────────────────────

class ProcessManager:
    def __init__(self, excluded_pid=0):
        self.excluded_pid = excluded_pid
        self.process_name = "RobloxPlayerBeta.exe"

    def is_game_active(self):
        for process in psutil.process_iter(['name', 'pid']):
            if process.info['name'] == self.process_name and process.info['pid'] != self.excluded_pid:
                return True
        return False

    def terminate_process(self, pid=None, tracker=None):
        if pid:
            try:
                process = psutil.Process(pid)
                # (optional) protect the launcher itself
                if pid == self.excluded_pid:
                    return False
                # primary method
                rc = os.system(f"taskkill /F /PID {pid}")
                if rc != 0:              # taskkill failed – try psutil
                    process.kill()
                # … tracker-cleanup exactly as before …
                    if tracker and pid in tracker.process_owners:
                        user_id = tracker.process_owners[pid]
                        if pid in tracker.user_processes[user_id]:
                            tracker.user_processes[user_id].remove(pid)
                        del tracker.process_owners[pid]
                    if tracker and pid in tracker.creation_timestamps:
                        del tracker.creation_timestamps[pid]
                    return True
            except psutil.NoSuchProcess:
                if tracker and pid in tracker.process_owners:
                    user_id = tracker.process_owners[pid]
                    if pid in tracker.user_processes[user_id]:
                        tracker.user_processes[user_id].remove(pid)
                    del tracker.process_owners[pid]
                if tracker and pid in tracker.creation_timestamps:
                    del tracker.creation_timestamps[pid]
            return False
        else:
            terminated = False
            for process in psutil.process_iter(['pid', 'name']):
                if process.info['name'] == self.process_name and process.info['pid'] != self.excluded_pid:
                    pid = process.info['pid']
                    os.system(f"taskkill /F /PID {pid}")

                    if tracker and pid in tracker.process_owners:
                        user_id = tracker.process_owners[pid]
                        if pid in tracker.user_processes[user_id]:
                            tracker.user_processes[user_id].remove(pid)
                        del tracker.process_owners[pid]
                    if tracker and pid in tracker.creation_timestamps:
                        del tracker.creation_timestamps[pid]
                    terminated = True
            return terminated

    def count_windows_by_process(self):
        active_pids = []
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'] == self.process_name and process.info['pid'] != self.excluded_pid:
                active_pids.append(process.info['pid'])

        window_counts = defaultdict(int)

        def window_callback(hwnd, extra):
            if win32gui.IsWindowVisible(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid in active_pids:
                    window_counts[pid] += 1

        win32gui.EnumWindows(window_callback, None)
        return window_counts

    def verify_process_active(self, pid):
        try:
            process = psutil.Process(pid)
            return process.name() == self.process_name and pid != self.excluded_pid
        except psutil.NoSuchProcess:
            return False

    def await_new_process(self, user_id, launch_timestamp, timeout, tracker):
        start_time = time.time()

        while time.time() - start_time < timeout:
            for process in psutil.process_iter(['pid', 'name', 'create_time']):
                if process.info['name'] == self.process_name and process.info['pid'] != self.excluded_pid:
                    pid = process.info['pid']
                    create_time = process.info['create_time']

                    if create_time > launch_timestamp and pid not in tracker.process_owners:
                        tracker.process_owners[pid] = user_id
                        tracker.user_processes[user_id].append(pid)
                        tracker.creation_timestamps[pid] = create_time
                        return pid

            time.sleep(0.5)

        return None

    def cleanup_dead_processes(self, tracker):
        active_pids = set()
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'] == self.process_name and process.info['pid'] != self.excluded_pid:
                active_pids.add(process.info['pid'])

        dead_pids = set(tracker.process_owners.keys()) - active_pids

        for pid in dead_pids:
            user_id = tracker.process_owners[pid]
            if pid in tracker.user_processes.get(user_id, []):
                tracker.user_processes[user_id].remove(pid)
            del tracker.process_owners[pid]
            if pid in tracker.creation_timestamps:
                del tracker.creation_timestamps[pid]

    def eliminate_orphaned_processes(self, tracker, valid_users):
        eliminated = False
        current_time = time.time()

        if tracker.initialization_mode:
            return False

        for process in psutil.process_iter(['pid', 'name', 'create_time']):
            if process.info['name'] == self.process_name and process.info['pid'] != self.excluded_pid:
                pid = process.info['pid']
                process_create_time = process.info['create_time']

                if current_time - process_create_time < tracker.protection_period:
                    continue

                if pid not in tracker.process_owners:
                    self.terminate_process(pid, tracker)
                    eliminated = True
                elif tracker.process_owners[pid] not in valid_users:
                    self.terminate_process(pid, tracker)
                    eliminated = True

        return eliminated

class GameLauncher:
    def __init__(self,
                 target_place,
                 process_mgr,
                 auth_handler,
                 process_tracker,
                 config_mgr,
                 launch_delay=4,
                 initial_delay=4):
        # objects & settings we’ll need later
        self.target_place     = target_place
        self.process_manager  = process_mgr
        self.auth_handler     = auth_handler
        self.tracker          = process_tracker
        self.cfg = config_mgr

        # timing
        self.launch_delay  = launch_delay        # normal relaunch cadence
        self.initial_delay = initial_delay       # first-run staggering

        self.process_timeout = 20   # seconds to wait for a new PID after os.startfile

    def _extract_private_server_info(self, private_server_link, cookie=None):
        import re

        if not private_server_link:
            return None, None, "direct"

        pattern1 = r'roblox\.com/games/(\d+)/[^?]*\?privateServerLinkCode=([A-Za-z0-9_-]+)'
        match1 = re.search(pattern1, private_server_link)

        if match1:
            place_id = match1.group(1)
            private_code = match1.group(2)
            return place_id, private_code, "direct"

        pattern2 = r'roblox\.com/share\?code=([A-Za-z0-9_-]+)&type=Server'
        match2 = re.search(pattern2, private_server_link)

        if match2:
            share_code = match2.group(1)

            if cookie:
                resolved_place_id, resolved_link_code = self._convert_share_link(share_code, cookie)
                if resolved_place_id and resolved_link_code:
                    return resolved_place_id, resolved_link_code, "resolved"
                else:
                    return None, share_code, "share"
            else:

                return None, share_code, "share"

        return None, None, "invalid"

    def _convert_share_link(self, share_code, cookie):
        import requests
        import json

        if not share_code or not cookie:
            return None, None

        api_url = "https://apis.roblox.com/sharelinks/v1/resolve-link"

        payload = {
            "linkId": share_code,
            "linkType": "Server"
        }

        session = requests.Session()
        session.cookies[".ROBLOSECURITY"] = cookie
        session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Referer": "https://www.roblox.com/"
        })

        try:

            response = session.post(api_url, json=payload, timeout=10)

            if response.status_code == 403:

                csrf_token = response.headers.get("X-CSRF-TOKEN")
                if csrf_token:
                    session.headers["X-CSRF-TOKEN"] = csrf_token
                    response = session.post(api_url, json=payload, timeout=10)
                else:
                    return None, None

            if response.status_code == 200:
                try:
                    data = response.json()

                    invite_data = data.get("privateServerInviteData")
                    if not invite_data:
                        return None, None

                    link_code = invite_data.get("linkCode")
                    place_id = invite_data.get("placeId")

                    if link_code and place_id:
                        return str(place_id), link_code
                    else:
                        return None, None

                except json.JSONDecodeError as e:
                    return None, None
            else:
                return None, None

        except requests.exceptions.RequestException as e:
            return None, None
        except Exception as e:
            return None, None

    def start_game_session(self, user_id, cookie, user_info=None, skip_cleanup=False):
        launch_timestamp = time.time()

        private_server_link = ""
        if user_info and isinstance(user_info, dict):
            private_server_link = user_info.get("private_server_link", "")

        place_id, private_code, link_type = self._extract_private_server_info(private_server_link, cookie)

        if link_type == "share" and private_code:

            resolved_place_id, resolved_link_code = self._convert_share_link(private_code, cookie)
            if resolved_place_id and resolved_link_code:
                place_id, private_code = resolved_place_id, resolved_link_code
                link_type = "resolved"

        # ── preferred order ───────────────────────────────────────────
        # 1. place ID parsed from the private-server link
        # 2. explicit "place" value in users.json
        # 3. manager-wide default  (self.target_place)
        user_place_cfg = user_info.get("place") if isinstance(user_info, dict) else None
        target_place = place_id or user_place_cfg or self.target_place

        if private_code:

            auth_ticket = self.auth_handler.obtain_auth_ticket(cookie)
            if auth_ticket:

                browser_identifier = f"{random.randint(100000,130000)}{random.randint(100000,900000)}"
                launcher_url = f"https://assetgame.roblox.com/game/PlaceLauncher.ashx?request=RequestPrivateGame&placeId={target_place}&linkCode={private_code}"

                game_url = (
                    f"roblox-player://1/1+launchmode:play"
                    f"+gameinfo:{auth_ticket}"
                    f"+launchtime:{int(launch_timestamp * 1000)}"
                    f"+browsertrackerid:{browser_identifier}"
                    f"+placelauncherurl:{launcher_url}"
                    f"+robloxLocale:en_us+gameLocale:en_us"
                )

            else:
                self.cfg.mark_bad_cookie(user_id, True)      # persist to file
                if user_info is not None:                    # update live copy
                    user_info["bad"] = True
                    user_info["inactive_since"] = time.time()
                return False
        else:

            auth_ticket = self.auth_handler.obtain_auth_ticket(cookie)
            if auth_ticket:
                browser_identifier = f"{random.randint(100000,130000)}{random.randint(100000,900000)}"
                launcher_url = f"https://assetgame.roblox.com/game/PlaceLauncher.ashx?request=RequestGame&placeId={target_place}"

                game_url = (
                    f"roblox-player://1/1+launchmode:play"
                    f"+gameinfo:{auth_ticket}"
                    f"+launchtime:{int(launch_timestamp * 1000)}"
                    f"+browsertrackerid:{browser_identifier}"
                    f"+placelauncherurl:{launcher_url}"
                    f"+robloxLocale:en_us+gameLocale:en_us"
                )
            else:
                self.cfg.mark_bad_cookie(user_id, True)      # persist to file
                if user_info is not None:                    # update live copy
                    user_info["bad"] = True
                    user_info["inactive_since"] = time.time()
                return False
        try:

            if not skip_cleanup:
                existing_pids = self.tracker.user_processes.get(user_id, []).copy()
                if existing_pids:
                    for pid in existing_pids:
                        if pid != self.process_manager.excluded_pid:
                            self.process_manager.terminate_process(pid, self.tracker)

            os.startfile(game_url)

            new_pid = self.process_manager.await_new_process(user_id, launch_timestamp, self.process_timeout, self.tracker)
            if new_pid:
                if user_info and user_info.get("bad", False):
                    self.cfg.mark_bad_cookie(user_id, False)     # ⬅ un-flag
                    user_info["bad"] = False                   # clear RAM
                return True
            else:
                return False
        except Exception as error:
            return False

    def initialize_all_sessions(self, user_configs: dict):
        self.tracker.initialization_mode = True
        try:
            for idx, (user_id, user_info) in enumerate(user_configs.items()):
                if user_info.get("bad", False):
                    continue     # flagged → skip
                cookie = user_info.get("cookie", "") if isinstance(user_info, dict) else user_info

                # kill anything already running for that user
                for pid in self.tracker.user_processes.get(user_id, []).copy():
                    if self.process_manager.verify_process_active(pid):
                        self.process_manager.terminate_process(pid, self.tracker)

                self.start_game_session(user_id, cookie, user_info, skip_cleanup=True)

                # stagger every first-run launch except the last one
                if idx < len(user_configs) - 1:
                    time.sleep(self.initial_delay)
        finally:
            self.tracker.initialization_mode = False


# ──────────────────────────────────────────────────────────────
# 1-C. execute_main_loop – new “process-only” heartbeat
# ──────────────────────────────────────────────────────────────
def execute_main_loop():
    manager      = RobloxManager()
    process_mgr  = ProcessManager(manager.excluded_pid)
    launcher = GameLauncher(
        manager.target_place,
        process_mgr,
        manager.auth_handler,
        manager.process_tracker,
        manager.config_manager,
        launch_delay=manager.timeouts["launch_delay"],
        initial_delay=manager.timeouts["initial_delay"]
)


    # track the last launch so we honour launch_delay
    user_state = {
        uid: {"last_launch": 0,
              "user_info" : info}
        for uid, info in manager.settings.items()
    }

    # fire everything once on boot
    launcher.initialize_all_sessions(manager.settings)
    for uid in user_state:
        user_state[uid]["last_launch"] = time.time()

    # ───── main loop ─────
    tickers = {'window': 0, 'cleanup': 0}
    while True:
        now = time.time()

        # housekeeping
        if now - tickers['cleanup'] >= manager.check_intervals['cleanup']:
            process_mgr.cleanup_dead_processes(manager.process_tracker)
            process_mgr.eliminate_orphaned_processes(
                manager.process_tracker, set(manager.settings.keys())
            )
            tickers['cleanup'] = now

        if now - tickers['window'] >= manager.check_intervals['window']:
            for pid, nwin in process_mgr.count_windows_by_process().items():
                if nwin > manager.window_limit and pid != manager.excluded_pid:
                    process_mgr.terminate_process(pid, manager.process_tracker)
            tickers['window'] = now

        # check each user – if **no live PID**, relaunch
        for uid, st in user_state.items():
                        # ── strap.exe limiter (only if nothing waiting to launch) ──
            pending_restarts = any(
                (not [pid for pid in manager.process_tracker.user_processes.get(uid, [])
                    if process_mgr.verify_process_active(pid)])
                for uid in user_state
            )
            if not pending_restarts:          # queue is empty
                limit_strap_helpers(threshold=50)

            live_pids = [pid for pid in manager.process_tracker.user_processes.get(uid, [])
                         if process_mgr.verify_process_active(pid)]
            if live_pids:
                continue                                             # still running

            if now - st["last_launch"] < manager.timeouts['launch_delay']:
                continue                                             # respect delay

            cookie = st["user_info"].get("cookie", "") \
                     if isinstance(st["user_info"], dict) \
                     else st["user_info"]
            launcher.start_game_session(uid, cookie, st["user_info"])
            st["last_launch"] = now

        time.sleep(manager.check_intervals['main_tick'])

if __name__ == "__main__":
    execute_main_loop()