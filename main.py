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

        def load_users(self):
            try:
                if self.users_file.exists():
                    with open(self.users_file, 'r', encoding='utf-8') as f:
                        users_data = json.load(f)

                        manager_format = {}
                        for user_id, user_info in users_data.items():
                            if isinstance(user_info, dict):
                                manager_format[user_id] = user_info
                            else:

                                manager_format[user_id] = {
                                    "username": f"User_{user_id}",
                                    "cookie": user_info,
                                    "private_server_link": "",
                                    "place": ""
                                }
                        return manager_format
                else:

                    old_config_path = Path("config.json")
                    if old_config_path.exists():
                        with open(old_config_path, 'r', encoding='utf-8') as f:
                            return json.load(f)
            except Exception as e:
                pass
            return {}

class RobloxManager:
    def __init__(self):
        self.config_manager = ConfigManager()
        self.settings = self._load_settings()
        self.process_tracker = ProcessTracker()
        self.auth_handler = AuthenticationHandler()
        self.presence_monitor = PresenceMonitor()

        app_settings = self._load_app_settings()

        self.target_place = "15532962292"
        self.window_limit = app_settings.get("window_limit", 1)

        self.check_intervals = {
            'window': 3,
            'presence': 1.5,
            'cleanup': 30
        }

        timeouts = app_settings.get("timeouts", {})
        self.timeouts = {
            'relaunch': 20,  
            'offline': timeouts.get("offline", 35),
            'launch_delay': timeouts.get("launch_delay", 4)
        }

        self.excluded_pid = 0  

    def _load_settings(self):
        try:

            if hasattr(self.config_manager, 'get_users_for_manager'):
                users = self.config_manager.get_users_for_manager()
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

class PresenceMonitor:
    def __init__(self):
        pass

    def check_user_activity(self, user_id, cookie, auth_handler):
        session = requests.Session()
        session.cookies[".ROBLOSECURITY"] = cookie
        session.headers.update({
            "Referer": "https://www.roblox.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                csrf_token = auth_handler.retrieve_csrf_token(cookie)
                if not csrf_token:
                    return None

                session.headers["X-CSRF-TOKEN"] = csrf_token

                response = session.post(
                    "https://presence.roblox.com/v1/presence/users",
                    json={"userIds": [user_id]},
                    timeout=5
                )

                if response.status_code == 200:
                    data = response.json()
                    if data.get("userPresences"):
                        presence = data["userPresences"][0]
                        return presence.get("userPresenceType") == 2

                elif response.status_code == 403:
                    if cookie in auth_handler.token_cache:
                        del auth_handler.token_cache[cookie]
                    continue

                elif response.status_code == 429:
                    return None

                else:
                    return None

            except Exception as error:
                continue

        return None

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
                if process.name() == self.process_name and pid != self.excluded_pid:
                    os.system(f"taskkill /F /PID {pid}")

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
    def __init__(self, target_place, process_manager, auth_handler, tracker):
        self.target_place = target_place
        self.process_manager = process_manager
        self.auth_handler = auth_handler
        self.tracker = tracker
        self.launch_delay = 4
        self.process_timeout = 20

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

        target_place = place_id if place_id else self.target_place

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
                return True
            else:
                return False
        except Exception as error:
            return False

    def initialize_all_sessions(self, user_configs):
        self.tracker.initialization_mode = True

        try:
            for index, (user_id, user_info) in enumerate(user_configs.items()):
                cookie = user_info.get("cookie", "") if isinstance(user_info, dict) else user_info

                existing_pids = self.tracker.user_processes.get(user_id, []).copy()
                if existing_pids:
                    for pid in existing_pids:
                        if pid != self.process_manager.excluded_pid:
                            self.process_manager.terminate_process(pid, self.tracker)

                self.start_game_session(user_id, cookie, user_info, skip_cleanup=True)

                if index < len(user_configs) - 1:
                    time.sleep(self.launch_delay)

        finally:
            self.tracker.initialization_mode = False

def execute_main_loop():
    manager = RobloxManager()
    process_mgr = ProcessManager(manager.excluded_pid)
    launcher = GameLauncher(manager.target_place, process_mgr, manager.auth_handler, manager.process_tracker)

    timing_trackers = {
        'window_check': 0,
        'relaunch': 0,
        'cleanup': 0,
        'orphan_check': 0
    }

    user_states = {user_id: {
        "last_active": 0,
        "inactive_since": None,
        "user_info": user_info,
        "requires_restart": False
    } for user_id, user_info in manager.settings.items()}

    launcher.initialize_all_sessions(manager.settings)

    while True:
        current_timestamp = time.time()

        try:
            if current_timestamp - timing_trackers['cleanup'] >= manager.check_intervals['cleanup']:
                process_mgr.cleanup_dead_processes(manager.process_tracker)
                timing_trackers['cleanup'] = current_timestamp

            if current_timestamp - timing_trackers['orphan_check'] >= (manager.check_intervals['cleanup'] * 2):
                process_mgr.eliminate_orphaned_processes(manager.process_tracker, set(manager.settings.keys()))
                timing_trackers['orphan_check'] = current_timestamp

            if current_timestamp - timing_trackers['window_check'] >= manager.check_intervals['window']:
                window_counts = process_mgr.count_windows_by_process()

                for pid, count in window_counts.items():
                    if count > manager.window_limit and pid != manager.excluded_pid:
                        process_mgr.terminate_process(pid, manager.process_tracker)

                timing_trackers['window_check'] = current_timestamp

            for user_id, state in user_states.items():
                cookie = state["user_info"].get("cookie", "") if isinstance(state["user_info"], dict) else state["user_info"]
                activity_status = manager.presence_monitor.check_user_activity(user_id, cookie, manager.auth_handler)

                if activity_status is None:
                    continue

                if activity_status:
                    user_states[user_id]["last_active"] = current_timestamp
                    user_states[user_id]["inactive_since"] = None
                    user_states[user_id]["requires_restart"] = False
                else:
                    if user_states[user_id]["inactive_since"] is None:
                        user_states[user_id]["inactive_since"] = current_timestamp

                    inactive_duration = current_timestamp - user_states[user_id]["inactive_since"]
                    if inactive_duration >= manager.timeouts['offline']:
                        if not user_states[user_id]["requires_restart"]:
                            user_states[user_id]["requires_restart"] = True

            restart_candidates = [user_id for user_id, state in user_states.items()
                                if state["requires_restart"]]

            if restart_candidates and (current_timestamp - timing_trackers['relaunch']) >= manager.timeouts['launch_delay']:
                target_user = restart_candidates[0]
                target_state = user_states[target_user]

                running_pids = []
                for pid in manager.process_tracker.user_processes.get(target_user, []):
                    if process_mgr.verify_process_active(pid):
                        running_pids.append(pid)

                if running_pids:
                    for pid in running_pids:
                        process_mgr.terminate_process(pid, manager.process_tracker)

                target_cookie = target_state["user_info"].get("cookie", "") if isinstance(target_state["user_info"], dict) else target_state["user_info"]
                if launcher.start_game_session(target_user, target_cookie, target_state["user_info"]):
                    user_states[target_user]["inactive_since"] = None
                    user_states[target_user]["requires_restart"] = False
                    timing_trackers['relaunch'] = current_timestamp

        except Exception as error:
            pass

        time.sleep(manager.check_intervals['presence'])

if __name__ == "__main__":
    execute_main_loop()