import psutil
import os
import sys
import time
import win32gui
import win32process
import random
import requests
import json
import logging
from pathlib import Path
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('jaram.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

APP_VERSION = "1.1.1"

try:
    from gui import ConfigManager
except ImportError:

    class SettingsHandler:
        def __init__(self):
            self.application_name = "JARAM"
            self.settings_directory = self._locate_config_path()
            self.accounts_file = self.settings_directory / "users.json"
            self._create_required_folders()

        def _locate_config_path(self):
            if os.name == 'nt':
                app_data = os.environ.get('APPDATA')
                if app_data:
                    return Path(app_data) / self.application_name
            return Path.home() / f".{self.application_name.lower()}"

        def _create_required_folders(self):
            try:
                self.settings_directory.mkdir(parents=True, exist_ok=True)
            except Exception as error:
                pass

        def retrieve_user_accounts(self):
            try:
                if self.accounts_file.exists():
                    with open(self.accounts_file, 'r', encoding='utf-8') as file_handle:
                        account_data = json.load(file_handle)

                        formatted_accounts = {}
                        for account_id, account_details in account_data.items():
                            if isinstance(account_details, dict):
                                # Ensure disabled field exists with default value
                                account_copy = account_details.copy()
                                if "disabled" not in account_copy:
                                    account_copy["disabled"] = False
                                formatted_accounts[account_id] = account_copy
                            else:

                                formatted_accounts[account_id] = {
                                    "username": f"User_{account_id}",
                                    "cookie": account_details,
                                    "server_type": "private",  # Default to private for backward compatibility
                                    "private_server_link": "",
                                    "place_id": "",
                                    "disabled": False  # Default to enabled for backward compatibility
                                }
                        return formatted_accounts
                else:

                    legacy_config = Path("config.json")
                    if legacy_config.exists():
                        with open(legacy_config, 'r', encoding='utf-8') as file_handle:
                            return json.load(file_handle)
            except Exception as error:
                pass
            return {}

    ConfigManager = SettingsHandler

def limit_strap_helpers(threshold: int = 50, *, kill_all: bool = False) -> None:
    """
    Trim *-strap.exe* helpers.

    • kill_all = False  ➜ keep the **oldest** helper and terminate any
    extras once the running count reaches or exceeds *threshold*.
    • kill_all = True   ➜ terminate **every** helper.

    Pass threshold=1 to "kill all but oldest" unconditionally.
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        helpers = [
            p for p in psutil.process_iter(['name', 'create_time'])
            if (n := p.info['name']) and n.lower().endswith('strap.exe')
        ]
        if not helpers:
            return

        if kill_all:
            killed_count = 0
            for p in helpers:
                try:
                    p.kill()
                    killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug(f"Failed to kill strap helper {p.pid}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error killing strap helper {p.pid}: {e}")
            logger.info(f"Killed {killed_count} strap helpers (kill_all mode)")
            return

        if len(helpers) < threshold:
            return                                    # nothing to trim

        helpers.sort(key=lambda p: p.info['create_time'])  # oldest first
        killed_count = 0
        for p in helpers[1:]:                         # keep index-0
            try:
                p.kill()
                killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.debug(f"Failed to kill strap helper {p.pid}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error killing strap helper {p.pid}: {e}")

        if killed_count > 0:
            logger.info(f"Killed {killed_count} excess strap helpers (kept oldest)")

    except Exception as e:
        logger.error(f"Error in limit_strap_helpers: {e}")

class GameAccountOrchestrator:
    def __init__(self):
        self.settings_handler = ConfigManager()
        self.user_configurations = self._retrieve_configurations()
        self.process_monitor = ProcessWatcher()
        self.security_manager = SecurityTokenHandler()
        self.activity_tracker = UserActivityMonitor()

        application_config = self._retrieve_app_configuration()

        self.game_place_id = "15532962292"
        self.maximum_windows = application_config.get("window_limit", 1)

        self.monitoring_intervals = {
            'window_check': 5,     
            'activity_check': 3,   
            'maintenance': 45      
        }

        timeout_settings = application_config.get("timeouts", {})
        self.timeout_configuration = {
            'restart_timeout': float('inf'),
            'inactivity_limit': timeout_settings.get("offline", 35),
            'startup_delay': timeout_settings.get("launch_delay", 15)
        }

        # Process management settings
        process_management = application_config.get("process_management", {})
        self.limit_strap_processes = process_management.get("limit_strap_processes", True)

        self.protected_process_id = 0

        # Initialize timeout monitor
        from timeout_monitor import TimeoutMonitor
        tm_cfg = application_config.get("timeout_monitor", {})
        self.timeout_monitor = TimeoutMonitor(
            kill_timeout=tm_cfg.get("kill_timeout", 1740),
            poll_interval=tm_cfg.get("poll_interval", 10),
            webhook_url=tm_cfg.get("webhook_url", ""),
            ping_message=tm_cfg.get("ping_message", "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"),
            kill_timeout_disabled=tm_cfg.get("kill_timeout_disabled", False)
        )

    def _retrieve_configurations(self):
        try:

            if hasattr(self.settings_handler, 'get_users_for_manager'):
                account_list = self.settings_handler.get_users_for_manager()
            else:
                account_list = self.settings_handler.retrieve_user_accounts()

            if not account_list:
                return {}
            return account_list
        except Exception as config_error:
            return {}

    def _retrieve_app_configuration(self):
        try:
            if hasattr(self.settings_handler, 'load_settings'):
                return self.settings_handler.load_settings()
            else:

                return {
                    "window_limit": 1,
                    "timeouts": {
                        "offline": 35,
                        "launch_delay": 15
                    },
                    "process_management": {
                        "limit_strap_processes": True
                    },
                    "timeout_monitor": {
                        "kill_timeout": 1740,
                        "kill_timeout_disabled": False,
                        "poll_interval": 10,
                        "webhook_url": "",
                        "ping_message": "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"
                    }
                }
        except Exception as config_error:
            return {
                "window_limit": 1,
                "timeouts": {
                    "offline": 35,
                    "launch_delay": 15
                },
                "process_management": {
                    "limit_strap_processes": True
                },
                "timeout_monitor": {
                    "kill_timeout": 1740,
                    "kill_timeout_disabled": False,
                    "poll_interval": 10,
                    "webhook_url": "",
                    "ping_message": "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"
                }
            }

class ProcessWatcher:
    def __init__(self):
        self.account_process_mapping = defaultdict(list)
        self.process_ownership = {}
        self.process_birth_times = {}
        self.safety_window = 60
        self.startup_phase = False

        self._cached_process_data = {}
        self._last_cache_update = 0
        self._cache_validity_period = 2  

    def fetch_cached_process_info(self, executable_name="RobloxPlayerBeta.exe"):
        """Retrieve cached process data to minimize system overhead"""
        timestamp_now = time.time()
        if timestamp_now - self._last_cache_update > self._cache_validity_period:

            self._cached_process_data = {}
            try:
                for running_process in psutil.process_iter(['pid', 'name', 'create_time']):
                    if running_process.info['name'] == executable_name:
                        self._cached_process_data[running_process.info['pid']] = running_process.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            self._last_cache_update = timestamp_now
        return self._cached_process_data

class SecurityTokenHandler:
    def __init__(self):
        self.csrf_token_storage = {}

    def fetch_security_token(self, authentication_cookie):
        if authentication_cookie in self.csrf_token_storage and self.csrf_token_storage[authentication_cookie]["expiry"] > time.time():
            return self.csrf_token_storage[authentication_cookie]["token"]

        http_session = requests.Session()
        http_session.cookies[".ROBLOSECURITY"] = authentication_cookie
        http_session.headers.update({
            "Referer": "https://www.roblox.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        })

        try:
            auth_response = http_session.post("https://auth.roblox.com/v1/authentication-ticket", timeout=5)
            if auth_response.status_code == 403 and "x-csrf-token" in auth_response.headers:
                security_token = auth_response.headers["x-csrf-token"]
                self.csrf_token_storage[authentication_cookie] = {
                    "token": security_token,
                    "expiry": time.time() + 1800
                }
                return security_token
        except Exception as auth_error:
            pass
        return None

    def generate_auth_ticket(self, authentication_cookie):
        http_session = requests.Session()
        http_session.headers.update({
            "Cookie": f".ROBLOSECURITY={authentication_cookie}",
            "Referer": "https://www.roblox.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
        })

        try:
            initial_response = http_session.post("https://auth.roblox.com/v1/authentication-ticket", timeout=5)
            if initial_response.status_code == 403 and "x-csrf-token" in initial_response.headers:
                security_token = initial_response.headers["x-csrf-token"]
                http_session.headers.update({
                    "X-CSRF-TOKEN": security_token,
                    "Content-Type": "application/json"
                })
                final_response = http_session.post("https://auth.roblox.com/v1/authentication-ticket", timeout=5)
                authentication_ticket = final_response.headers.get("rbx-authentication-ticket")
                if authentication_ticket:
                    return authentication_ticket
        except Exception as ticket_error:
            pass
        return None

class UserActivityMonitor:
    def __init__(self):

        self._connection_pool = {}
        self._previous_cleanup = time.time()
        self._maintenance_frequency = 300  

        self._previous_checks = {}
        self._throttle_interval = 5  

    def _acquire_session(self, authentication_cookie):
        """Retrieve or establish HTTP session for specified cookie"""
        timestamp_current = time.time()

        if timestamp_current - self._previous_cleanup > self._maintenance_frequency:
            self._perform_session_cleanup()
            self._previous_cleanup = timestamp_current

        if authentication_cookie not in self._connection_pool:
            new_session = requests.Session()
            new_session.cookies[".ROBLOSECURITY"] = authentication_cookie
            new_session.headers.update({
                "Referer": "https://www.roblox.com/",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            })
            self._connection_pool[authentication_cookie] = {
                'session': new_session,
                'last_accessed': timestamp_current
            }
        else:
            self._connection_pool[authentication_cookie]['last_accessed'] = timestamp_current

        return self._connection_pool[authentication_cookie]['session']

    def _perform_session_cleanup(self):
        """Eliminate stale sessions to prevent memory accumulation"""
        timestamp_current = time.time()
        stale_cookies = []

        for cookie_key, session_info in self._connection_pool.items():
            if timestamp_current - session_info['last_accessed'] > self._maintenance_frequency:
                session_info['session'].close()
                stale_cookies.append(cookie_key)

        for stale_cookie in stale_cookies:
            del self._connection_pool[stale_cookie]

    def verify_user_online_status(self, account_id, authentication_cookie, security_handler):

        timestamp_now = time.time()
        if account_id in self._previous_checks:
            if timestamp_now - self._previous_checks[account_id] < self._throttle_interval:
                return None  

        self._previous_checks[account_id] = timestamp_now

        active_session = self._acquire_session(authentication_cookie)

        retry_attempts = 3
        for current_attempt in range(retry_attempts):
            try:
                security_token = security_handler.fetch_security_token(authentication_cookie)
                if not security_token:
                    return None

                active_session.headers["X-CSRF-TOKEN"] = security_token

                api_response = active_session.post(
                    "https://presence.roblox.com/v1/presence/users",
                    json={"userIds": [account_id]},
                    timeout=5
                )

                if api_response.status_code == 200:
                    response_data = api_response.json()
                    if response_data.get("userPresences"):
                        user_presence = response_data["userPresences"][0]
                        return user_presence.get("userPresenceType") == 2

                elif api_response.status_code == 403:
                    if authentication_cookie in security_handler.csrf_token_storage:
                        del security_handler.csrf_token_storage[authentication_cookie]
                    continue

                elif api_response.status_code == 429:
                    return None

                else:
                    return None

            except Exception as presence_error:
                continue

        return None

class ApplicationProcessController:
    def __init__(self, protected_process_id=0):
        self.protected_process_id = protected_process_id
        self.target_executable = "RobloxPlayerBeta.exe"
        self.strap_suffix = "strap.exe"

    def detect_active_game_instances(self, process_watcher=None):
        if process_watcher:

            cached_process_info = process_watcher.fetch_cached_process_info(self.target_executable)
            for process_id in cached_process_info:
                if process_id != self.protected_process_id:
                    return True
            return False
        else:

            for running_process in psutil.process_iter(['name', 'pid']):
                if running_process.info['name'] == self.target_executable and running_process.info['pid'] != self.protected_process_id:
                    return True
            return False

    def eliminate_process(self, process_id=None, process_watcher=None):
        if process_id:
            try:
                target_process = psutil.Process(process_id)
                if target_process.name() == self.target_executable and process_id != self.protected_process_id:
                    os.system(f"taskkill /F /PID {process_id}")

                    if process_watcher and process_id in process_watcher.process_ownership:
                        account_id = process_watcher.process_ownership[process_id]
                        if process_id in process_watcher.account_process_mapping[account_id]:
                            process_watcher.account_process_mapping[account_id].remove(process_id)
                        del process_watcher.process_ownership[process_id]
                    if process_watcher and process_id in process_watcher.process_birth_times:
                        del process_watcher.process_birth_times[process_id]
                    return True
            except psutil.NoSuchProcess:
                if process_watcher and process_id in process_watcher.process_ownership:
                    account_id = process_watcher.process_ownership[process_id]
                    if process_id in process_watcher.account_process_mapping[account_id]:
                        process_watcher.account_process_mapping[account_id].remove(process_id)
                    del process_watcher.process_ownership[process_id]
                if process_watcher and process_id in process_watcher.process_birth_times:
                    del process_watcher.process_birth_times[process_id]
            return False
        else:
            elimination_successful = False
            for running_process in psutil.process_iter(['pid', 'name']):
                if running_process.info['name'] == self.target_executable and running_process.info['pid'] != self.protected_process_id:
                    current_pid = running_process.info['pid']
                    os.system(f"taskkill /F /PID {current_pid}")

                    if process_watcher and current_pid in process_watcher.process_ownership:
                        account_id = process_watcher.process_ownership[current_pid]
                        if current_pid in process_watcher.account_process_mapping[account_id]:
                            process_watcher.account_process_mapping[account_id].remove(current_pid)
                        del process_watcher.process_ownership[current_pid]
                    if process_watcher and current_pid in process_watcher.process_birth_times:
                        del process_watcher.process_birth_times[current_pid]
                    elimination_successful = True
            return elimination_successful

    def enumerate_window_instances(self, process_watcher=None):
        if process_watcher:

            cached_process_info = process_watcher.fetch_cached_process_info(self.target_executable)
            relevant_pids = [process_id for process_id in cached_process_info.keys() if process_id != self.protected_process_id]
        else:

            relevant_pids = []
            for running_process in psutil.process_iter(['pid', 'name']):
                if running_process.info['name'] == self.target_executable and running_process.info['pid'] != self.protected_process_id:
                    relevant_pids.append(running_process.info['pid'])

        window_tallies = defaultdict(int)

        def window_enumeration_callback(window_handle, additional_data):
            if win32gui.IsWindowVisible(window_handle):
                _, associated_pid = win32process.GetWindowThreadProcessId(window_handle)
                if associated_pid in relevant_pids:
                    window_tallies[associated_pid] += 1

        win32gui.EnumWindows(window_enumeration_callback, None)
        return window_tallies

    def confirm_process_running(self, process_id):
        try:
            target_process = psutil.Process(process_id)
            return target_process.name() == self.target_executable and process_id != self.protected_process_id
        except psutil.NoSuchProcess:
            return False

    def monitor_for_new_process(self, account_id, startup_timestamp, wait_timeout, process_watcher):
        monitoring_start = time.time()

        while time.time() - monitoring_start < wait_timeout:

            process_watcher._last_cache_update = 0  
            cached_process_info = process_watcher.fetch_cached_process_info(self.target_executable)

            for process_id, process_details in cached_process_info.items():
                if process_id != self.protected_process_id:
                    process_creation_time = process_details['create_time']

                    if process_creation_time > startup_timestamp and process_id not in process_watcher.process_ownership:
                        process_watcher.process_ownership[process_id] = account_id
                        process_watcher.account_process_mapping[account_id].append(process_id)
                        process_watcher.process_birth_times[process_id] = process_creation_time
                        return process_id

            time.sleep(0.5)

        return None

    def purge_terminated_processes(self, process_watcher):

        cached_process_info = process_watcher.fetch_cached_process_info(self.target_executable)
        currently_active_pids = set(process_id for process_id in cached_process_info.keys() if process_id != self.protected_process_id)

        defunct_pids = set(process_watcher.process_ownership.keys()) - currently_active_pids

        for defunct_pid in defunct_pids:
            account_id = process_watcher.process_ownership[defunct_pid]
            if defunct_pid in process_watcher.account_process_mapping.get(account_id, []):
                process_watcher.account_process_mapping[account_id].remove(defunct_pid)
            del process_watcher.process_ownership[defunct_pid]
            if defunct_pid in process_watcher.process_birth_times:
                del process_watcher.process_birth_times[defunct_pid]

    def remove_unmanaged_processes(self, process_watcher, authorized_accounts):
        cleanup_performed = False
        timestamp_current = time.time()

        if process_watcher.startup_phase:
            return False

        cached_process_info = process_watcher.fetch_cached_process_info(self.target_executable)

        for process_id, process_details in cached_process_info.items():
            if process_id != self.protected_process_id:
                process_startup_time = process_details['create_time']

                if timestamp_current - process_startup_time < process_watcher.safety_window:
                    continue

                if process_id not in process_watcher.process_ownership:
                    self.eliminate_process(process_id, process_watcher)
                    cleanup_performed = True
                elif process_watcher.process_ownership[process_id] not in authorized_accounts:
                    self.eliminate_process(process_id, process_watcher)
                    cleanup_performed = True

        return cleanup_performed

    def limit_strap_processes(self):
        """
        Identifies all running 'strap.exe' processes, sorts them by creation time,
        and terminates all but the oldest one.
        """
        try:
            # Get all processes whose names end with 'strap.exe'
            strap_processes = []
            for process in psutil.process_iter(['name', 'create_time', 'pid']):
                try:
                    process_name = process.info['name']
                    if process_name and process_name.lower().endswith(self.strap_suffix):
                        strap_processes.append(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # If there are 1 or fewer 'strap.exe' processes, nothing to do
            if len(strap_processes) <= 1:
                return False

            # Sort the list of 'strap.exe' processes by their creation time (oldest first)
            strap_processes.sort(key=lambda p: p.info['create_time'])

            # Kill all processes except the first (oldest) one
            killed_any = False
            for process in strap_processes[1:]:  # Slice from the second element to the end
                try:
                    process.kill()
                    killed_any = True
                except psutil.NoSuchProcess:
                    # Process might have already terminated
                    pass
                except Exception:
                    # Handle other potential errors during termination
                    pass

            return killed_any
        except Exception:
            return False

class GameSessionInitiator:
    def __init__(self, destination_place, process_controller, security_handler, process_watcher):
        self.destination_place = destination_place
        self.process_controller = process_controller
        self.security_handler = security_handler
        self.process_watcher = process_watcher
        self.startup_interval = 15
        self.process_wait_timeout = 20

    def _parse_server_connection_details(self, server_link, authentication_cookie=None):
        import re

        if not server_link:
            return None, None, "standard"

        direct_pattern = r'roblox\.com/games/(\d+)/[^?]*\?privateServerLinkCode=([A-Za-z0-9_-]+)'
        direct_match = re.search(direct_pattern, server_link)

        if direct_match:
            game_place_id = direct_match.group(1)
            server_access_code = direct_match.group(2)
            return game_place_id, server_access_code, "standard"

        share_pattern = r'roblox\.com/share\?code=([A-Za-z0-9_-]+)&type=Server'
        share_match = re.search(share_pattern, server_link)

        if share_match:
            share_identifier = share_match.group(1)

            if authentication_cookie:
                resolved_game_id, resolved_access_code = self._resolve_shared_server_link(share_identifier, authentication_cookie)
                if resolved_game_id and resolved_access_code:
                    return resolved_game_id, resolved_access_code, "resolved"
                else:
                    return None, share_identifier, "shared"
            else:

                return None, share_identifier, "shared"

        return None, None, "unsupported"

    def _resolve_shared_server_link(self, share_identifier, authentication_cookie):
        import requests
        import json

        if not share_identifier or not authentication_cookie:
            return None, None

        resolution_endpoint = "https://apis.roblox.com/sharelinks/v1/resolve-link"

        request_data = {
            "linkId": share_identifier,
            "linkType": "Server"
        }

        http_session = requests.Session()
        http_session.cookies[".ROBLOSECURITY"] = authentication_cookie
        http_session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://www.roblox.com/"
        })

        try:

            api_response = http_session.post(resolution_endpoint, json=request_data, timeout=10)

            if api_response.status_code == 403:

                security_token = api_response.headers.get("X-CSRF-TOKEN")
                if security_token:
                    http_session.headers["X-CSRF-TOKEN"] = security_token
                    api_response = http_session.post(resolution_endpoint, json=request_data, timeout=10)
                else:
                    return None, None

            if api_response.status_code == 200:
                try:
                    response_content = api_response.json()

                    server_invitation_data = response_content.get("privateServerInviteData")
                    if not server_invitation_data:
                        return None, None

                    access_code = server_invitation_data.get("linkCode")
                    game_place_id = server_invitation_data.get("placeId")

                    if access_code and game_place_id:
                        return str(game_place_id), access_code
                    else:
                        return None, None

                except json.JSONDecodeError as decode_error:
                    return None, None
            else:
                return None, None

        except requests.exceptions.RequestException as request_error:
            return None, None
        except Exception as general_error:
            return None, None

    def initiate_gaming_session(self, account_id, authentication_cookie, account_details=None, bypass_cleanup=False):
        session_start_time = time.time()

        # Determine server type and connection details
        server_type = "private"  # Default to private for backward compatibility
        server_connection_link = ""
        place_id_override = None

        if account_details and isinstance(account_details, dict):
            server_type = account_details.get("server_type", "private")

            if server_type == "private":
                server_connection_link = account_details.get("private_server_link", "")
            else:  # public server
                place_id_override = account_details.get("place_id", "")

        # Handle private server logic
        game_place_id = None
        server_access_code = None
        connection_type = "standard"

        if server_type == "private" and server_connection_link:
            game_place_id, server_access_code, connection_type = self._parse_server_connection_details(server_connection_link, authentication_cookie)

            if connection_type == "shared" and server_access_code:
                # Resolve shared server link
                resolved_game_id, resolved_server_code = self._resolve_shared_server_link(server_access_code, authentication_cookie)
                if resolved_game_id and resolved_server_code:
                    game_place_id, server_access_code = resolved_game_id, resolved_server_code
                    connection_type = "resolved"

        # Determine final place ID
        if server_type == "public" and place_id_override:
            final_place_id = place_id_override
        elif game_place_id:
            final_place_id = game_place_id
        else:
            final_place_id = self.destination_place

        # Generate authentication ticket
        authentication_ticket = self.security_handler.generate_auth_ticket(authentication_cookie)
        if not authentication_ticket:
            return False

        browser_session_id = f"{random.randint(100000,130000)}{random.randint(100000,900000)}"

        # Create appropriate launcher endpoint based on server type
        if server_type == "private" and server_access_code:
            # Private server with access code
            game_launcher_endpoint = f"https://assetgame.roblox.com/game/PlaceLauncher.ashx?request=RequestPrivateGame&placeId={final_place_id}&linkCode={server_access_code}"
        else:
            # Public server (or private server without access code - fallback to public)
            game_launcher_endpoint = f"https://assetgame.roblox.com/game/PlaceLauncher.ashx?request=RequestGame&placeId={final_place_id}"

        # Create Roblox protocol URL
        roblox_protocol_url = (
            f"roblox-player://1/1+launchmode:play"
            f"+gameinfo:{authentication_ticket}"
            f"+launchtime:{int(session_start_time * 1000)}"
            f"+browsertrackerid:{browser_session_id}"
            f"+placelauncherurl:{game_launcher_endpoint}"
            f"+robloxLocale:en_us+gameLocale:en_us"
        )

        try:

            if not bypass_cleanup:
                active_process_ids = self.process_watcher.account_process_mapping.get(account_id, []).copy()
                if active_process_ids:
                    for process_id in active_process_ids:
                        if process_id != self.process_controller.protected_process_id:
                            self.process_controller.eliminate_process(process_id, self.process_watcher)

            os.startfile(roblox_protocol_url)

            spawned_process_id = self.process_controller.monitor_for_new_process(account_id, session_start_time, self.process_wait_timeout, self.process_watcher)
            if spawned_process_id:
                return True
            else:
                return False
        except Exception as launch_error:
            return False

    def bootstrap_all_gaming_sessions(self, account_configurations):
        self.process_watcher.startup_phase = True

        try:
            enabled_accounts = []
            for sequence_index, (account_id, account_details) in enumerate(account_configurations.items()):
                # Skip disabled accounts
                if isinstance(account_details, dict) and account_details.get("disabled", False):
                    continue

                enabled_accounts.append((sequence_index, account_id, account_details))

            for sequence_index, (_, account_id, account_details) in enumerate(enabled_accounts):
                authentication_cookie = account_details.get("cookie", "") if isinstance(account_details, dict) else account_details

                active_process_ids = self.process_watcher.account_process_mapping.get(account_id, []).copy()
                if active_process_ids:
                    for process_id in active_process_ids:
                        if process_id != self.process_controller.protected_process_id:
                            self.process_controller.eliminate_process(process_id, self.process_watcher)

                self.initiate_gaming_session(account_id, authentication_cookie, account_details, bypass_cleanup=True)

                if sequence_index < len(enabled_accounts) - 1:
                    time.sleep(self.startup_interval)

        finally:
            self.process_watcher.startup_phase = False

def run_primary_monitoring_loop():
    orchestrator = GameAccountOrchestrator()
    process_controller = ApplicationProcessController(orchestrator.protected_process_id)
    session_initiator = GameSessionInitiator(orchestrator.game_place_id, process_controller, orchestrator.security_manager, orchestrator.process_monitor)

    monitoring_timestamps = {
        'window_monitoring': 0,
        'session_restart': 0,
        'system_maintenance': 0,
        'orphan_elimination': 0
    }

    account_status_tracking = {account_id: {
        "previous_activity": 0,
        "inactivity_start": None,
        "account_details": account_info,
        "needs_session_restart": False
    } for account_id, account_info in orchestrator.user_configurations.items()
    if not (isinstance(account_info, dict) and account_info.get("disabled", False))}

    session_initiator.bootstrap_all_gaming_sessions(orchestrator.user_configurations)

    while True:
        timestamp_current = time.time()

        try:
            if timestamp_current - monitoring_timestamps['system_maintenance'] >= orchestrator.monitoring_intervals['maintenance']:
                process_controller.purge_terminated_processes(orchestrator.process_monitor)
                monitoring_timestamps['system_maintenance'] = timestamp_current

            if timestamp_current - monitoring_timestamps['orphan_elimination'] >= (orchestrator.monitoring_intervals['maintenance'] * 2):
                process_controller.remove_unmanaged_processes(orchestrator.process_monitor, set(orchestrator.user_configurations.keys()))

                # Limit strap processes if enabled
                if orchestrator.limit_strap_processes:
                    process_controller.limit_strap_processes()

                monitoring_timestamps['orphan_elimination'] = timestamp_current

            if timestamp_current - monitoring_timestamps['window_monitoring'] >= orchestrator.monitoring_intervals['window_check']:
                window_instance_counts = process_controller.enumerate_window_instances(orchestrator.process_monitor)

                for process_id, window_count in window_instance_counts.items():
                    if window_count > orchestrator.maximum_windows and process_id != orchestrator.protected_process_id:
                        process_controller.eliminate_process(process_id, orchestrator.process_monitor)

                monitoring_timestamps['window_monitoring'] = timestamp_current

            for account_id, status_info in account_status_tracking.items():
                authentication_cookie = status_info["account_details"].get("cookie", "") if isinstance(status_info["account_details"], dict) else status_info["account_details"]
                online_status = orchestrator.activity_tracker.verify_user_online_status(account_id, authentication_cookie, orchestrator.security_manager)

                if online_status is None:
                    continue

                if online_status:
                    account_status_tracking[account_id]["previous_activity"] = timestamp_current
                    account_status_tracking[account_id]["inactivity_start"] = None
                    account_status_tracking[account_id]["needs_session_restart"] = False
                else:
                    if account_status_tracking[account_id]["inactivity_start"] is None:
                        account_status_tracking[account_id]["inactivity_start"] = timestamp_current

                    offline_duration = timestamp_current - account_status_tracking[account_id]["inactivity_start"]
                    if offline_duration >= orchestrator.timeout_configuration['inactivity_limit']:
                        if not account_status_tracking[account_id]["needs_session_restart"]:
                            account_status_tracking[account_id]["needs_session_restart"] = True

            accounts_requiring_restart = [account_id for account_id, status_info in account_status_tracking.items()
                                        if status_info["needs_session_restart"]]

            if accounts_requiring_restart and (timestamp_current - monitoring_timestamps['session_restart']) >= orchestrator.timeout_configuration['startup_delay']:
                primary_restart_candidate = accounts_requiring_restart[0]
                candidate_status = account_status_tracking[primary_restart_candidate]

                active_process_list = []
                for process_id in orchestrator.process_monitor.account_process_mapping.get(primary_restart_candidate, []):
                    if process_controller.confirm_process_running(process_id):
                        active_process_list.append(process_id)

                if active_process_list:
                    for process_id in active_process_list:
                        process_controller.eliminate_process(process_id, orchestrator.process_monitor)

                candidate_authentication_cookie = candidate_status["account_details"].get("cookie", "") if isinstance(candidate_status["account_details"], dict) else candidate_status["account_details"]
                if session_initiator.initiate_gaming_session(primary_restart_candidate, candidate_authentication_cookie, candidate_status["account_details"]):
                    account_status_tracking[primary_restart_candidate]["inactivity_start"] = None
                    account_status_tracking[primary_restart_candidate]["needs_session_restart"] = False
                    monitoring_timestamps['session_restart'] = timestamp_current

        except Exception as monitoring_error:
            pass

        time.sleep(orchestrator.monitoring_intervals['activity_check'])

def check_for_updates_on_startup():
    """Check for updates on startup and prompt user if available."""
    try:
        print("Checking for updates...")
        from auto_updater import AutoUpdater

        updater = AutoUpdater()
        update_info = updater.check_for_updates(timeout=10)

        if update_info and update_info.get('available', False):
            latest_version = update_info.get('latest_version', 'Unknown')
            current_version = update_info.get('current_version', APP_VERSION)

            print(f"\n🎉 UPDATE AVAILABLE!")
            print(f"Current Version: {current_version}")
            print(f"Latest Version:  {latest_version}")
            print(f"Release URL: {update_info.get('release_url', 'N/A')}")

            release_notes = update_info.get('release_notes', '')
            if release_notes:
                print(f"\nRelease Notes:\n{release_notes[:200]}...")

            print("\nWould you like to download and install the update?")
            print("1. Yes - Download and install now")
            print("2. No - Continue with current version")
            print("3. Open GUI to manage update")

            while True:
                try:
                    choice = input("\nEnter your choice (1/2/3): ").strip()

                    if choice == '1':
                        download_and_install_update(updater, update_info)
                        break
                    elif choice == '2':
                        print("Continuing with current version...")
                        break
                    elif choice == '3':
                        print("Opening GUI for update management...")
                        import subprocess
                        subprocess.Popen([sys.executable, "gui.py"])
                        return False  
                    else:
                        print("Invalid choice. Please enter 1, 2, or 3.")
                except KeyboardInterrupt:
                    print("\nSkipping update check...")
                    break
        else:
            print("✅ You have the latest version")

    except Exception as e:
        print(f"⚠️  Could not check for updates: {e}")

    return True  

def download_and_install_update(updater, update_info):
    """Download and install the update."""
    try:
        download_url = update_info.get('download_url')
        if not download_url:
            print("❌ No download URL available")
            return False

        print(f"\nDownloading update from: {download_url}")

        def progress_callback(progress):
            bar_length = 30
            filled_length = int(bar_length * progress / 100)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            print(f'\rProgress: |{bar}| {progress:.1f}%', end='', flush=True)

        file_path = updater.download_update(download_url, progress_callback)
        print()  

        if file_path:
            print(f"✅ Download completed: {file_path}")

            apply_choice = input("\nApply the update now? (y/N): ").strip().lower()
            if apply_choice in ['y', 'yes']:
                print("Applying update...")
                if updater.apply_update(file_path):
                    print("✅ Update applied successfully!")
                    print("Restarting application...")

                    import subprocess
                    subprocess.Popen([sys.executable] + sys.argv)
                    sys.exit(0)
                else:
                    print("❌ Failed to apply update")
                    return False
            else:
                print(f"Update downloaded to: {file_path}")
                print("You can apply it later by running the GUI.")
        else:
            print("❌ Download failed")
            return False

    except Exception as e:
        print(f"❌ Error during update process: {e}")
        return False

    return True

if __name__ == "__main__":
    print(f"JARAM v{APP_VERSION} - Just Another Roblox Account Manager")
    print("=" * 60)

    if check_for_updates_on_startup():
        print("\nStarting main loop...")
        run_primary_monitoring_loop()