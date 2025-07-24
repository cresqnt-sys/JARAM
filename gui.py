import sys
import json
import time
import os
import shutil
import requests
import psutil
import re
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QGridLayout, QTabWidget, QTableWidget,
                            QTableWidgetItem, QPushButton, QLabel, QLineEdit,
                            QSpinBox, QTextEdit, QGroupBox,QStackedLayout,
                            QProgressBar, QComboBox, QCheckBox, QSplitter,
                            QHeaderView, QMessageBox, QDialog, QDialogButtonBox,
                            QFormLayout, QScrollArea, QFrame, QSizePolicy)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt, QSize,  QBuffer, QByteArray, QIODevice, QRectF, QPointF
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter, QMovie, QRegion, QPainterPath
from main import RobloxManager, ProcessManager, GameLauncher
from cookie_extractor import CookieExtractor
from RAM_export import transform         # re-use your parsing helper
from main import limit_strap_helpers
from log_utils import find_log_for_username, R_DISC_REASON, R_DISC_NOTIFY, R_DISC_SENDING, R_CONN_LOST

def _get_icon_path():

    icon_path = "JARAM.ico"
    if os.path.exists(icon_path):
        return icon_path

    if hasattr(sys, '_MEIPASS'):
        icon_path = os.path.join(sys._MEIPASS, "JARAM.ico")
        if os.path.exists(icon_path):
            return icon_path

    script_dir = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(script_dir, "JARAM.ico")
    if os.path.exists(icon_path):
        return icon_path

    return None

class ConfigManager:

    def __init__(self):
        self.app_name = "JARAM"  
        self.config_dir = self._get_config_directory()
        self.users_file = self.config_dir / "users.json"
        self.settings_file = self.config_dir / "settings.json"
        self.backup_dir = self.config_dir / "backups"
        

        self._ensure_directories()

        self.default_settings = {
            "window_limit": 1,
            "timeouts": {
                "strap_threshold": 10,
                "offline"             : 25,   # restart-after-inactive
                "launch_delay"        : 10,    # normal relaunch cadence
                "initial_delay"       : 10,     # seconds between first-run launches
                "kill_timeout"        : 1740,  # 29m
                "poll_interval"       : 10,
                "webhook_url"         : "",     # fill in GUI
                "ping_message"        : "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging. Leave webhook empty if not interested"
            }
        }


        self.default_user_structure = {
            "username": "",
            "cookie": "",
            "private_server_link": "",
            "place": "",
            "bad": False
        }
        

    def _get_config_directory(self):
        if os.name == 'nt':  
            appdata = os.environ.get('APPDATA')
            if appdata:
                return Path(appdata) / self.app_name

        return Path.home() / f".{self.app_name.lower()}"

    def _ensure_directories(self):
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self.backup_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            pass

    def _create_backup(self, file_path):
        if not file_path.exists():
            return

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.stem}_{timestamp}.json"
            backup_path = self.backup_dir / backup_name

            shutil.copy2(file_path, backup_path)

            self._cleanup_old_backups(file_path.stem)
        except Exception as e:
            pass

    def _cleanup_old_backups(self, file_stem):
        try:
            pattern = f"{file_stem}_*.json"
            backups = sorted(self.backup_dir.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)

            for backup in backups[10:]:
                backup.unlink()
        except Exception as e:
            pass

    def _safe_write_json(self, file_path, data):
        temp_path = file_path.with_suffix('.tmp')

        try:

            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            if os.name == 'nt':  
                if file_path.exists():
                    file_path.unlink()
                temp_path.rename(file_path)
            else:
                temp_path.rename(file_path)

            return True
        except Exception as e:

            if temp_path.exists():
                temp_path.unlink()
            raise e
    # ADD this helper anywhere inside the class
    def _deep_update(self, base: dict, updates: dict):
        """Recursive dict.update so nested keys survive partial files."""
        for k, v in updates.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k] = self._deep_update(base[k], v)
            else:
                base[k] = v
        return base

    def load_users(self):
        try:
            if self.users_file.exists():
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    users_data = json.load(f)

                    return self._ensure_new_format(users_data)
            else:

                return self._migrate_old_config()
        except Exception as e:
            return {}

    def save_users(self, users_data):
        try:

            formatted_data = self._ensure_new_format(users_data)

            self._create_backup(self.users_file)

            self._safe_write_json(self.users_file, formatted_data)
            return True
        except Exception as e:
            return False

    def load_settings(self):
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)

                settings = json.loads(json.dumps(self.default_settings))  # deep copy
                settings = self._deep_update(settings, loaded)
                return settings
            else:
                return json.loads(json.dumps(self.default_settings))
        except Exception:
            return json.loads(json.dumps(self.default_settings))

    def save_settings(self, settings_data):
        try:

            self._create_backup(self.settings_file)

            self._safe_write_json(self.settings_file, settings_data)
            return True
        except Exception as e:
            return False

    def _migrate_old_config(self):
        old_config_path = Path("config.json")
        if old_config_path.exists():
            try:
                with open(old_config_path, 'r', encoding='utf-8') as f:
                    old_data = json.load(f)

                new_data = self._convert_to_new_format(old_data)

                if self.save_users(new_data):
                    return new_data
            except Exception as e:
                pass

        return {}

    def _convert_to_new_format(self, old_data):
        new_data = {}
        for user_id, cookie in old_data.items():
            if isinstance(cookie, str):

                new_data[user_id] = {
                    "username": f"User_{user_id}",  
                    "cookie": cookie,
                    "private_server_link": "",
                    "place": "",
                    "bad": False
                }
            else:

                new_data[user_id] = cookie
        return new_data

    def _ensure_new_format(self, users_data):
        if not users_data:
            return {}

        new_data = {}
        for user_id, user_info in users_data.items():
            if isinstance(user_info, str):

                new_data[user_id] = {
                    "username": f"User_{user_id}",
                    "cookie": user_info,
                    "private_server_link": "",
                    "place": ""
                }
            elif isinstance(user_info, dict):

                new_data[user_id] = {
                    "username": user_info.get("username", f"User_{user_id}"),
                    "cookie": user_info.get("cookie", ""),
                    "private_server_link": user_info.get("private_server_link", ""),
                    "place": user_info.get("place", ""),
                    "bad":  user_info.get("bad", False)
                }
            else:

                new_data[user_id] = {
                    "username": f"User_{user_id}",
                    "cookie": "",
                    "private_server_link": "",
                    "place": "",
                    "bad":  ""
                }
        return new_data

    def mark_bad_cookie(self, user_id: str, state: bool) -> None:
        users = self.load_users()
        if user_id in users and users[user_id].get("bad", False) != state:
            users[user_id]["bad"] = state
            self.save_users(users)

    def clear_all_bad_flags(self):
        users = self.load_users()
        for info in users.values():
            info["bad"] = False
        self.save_users(users)

    def get_users_for_manager(self):
        users = self.load_users()
        manager_format = {}
        for user_id, user_info in users.items():
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

    def get_config_info(self):
        return {
            "config_dir": str(self.config_dir),
            "users_file": str(self.users_file),
            "settings_file": str(self.settings_file),
            "backup_dir": str(self.backup_dir)
        }
        
    def mark_user_bad_cookie(self, user_id):
        users = self.load_users()
        if user_id in users:
            users[user_id]["bad_cookie"] = True
            self.save_users(users)

    def clear_all_bad_cookies(self):
        users = self.load_users()
        for user in users.values():
            user["bad_cookie"] = False
        self.save_users(users)


class ModernStyle:
    BACKGROUND = "#1e1e1e"
    SURFACE = "#2d2d2d"
    SURFACE_VARIANT = "#3d3d3d"
    PRIMARY = "#6366f1"
    PRIMARY_VARIANT = "#4f46e5"
    SECONDARY = "#10b981"
    ERROR = "#ef4444"
    WARNING = "#f59e0b"
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#a1a1aa"
    BORDER = "#404040"

    @staticmethod
    def get_stylesheet():
        return f"""
        QMainWindow {{
            background-color: {ModernStyle.BACKGROUND};
            color: {ModernStyle.TEXT_PRIMARY};
        }}

        QWidget {{
            background-color: {ModernStyle.BACKGROUND};
            color: {ModernStyle.TEXT_PRIMARY};
            font-family: 'Segoe UI', Arial, sans-serif;
        }}

        QTabWidget::pane {{
            border: 1px solid {ModernStyle.BORDER};
            background-color: {ModernStyle.SURFACE};
            border-radius: 8px;
        }}

        QTabBar::tab {{
            background-color: {ModernStyle.SURFACE_VARIANT};
            color: {ModernStyle.TEXT_SECONDARY};
            padding: 12px 20px;
            margin-right: 2px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
        }}

        QTabBar::tab:selected {{
            background-color: {ModernStyle.PRIMARY};
            color: {ModernStyle.TEXT_PRIMARY};
        }}

        QTableWidget {{
            background-color: {ModernStyle.SURFACE};
            border: 1px solid {ModernStyle.BORDER};
            border-radius: 8px;
            gridline-color: {ModernStyle.BORDER};
            selection-background-color: {ModernStyle.PRIMARY_VARIANT};
        }}

        QTableWidget::item {{
            padding: 8px;
            border-bottom: 1px solid {ModernStyle.BORDER};
        }}

        QHeaderView::section {{
            background-color: {ModernStyle.SURFACE_VARIANT};
            color: {ModernStyle.TEXT_PRIMARY};
            padding: 10px;
            border: none;
            font-weight: bold;
        }}

        QPushButton {{
            background-color: {ModernStyle.PRIMARY};
            color: {ModernStyle.TEXT_PRIMARY};
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 500;
            min-width: 80px;
            min-height: 28px;
            font-size: 13px;
        }}

        QPushButton:hover {{
            background-color: {ModernStyle.PRIMARY_VARIANT};
        }}

        QPushButton:pressed {{
            background-color: 
        }}

        QPushButton:disabled {{
            background-color: {ModernStyle.SURFACE_VARIANT};
            color: {ModernStyle.TEXT_SECONDARY};
        }}

        QPushButton.success {{
            background-color: {ModernStyle.SECONDARY};
        }}

        QPushButton.success:hover {{
            background-color: 
        }}

        QPushButton.danger {{
            background-color: {ModernStyle.ERROR};
        }}

        QPushButton.danger:hover {{
            background-color: 
        }}

        QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
            background-color: {ModernStyle.SURFACE};
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 6px;
            padding: 8px 12px;
            color: {ModernStyle.TEXT_PRIMARY};
        }}

        QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
            border-color: {ModernStyle.PRIMARY};
        }}

        QTextEdit {{
            background-color: {ModernStyle.SURFACE};
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 6px;
            padding: 8px;
            color: {ModernStyle.TEXT_PRIMARY};
        }}

        QGroupBox {{
            font-weight: bold;
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
        }}

        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px 0 8px;
            color: {ModernStyle.TEXT_PRIMARY};
        }}

        QLabel {{
            color: {ModernStyle.TEXT_PRIMARY};
        }}

        QProgressBar {{
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 6px;
            text-align: center;
            background-color: {ModernStyle.SURFACE};
        }}

        QProgressBar::chunk {{
            background-color: {ModernStyle.PRIMARY};
            border-radius: 4px;
        }}

        QCheckBox {{
            color: {ModernStyle.TEXT_PRIMARY};
            spacing: 8px;
        }}

        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {ModernStyle.BORDER};
            border-radius: 4px;
            background-color: {ModernStyle.SURFACE};
        }}

        QCheckBox::indicator:checked {{
            background-color: {ModernStyle.PRIMARY};
            border-color: {ModernStyle.PRIMARY};
        }}
        
        QCheckBox::indicator:disabled {{
            background-color: {ModernStyle.SURFACE};
            border-color: {ModernStyle.SURFACE};
        }}

        QScrollBar:vertical {{
            background-color: {ModernStyle.SURFACE};
            width: 12px;
            border-radius: 6px;
        }}

        QScrollBar::handle:vertical {{
            background-color: {ModernStyle.SURFACE_VARIANT};
            border-radius: 6px;
            min-height: 20px;
        }}

        QScrollBar::handle:vertical:hover {{
            background-color: {ModernStyle.BORDER};
        }}
        """

class WorkerThread(QThread):
    log_signal     = pyqtSignal(str)
    status_signal  = pyqtSignal(dict)
    process_signal = pyqtSignal(dict)

    def __init__(self, cfg_manager):
        super().__init__()
        self.cfg_manager      = cfg_manager
        self.running          = False
        self.manager          = None
        self.process_mgr      = None
        self.launcher         = None
        self.user_states      = {}
        self.log_pointers     = {}      #  NEW  {uid: last_byte_read}
        self.timing_trackers  = {}

        # thread-local mirrors (set after manager loads)
        self.restart_threshold = 0
        self.strap_threshold = 50
        self.initial_delay     = 0
        
        self._last_proc_count = 0
        self._last_growth_ts  = time.time()
        
        self.log_inactivity_timeout = 120      # seconds (2 min)

    def _trace(self, uid: str, msg: str, *, every: float = 30.0) -> None:
        """
        Emit at most one identical trace per user every *every* seconds.
        Grouping key = (uid, first word of msg).
        """
        now = time.time()
        key = (uid, msg.split()[0])               # e.g., (“8735…”, “read”)
        if not hasattr(self, "_trace_ts"):
            self._trace_ts = {}
        last = self._trace_ts.get(key, 0.0)

        if now - last >= every:
            self.log_signal.emit(f"[SCAN-TRACE] {uid}: {msg}")
            self._trace_ts[key] = now

    def _log(self, msg: str):
        """Thread-safe logger → GUI Logs tab."""
        self.log_signal.emit(msg)

    def initialize_manager(self) -> bool:
        try:
            self.manager = RobloxManager(config_manager=self.cfg_manager)

            self.manager.timeout_monitor.start()
            
            self.restart_threshold = self.manager.timeouts["offline"]
            self.initial_delay     = self.manager.timeouts["initial_delay"]

            self.process_mgr = ProcessManager(self.manager.excluded_pid)
            self.launcher = GameLauncher(
                self.manager.target_place,
                self.process_mgr,
                self.manager.auth_handler,
                self.manager.process_tracker,
                self.manager.config_manager,
                launch_delay = self.manager.timeouts["launch_delay"],
                initial_delay= self.manager.timeouts["initial_delay"]
            )

            now = time.time()
            while not self.manager.timeout_monitor.msg_q.empty():
                self.log_signal.emit(self.manager.timeout_monitor.msg_q.get_nowait())
            self.user_states = {
                uid: {
                    "last_active"    : now,
                    "inactive_since" : None,
                    "user_info"      : info,
                    "requires_restart": False,
                    "status"         : "Initializing"
                } for uid, info in self.manager.settings.items()
            }
            for uid, info in self.manager.settings.items():
                username = info.get("username") if isinstance(info, dict) else None
                log_path = find_log_for_username(username, allow_fallback=False)
                if log_path and os.path.isfile(log_path):
                    self.log_pointers[uid] = os.path.getsize(log_path)
                else:
                    self.log_pointers[uid] = 0


            self.timing_trackers = {
                'window'  : 0,
                'cleanup' : 0,
                'relaunch': 0
            }
            return True
        except Exception as e:
            self.log_signal.emit(f"Manager init failed: {e}")
            return False

    def apply_new_settings(self, cfg: dict):
        if not self.manager:
            return
        self.manager.window_limit               = cfg["window_limit"]
        self.manager.timeouts["launch_delay"]   = cfg["timeouts"]["launch_delay"]
        self.manager.timeouts["offline"]        = cfg["timeouts"]["offline"]
        self.manager.timeouts["initial_delay"]  = cfg["timeouts"]["initial_delay"]
        self.strap_threshold = cfg["timeouts"].get("strap_threshold", 50)

        
        tm = cfg["timeout_monitor"]
        self.manager.timeout_monitor.kill_timeout        = tm["kill_timeout"]
        self.manager.timeout_monitor.poll_interval       = tm["poll_interval"]
        self.manager.timeout_monitor.webhook_url         = tm["webhook_url"]
        self.manager.timeout_monitor.ping_message        = tm["ping_message"]

        self.restart_threshold = cfg["timeouts"]["offline"]
        self.initial_delay     = cfg["timeouts"]["initial_delay"]

        if self.launcher:
            self.launcher.launch_delay  = cfg["timeouts"]["launch_delay"]
            self.launcher.initial_delay = cfg["timeouts"]["initial_delay"]



    def restart_user_session(self, user_id):
        if not self.manager or user_id not in self.user_states:
            return False

        try:
            state = self.user_states[user_id]

            for pid in self.manager.process_tracker.user_processes.get(user_id, []):
                if self.process_mgr.verify_process_active(pid):
                    self.process_mgr.terminate_process(pid, self.manager.process_tracker)

            cookie = state["user_info"].get("cookie", "") if isinstance(state["user_info"], dict) else state["user_info"]
            try:
                if self.launcher.start_game_session(user_id, cookie, state["user_info"]):
                    self.user_states[user_id]["inactive_since"] = None
                    self.user_states[user_id]["requires_restart"] = False
                    self.user_states[user_id]["status"] = "Restarting"
                    return True
                else:
                    return False
            except Exception as e:
                return False
        except Exception as e:
            return False

    def kill_user_processes(self, user_id: str) -> bool:
        if not self.manager or user_id not in self.user_states:
            return False

        try:
            for pid in self.manager.process_tracker.user_processes.get(user_id, []).copy():
                # always attempt to kill – even if verify() says it's gone or renamed
                self.process_mgr.terminate_process(pid, self.manager.process_tracker)
            return True
        except Exception:
            return False


    def kill_all_processes(self):
        if not self.process_mgr:
            return False

        try:
            killed = self.process_mgr.terminate_process(None, self.manager.process_tracker)
            return killed
        except Exception as e:
            return False

    def cleanup_dead_processes(self):
        if not self.process_mgr:
            return False

        try:
            self.process_mgr.cleanup_dead_processes(self.manager.process_tracker)
            return True
        except Exception as e:
            return False

    def run(self):
        if not self.initialize_manager():
            return

        self.running = True

        # one-by-one first launch
        self.launcher.initialize_all_sessions(self.manager.settings)

        while self.running:
            now = time.time()

            # -- housekeeping
            if now - self.timing_trackers['cleanup'] >= self.manager.check_intervals['cleanup']:
                self.process_mgr.cleanup_dead_processes(self.manager.process_tracker)
                self.timing_trackers['cleanup'] = now

            if now - self.timing_trackers['window'] >= self.manager.check_intervals['window']:
                for pid, nwin in self.process_mgr.count_windows_by_process().items():
                    if nwin > self.manager.window_limit and pid != self.manager.excluded_pid:
                        self.process_mgr.terminate_process(pid, self.manager.process_tracker)
                self.timing_trackers['window'] = now
            
            # ── low-count watchdog ───────────────────────────────────────────
            STUCK_TIMEOUT = 300        # seconds without growth  → action (5 min)

            total_users = len(self.manager.settings)

            active_processes = sum(
                1
                for p in psutil.process_iter(['name', 'pid'])
                if p.info['name'] == 'RobloxPlayerBeta.exe'
                and p.info['pid'] != self.manager.excluded_pid
            )

            # reset timer whenever the process count grows
            if active_processes > self._last_proc_count:
                self._last_proc_count = active_processes
                self._last_growth_ts  = now
            else:
                self._last_proc_count = active_processes

            # condition met: fewer PIDs than users **and** no growth for ≥ STUCK_TIMEOUT
            if active_processes < total_users and (now - self._last_growth_ts) >= STUCK_TIMEOUT:
                # Trim helpers but preserve the single oldest instance
                limit_strap_helpers(threshold=1, kill_all=False)
                self._last_growth_ts = now    # restart the timer


            # -- per-user heartbeat ----------------------------------------
            status = {}
            kill_t = self.manager.timeout_monitor.kill_timeout

            for uid, st in self.user_states.items():

                # ── 1. bad-cookie rows stay, but never launch ───────────────
                if st["user_info"].get("bad", False):
                    st["status"] = "Bad"

                    # make a minimal row so the GUI can display it
                    status[uid] = {
                        "status"        : "Bad",
                        "pids"          : [],          # none running
                        "needs_restart" : False,
                        "last_active"   : st["last_active"],
                        "inactive_since": st["inactive_since"],
                        "ttl"           : []
                    }
                    continue                           # skip launch / restart logic # do NOT manage this account
                live = [
                    pid for pid in self.manager.process_tracker.user_processes.get(uid, [])
                    if self.process_mgr.verify_process_active(pid)
                ]
                
                # ── instant disconnect detection ─────────────────────────────
                uname     = str(st.get("user_info", {}).get("username", "")).lower()
                log_path  = find_log_for_username(uname, allow_fallback=False)
                disconnect_code = None         # will hold “276”, “17”, etc.

                if not live:
                    self._trace(uid, "skip — no live proc")
                elif not log_path or not os.path.isfile(log_path):
                    self._trace(uid, f"skip — log not found ({log_path})")
                else:
                    try:
                        last_pos   = self.log_pointers.get(uid, 0)
                        current_sz = os.path.getsize(log_path)

                        # log rotated? → start scanning from END to avoid old lines
                        if current_sz < last_pos:
                            last_pos = current_sz

                        # read only new bytes
                        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(last_pos)
                            chunk = f.read()

                        self.log_pointers[uid] = current_sz
                        if chunk:
                            self._trace(uid, f"read {len(chunk)} bytes")

                            for line in chunk.splitlines():
                                # ── skip chat-relay lines like
                                #    “… Incoming MessageReceived … Text: [FLog::Network] …”
                                pos_net = line.lower().find("[flog::network]")
                                pos_txt = line.lower().find("text:")

                                if pos_txt != -1 and pos_txt < pos_net:
                                    continue          # embedded quote – not a genuine network log

                                # --- genuine disconnect markers ---------------------------------
                                if   (m := R_DISC_REASON.search(line)) \
                                or (m := R_DISC_NOTIFY.search(line)) \
                                or (m := R_DISC_SENDING.search(line)):
                                    disconnect_code = m.group(1)
                                    break
                                elif R_CONN_LOST.search(line):
                                    disconnect_code = "unknown"
                                    break
                            if disconnect_code is not None:
                                self.log_signal.emit(
                                    f"⚠️  {uname} disconnect detected (reason {disconnect_code}) – terminating process"
                                )
                                self.kill_user_processes(uid)
                                st["requires_restart"] = True

                    except Exception as e:
                        self._trace(uid, f"log scan error: {e}")

                # ----- TTL list (for display) -----------------------------
                ttl_list = []
                for pid in live:
                    ct  = self.manager.process_tracker.creation_timestamps.get(pid, now)
                    ttl = max(0, int(kill_t - (now - ct)))
                    ttl_list.append(ttl)

                # ----- state machine --------------------------------------
                if live:                                        # client running
                    st["last_active"]     = now
                    st["inactive_since"]  = None
                    st["requires_restart"]= False
                    st["status"]          = "Active"
                else:                                           # all windows gone
                    if st["inactive_since"] is None:
                        st["inactive_since"] = now
                    idle = now - st["inactive_since"]
                    st["status"] = f"Inactive ({int(idle)} s)"
                    if idle >= self.restart_threshold:
                        st["requires_restart"] = True

                # ----- row sent to GUI ------------------------------------
                status[uid] = {
                    "status"        : st["status"],
                    "pids"          : live,
                    "needs_restart" : st["requires_restart"],
                    "last_active"   : st["last_active"],
                    "inactive_since": st["inactive_since"],
                    "ttl"           : ttl_list

                }

            self.status_signal.emit(status)

            # 1️⃣  build a dict:  pid -> {user_id, created, windows}
            proc_info = {}
            for uid, pids in self.manager.process_tracker.user_processes.items():
                for pid in pids:
                    if not self.process_mgr.verify_process_active(pid):
                        continue
                    created = datetime.fromtimestamp(
                        self.manager.process_tracker.creation_timestamps.get(pid, time.time())
                    ).strftime("%H:%M:%S")
                    windows = self.process_mgr.count_windows_by_process().get(pid, 0)
                    proc_info[pid] = {
                        "user_id": uid,
                        "created": created,
                        "windows": windows,
                    }

            # 2️⃣  notify the GUI
            self.process_signal.emit(proc_info)

            # auto-restart oldest candidate
            restartables = [
                u for u, s in self.user_states.items()
                if s["requires_restart"] and not s["user_info"].get("bad", False)            
]
            if restartables and (now - self.timing_trackers['relaunch']) >= self.manager.timeouts["launch_delay"]:
                uid   = restartables[0]
                info  = self.user_states[uid]["user_info"]
                cookie = info.get("cookie", "") if isinstance(info, dict) else info
                self.launcher.start_game_session(uid, cookie, info)
                self.user_states[uid]["inactive_since"] = None
                self.user_states[uid]["requires_restart"] = False
                self.user_states[uid]["status"] = "Restarting"
                self.timing_trackers['relaunch'] = now
                
                            # ── strap.exe limiter (queue empty) ───────────────────────
            if not restartables:
                limit_strap_helpers(threshold=self.strap_threshold)
            time.sleep(self.manager.check_intervals['main_tick'])

    def stop(self):
        if self.manager and self.manager.timeout_monitor:
            self.manager.timeout_monitor.stop()
        self.running = False

class UserManagementDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("User Account Management")
        self.setModal(True)

        self.resize(1400, 850)
        self.setMinimumSize(1200, 700)
        self.config_manager = ConfigManager()
        self.cookie_extractor = CookieExtractor(self)
        self.selected_user_id = None
        self.setup_ui()
        self.load_users()
        self.skip_private_server_warning = False      # session-only


    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setChildrenCollapsible(False)

        left_panel = self._create_user_list_panel()
        main_splitter.addWidget(left_panel)

        right_panel = self._create_user_form_panel()
        main_splitter.addWidget(right_panel)

        main_splitter.setSizes([980, 420])
        main_layout.addWidget(main_splitter)

        controls_layout = self._create_controls_layout()
        main_layout.addLayout(controls_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.save_and_close)
        button_box.rejected.connect(self.reject)
        main_layout.addWidget(button_box)

    def _create_user_list_panel(self):
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 10, 0)

        header_label = QLabel("User Accounts")
        header_label.setStyleSheet(f"""
            QLabel {{
                font-size: 16px;
                font-weight: bold;
                color: {ModernStyle.TEXT_PRIMARY};
                padding: 10px 0;
                border-bottom: 2px solid {ModernStyle.PRIMARY};
            }}
        """)
        panel_layout.addWidget(header_label)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet(f"""
            QScrollArea {{
                border: 1px solid {ModernStyle.BORDER};
                border-radius: 8px;
                background-color: {ModernStyle.SURFACE};
            }}
        """)

        self.user_list_widget = QWidget()
        self.user_list_layout = QVBoxLayout(self.user_list_widget)
        self.user_list_layout.setSpacing(8)
        self.user_list_layout.setContentsMargins(15, 15, 15, 15)

        scroll_area.setWidget(self.user_list_widget)
        panel_layout.addWidget(scroll_area)

        return panel

    def _create_user_form_panel(self):
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(10, 0, 0, 0)

        self.form_header = QLabel("Add New User")
        self.form_header.setStyleSheet(f"""
            QLabel {{
                font-size: 16px;
                font-weight: bold;
                color: {ModernStyle.TEXT_PRIMARY};
                padding: 10px 0;
                border-bottom: 2px solid {ModernStyle.SECONDARY};
            }}
        """)
        panel_layout.addWidget(self.form_header)

        form_container = QWidget()
        form_container.setStyleSheet(f"""
            QWidget {{
                background-color: {ModernStyle.BACKGROUND};
                border: 1px solid {ModernStyle.SURFACE};
                border-radius: 8px;
                padding: 15px;
            }}
        """)
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(12)

        self.user_id_input = QLineEdit()
        self.user_id_input.setPlaceholderText("Enter user ID (e.g., 123456789)")
        self.user_id_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(QLabel("User ID:"))
        form_layout.addWidget(self.user_id_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username (e.g., PlayerName)")
        self.username_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(QLabel("Username:"))
        form_layout.addWidget(self.username_input)

        self.private_server_input = QLineEdit()
        self.private_server_input.setPlaceholderText("Enter private server link (recommended)")
        self.private_server_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(QLabel("Private Server Link:"))
        form_layout.addWidget(self.private_server_input)

        self.place_input = QLineEdit()
        self.place_input.setPlaceholderText("Enter place ID")
        self.place_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(QLabel("Place:"))
        form_layout.addWidget(self.place_input)

        form_layout.addWidget(QLabel("Cookie:"))
        cookie_layout = QHBoxLayout()
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("Enter .ROBLOSECURITY cookie")
        self.cookie_input.setStyleSheet(self._get_input_style())
        cookie_layout.addWidget(self.cookie_input)

        self.browser_login_btn = QPushButton("Login with Browser")
        self.browser_login_btn.setStyleSheet(self._get_secondary_button_style())
        self.browser_login_btn.setToolTip("Open browser to login and automatically extract cookie")
        self.browser_login_btn.clicked.connect(self.extract_cookie_from_browser)
        cookie_layout.addWidget(self.browser_login_btn)
        form_layout.addLayout(cookie_layout)

        button_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add User")
        self.add_btn.setStyleSheet(self._get_primary_button_style())
        self.add_btn.clicked.connect(self.add_user)
        button_layout.addWidget(self.add_btn)

        self.update_btn = QPushButton("Update User")
        self.update_btn.setStyleSheet(self._get_primary_button_style())
        self.update_btn.clicked.connect(self.update_user)
        self.update_btn.hide()  
        button_layout.addWidget(self.update_btn)

        self.cancel_edit_btn = QPushButton("Cancel Edit")
        self.cancel_edit_btn.setStyleSheet(self._get_secondary_button_style())
        self.cancel_edit_btn.clicked.connect(self.cancel_edit)
        self.cancel_edit_btn.hide()  
        button_layout.addWidget(self.cancel_edit_btn)

        form_layout.addLayout(button_layout)
        panel_layout.addWidget(form_container)
        panel_layout.addStretch()

        return panel

    def _create_controls_layout(self):
        controls_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh List")
        refresh_btn.setStyleSheet(self._get_secondary_button_style())
        refresh_btn.clicked.connect(self.refresh_user_list)
        controls_layout.addWidget(refresh_btn)

        controls_layout.addStretch()

        return controls_layout

    def _get_input_style(self):
        return f"""
            QLineEdit {{
                background-color: {ModernStyle.SURFACE};
                border: 2px solid {ModernStyle.BORDER};
                border-radius: 6px;
                padding: 10px 12px;
                color: {ModernStyle.TEXT_PRIMARY};
                font-size: 13px;
                min-height: 20px;
            }}
            QLineEdit:focus {{
                border-color: {ModernStyle.PRIMARY};
            }}
        """

    def _get_primary_button_style(self):
        return f"""
            QPushButton {{
                background-color: {ModernStyle.PRIMARY};
                color: {ModernStyle.TEXT_PRIMARY};
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
                min-height: 20px;
                min-width: 100px;
            }}
            QPushButton:hover {{
                background-color: {ModernStyle.PRIMARY_VARIANT};
            }}
            QPushButton:pressed {{
                background-color: 
            }}
        """

    def _get_secondary_button_style(self):
        return f"""
            QPushButton {{
                background-color: {ModernStyle.SURFACE_VARIANT};
                color: {ModernStyle.TEXT_PRIMARY};
                border: 1px solid {ModernStyle.BORDER};
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: 500;
                font-size: 13px;
                min-height: 20px;
                min-width: 100px;
            }}
            QPushButton:hover {{
                background-color: {ModernStyle.BORDER};
            }}
        """

    def _get_action_button_style(self, color_type="primary"):
        if color_type == "danger":
            bg_color = ModernStyle.ERROR
            hover_color = "#dc2626"
            pressed_color = "#b91c1c"
        else:
            bg_color = ModernStyle.PRIMARY
            hover_color = ModernStyle.PRIMARY_VARIANT
            pressed_color = "#3730a3"

        return f"""
            QPushButton {{
                background-color: {bg_color};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: 600;
                font-size: 12px;
                min-width: 70px;
                max-width: 80px;
                min-height: 30px;
                max-height: 32px;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:pressed {{
                background-color: {pressed_color};
            }}
        """

    def load_users(self):
        try:
            self.original_config = self.config_manager.load_users()
            self.refresh_user_list()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load users: {e}")
            self.original_config = {}
            self.refresh_user_list()

    def refresh_user_list(self):

        for i in reversed(range(self.user_list_layout.count())):
            child = self.user_list_layout.itemAt(i).widget()
            if child:
                child.setParent(None)

        for user_id, user_info in self.original_config.items():
            user_card = self._create_user_card(user_id, user_info)
            self.user_list_layout.addWidget(user_card)

        self.user_list_layout.addStretch()

    def _create_user_card(self, user_id, user_info):
        card = QWidget()
        card.setStyleSheet(f"""
            QWidget {{
                background-color: {ModernStyle.SURFACE_VARIANT};
                border: 1px solid {ModernStyle.BORDER};
                border-radius: 8px;
                padding: 12px;
                margin: 2px;
            }}
            QWidget:hover {{
                border-color: {ModernStyle.PRIMARY};
                background-color: {ModernStyle.SURFACE};
            }}
        """)

        card.setMinimumHeight(100)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        layout = QVBoxLayout(card)
        layout.setSpacing(6)
        layout.setContentsMargins(8, 8, 8, 8)

        if isinstance(user_info, dict):
            username = user_info.get("username", f"User_{user_id}")
            private_server_link = user_info.get("private_server_link", "")
            place = user_info.get("place", "")
            cookie = user_info.get("cookie", "")
        else:
            username = f"User_{user_id}"
            private_server_link = ""
            place = ""
            cookie = user_info

        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)

        user_id_label = QLabel(f"ID: {user_id}")
        user_id_label.setStyleSheet(f"""
            QLabel {{
                font-weight: bold;
                font-size: 14px;
                color: {ModernStyle.PRIMARY};
                margin: 0px;
                padding: 0px;
            }}
        """)
        user_id_label.setWordWrap(True)
        header_layout.addWidget(user_id_label)

        username_label = QLabel(f"User: {username}")
        username_label.setStyleSheet(f"""
            QLabel {{
                font-size: 12px;
                color: {ModernStyle.TEXT_PRIMARY};
                font-weight: 500;
                margin: 0px;
                padding: 0px;
            }}
        """)
        username_label.setWordWrap(True)
        header_layout.addWidget(username_label)

        layout.addLayout(header_layout)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        if place:
            place_label = QLabel(f"Place: {place}")
            place_label.setStyleSheet(f"""
                QLabel {{
                    color: {ModernStyle.TEXT_SECONDARY};
                    font-size: 11px;
                    margin: 0px;
                    padding: 0px;
                }}
            """)
            place_label.setWordWrap(True)
            info_layout.addWidget(place_label)

        if private_server_link:

            if "roblox.com/share" in private_server_link:
                server_text = "Share Link: " + private_server_link.split("?")[1][:25] + "..."
            elif len(private_server_link) > 35:
                server_text = "Server: " + private_server_link[:35] + "..."
            else:
                server_text = f"Server: {private_server_link}"

            server_label = QLabel(server_text)
            server_label.setStyleSheet(f"""
                QLabel {{
                    color: {ModernStyle.TEXT_SECONDARY};
                    font-size: 11px;
                    margin: 0px;
                    padding: 0px;
                }}
            """)
            server_label.setWordWrap(True)
            server_label.setToolTip(private_server_link)  
            info_layout.addWidget(server_label)

        layout.addLayout(info_layout)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(6)
        button_layout.setContentsMargins(0, 4, 0, 0)

        edit_btn = QPushButton("Edit")
        edit_btn.setStyleSheet(self._get_action_button_style("primary"))
        edit_btn.clicked.connect(lambda: self.edit_user_card(user_id))
        button_layout.addWidget(edit_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.setStyleSheet(self._get_action_button_style("danger"))
        delete_btn.clicked.connect(lambda: self.delete_user_by_id(user_id))
        button_layout.addWidget(delete_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        return card

    def edit_user_card(self, user_id):
        if user_id not in self.original_config:
            QMessageBox.warning(self, "Error", f"User {user_id} not found!")
            return

        self.selected_user_id = user_id
        self.form_header.setText(f"Edit User {user_id}")

        user_info = self.original_config[user_id]
        if isinstance(user_info, dict):
            self.user_id_input.setText(user_id)
            self.user_id_input.setEnabled(False)  
            self.username_input.setText(user_info.get("username", f"User_{user_id}"))
            self.private_server_input.setText(user_info.get("private_server_link", ""))
            self.place_input.setText(user_info.get("place", ""))
            self.cookie_input.setText(user_info.get("cookie", ""))
        else:
            self.user_id_input.setText(user_id)
            self.user_id_input.setEnabled(False)
            self.username_input.setText(f"User_{user_id}")
            self.private_server_input.setText("")
            self.place_input.setText("")
            self.cookie_input.setText(user_info)

        self.add_btn.hide()
        self.update_btn.show()
        self.cancel_edit_btn.show()

    def cancel_edit(self):
        self.selected_user_id = None
        self.form_header.setText("Add New User")

        self.user_id_input.clear()
        self.user_id_input.setEnabled(True)
        self.username_input.clear()
        self.private_server_input.clear()
        self.place_input.clear()
        self.cookie_input.clear()

        self.add_btn.show()
        self.update_btn.hide()
        self.cancel_edit_btn.hide()

    def update_user(self):
        if not self.selected_user_id:
            return

        user_id = self.selected_user_id
        username = self.username_input.text().strip()
        private_server_link = self.private_server_input.text().strip()
        place = self.place_input.text().strip()
        cookie = self.cookie_input.text().strip()

        if not username:
            username = f"User_{user_id}"

        if not private_server_link:
            if not self._confirm_missing_ps_link():
                self.private_server_input.setFocus()
                return


        if not cookie:
            QMessageBox.warning(self, "Error", "Cookie cannot be empty!")
            self.cookie_input.setFocus()
            return

        self.original_config[user_id] = {
            "username": username,
            "private_server_link": private_server_link,
            "place": place,
            "cookie": cookie,
            "bad": False
        }

        self.refresh_user_list()
        self.cancel_edit()
        QMessageBox.information(self, "Success", f"User {user_id} ({username}) updated successfully!")

    def _confirm_missing_ps_link(self) -> bool:
        """Return True to proceed with save, False to cancel."""
        if self.skip_private_server_warning:
            return True

        box = QMessageBox(self)
        box.setWindowTitle("No Private Server Link")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(
            "You didn’t enter a Private Server Link.\n\n"
            "If you continue, the account will launch into a public server "
            "using ‘Place:’ (or Sols RNG public lobby if that's missing as well)."
        )
        box.setInformativeText("Save anyway?")
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Yes)

        chk = QCheckBox("Don’t warn me again")
        box.setCheckBox(chk)

        decision = box.exec() == QMessageBox.StandardButton.Yes
        if decision and chk.isChecked():
            self.skip_private_server_warning = True   # remember only for this run
        return decision

    def add_user(self):
        user_id = self.user_id_input.text().strip()
        username = self.username_input.text().strip()
        private_server_link = self.private_server_input.text().strip()
        place = self.place_input.text().strip()
        cookie = self.cookie_input.text().strip()

        if not user_id:
            QMessageBox.warning(self, "Error", "Please enter a User ID")
            self.user_id_input.setFocus()
            return

        if not user_id.isdigit():
            QMessageBox.warning(self, "Error", "User ID should be numeric (e.g., 123456789)")
            self.user_id_input.setFocus()
            return

        if user_id in self.original_config:
            QMessageBox.warning(self, "Error", f"User ID {user_id} already exists. Use Edit to modify existing users.")
            self.user_id_input.setFocus()
            return

        if not private_server_link:
            if not self._confirm_missing_ps_link():
                self.private_server_input.setFocus()
                return

        if not cookie:
            QMessageBox.warning(self, "Error", "Please enter a Cookie")
            self.cookie_input.setFocus()
            return

        if not username:
            username = f"User_{user_id}"

        import re
        pattern1 = r'roblox\.com/games/\d+/[^?]*\?privateServerLinkCode=[A-Za-z0-9_-]+'
        pattern2 = r'roblox\.com/share\?code=[A-Za-z0-9_-]+&type=Server'

        if not (re.search(pattern1, private_server_link) or re.search(pattern2, private_server_link)):
            reply = QMessageBox.question(self, "Private Server Link Warning",
                                       "The private server link doesn't appear to be in the expected format.\n\n"
                                       "Supported formats:\n"
                                       "• Direct Link: https://www.roblox.com/games/[ID]/[NAME]?privateServerLinkCode=[CODE]\n"
                                       "• Share Link: https://www.roblox.com/share?code=[CODE]&type=Server\n\n"
                                       "Continue anyway?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                self.private_server_input.setFocus()
                return

        if not cookie.startswith('_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_'):
            reply = QMessageBox.question(self, "Cookie Warning",
                                       "The cookie doesn't appear to be in the expected ROBLOSECURITY format. Continue anyway?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                self.cookie_input.setFocus()
                return

        try:

            self.original_config[user_id] = {
                "username": username,
                "private_server_link": private_server_link,
                "place": place,
                "cookie": cookie,
                "bad": False
            }

            self.user_id_input.clear()
            self.username_input.clear()
            self.private_server_input.clear()
            self.place_input.clear()
            self.cookie_input.clear()

            self.refresh_user_list()

            QMessageBox.information(self, "Success", f"User {user_id} ({username}) added successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add user: {e}")

    def extract_cookie_from_browser(self):
        try:
            self.browser_login_btn.setEnabled(False)
            self.browser_login_btn.setText("Extracting...")

            self.cookie_extractor.extract_cookie_async(
                callback=self._on_cookie_extraction_complete,
                parent_widget=self
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start cookie extraction: {str(e)}")
            self._reset_browser_button()

    def _on_cookie_extraction_complete(self, cookie: str):
        try:
            if cookie:
                self.cookie_input.setText(cookie)
                QMessageBox.information(self, "Success",
                                      "Cookie extracted successfully!\n\n"
                                      "The cookie has been automatically filled in the input field.")
            else:
                QMessageBox.information(self, "Extraction Cancelled",
                                      "Cookie extraction was cancelled or failed.\n\n"
                                      "You can try again or enter the cookie manually.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error handling extracted cookie: {str(e)}")
        finally:
            self._reset_browser_button()

    def _reset_browser_button(self):
        self.browser_login_btn.setEnabled(True)
        self.browser_login_btn.setText("Login with Browser")

    def delete_user_by_id(self, user_id):
        user_info = self.original_config.get(user_id, {})
        if isinstance(user_info, dict):
            username = user_info.get("username", f"User_{user_id}")
        else:
            username = f"User_{user_id}"

        reply = QMessageBox.question(self, "Confirm Delete",
                                   f"Are you sure you want to delete user {user_id} ({username})?\n\n"
                                   f"This action cannot be undone.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            if user_id in self.original_config:

                if self.selected_user_id == user_id:
                    self.cancel_edit()

                del self.original_config[user_id]
                self.refresh_user_list()
                QMessageBox.information(self, "Success", f"User {user_id} ({username}) deleted successfully!")
            else:
                QMessageBox.warning(self, "Error", f"User {user_id} not found in configuration!")

    def save_and_close(self):
        if self.config_manager.save_users(self.original_config):
            config_info = self.config_manager.get_config_info()
            QMessageBox.information(self, "Success",
                                  f"User configuration saved successfully!\n\n"
                                  f"Location: {config_info['users_file']}\n"
                                  f"Backup created in: {config_info['backup_dir']}")
            self.accept()
        else:
            QMessageBox.critical(self, "Error",
                               "Failed to save user configuration. Please check the logs for details.")


class BorderRing(QWidget):
    """Transparent widget that draws a circular ring and ignores mouse events."""
    def __init__(self, diameter: int, border_px: int, colour: str, parent=None):
        super().__init__(parent)
        self.setFixedSize(diameter, diameter)

        # NEW — tell Qt to honour the stylesheet even with a transparent bg
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

        self.setStyleSheet(
            f"border:{border_px}px solid {colour};"
            f"border-radius:{diameter//2}px;"
            "background:transparent;"
        )


class RoundMovieLabel(QLabel):
    def __init__(self, diameter: int, border_px: int, border_color: str, parent=None):
        super().__init__(parent)
        self.setFixedSize(diameter, diameter)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"border:{border_px}px solid {border_color};"
            f"border-radius:{diameter//2}px;"
            f"background-color:{ModernStyle.SURFACE};"
        )

        # ── build a mask that ends halfway through the ring ──────────────
        half = diameter / 2
        r    = half - border_px / 1          # 60 − 1.5 = 58.5  (includes border)
        path = QPainterPath()
        path.addEllipse(QPointF(half, half), r, r)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

        # inner square you can show safely (used for movie scaling)
        self._inner_side = int(round(r * 2))   # 117 px


        
class RobloxManagerGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.process_data = {}
        self.config_manager = ConfigManager()
        self.setup_ui()
        self.setup_timers()

    def setup_ui(self):
        self.setWindowTitle("Jirach1 + JARAM - Just Another Roblox Account Manager")
        self.setGeometry(100, 100, 1200, 800)

        icon_path = _get_icon_path()
        if icon_path and os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        header_layout = QHBoxLayout()

        title_label = QLabel("Jirach1 + JARAM - Just Another Roblox Account Manager")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        self.start_btn = QPushButton("Start Manager")
        self.start_btn.setProperty("class", "success")
        self.start_btn.clicked.connect(self.start_manager)
        header_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Manager")
        self.stop_btn.setProperty("class", "danger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_manager)
        header_layout.addWidget(self.stop_btn)

        main_layout.addLayout(header_layout)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Stopped")
        self.status_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY}; font-weight: bold;")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.uptime_label = QLabel("Uptime: 00:00:00")
        status_layout.addWidget(self.uptime_label)

        main_layout.addLayout(status_layout)

        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        self.setup_dashboard_tab()
        self.setup_users_tab()
        self.setup_processes_tab()
        self.setup_logs_tab()
        self.setup_settings_tab()
        self.setup_RAMEXPORT_tab()
        self.setup_credits_tab()

        self.setup_menu_bar()

        self.setStyleSheet(ModernStyle.get_stylesheet())

        self.start_time = None
        self.user_data = {}

    def setup_menu_bar(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        manage_users_action = file_menu.addAction("Manage Users")
        manage_users_action.triggered.connect(self.open_user_management)

        file_menu.addSeparator()

        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)

        help_menu = menubar.addMenu("Help")

        config_location_action = help_menu.addAction("Show Config Location")
        config_location_action.triggered.connect(self.show_config_location)

        help_menu.addSeparator()

        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)

    def setup_dashboard_tab(self):
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)

        stats_group = QGroupBox("System Statistics")
        stats_layout = QGridLayout(stats_group)

        self.total_users_label = QLabel("0")
        self.total_users_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {ModernStyle.PRIMARY};")
        stats_layout.addWidget(QLabel("Total Users:"), 0, 0)
        stats_layout.addWidget(self.total_users_label, 0, 1)

        self.active_users_label = QLabel("0")
        self.active_users_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {ModernStyle.SECONDARY};")
        stats_layout.addWidget(QLabel("Active Users:"), 0, 2)
        stats_layout.addWidget(self.active_users_label, 0, 3)

        self.total_processes_label = QLabel("0")
        self.total_processes_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {ModernStyle.WARNING};")
        stats_layout.addWidget(QLabel("Total Processes:"), 1, 0)
        stats_layout.addWidget(self.total_processes_label, 1, 1)

        self.pending_restarts_label = QLabel("0")
        self.pending_restarts_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {ModernStyle.ERROR};")
        stats_layout.addWidget(QLabel("Pending Restarts:"), 1, 2)
        stats_layout.addWidget(self.pending_restarts_label, 1, 3)

        layout.addWidget(stats_group)

        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)

        restart_all_btn = QPushButton("Restart All Sessions")
        restart_all_btn.clicked.connect(self.restart_all_sessions)
        actions_layout.addWidget(restart_all_btn)

        kill_all_btn = QPushButton("Kill All Processes")
        kill_all_btn.setProperty("class", "danger")
        kill_all_btn.clicked.connect(self.kill_all_processes)
        actions_layout.addWidget(kill_all_btn)

        cleanup_btn = QPushButton("Cleanup Dead Processes")
        cleanup_btn.clicked.connect(self.cleanup_processes)
        actions_layout.addWidget(cleanup_btn)

        actions_layout.addStretch()

        layout.addWidget(actions_group)

        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)

        self.activity_list = QTextEdit()
        self.activity_list.setMaximumHeight(200)
        self.activity_list.setReadOnly(True)
        activity_layout.addWidget(self.activity_list)

        layout.addWidget(activity_group)

        layout.addStretch()

        self.tab_widget.addTab(dashboard_widget, "Dashboard")

    def setup_users_tab(self):
        users_widget = QWidget()
        layout = QVBoxLayout(users_widget)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(10)      # was 9
        self.users_table.setHorizontalHeaderLabels([
            "User ID","Username","Private Server","Place",
            "Status","PIDs","TTL(s)","Last Active",
            "Inactive For","Actions"
])


        header = self.users_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)  
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)  
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)  
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)  
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Fixed)  

        self.users_table.setColumnWidth(2, 200)  
        self.users_table.setColumnWidth(3, 100)  
        self.users_table.setColumnWidth(6, 100)  
        self.users_table.setColumnWidth(8, 160)  
        self.users_table.setColumnWidth(9, 170)
        self.users_table.verticalHeader().setDefaultSectionSize(60)

        layout.addWidget(self.users_table)

        controls_layout = QHBoxLayout()

        refresh_users_btn = QPushButton("Refresh")
        refresh_users_btn.clicked.connect(self.refresh_users)
        controls_layout.addWidget(refresh_users_btn)

        add_user_btn = QPushButton("Modify Users")
        add_user_btn.clicked.connect(self.open_user_management)
        controls_layout.addWidget(add_user_btn)

        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        self.tab_widget.addTab(users_widget, "Users")

    def setup_processes_tab(self):
        processes_widget = QWidget()
        layout = QVBoxLayout(processes_widget)

        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(5)
        self.processes_table.setHorizontalHeaderLabels([
            "PID", "User ID", "Created", "Windows", "Actions"
        ])

        header = self.processes_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)  
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)  

        self.processes_table.setColumnWidth(2, 100)  
        self.processes_table.setColumnWidth(4, 110)  

        self.processes_table.verticalHeader().setDefaultSectionSize(60)

        layout.addWidget(self.processes_table)

        controls_layout = QHBoxLayout()

        refresh_processes_btn = QPushButton("Refresh")
        refresh_processes_btn.clicked.connect(self.refresh_processes)
        controls_layout.addWidget(refresh_processes_btn)

        kill_selected_btn = QPushButton("Kill Selected")
        kill_selected_btn.setProperty("class", "danger")
        kill_selected_btn.clicked.connect(self.kill_selected_process)
        controls_layout.addWidget(kill_selected_btn)

        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        self.tab_widget.addTab(processes_widget, "Processes")

    def setup_logs_tab(self):
        logs_widget = QWidget()
        layout = QVBoxLayout(logs_widget)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 10))
        layout.addWidget(self.log_display)

        controls_layout = QHBoxLayout()

        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        controls_layout.addWidget(clear_logs_btn)

        save_logs_btn = QPushButton("Save Logs")
        save_logs_btn.clicked.connect(self.save_logs)
        controls_layout.addWidget(save_logs_btn)

        controls_layout.addStretch()

        self.scan_trace_chk = QCheckBox("Show SCAN-TRACE messages", self)
        self.scan_trace_chk.setChecked(False)      # default = ON
        controls_layout.addWidget(self.scan_trace_chk)
        
        self.auto_scroll_checkbox = QCheckBox("Auto-scroll")
        self.auto_scroll_checkbox.setChecked(True)
        controls_layout.addWidget(self.auto_scroll_checkbox)

        layout.addLayout(controls_layout)

        self.tab_widget.addTab(logs_widget, "Logs")

    def setup_settings_tab(self):
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        basic_group = QGroupBox("Basic Settings")
        basic_layout = QFormLayout(basic_group)

        self.settings_window_limit_input = QSpinBox()
        self.settings_window_limit_input.setRange(1, 999)
        self.settings_window_limit_input.setToolTip("Maximum windows per Roblox process")
        basic_layout.addRow("Window Limit:", self.settings_window_limit_input)

        content_layout.addWidget(basic_group)

        timing_group = QGroupBox("Timing Settings")
        timing_layout = QFormLayout(timing_group)
        
        timeout_group = QGroupBox("Shutdown Settings")
        timeout_layout = QFormLayout(timeout_group)

        self.settings_strap_threshold_input = QSpinBox()
        self.settings_strap_threshold_input.setRange(1, 200)
        self.settings_strap_threshold_input.setToolTip("Max number of strap.exe helpers before trimming")
        timeout_layout.addRow("-Strap Limit:", self.settings_strap_threshold_input)
        
        self.kill_timeout_input = QSpinBox()
        self.kill_timeout_input.setRange(60, 7200)
        self.kill_timeout_input.setSuffix(" s")
        self.kill_timeout_input.setToolTip("Time until window auto-closes (≤ 1,740s recommended)")
        timeout_layout.addRow("Kill After:", self.kill_timeout_input)

        self.poll_interval_input = QSpinBox()
        self.poll_interval_input.setRange(1, 120)
        self.poll_interval_input.setSuffix(" s")
        self.poll_interval_input.setToolTip("Polling Interval + Kill After must stay under 1,800s")
        timeout_layout.addRow("Poll Interval:", self.poll_interval_input)

        self.webhook_input = QLineEdit()
        self.webhook_input.setPlaceholderText("Discord webhook URL")
        self.webhook_input.setToolTip("Keep empty to disable")
        timeout_layout.addRow("Webhook URL:", self.webhook_input)

        self.ping_msg_input = QLineEdit()
        self.ping_msg_input.setPlaceholderText("Ping message (optional)")
        timeout_layout.addRow("Ping Message:", self.ping_msg_input)

        content_layout.addWidget(timeout_group)

        self.settings_offline_threshold_input = QSpinBox()
        self.settings_offline_threshold_input.setRange(10, 120)
        self.settings_offline_threshold_input.setSuffix(" s")
        self.settings_offline_threshold_input.setToolTip("How long to wait before restarting inactive users")
        timing_layout.addRow("Restart Inactive After:", self.settings_offline_threshold_input)
        
        self.settings_initial_delay_input = QSpinBox()
        self.settings_initial_delay_input.setRange(5, 60)
        self.settings_initial_delay_input.setSuffix(" s")
        self.settings_initial_delay_input.setToolTip("Seconds between first-run launches when staggering is ON")
        timing_layout.addRow("Initial Launch Delay:", self.settings_initial_delay_input)

        self.settings_launch_delay_input = QSpinBox()
        self.settings_launch_delay_input.setRange(1, 120)
        self.settings_launch_delay_input.setSuffix(" s")
        self.settings_launch_delay_input.setToolTip("Delay between launching sessions")
        timing_layout.addRow("Launch Delay:", self.settings_launch_delay_input)

        content_layout.addWidget(timing_group)

        buttons_layout = QHBoxLayout()

        save_settings_btn = QPushButton("Save Settings")
        save_settings_btn.setProperty("class", "success")
        save_settings_btn.clicked.connect(self.save_settings)
        buttons_layout.addWidget(save_settings_btn)

        reset_settings_btn = QPushButton("Reset to Defaults")
        reset_settings_btn.clicked.connect(self.reset_settings)
        buttons_layout.addWidget(reset_settings_btn)
        
        clear_bad_btn = QPushButton("Clear Bad Flags")
        clear_bad_btn.clicked.connect(self._clear_bad_flags)
        buttons_layout.addWidget(clear_bad_btn)

        buttons_layout.addStretch()

        content_layout.addLayout(buttons_layout)
        content_layout.addStretch()

        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)

        self.tab_widget.addTab(settings_widget, "Settings")

        self.load_settings_tab()
        
    def setup_RAMEXPORT_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # ── API parameters ─────────────────────────────────────────
        form = QFormLayout()

        self.ram_port_input  = QLineEdit("7963")
        form.addRow("RAM Port:", self.ram_port_input)

        self.ram_group_input = QLineEdit()
        form.addRow("Group (Blank = All):", self.ram_group_input)

        self.ram_pwd_input   = QLineEdit()
        self.ram_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Password:", self.ram_pwd_input)

        layout.addLayout(form)

        # ── merge / replace toggles ───────────────────────────────
        self.merge_chk = QCheckBox("Merge with existing users.json (otherwise replace)")
        self.merge_chk.setChecked(True)
        layout.addWidget(self.merge_chk)

        self.replace_cookie_chk = QCheckBox("Overwrite existing cookies")
        self.replace_ps_chk     = QCheckBox("Overwrite existing private-servers")

        def _merge_toggled(checked: bool):          # checked is True / False
            self.replace_cookie_chk.setEnabled(checked)
            self.replace_ps_chk.setEnabled(checked)

        self.merge_chk.toggled.connect(_merge_toggled)   # use toggled(bool)
        _merge_toggled(self.merge_chk.isChecked())       # set initial state

        layout.addWidget(self.replace_cookie_chk)
        layout.addWidget(self.replace_ps_chk)

        # ── run button ─────────────────────────────────────────────
        run_btn = QPushButton("Fetch && Apply Accounts")
        run_btn.setProperty("class", "success")
        run_btn.clicked.connect(self.execute_ram_import)
        layout.addWidget(run_btn)

        layout.addStretch()
        self.tab_widget.addTab(tab, "RAM Export")
        
    @staticmethod
    def _make_dev_card(name: str,
                    movie_bytes: bytes,
                    fallback: str = "GIF\nError") -> QWidget:
        card   = QWidget()
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(15)

        ring_px = 6                         # ← any thickness you want

        outer = QWidget()
        outer.setFixedSize(120, 120)

        # -------- coloured ring (layer 1) --------
        ring = BorderRing(120, ring_px, ModernStyle.PRIMARY, parent=outer)
        ring.move(0, 0)

        # -------- masked GIF holder (layer 0) ----
        inner_d = 120 - ring_px * 2         # 120 − 6*2 = 108 px
        holder  = RoundMovieLabel(inner_d, 0, "transparent", parent=outer)
        holder.setFixedSize(inner_d, inner_d)
        holder.move(ring_px, ring_px)       # gap = ring thickness
        
        try:
            buf = QBuffer()
            buf.setData(QByteArray(movie_bytes))
            buf.open(QIODevice.OpenModeFlag.ReadOnly)

            mv = QMovie()
            mv.setDevice(buf)
            mv.setCacheMode(QMovie.CacheMode.CacheAll)
            mv.setScaledSize(QSize(150, False))      # == holder size

            buf.setParent(mv)
            mv.setParent(holder)
            holder.setMovie(mv)
            mv.start()

        except Exception:
            holder.setText(fallback)
            holder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            holder.setStyleSheet(
                f"color:{ModernStyle.TEXT_SECONDARY};"
                f"border:1px dashed {ModernStyle.PRIMARY};"
            )

        layout.addWidget(outer)

        # name label
        lbl = QLabel(name)
        f   = QFont(); f.setPointSize(16); f.setBold(True)
        lbl.setFont(f)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(f"color:{ModernStyle.SECONDARY}")
        layout.addWidget(lbl)

        return card

    def setup_credits_tab(self):
        credits_widget = QWidget()
        layout = QVBoxLayout(credits_widget)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(20)

        title_label = QLabel("JARAM Credits")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"color: {ModernStyle.PRIMARY}; margin: 20px 0;")
        content_layout.addWidget(title_label)

        developer_group = QGroupBox("Developer")

        # ── Two dev cards, side-by-side ──────────────────────────────
        developer_layout = QHBoxLayout(developer_group)
        developer_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        developer_layout.setSpacing(40)

        # — Jirach1 —
        try:
            bytes_j = Path(__file__).with_name("jirachi.gif").read_bytes()
        except FileNotFoundError:
            bytes_j = urlopen("https://kyl.neocities.org/jirachi.gif").read()

        developer_layout.addWidget(self._make_dev_card("Jirach1", bytes_j))

        # — cresqnt —
        try:
            bytes_c = Path(__file__).with_name("cresqnt.gif").read_bytes()
        except FileNotFoundError:
            bytes_c = urlopen("https://media1.tenor.com/m/CNBGgG2DU10AAAAd/nyan-cat-poptart.gif").read()

        developer_layout.addWidget(self._make_dev_card("cresqnt",  bytes_c))

        content_layout.addWidget(developer_group)

        support_group = QGroupBox("Support")
        support_layout = QVBoxLayout(support_group)

        support_label = QLabel("Discord Support Server:")
        support_label.setStyleSheet(f"color: {ModernStyle.TEXT_PRIMARY}; font-weight: bold; margin-bottom: 5px;")
        support_layout.addWidget(support_label)

        discord_btn = QPushButton("https://discord.gg/6cuCu6ymkX")
        discord_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: 
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 6px;
                font-weight: bold;
                text-align: left;
            }}
            QPushButton:hover {{
                background-color: 
            }}
        """)
        discord_btn.clicked.connect(lambda: self.open_url("https://discord.gg/6cuCu6ymkX"))
        support_layout.addWidget(discord_btn)

        content_layout.addWidget(support_group) 
#---------------------------------------------------------------------------------------------------
        support_group2 = QGroupBox("Additional") #lazy copy and paste...
        support_layout2 = QVBoxLayout(support_group2)

        support_label2 = QLabel("The Best Glitch Hunt Server:")
        support_label2.setStyleSheet(f"color: {ModernStyle.TEXT_PRIMARY}; font-weight: bold; margin-bottom: 5px;")
        support_layout2.addWidget(support_label2)

        discord_btn2 = QPushButton("https://discord.gg/YPvhKFTjEF")
        discord_btn2.setStyleSheet(f"""
            QPushButton {{
                background-color: 
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 6px;
                font-weight: bold;
                text-align: left;
            }}
            QPushButton:hover {{
                background-color: 
            }}
        """)
        discord_btn2.clicked.connect(lambda: self.open_url("https://discord.gg/YPvhKFTjEF"))
        support_layout2.addWidget(discord_btn2)

        content_layout.addWidget(support_group2)
        
        license_group = QGroupBox("License | Legal")
        license_layout = QVBoxLayout(license_group)

        copyright_label = QLabel("© 2025 cresqnt")
        copyright_label.setStyleSheet(f"color: {ModernStyle.TEXT_PRIMARY}; font-weight: bold; margin-bottom: 10px;")
        license_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under AGPL-3.0")
        license_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY}; margin-bottom: 10px;")
        license_layout.addWidget(license_label)

        content_layout.addWidget(license_group)

        content_layout.addStretch()

        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)

        self.tab_widget.addTab(credits_widget, "Credits")
        
    def execute_ram_import(self):
        base_url = f"http://127.0.0.1:{self.ram_port_input.text().strip() or '7963'}"
        params   = {
            "Password"      : self.ram_pwd_input.text().strip(),
            "IncludeCookies": "true"
        }
        group_val = self.ram_group_input.text().strip()
        if group_val:
            params["Group"] = group_val

        try:
            r = requests.get(f"{base_url}/GetAccountsJson", params=params, timeout=15)
            if r.status_code == 200:
                accounts_raw = r.json()
            elif r.status_code == 400:
                raise RuntimeError("400 Bad Request – “Allow external connections” is OFF in Roblox Account Manager.")
            elif r.status_code == 401:
                raise RuntimeError("401 Unauthorized – Wrong Password")
            elif r.status_code == 404:
                raise RuntimeError("404 Not Found – RAM endpoint missing on this port.")#
            elif r.status_code == 500:
                raise RuntimeError("500 Server Error – RAM threw an internal error.")
            else:
                raise RuntimeError(f"{r.status_code} {r.reason} – RAM API request failed.")

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as net_err:
            QMessageBox.critical(
                self,
                "Port / Connection Error",
                f"Could not reach Roblox Account Manager at port {self.ram_port_input.text()}\n"
                "• Is Roblox Account Manager open?\n"
                "• Is the port correct?\n"
                "*NOTE: Roblox Account Manager must be restarted whenever you change the port.\n\n"
            )
            return

        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))
            return


        new_users = transform(accounts_raw)        # -> JARAM user-dict
        if not new_users:
            QMessageBox.warning(self, "No Accounts", "RAM returned 0 usable accounts.")
            return

        # --- backup BEFORE touching users.json --------------------
        self.config_manager._create_backup(self.config_manager.users_file)

        if not self.merge_chk.isChecked():
            merged = new_users                       # full replace
        else:
            merged = self.config_manager.load_users()
            for uid, info in new_users.items():
                if uid not in merged:
                    merged[uid] = info
                else:                                # existing user
                    if self.replace_cookie_chk.isChecked():
                        merged[uid]["cookie"] = info.get("cookie", "")
                        merged[uid]["bad"] = False
                    if self.replace_ps_chk.isChecked():
                        merged[uid]["private_server_link"] = info.get("private_server_link", "")
                        merged[uid]["place"]               = info.get("place", "")

        if self.config_manager.save_users(merged):
            QMessageBox.information(self, "Success",
                f"Imported {len(new_users)} accounts.\n"
                f"Total users.json entries: {len(merged)}")
            self.add_log("RAM import complete — users.json updated.")
        else:
            QMessageBox.critical(self, "Save Error", "Failed to write users.json!")


    def open_url(self, url):
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open URL: {e}")

    def setup_timers(self):

        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(1000)  

        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self.update_uptime)
        self.uptime_timer.start(1000)

    def start_manager(self):
        if self.worker_thread and self.worker_thread.isRunning():
            return

        try:
            config = self.config_manager.get_users_for_manager()
            if not config:
                QMessageBox.warning(self, "No Users",
                                  "No users found in configuration. Please add users first using File → Manage Users.")
                return
        except Exception as e:
            QMessageBox.critical(self, "Config Error", f"Error reading user configuration: {e}")
            return

        self.worker_thread = WorkerThread(self.config_manager)
        self.worker_thread.log_signal.connect(self.add_log)
        self.worker_thread.status_signal.connect(self.update_user_status)
        self.worker_thread.process_signal.connect(self.update_process_data)
        self.worker_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Running")
        self.status_label.setStyleSheet(f"color: {ModernStyle.SECONDARY}; font-weight: bold;")
        self.start_time = time.time()

    def stop_manager(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop()
            self.worker_thread.wait()

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")
        self.status_label.setStyleSheet(f"color: {ModernStyle.ERROR}; font-weight: bold;")
        self.start_time = None

    def update_uptime(self):
        if self.start_time:
            uptime = time.time() - self.start_time
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            seconds = int(uptime % 60)
            self.uptime_label.setText(f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.uptime_label.setText("Uptime: 00:00:00")

    def update_ui(self):

        active_users = sum(1 for data in self.user_data.values() if data.get('status') == 'Active')
        total_processes = sum(len(data.get('pids', [])) for data in self.user_data.values())
        pending_restarts = sum(1 for data in self.user_data.values() if data.get('needs_restart', False))
        users_cfg = self.config_manager.load_users()
        good = [u for u, i in users_cfg.items() if not i.get("bad")]

        self.total_users_label.setText(f"{len(good)}")
        self.active_users_label.setText(str(active_users))
        self.total_processes_label.setText(str(total_processes))
        self.pending_restarts_label.setText(str(pending_restarts))

    def update_user_status(self, status_data):
        self.user_data = status_data
        self.refresh_users()

    def update_process_data(self, process_data):
        self.process_data = process_data
        self.refresh_processes()

    def refresh_users(self):
        self.users_table.setRowCount(len(self.user_data))

        users_cfg = self.config_manager.load_users()

        # good first, bad last
        ordered = sorted(
            self.user_data.items(),
            key=lambda kv: bool(users_cfg.get(kv[0], {}).get("bad", False))
        )

        for row, (user_id, runtime) in enumerate(ordered):
            u_conf   = users_cfg.get(user_id, {})
            bad_flag = bool(u_conf.get("bad", False))

            # ── static columns ───────────────────────────────────────
            username  = u_conf.get("username", f"User_{user_id}")
            ps_link   = u_conf.get("private_server_link", "")
            place     = u_conf.get("place", "")

            self.users_table.setItem(row, 0, QTableWidgetItem(user_id))
            self.users_table.setItem(row, 1, QTableWidgetItem(username))

            trimmed_link = ps_link[:25] + "..." if len(ps_link) > 25 else ps_link
            self.users_table.setItem(row, 2, QTableWidgetItem(trimmed_link))
            self.users_table.setItem(row, 3, QTableWidgetItem(place))

            # ── status cell ──────────────────────────────────────────
            if bad_flag:
                status_text, colour = "Bad", QColor(ModernStyle.ERROR)
            else:
                raw = runtime.get("status", "Unknown")
                if "Active" in raw:
                    colour = QColor(ModernStyle.SECONDARY)
                elif "Inactive" in raw:
                    colour = QColor(ModernStyle.WARNING)
                elif "Restarting" in raw:
                    colour = QColor(ModernStyle.PRIMARY)
                else:
                    colour = QColor(ModernStyle.ERROR)
                status_text = raw

            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(colour)
            self.users_table.setItem(row, 4, status_item)

            # ── runtime columns ─────────────────────────────────────
            pids = runtime.get('pids', [])
            self.users_table.setItem(row, 5,
                                    QTableWidgetItem(', '.join(map(str, pids)) or 'None'))

            ttl_list = runtime.get('ttl', [])
            self.users_table.setItem(row, 6,
                                    QTableWidgetItem(', '.join(f"{t}s" for t in ttl_list) or 'N/A'))

            last_active = runtime.get('last_active', 0)
            last_active_str = datetime.fromtimestamp(last_active).strftime("%H:%M:%S") if last_active else "Never"
            self.users_table.setItem(row, 7, QTableWidgetItem(last_active_str))

            inactive_since = runtime.get('inactive_since')
            dur = int(time.time() - inactive_since) if inactive_since else None
            self.users_table.setItem(row, 8, QTableWidgetItem(f"{dur}s" if dur else "N/A"))

            # ── action buttons ──────────────────────────────────────
            actions_widget  = QWidget()
            actions_layout  = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(8, 5, 8, 5)
            actions_layout.setSpacing(12)

            restart_btn = QPushButton("Restart")
            restart_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.PRIMARY};
                    color: {ModernStyle.TEXT_PRIMARY};
                    border: none;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: 500;
                    font-size: 11px;
                    min-width: 40px;
                    max-width: 50px;
                    min-height: 26px;
                    max-height: 28px;
                }}
                QPushButton:hover {{
                    background-color: {ModernStyle.ERROR};
                }}
            """)
            restart_btn.clicked.connect(lambda _, uid=user_id: self.restart_user_session(uid))
            actions_layout.addWidget(restart_btn)

            kill_btn = QPushButton("Kill")
            kill_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.ERROR};
                    color: {ModernStyle.TEXT_PRIMARY};
                    border: none;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: 500;
                    font-size: 11px;
                    min-width: 40px;
                    max-width: 50px;
                    min-height: 26px;
                    max-height: 28px;
                }}
                QPushButton:hover {{
                    background-color: {ModernStyle.ERROR};
                }}
            """)
            kill_btn.clicked.connect(lambda _, uid=user_id: self.kill_user_processes(uid))
            actions_layout.addWidget(kill_btn)

            self.users_table.setCellWidget(row, 9, actions_widget)


    def refresh_processes(self):
        self.processes_table.setRowCount(len(self.process_data))

        for row, (pid, data) in enumerate(self.process_data.items()):
            self.processes_table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.processes_table.setItem(row, 1, QTableWidgetItem(data.get('user_id', 'Unknown')))
            self.processes_table.setItem(row, 2, QTableWidgetItem(data.get('created', 'Unknown')))

            windows = data.get('windows', 0)
            windows_item = QTableWidgetItem(str(windows))
            if windows > 1:
                windows_item.setForeground(QColor(ModernStyle.WARNING))
            self.processes_table.setItem(row, 3, windows_item)

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(8, 5, 8, 5)

            kill_btn = QPushButton("Kill")
            kill_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.ERROR};
                    color: {ModernStyle.TEXT_PRIMARY};
                    border: none;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: 500;
                    font-size: 11px;
                    min-width: 50px;
                    max-width: 60px;
                    min-height: 26px;
                    max-height: 28px;
                }}
                QPushButton:hover {{
                    background-color: 
                }}
            """)
            kill_btn.clicked.connect(lambda checked, p=pid: self.kill_specific_process(p))
            actions_layout.addWidget(kill_btn)

            self.processes_table.setCellWidget(row, 4, actions_widget)

    def add_log(self, message):
        if message.startswith("[SCAN-TRACE]") and not self.scan_trace_chk.isChecked():
            return    
        print("add_log():", message)
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"

        self.log_display.append(formatted_message)
        self.activity_list.append(formatted_message)

        if self.auto_scroll_checkbox.isChecked():
            scrollbar = self.log_display.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

        activity_text = self.activity_list.toPlainText()
        lines = activity_text.split('\n')
        if len(lines) > 10:
            self.activity_list.setPlainText('\n'.join(lines[-10:]))

    def clear_logs(self):
        self.log_display.clear()

    def save_logs(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"roblox_manager_logs_{timestamp}.txt"

            with open(filename, 'w') as f:
                f.write(self.log_display.toPlainText())

            QMessageBox.information(self, "Success", f"Logs saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save logs: {e}")

    def open_user_management(self):
        dialog = UserManagementDialog(self)
        dialog.exec()

    def open_settings(self):
        self.tab_widget.setCurrentIndex(4)

    def load_settings_tab(self):
        cfg = self.config_manager.load_settings()

        self.settings_window_limit_input.setValue(cfg.get("window_limit", 1))

        self.settings_initial_delay_input.setValue(
                cfg.get("timeouts", {}).get("initial_delay", 4))

        self.settings_offline_threshold_input.setValue(
                cfg.get("timeouts", {}).get("offline", 35))

        self.settings_launch_delay_input.setValue(
                cfg.get("timeouts", {}).get("launch_delay", 4))
        
        self.settings_strap_threshold_input.setValue(
                cfg.get("timeouts", {}).get("strap_threshold", 50))

        tm = cfg.get("timeout_monitor", {})
        self.kill_timeout_input.setValue(tm.get("kill_timeout", 1740))
        self.poll_interval_input.setValue(tm.get("poll_interval", 10))
        self.webhook_input.setText(tm.get("webhook_url", ""))
        self.ping_msg_input.setText(tm.get("ping_message", "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"))

    def save_settings(self):
        settings = {
            "window_limit": self.settings_window_limit_input.value(),
            "timeouts": {
                "initial_delay": self.settings_initial_delay_input.value(),
                "offline"      : self.settings_offline_threshold_input.value(),
                "launch_delay" : self.settings_launch_delay_input.value(),
                "strap_threshold": self.settings_strap_threshold_input.value(),

            },
            "timeout_monitor": {                              # NEW block
            "kill_timeout" : self.kill_timeout_input.value(),
            "poll_interval": self.poll_interval_input.value(),
            "webhook_url"  : self.webhook_input.text().strip(),
            "ping_message" : self.ping_msg_input.text().strip() or "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging. Leave webhook empty if not interested"
            }
        }

        if self.config_manager.save_settings(settings):
            if self.worker_thread and self.worker_thread.isRunning():
                self.worker_thread.apply_new_settings(settings)
            QMessageBox.information(self, "Success", "Settings saved and applied!")
        else:
            QMessageBox.critical(self, "Error", "Failed to save settings.")



    def reset_settings(self):
        """Load the hard-coded defaults from ConfigManager into the UI."""
        defaults = self.config_manager.default_settings          # ← one source of truth
        t        = defaults["timeouts"]                          # short alias

        # ── basic limits ──────────────────────────────────────────
        self.settings_window_limit_input.setValue(defaults["window_limit"])

        # ── launch / restart timings ──────────────────────────────
        self.settings_initial_delay_input.setValue(t["initial_delay"])
        self.settings_launch_delay_input.setValue(t["launch_delay"])
        self.settings_offline_threshold_input.setValue(t["offline"])

        # ── helper / strap limiter ────────────────────────────────
        self.settings_strap_threshold_input.setValue(t["strap_threshold"])

        # ── timeout-monitor block (kill / poll / webhook) ─────────
        self.kill_timeout_input.setValue(t["kill_timeout"])
        self.poll_interval_input.setValue(t["poll_interval"])
        self.webhook_input.setText(t["webhook_url"])
        self.ping_msg_input.setText(t["ping_message"])

        QMessageBox.information(
            self,
            "Reset Complete",
            "All settings have been restored to their default values.\n"
            "Click “Save Settings” to confirm them."
        )

    def _clear_bad_flags(self):
        users = self.config_manager.load_users()
        for info in users.values():
            info["bad"] = False
        self.config_manager.save_users(users)
        QMessageBox.information(self, "Done", "All bad-cookie marks cleared.")
        self.refresh_users()                # live update
        self.load_settings_tab()            # if you show counts here

    def show_config_location(self):
        config_info = self.config_manager.get_config_info()

        msg = QMessageBox(self)
        msg.setWindowTitle("Configuration Location")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText("JARAM Configuration Files")
        msg.setDetailedText(
            f"Configuration Directory:\n{config_info['config_dir']}\n\n"
            f"Users File:\n{config_info['users_file']}\n\n"
            f"Settings File:\n{config_info['settings_file']}\n\n"
            f"Backups Directory:\n{config_info['backup_dir']}\n\n"
            "All configuration files are automatically backed up before changes."
        )

        open_button = msg.addButton("Open Folder", QMessageBox.ButtonRole.ActionRole)
        msg.addButton(QMessageBox.StandardButton.Ok)

        msg.exec()

        if msg.clickedButton() == open_button:
            try:
                os.startfile(config_info['config_dir'])
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to open folder: {e}")

    def show_about(self):
        config_info = self.config_manager.get_config_info()
        QMessageBox.about(self, "About JARAM",
                         "JARAM X Jirach1(Just Another Roblox Account Manager) v1.1\n\n"
                         "Advanced multi-account Roblox session manager\n"
                         "with automated presence monitoring and process management.\n\n"
                         "Built with PyQt6 and modern design principles.\n\n"
                         "Jirach1 was here.\n\n"
                         f"Configuration stored in:\n{config_info['config_dir']}")

    def restart_all_sessions(self):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Restart",
                                   "Are you sure you want to restart all sessions?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            restartables = [
                user_id
                for user_id, state in self.worker_thread.user_states.items()
                if not state["user_info"].get("bad", False)
            ]

            def delayed_restart():
                for i, user_id in enumerate(restartables):
                    delay = i * self.worker_thread.launcher.launch_delay
                    QTimer.singleShot(delay * 1000, lambda uid=user_id: self.worker_thread.restart_user_session(uid))

            self.add_log(f"Queued restart for {len(restartables)} sessions using delay={self.worker_thread.launcher.launch_delay}s")
            delayed_restart()
            
    def kill_all_processes(self):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Kill All",
                                   "Are you sure you want to kill ALL Roblox processes?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.worker_thread.kill_all_processes()

    def cleanup_processes(self):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        self.worker_thread.cleanup_dead_processes()

    def restart_user_session(self, user_id):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        self.worker_thread.restart_user_session(user_id)

    def kill_user_processes(self, user_id):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Kill",
                                   f"Are you sure you want to kill processes for user {user_id}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.worker_thread.kill_user_processes(user_id)

    def kill_specific_process(self, pid):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Kill",
                                   f"Are you sure you want to kill process {pid}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if self.worker_thread.process_mgr:
                self.worker_thread.process_mgr.terminate_process(
                    int(pid), self.worker_thread.manager.process_tracker
                )

    def kill_selected_process(self):
        current_row = self.processes_table.currentRow()
        if current_row >= 0:
            pid_item = self.processes_table.item(current_row, 0)
            if pid_item:
                pid = pid_item.text()
                self.kill_specific_process(pid)

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            reply = QMessageBox.question(self, "Confirm Exit",
                                       "The manager is still running. Do you want to stop it and exit?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_manager()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
            

def main():
    app = QApplication(sys.argv)

    app.setApplicationName("JARAM")
    app.setApplicationVersion("1.1")
    app.setOrganizationName("cresqnt")

    icon_path = _get_icon_path()
    if icon_path and os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = RobloxManagerGUI()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()