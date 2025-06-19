import sys
import json
import time
import os
import shutil
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QGridLayout, QTabWidget, QTableWidget,
                            QTableWidgetItem, QPushButton, QLabel, QLineEdit,
                            QSpinBox, QDoubleSpinBox, QTextEdit, QGroupBox,
                            QProgressBar, QComboBox, QCheckBox, QSplitter,
                            QHeaderView, QMessageBox, QDialog, QDialogButtonBox,
                            QFormLayout, QScrollArea, QFrame)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt, QSize
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter
from main import RobloxManager, ProcessManager, GameLauncher

class ConfigManager:
    """Robust configuration manager that saves to AppData/JARAM folder"""

    def __init__(self):
        self.app_name = "JARAM"  
        self.config_dir = self._get_config_directory()
        self.users_file = self.config_dir / "users.json"
        self.settings_file = self.config_dir / "settings.json"
        self.backup_dir = self.config_dir / "backups"

        self._ensure_directories()

        self.default_settings = {
            "place_id": "85896571713843",
            "window_limit": 1,
            "excluded_pid": 0,
            "check_intervals": {
                "window": 3.0,
                "presence": 1.5,
                "cleanup": 30.0
            },
            "timeouts": {
                "relaunch": 20,
                "offline": 35,
                "launch_delay": 4
            }
        }

        self.default_user_structure = {
            "username": "",
            "cookie": "",
            "private_server_link": "",
            "place": ""
        }

    def _get_config_directory(self):
        """Get the configuration directory in AppData"""
        if os.name == 'nt':  
            appdata = os.environ.get('APPDATA')
            if appdata:
                return Path(appdata) / self.app_name

        return Path.home() / f".{self.app_name.lower()}"

    def _ensure_directories(self):
        """Ensure all necessary directories exist"""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self.backup_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Failed to create config directories: {e}")

    def _create_backup(self, file_path):
        """Create a backup of the configuration file"""
        if not file_path.exists():
            return

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.stem}_{timestamp}.json"
            backup_path = self.backup_dir / backup_name

            shutil.copy2(file_path, backup_path)

            self._cleanup_old_backups(file_path.stem)
        except Exception as e:
            print(f"Failed to create backup: {e}")

    def _cleanup_old_backups(self, file_stem):
        """Keep only the last 10 backups for a file"""
        try:
            pattern = f"{file_stem}_*.json"
            backups = sorted(self.backup_dir.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)

            for backup in backups[10:]:
                backup.unlink()
        except Exception as e:
            print(f"Failed to cleanup old backups: {e}")

    def _safe_write_json(self, file_path, data):
        """Safely write JSON data with atomic operation"""
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

    def load_users(self):
        """Load user configuration"""
        try:
            if self.users_file.exists():
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    users_data = json.load(f)

                    return self._ensure_new_format(users_data)
            else:

                return self._migrate_old_config()
        except Exception as e:
            print(f"Failed to load users: {e}")
            return {}

    def save_users(self, users_data):
        """Save user configuration with backup"""
        try:

            formatted_data = self._ensure_new_format(users_data)

            self._create_backup(self.users_file)

            self._safe_write_json(self.users_file, formatted_data)
            return True
        except Exception as e:
            print(f"Failed to save users: {e}")
            return False

    def load_settings(self):
        """Load application settings"""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)

                    settings = self.default_settings.copy()
                    settings.update(loaded_settings)
                    return settings
            else:
                return self.default_settings.copy()
        except Exception as e:
            print(f"Failed to load settings: {e}")
            return self.default_settings.copy()

    def save_settings(self, settings_data):
        """Save application settings with backup"""
        try:

            self._create_backup(self.settings_file)

            self._safe_write_json(self.settings_file, settings_data)
            return True
        except Exception as e:
            print(f"Failed to save settings: {e}")
            return False

    def _migrate_old_config(self):
        """Migrate from old config.json format"""
        old_config_path = Path("config.json")
        if old_config_path.exists():
            try:
                with open(old_config_path, 'r', encoding='utf-8') as f:
                    old_data = json.load(f)

                new_data = self._convert_to_new_format(old_data)

                if self.save_users(new_data):
                    print(f"Migrated configuration from config.json to {self.users_file}")
                    return new_data
            except Exception as e:
                print(f"Failed to migrate old config: {e}")

        return {}

    def _convert_to_new_format(self, old_data):
        """Convert old format {user_id: cookie} to new format {user_id: {username, cookie, private_server_link, place}}"""
        new_data = {}
        for user_id, cookie in old_data.items():
            if isinstance(cookie, str):

                new_data[user_id] = {
                    "username": f"User_{user_id}",  
                    "cookie": cookie,
                    "private_server_link": "",
                    "place": ""
                }
            else:

                new_data[user_id] = cookie
        return new_data

    def _ensure_new_format(self, users_data):
        """Ensure users data is in new format with usernames and private server links"""
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
                    "place": user_info.get("place", "")
                }
            else:

                new_data[user_id] = {
                    "username": f"User_{user_id}",
                    "cookie": "",
                    "private_server_link": "",
                    "place": ""
                }
        return new_data

    def get_users_for_manager(self):
        """Get users in the format expected by RobloxManager (user_id -> user_info)"""
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
        """Get information about configuration location"""
        return {
            "config_dir": str(self.config_dir),
            "users_file": str(self.users_file),
            "settings_file": str(self.settings_file),
            "backup_dir": str(self.backup_dir)
        }

class ModernStyle:
    """Modern dark theme styling constants"""
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
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 500;
            min-width: 80px;
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
    """Background thread for running the Roblox manager"""
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(dict)
    process_signal = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running = False
        self.manager = None
        self.process_mgr = None
        self.launcher = None
        self.user_states = {}
        self.timing_trackers = {}

    def initialize_manager(self):
        """Initialize the Roblox manager components"""
        try:
            self.manager = RobloxManager()
            self.process_mgr = ProcessManager(self.manager.excluded_pid)
            self.launcher = GameLauncher(
                self.manager.target_place,
                self.process_mgr,
                self.manager.auth_handler,
                self.manager.process_tracker
            )

            self.user_states = {user_id: {
                "last_active": 0,
                "inactive_since": None,
                "user_info": user_info,
                "requires_restart": False,
                "status": "Initializing",
                "last_check": 0
            } for user_id, user_info in self.manager.settings.items()}

            self.timing_trackers = {
                'window_check': 0,
                'relaunch': 0,
                'cleanup': 0,
                'orphan_check': 0
            }

            return True
        except Exception as e:
            self.log_signal.emit(f"Failed to initialize manager: {e}")
            return False

    def restart_user_session(self, user_id):
        """Restart a specific user session"""
        if not self.manager or user_id not in self.user_states:
            return False

        try:
            state = self.user_states[user_id]
            self.log_signal.emit(f"Manually restarting session for user {user_id}")

            for pid in self.manager.process_tracker.user_processes.get(user_id, []):
                if self.process_mgr.verify_process_active(pid):
                    self.process_mgr.terminate_process(pid, self.manager.process_tracker)

            cookie = state["user_info"].get("cookie", "") if isinstance(state["user_info"], dict) else state["user_info"]
            try:
                if self.launcher.start_game_session(user_id, cookie, state["user_info"]):
                    self.user_states[user_id]["inactive_since"] = None
                    self.user_states[user_id]["requires_restart"] = False
                    self.user_states[user_id]["status"] = "Restarting"
                    self.log_signal.emit(f"Successfully restarted session for user {user_id}")
                    return True
                else:
                    self.log_signal.emit(f"Failed to restart session for user {user_id}")
                    return False
            except Exception as e:
                self.log_signal.emit(f"Error during session restart for user {user_id}: {e}")
                return False
        except Exception as e:
            self.log_signal.emit(f"Error restarting user {user_id}: {e}")
            return False

    def kill_user_processes(self, user_id):
        """Kill all processes for a specific user"""
        if not self.manager or user_id not in self.user_states:
            return False

        try:
            killed_count = 0
            for pid in self.manager.process_tracker.user_processes.get(user_id, []).copy():
                if self.process_mgr.verify_process_active(pid):
                    if self.process_mgr.terminate_process(pid, self.manager.process_tracker):
                        killed_count += 1

            self.log_signal.emit(f"Killed {killed_count} processes for user {user_id}")
            return True
        except Exception as e:
            self.log_signal.emit(f"Error killing processes for user {user_id}: {e}")
            return False

    def kill_all_processes(self):
        """Kill all Roblox processes"""
        if not self.process_mgr:
            return False

        try:
            killed = self.process_mgr.terminate_process(None, self.manager.process_tracker)
            if killed:
                self.log_signal.emit("All Roblox processes terminated")
            else:
                self.log_signal.emit("No Roblox processes found to terminate")
            return killed
        except Exception as e:
            self.log_signal.emit(f"Error killing all processes: {e}")
            return False

    def cleanup_dead_processes(self):
        """Cleanup dead processes"""
        if not self.process_mgr:
            return False

        try:
            self.process_mgr.cleanup_dead_processes(self.manager.process_tracker)
            self.log_signal.emit("Dead processes cleaned up")
            return True
        except Exception as e:
            self.log_signal.emit(f"Error cleaning up processes: {e}")
            return False

    def run(self):
        """Main worker thread loop"""
        if not self.initialize_manager():
            return

        self.running = True
        self.log_signal.emit("Roblox Manager started successfully")

        try:
            self.launcher.initialize_all_sessions(self.manager.settings)
            self.log_signal.emit(f"Initialized {len(self.manager.settings)} user sessions")
        except Exception as e:
            self.log_signal.emit(f"Failed to initialize sessions: {e}")

        while self.running:
            current_timestamp = time.time()

            try:

                if current_timestamp - self.timing_trackers['cleanup'] >= self.manager.check_intervals['cleanup']:
                    self.process_mgr.cleanup_dead_processes(self.manager.process_tracker)
                    self.timing_trackers['cleanup'] = current_timestamp

                if current_timestamp - self.timing_trackers['orphan_check'] >= (self.manager.check_intervals['cleanup'] * 2):
                    self.log_signal.emit("[ORPHAN CHECK] Starting orphan process cleanup...")
                    eliminated = self.process_mgr.eliminate_orphaned_processes(
                        self.manager.process_tracker,
                        set(self.manager.settings.keys())
                    )
                    if eliminated:
                        self.log_signal.emit("[ORPHAN CHECK] Eliminated orphaned processes")
                    else:
                        self.log_signal.emit("[ORPHAN CHECK] No orphaned processes found")
                    self.timing_trackers['orphan_check'] = current_timestamp

                if current_timestamp - self.timing_trackers['window_check'] >= self.manager.check_intervals['window']:
                    window_counts = self.process_mgr.count_windows_by_process()

                    process_data = {}
                    for pid, user_id in self.manager.process_tracker.process_owners.items():
                        if self.process_mgr.verify_process_active(pid):
                            create_time = self.manager.process_tracker.creation_timestamps.get(pid, 0)
                            window_count = window_counts.get(pid, 0)
                            process_data[pid] = {
                                'user_id': user_id,
                                'created': datetime.fromtimestamp(create_time).strftime("%H:%M:%S") if create_time else "Unknown",
                                'windows': window_count
                            }

                    self.process_signal.emit(process_data)

                    for pid, count in window_counts.items():
                        if count > self.manager.window_limit and pid != self.manager.excluded_pid:
                            user_id = self.manager.process_tracker.process_owners.get(pid, "Unknown")
                            self.log_signal.emit(f"PID {pid} (User: {user_id}) exceeded window limit ({count})! Terminating...")
                            self.process_mgr.terminate_process(pid, self.manager.process_tracker)

                    self.timing_trackers['window_check'] = current_timestamp

                status_data = {}
                for user_id, state in self.user_states.items():

                    if current_timestamp - state.get("last_check", 0) < 3:

                        status_data[user_id] = {
                            'status': state.get('status', 'Unknown'),
                            'pids': self.manager.process_tracker.user_processes.get(user_id, []),
                            'needs_restart': state.get("requires_restart", False),
                            'last_active': state.get("last_active", 0),
                            'inactive_since': state.get("inactive_since")
                        }
                        continue

                    cookie = state["user_info"].get("cookie", "") if isinstance(state["user_info"], dict) else state["user_info"]
                    activity_status = self.manager.presence_monitor.check_user_activity(
                        user_id, cookie, self.manager.auth_handler
                    )

                    state["last_check"] = current_timestamp

                    if activity_status is None:

                        status_data[user_id] = {
                            'status': state.get('status', 'API Error'),
                            'pids': self.manager.process_tracker.user_processes.get(user_id, []),
                            'needs_restart': state.get("requires_restart", False),
                            'last_active': state.get("last_active", 0),
                            'inactive_since': state.get("inactive_since")
                        }
                        continue

                    if activity_status:
                        self.user_states[user_id]["last_active"] = current_timestamp
                        self.user_states[user_id]["inactive_since"] = None
                        self.user_states[user_id]["requires_restart"] = False
                        self.user_states[user_id]["status"] = "Active"
                        status = "Active"
                    else:
                        if self.user_states[user_id]["inactive_since"] is None:
                            self.user_states[user_id]["inactive_since"] = current_timestamp

                        inactive_duration = current_timestamp - self.user_states[user_id]["inactive_since"]
                        if inactive_duration >= self.manager.timeouts['offline']:
                            if not self.user_states[user_id]["requires_restart"]:
                                self.user_states[user_id]["requires_restart"] = True
                                self.log_signal.emit(f"User {user_id} marked for restart after {int(inactive_duration)}s offline")

                        status = f"Inactive ({int(inactive_duration)}s)"
                        self.user_states[user_id]["status"] = status

                    pids = self.manager.process_tracker.user_processes.get(user_id, [])

                    status_data[user_id] = {
                        'status': status,
                        'pids': pids,
                        'needs_restart': self.user_states[user_id]["requires_restart"],
                        'last_active': self.user_states[user_id]["last_active"],
                        'inactive_since': self.user_states[user_id]["inactive_since"]
                    }

                self.status_signal.emit(status_data)

                restart_candidates = [user_id for user_id, state in self.user_states.items()
                                    if state["requires_restart"]]

                if restart_candidates and (current_timestamp - self.timing_trackers['relaunch']) >= self.manager.timeouts['launch_delay']:
                    target_user = restart_candidates[0]
                    target_state = self.user_states[target_user]

                    self.log_signal.emit(f"Auto-restarting session for user {target_user}...")

                    running_pids = []
                    for pid in self.manager.process_tracker.user_processes.get(target_user, []):
                        if self.process_mgr.verify_process_active(pid):
                            running_pids.append(pid)

                    if running_pids:
                        self.log_signal.emit(f"Terminating {len(running_pids)} existing processes for user {target_user}")
                        for pid in running_pids:
                            self.process_mgr.terminate_process(pid, self.manager.process_tracker)

                    target_cookie = target_state["user_info"].get("cookie", "") if isinstance(target_state["user_info"], dict) else target_state["user_info"]
                    try:
                        if self.launcher.start_game_session(target_user, target_cookie, target_state["user_info"]):
                            self.user_states[target_user]["inactive_since"] = None
                            self.user_states[target_user]["requires_restart"] = False
                            self.user_states[target_user]["status"] = "Restarting"
                            self.timing_trackers['relaunch'] = current_timestamp
                            self.log_signal.emit(f"Successfully restarted session for user {target_user}")
                        else:
                            self.log_signal.emit(f"Failed to restart session for user {target_user}")
                    except Exception as e:
                        self.log_signal.emit(f"Error during auto-restart for user {target_user}: {e}")

            except Exception as error:
                self.log_signal.emit(f"[WORKER ERROR] {error}")

            time.sleep(self.manager.check_intervals['presence'])

    def stop(self):
        """Stop the worker thread"""
        self.running = False
        self.log_signal.emit("Roblox Manager stopped")

class UserManagementDialog(QDialog):
    """Dialog for managing user accounts"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("User Account Management")
        self.setModal(True)
        self.resize(800, 500)
        self.config_manager = ConfigManager()
        self.setup_ui()
        self.load_users()
        self.original_config = {}

    def setup_ui(self):
        layout = QVBoxLayout(self)

        self.user_table = QTableWidget()
        self.user_table.setColumnCount(6)
        self.user_table.setHorizontalHeaderLabels(["User ID", "Username", "Private Server Link", "Place", "Cookie", "Actions"])
        header = self.user_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)           
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)           
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  
        layout.addWidget(self.user_table)

        add_group = QGroupBox("Add New User")
        add_layout = QFormLayout(add_group)

        self.user_id_input = QLineEdit()
        self.user_id_input.setPlaceholderText("Enter user ID (e.g., 123456789)")
        add_layout.addRow("User ID:", self.user_id_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username (e.g., PlayerName)")
        add_layout.addRow("Username:", self.username_input)

        self.private_server_input = QLineEdit()
        self.private_server_input.setPlaceholderText("Enter private server link (required) - Supports both direct links and share links")
        add_layout.addRow("Private Server Link:", self.private_server_input)

        self.place_input = QLineEdit()
        self.place_input.setPlaceholderText("Enter place/game name (optional)")
        add_layout.addRow("Place:", self.place_input)

        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("Enter .ROBLOSECURITY cookie")
        add_layout.addRow("Cookie:", self.cookie_input)

        add_btn = QPushButton("Add User")
        add_btn.clicked.connect(self.add_user)
        add_layout.addRow(add_btn)

        layout.addWidget(add_group)

        controls_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh Table")
        refresh_btn.clicked.connect(self.refresh_user_table)
        controls_layout.addWidget(refresh_btn)

        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.save_and_close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def load_users(self):
        """Load users from config file"""
        try:
            self.original_config = self.config_manager.load_users()
            self.refresh_user_table()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load users: {e}")
            self.original_config = {}
            self.refresh_user_table()

    def refresh_user_table(self):
        """Refresh the user table display"""
        self.user_table.setRowCount(len(self.original_config))

        for row, (user_id, user_info) in enumerate(self.original_config.items()):

            self.user_table.setItem(row, 0, QTableWidgetItem(user_id))

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

            self.user_table.setItem(row, 1, QTableWidgetItem(username))

            display_private_server = private_server_link[:30] + "..." if len(private_server_link) > 30 else private_server_link
            self.user_table.setItem(row, 2, QTableWidgetItem(display_private_server))

            self.user_table.setItem(row, 3, QTableWidgetItem(place))

            display_cookie = cookie[:20] + "..." if len(cookie) > 20 else cookie
            self.user_table.setItem(row, 4, QTableWidgetItem(display_cookie))

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)
            actions_layout.setSpacing(4)

            edit_btn = QPushButton("Edit")
            edit_btn.setMaximumWidth(60)
            edit_btn.clicked.connect(lambda checked, uid=user_id: self.edit_user(uid))
            actions_layout.addWidget(edit_btn)

            delete_btn = QPushButton("Delete")
            delete_btn.setProperty("class", "danger")
            delete_btn.setMaximumWidth(70)
            delete_btn.clicked.connect(lambda checked, uid=user_id: self.delete_user_by_id(uid))
            actions_layout.addWidget(delete_btn)

            self.user_table.setCellWidget(row, 5, actions_widget)

    def add_user(self):
        """Add a new user"""
        user_id = self.user_id_input.text().strip()
        username = self.username_input.text().strip()
        private_server_link = self.private_server_input.text().strip()
        place = self.place_input.text().strip()
        cookie = self.cookie_input.text().strip()

        if not user_id:
            QMessageBox.warning(self, "Error", "Please enter a User ID")
            self.user_id_input.setFocus()
            return

        if not private_server_link:
            QMessageBox.warning(self, "Error", "Please enter a Private Server Link")
            self.private_server_input.setFocus()
            return

        if not cookie:
            QMessageBox.warning(self, "Error", "Please enter a Cookie")
            self.cookie_input.setFocus()
            return

        if not user_id.isdigit():
            QMessageBox.warning(self, "Error", "User ID should be numeric (e.g., 123456789)")
            self.user_id_input.setFocus()
            return

        if not username:
            username = f"User_{user_id}"  

        if user_id in self.original_config:
            QMessageBox.warning(self, "Error", f"User ID {user_id} already exists. Use Edit to modify existing users.")
            self.user_id_input.setFocus()
            return

        import re

        pattern1 = r'roblox\.com/games/\d+/[^?]*\?privateServerLinkCode=[A-Za-z0-9_-]+'

        pattern2 = r'roblox\.com/share\?code=[A-Za-z0-9_-]+&type=Server'

        if not (re.search(pattern1, private_server_link) or re.search(pattern2, private_server_link)):
            reply = QMessageBox.question(self, "Private Server Link Warning",
                                       "The private server link doesn't appear to be in the expected format.\n\n"
                                       "Supported formats:\n"
                                       "• Direct Link: https://www.roblox.com/games/[ID]/[NAME]?privateServerLinkCode=[CODE]\n"
                                       "• Share Link: https://www.roblox.com/share?code=[CODE]&type=Server\n\n"
                                       "Share links will be automatically resolved using the Roblox API when launching.\n"
                                       "This provides direct client launching without browser interaction.\n\n"
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
                "cookie": cookie
            }

            self.user_id_input.clear()
            self.username_input.clear()
            self.private_server_input.clear()
            self.place_input.clear()
            self.cookie_input.clear()

            self.refresh_user_table()

            QMessageBox.information(self, "Success", f"User {user_id} ({username}) added successfully!")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add user: {e}")

    def edit_user(self, user_id):
        """Edit an existing user"""
        if user_id not in self.original_config:
            QMessageBox.warning(self, "Error", f"User {user_id} not found!")
            return

        user_info = self.original_config[user_id]
        if isinstance(user_info, dict):
            current_username = user_info.get("username", f"User_{user_id}")
            current_private_server_link = user_info.get("private_server_link", "")
            current_place = user_info.get("place", "")
            current_cookie = user_info.get("cookie", "")
        else:

            current_username = f"User_{user_id}"
            current_private_server_link = ""
            current_place = ""
            current_cookie = user_info

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit User {user_id}")
        dialog.setModal(True)
        dialog.resize(400, 200)

        layout = QVBoxLayout(dialog)

        form_layout = QFormLayout()

        user_id_label = QLabel(user_id)
        user_id_label.setStyleSheet("font-weight: bold; color: #666;")
        form_layout.addRow("User ID:", user_id_label)

        username_edit = QLineEdit(current_username)
        username_edit.setPlaceholderText("Enter username")
        form_layout.addRow("Username:", username_edit)

        private_server_edit = QLineEdit(current_private_server_link)
        private_server_edit.setPlaceholderText("Enter private server link")
        form_layout.addRow("Private Server Link:", private_server_edit)

        place_edit = QLineEdit(current_place)
        place_edit.setPlaceholderText("Enter place/game name")
        form_layout.addRow("Place:", place_edit)

        cookie_edit = QLineEdit(current_cookie)
        cookie_edit.setPlaceholderText("Enter .ROBLOSECURITY cookie")
        form_layout.addRow("Cookie:", cookie_edit)

        layout.addLayout(form_layout)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_username = username_edit.text().strip()
            new_private_server_link = private_server_edit.text().strip()
            new_place = place_edit.text().strip()
            new_cookie = cookie_edit.text().strip()

            if not new_username:
                new_username = f"User_{user_id}"

            if not new_private_server_link:
                QMessageBox.warning(self, "Error", "Private server link cannot be empty!")
                return

            if not new_cookie:
                QMessageBox.warning(self, "Error", "Cookie cannot be empty!")
                return

            self.original_config[user_id] = {
                "username": new_username,
                "private_server_link": new_private_server_link,
                "place": new_place,
                "cookie": new_cookie
            }

            self.refresh_user_table()

            QMessageBox.information(self, "Success", f"User {user_id} updated successfully!")

    def delete_user_by_id(self, user_id):
        """Delete a user by user ID"""

        user_info = self.original_config.get(user_id, {})
        if isinstance(user_info, dict):
            username = user_info.get("username", f"User_{user_id}")
        else:
            username = f"User_{user_id}"

        reply = QMessageBox.question(self, "Confirm Delete",
                                   f"Are you sure you want to delete user {user_id} ({username})?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:

            if user_id in self.original_config:
                del self.original_config[user_id]

                self.refresh_user_table()
                QMessageBox.information(self, "Success", f"User {user_id} ({username}) deleted successfully!")
            else:
                QMessageBox.warning(self, "Error", f"User {user_id} not found in configuration!")

    def delete_user(self, row):
        """Delete a user by row (legacy method for compatibility)"""
        if row >= self.user_table.rowCount():
            return

        user_id_item = self.user_table.item(row, 0)
        if not user_id_item:
            return

        user_id = user_id_item.text()
        self.delete_user_by_id(user_id)

    def save_and_close(self):
        """Save users to config file and close"""
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

class SettingsDialog(QDialog):
    """Dialog for application settings"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(500, 400)
        self.config_manager = ConfigManager()
        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        game_group = QGroupBox("Game Settings")
        game_layout = QFormLayout(game_group)

        place_id_label = QLabel("Place ID:")
        place_id_label.setToolTip("The Roblox place ID to launch (e.g., 85896571713843)")
        self.place_id_input = QLineEdit()
        self.place_id_input.setPlaceholderText("Enter Roblox Place ID (e.g., 85896571713843)")
        self.place_id_input.setToolTip("The ID of the Roblox place/game to launch for all users")
        game_layout.addRow(place_id_label, self.place_id_input)

        self.window_limit_input = QSpinBox()
        self.window_limit_input.setRange(1, 10)
        self.window_limit_input.setToolTip("Maximum number of windows allowed per Roblox process")
        game_layout.addRow("Window Limit:", self.window_limit_input)

        self.excluded_pid_input = QSpinBox()
        self.excluded_pid_input.setRange(0, 999999)
        self.excluded_pid_input.setToolTip("Process ID to exclude from management (0 = none)")
        game_layout.addRow("Excluded PID:", self.excluded_pid_input)

        layout.addWidget(game_group)

        timing_group = QGroupBox("Timing Settings")
        timing_layout = QFormLayout(timing_group)

        self.window_check_input = QDoubleSpinBox()
        self.window_check_input.setRange(0.1, 60.0)
        self.window_check_input.setSuffix(" seconds")
        timing_layout.addRow("Window Check Interval:", self.window_check_input)

        self.presence_check_input = QDoubleSpinBox()
        self.presence_check_input.setRange(0.1, 10.0)
        self.presence_check_input.setSuffix(" seconds")
        timing_layout.addRow("Presence Check Interval:", self.presence_check_input)

        self.cleanup_interval_input = QDoubleSpinBox()
        self.cleanup_interval_input.setRange(1.0, 300.0)
        self.cleanup_interval_input.setSuffix(" seconds")
        timing_layout.addRow("Cleanup Interval:", self.cleanup_interval_input)

        layout.addWidget(timing_group)

        timeout_group = QGroupBox("Timeout Settings")
        timeout_layout = QFormLayout(timeout_group)

        self.relaunch_timeout_input = QSpinBox()
        self.relaunch_timeout_input.setRange(5, 120)
        self.relaunch_timeout_input.setSuffix(" seconds")
        timeout_layout.addRow("Relaunch Timeout:", self.relaunch_timeout_input)

        self.offline_threshold_input = QSpinBox()
        self.offline_threshold_input.setRange(10, 300)
        self.offline_threshold_input.setSuffix(" seconds")
        timeout_layout.addRow("Offline Threshold:", self.offline_threshold_input)

        self.launch_delay_input = QSpinBox()
        self.launch_delay_input.setRange(1, 30)
        self.launch_delay_input.setSuffix(" seconds")
        timeout_layout.addRow("Launch Delay:", self.launch_delay_input)

        layout.addWidget(timeout_group)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.save_and_close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def load_settings(self):
        """Load current settings"""
        settings = self.config_manager.load_settings()

        self.place_id_input.setText(settings.get("place_id", "85896571713843"))
        self.window_limit_input.setValue(settings.get("window_limit", 1))
        self.excluded_pid_input.setValue(settings.get("excluded_pid", 0))

        check_intervals = settings.get("check_intervals", {})
        self.window_check_input.setValue(check_intervals.get("window", 3.0))
        self.presence_check_input.setValue(check_intervals.get("presence", 1.5))
        self.cleanup_interval_input.setValue(check_intervals.get("cleanup", 30.0))

        timeouts = settings.get("timeouts", {})
        self.relaunch_timeout_input.setValue(timeouts.get("relaunch", 20))
        self.offline_threshold_input.setValue(timeouts.get("offline", 35))
        self.launch_delay_input.setValue(timeouts.get("launch_delay", 4))

    def save_and_close(self):
        """Save settings and close"""
        settings = {
            "place_id": self.place_id_input.text(),
            "window_limit": self.window_limit_input.value(),
            "excluded_pid": self.excluded_pid_input.value(),
            "check_intervals": {
                "window": self.window_check_input.value(),
                "presence": self.presence_check_input.value(),
                "cleanup": self.cleanup_interval_input.value()
            },
            "timeouts": {
                "relaunch": self.relaunch_timeout_input.value(),
                "offline": self.offline_threshold_input.value(),
                "launch_delay": self.launch_delay_input.value()
            }
        }

        if self.config_manager.save_settings(settings):
            config_info = self.config_manager.get_config_info()
            QMessageBox.information(self, "Success",
                                  f"Settings saved successfully!\n\n"
                                  f"Location: {config_info['settings_file']}\n"
                                  f"Backup created in: {config_info['backup_dir']}")
            self.accept()
        else:
            QMessageBox.critical(self, "Error",
                               "Failed to save settings. Please check the logs for details.")

class RobloxManagerGUI(QMainWindow):
    """Main GUI window for Roblox Manager"""

    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.process_data = {}
        self.config_manager = ConfigManager()
        self.setup_ui()
        self.setup_timers()

    def setup_ui(self):
        """Setup the main user interface"""
        self.setWindowTitle("JARAM - Just Another Roblox Account Manager")
        self.setGeometry(100, 100, 1200, 800)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        header_layout = QHBoxLayout()

        title_label = QLabel("JARAM - Just Another Roblox Account Manager")
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
        self.setup_credits_tab()

        self.setup_menu_bar()

        self.setStyleSheet(ModernStyle.get_stylesheet())

        self.start_time = None
        self.user_data = {}

    def setup_menu_bar(self):
        """Setup the menu bar"""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")

        manage_users_action = file_menu.addAction("Manage Users")
        manage_users_action.triggered.connect(self.open_user_management)

        file_menu.addSeparator()

        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)

        settings_menu = menubar.addMenu("Settings")

        preferences_action = settings_menu.addAction("Preferences")
        preferences_action.triggered.connect(self.open_settings)

        help_menu = menubar.addMenu("Help")

        config_location_action = help_menu.addAction("Show Config Location")
        config_location_action.triggered.connect(self.show_config_location)

        help_menu.addSeparator()

        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)

    def setup_dashboard_tab(self):
        """Setup the main dashboard tab"""
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
        """Setup the users monitoring tab"""
        users_widget = QWidget()
        layout = QVBoxLayout(users_widget)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(9)
        self.users_table.setHorizontalHeaderLabels([
            "User ID", "Username", "Private Server", "Place", "Status", "PIDs", "Last Active", "Inactive Duration", "Actions"
        ])

        header = self.users_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)           
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)           
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)  

        layout.addWidget(self.users_table)

        controls_layout = QHBoxLayout()

        refresh_users_btn = QPushButton("Refresh")
        refresh_users_btn.clicked.connect(self.refresh_users)
        controls_layout.addWidget(refresh_users_btn)

        add_user_btn = QPushButton("Add User")
        add_user_btn.clicked.connect(self.open_user_management)
        controls_layout.addWidget(add_user_btn)

        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        self.tab_widget.addTab(users_widget, "Users")

    def setup_processes_tab(self):
        """Setup the processes monitoring tab"""
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
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

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
        """Setup the logs tab"""
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

        self.auto_scroll_checkbox = QCheckBox("Auto-scroll")
        self.auto_scroll_checkbox.setChecked(True)
        controls_layout.addWidget(self.auto_scroll_checkbox)

        layout.addLayout(controls_layout)

        self.tab_widget.addTab(logs_widget, "Logs")

    def setup_settings_tab(self):
        """Setup the settings tab"""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)

        info_label = QLabel("Configure settings")
        info_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY}; margin-bottom: 10px;")
        layout.addWidget(info_label)

        settings_btn = QPushButton("Open Settings")
        settings_btn.clicked.connect(self.open_settings)
        layout.addWidget(settings_btn)

        layout.addStretch()

        self.tab_widget.addTab(settings_widget, "Settings")

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
        developer_layout = QVBoxLayout(developer_group)
        developer_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        dev_container = QWidget()
        dev_container_layout = QVBoxLayout(dev_container)
        dev_container_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dev_container_layout.setSpacing(15)

        pfp_label = QLabel()
        pfp_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pfp_label.setFixedSize(120, 120)
        pfp_label.setStyleSheet(f"""
            QLabel {{
                border: 3px solid {ModernStyle.PRIMARY};
                border-radius: 60px;
                background-color: {ModernStyle.SURFACE};
            }}
        """)

        try:
            import urllib.request
            pfp_url = "https://raw.githubusercontent.com/cresqnt-sys/MultiScope/refs/heads/main/cresqnt.png"

            with urllib.request.urlopen(pfp_url) as response:
                image_data = response.read()

            pixmap = QPixmap()
            pixmap.loadFromData(image_data)

            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(114, 114, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)

                rounded_pixmap = QPixmap(114, 114)
                rounded_pixmap.fill(Qt.GlobalColor.transparent)

                painter = QPainter(rounded_pixmap)
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                painter.setBrush(QColor(0, 0, 0))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(0, 0, 114, 114)
                painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
                painter.drawPixmap(0, 0, scaled_pixmap)
                painter.end()

                pfp_label.setPixmap(rounded_pixmap)
            else:
                pfp_label.setText("No Image")
                pfp_label.setStyleSheet(f"""
                    QLabel {{
                        border: 3px solid {ModernStyle.PRIMARY};
                        border-radius: 60px;
                        background-color: {ModernStyle.SURFACE};
                        color: {ModernStyle.TEXT_SECONDARY};
                    }}
                """)
        except Exception:
            pfp_label.setText("Error\nLoading\nImage")
            pfp_label.setStyleSheet(f"""
                QLabel {{
                    border: 3px solid {ModernStyle.PRIMARY};
                    border-radius: 60px;
                    background-color: {ModernStyle.SURFACE};
                    color: {ModernStyle.TEXT_SECONDARY};
                }}
            """)

        dev_container_layout.addWidget(pfp_label)

        dev_label = QLabel("cresqnt")
        dev_font = QFont()
        dev_font.setPointSize(16)
        dev_font.setBold(True)
        dev_label.setFont(dev_font)
        dev_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dev_label.setStyleSheet(f"color: {ModernStyle.SECONDARY}; margin: 0;")
        dev_container_layout.addWidget(dev_label)

        developer_layout.addWidget(dev_container)

        content_layout.addWidget(developer_group)

        support_group = QGroupBox("Support")
        support_layout = QVBoxLayout(support_group)

        support_label = QLabel("Discord Support Server:")
        support_label.setStyleSheet(f"color: {ModernStyle.TEXT_PRIMARY}; font-weight: bold; margin-bottom: 5px;")
        support_layout.addWidget(support_label)

        discord_btn = QPushButton("https://discord.gg/6cuCu6ymkX")
        discord_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #5865F2;
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 6px;
                font-weight: bold;
                text-align: left;
            }}
            QPushButton:hover {{
                background-color: #4752C4;
            }}
        """)
        discord_btn.clicked.connect(lambda: self.open_url("https://discord.gg/6cuCu6ymkX"))
        support_layout.addWidget(discord_btn)

        content_layout.addWidget(support_group)

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

    def open_url(self, url):
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open URL: {e}")

    def setup_timers(self):
        """Setup update timers"""

        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(1000)  

        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self.update_uptime)
        self.uptime_timer.start(1000)

    def start_manager(self):
        """Start the Roblox manager"""
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

        self.worker_thread = WorkerThread()
        self.worker_thread.log_signal.connect(self.add_log)
        self.worker_thread.status_signal.connect(self.update_user_status)
        self.worker_thread.process_signal.connect(self.update_process_data)
        self.worker_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Running")
        self.status_label.setStyleSheet(f"color: {ModernStyle.SECONDARY}; font-weight: bold;")
        self.start_time = time.time()

        self.add_log("Roblox Manager started")

    def stop_manager(self):
        """Stop the Roblox manager"""
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop()
            self.worker_thread.wait()

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Stopped")
        self.status_label.setStyleSheet(f"color: {ModernStyle.ERROR}; font-weight: bold;")
        self.start_time = None

        self.add_log("Roblox Manager stopped")

    def update_uptime(self):
        """Update the uptime display"""
        if self.start_time:
            uptime = time.time() - self.start_time
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            seconds = int(uptime % 60)
            self.uptime_label.setText(f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.uptime_label.setText("Uptime: 00:00:00")

    def update_ui(self):
        """Update UI elements"""

        total_users = len(self.user_data)
        active_users = sum(1 for data in self.user_data.values() if data.get('status') == 'Active')
        total_processes = sum(len(data.get('pids', [])) for data in self.user_data.values())
        pending_restarts = sum(1 for data in self.user_data.values() if data.get('needs_restart', False))

        self.total_users_label.setText(str(total_users))
        self.active_users_label.setText(str(active_users))
        self.total_processes_label.setText(str(total_processes))
        self.pending_restarts_label.setText(str(pending_restarts))

    def update_user_status(self, status_data):
        """Update user status from worker thread"""
        self.user_data = status_data
        self.refresh_users()

    def update_process_data(self, process_data):
        """Update process data from worker thread"""
        self.process_data = process_data
        self.refresh_processes()

    def refresh_users(self):
        """Refresh the users table"""
        self.users_table.setRowCount(len(self.user_data))

        users_config = self.config_manager.load_users()

        for row, (user_id, data) in enumerate(self.user_data.items()):

            self.users_table.setItem(row, 0, QTableWidgetItem(user_id))

            user_info = users_config.get(user_id, {})
            if isinstance(user_info, dict):
                username = user_info.get("username", f"User_{user_id}")
                private_server_link = user_info.get("private_server_link", "")
                place = user_info.get("place", "")
            else:
                username = f"User_{user_id}"
                private_server_link = ""
                place = ""

            self.users_table.setItem(row, 1, QTableWidgetItem(username))

            display_private_server = private_server_link[:25] + "..." if len(private_server_link) > 25 else private_server_link
            self.users_table.setItem(row, 2, QTableWidgetItem(display_private_server))

            self.users_table.setItem(row, 3, QTableWidgetItem(place))

            status_item = QTableWidgetItem(data.get('status', 'Unknown'))
            if 'Active' in data.get('status', ''):
                status_item.setForeground(QColor(ModernStyle.SECONDARY))
            elif 'Inactive' in data.get('status', ''):
                status_item.setForeground(QColor(ModernStyle.WARNING))
            elif 'Restarting' in data.get('status', ''):
                status_item.setForeground(QColor(ModernStyle.PRIMARY))
            else:
                status_item.setForeground(QColor(ModernStyle.ERROR))
            self.users_table.setItem(row, 4, status_item)

            pids = data.get('pids', [])
            pids_text = ', '.join(map(str, pids)) if pids else 'None'
            self.users_table.setItem(row, 5, QTableWidgetItem(pids_text))

            last_active = data.get('last_active', 0)
            if last_active > 0:
                last_active_str = datetime.fromtimestamp(last_active).strftime("%H:%M:%S")
            else:
                last_active_str = "Never"
            self.users_table.setItem(row, 6, QTableWidgetItem(last_active_str))

            inactive_since = data.get('inactive_since')
            if inactive_since:
                duration = int(time.time() - inactive_since)
                duration_str = f"{duration}s"
            else:
                duration_str = "N/A"
            self.users_table.setItem(row, 7, QTableWidgetItem(duration_str))

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)

            restart_btn = QPushButton("Restart")
            restart_btn.setMaximumWidth(80)
            restart_btn.clicked.connect(lambda checked, uid=user_id: self.restart_user_session(uid))
            actions_layout.addWidget(restart_btn)

            kill_btn = QPushButton("Kill")
            kill_btn.setProperty("class", "danger")
            kill_btn.setMaximumWidth(60)
            kill_btn.clicked.connect(lambda checked, uid=user_id: self.kill_user_processes(uid))
            actions_layout.addWidget(kill_btn)

            self.users_table.setCellWidget(row, 8, actions_widget)

    def refresh_processes(self):
        """Refresh the processes table"""
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
            actions_layout.setContentsMargins(4, 4, 4, 4)

            kill_btn = QPushButton("Kill")
            kill_btn.setProperty("class", "danger")
            kill_btn.setMaximumWidth(60)
            kill_btn.clicked.connect(lambda checked, p=pid: self.kill_specific_process(p))
            actions_layout.addWidget(kill_btn)

            self.processes_table.setCellWidget(row, 4, actions_widget)

    def add_log(self, message):
        """Add a log message"""
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
        """Clear the log display"""
        self.log_display.clear()

    def save_logs(self):
        """Save logs to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"roblox_manager_logs_{timestamp}.txt"

            with open(filename, 'w') as f:
                f.write(self.log_display.toPlainText())

            QMessageBox.information(self, "Success", f"Logs saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save logs: {e}")

    def open_user_management(self):
        """Open user management dialog"""
        dialog = UserManagementDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.add_log("User configuration updated")

    def open_settings(self):
        """Open settings dialog"""
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.add_log("Settings updated")

    def show_config_location(self):
        """Show configuration location dialog"""
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
        """Show about dialog"""
        config_info = self.config_manager.get_config_info()
        QMessageBox.about(self, "About JARAM",
                         "JARAM (Just Another Roblox Account Manager) v1.0\n\n"
                         "Advanced multi-account Roblox session manager\n"
                         "with automated presence monitoring and process management.\n\n"
                         "Built with PyQt6 and modern design principles.\n\n"
                         f"Configuration stored in:\n{config_info['config_dir']}")

    def restart_all_sessions(self):
        """Restart all user sessions"""
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Restart",
                                   "Are you sure you want to restart all sessions?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.add_log("Restarting all sessions...")
            for user_id in self.user_data.keys():
                self.worker_thread.restart_user_session(user_id)

    def kill_all_processes(self):
        """Kill all Roblox processes"""
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Kill All",
                                   "Are you sure you want to kill ALL Roblox processes?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.worker_thread.kill_all_processes()

    def cleanup_processes(self):
        """Cleanup dead processes"""
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        self.worker_thread.cleanup_dead_processes()

    def restart_user_session(self, user_id):
        """Restart a specific user session"""
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        self.worker_thread.restart_user_session(user_id)

    def kill_user_processes(self, user_id):
        """Kill processes for a specific user"""
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Kill",
                                   f"Are you sure you want to kill processes for user {user_id}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.worker_thread.kill_user_processes(user_id)

    def kill_specific_process(self, pid):
        """Kill a specific process by PID"""
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Kill",
                                   f"Are you sure you want to kill process {pid}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if self.worker_thread.process_mgr:
                success = self.worker_thread.process_mgr.terminate_process(
                    int(pid), self.worker_thread.manager.process_tracker
                )
                if success:
                    self.add_log(f"Successfully killed process {pid}")
                else:
                    self.add_log(f"Failed to kill process {pid}")

    def kill_selected_process(self):
        """Kill the selected process"""
        current_row = self.processes_table.currentRow()
        if current_row >= 0:
            pid_item = self.processes_table.item(current_row, 0)
            if pid_item:
                pid = pid_item.text()
                self.kill_specific_process(pid)

    def closeEvent(self, event):
        """Handle application close event"""
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
    """Main application entry point"""
    app = QApplication(sys.argv)

    app.setApplicationName("Roblox Manager")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("Roblox Manager")

    window = RobloxManagerGUI()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()