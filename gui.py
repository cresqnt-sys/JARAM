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
                            QSpinBox, QTextEdit, QGroupBox,
                            QProgressBar, QComboBox, QCheckBox, QSplitter,
                            QHeaderView, QMessageBox, QDialog, QDialogButtonBox,
                            QFormLayout, QScrollArea, QFrame, QSizePolicy)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt, QSize
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter
from main import RobloxManager, ProcessManager, GameLauncher
from cookie_extractor import CookieExtractor

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
                    loaded_settings = json.load(f)

                    settings = self.default_settings.copy()
                    settings.update(loaded_settings)
                    return settings
            else:
                return self.default_settings.copy()
        except Exception as e:
            return self.default_settings.copy()

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
                    "place": ""
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
            return False

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

    def kill_user_processes(self, user_id):
        if not self.manager or user_id not in self.user_states:
            return False

        try:
            killed_count = 0
            for pid in self.manager.process_tracker.user_processes.get(user_id, []).copy():
                if self.process_mgr.verify_process_active(pid):
                    if self.process_mgr.terminate_process(pid, self.manager.process_tracker):
                        killed_count += 1

            return True
        except Exception as e:
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

        try:
            self.launcher.initialize_all_sessions(self.manager.settings)
        except Exception as e:
            pass

        while self.running:
            current_timestamp = time.time()

            try:

                if current_timestamp - self.timing_trackers['cleanup'] >= self.manager.check_intervals['cleanup']:
                    self.process_mgr.cleanup_dead_processes(self.manager.process_tracker)
                    self.timing_trackers['cleanup'] = current_timestamp

                if current_timestamp - self.timing_trackers['orphan_check'] >= (self.manager.check_intervals['cleanup'] * 2):
                    self.process_mgr.eliminate_orphaned_processes(
                        self.manager.process_tracker,
                        set(self.manager.settings.keys())
                    )
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

                    running_pids = []
                    for pid in self.manager.process_tracker.user_processes.get(target_user, []):
                        if self.process_mgr.verify_process_active(pid):
                            running_pids.append(pid)

                    if running_pids:
                        for pid in running_pids:
                            self.process_mgr.terminate_process(pid, self.manager.process_tracker)

                    target_cookie = target_state["user_info"].get("cookie", "") if isinstance(target_state["user_info"], dict) else target_state["user_info"]
                    try:
                        if self.launcher.start_game_session(target_user, target_cookie, target_state["user_info"]):
                            self.user_states[target_user]["inactive_since"] = None
                            self.user_states[target_user]["requires_restart"] = False
                            self.user_states[target_user]["status"] = "Restarting"
                            self.timing_trackers['relaunch'] = current_timestamp
                    except Exception as e:
                        pass

            except Exception as error:
                pass

            time.sleep(self.manager.check_intervals['presence'])

    def stop(self):
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
                background-color: {ModernStyle.SURFACE};
                border: 1px solid {ModernStyle.BORDER};
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
        self.private_server_input.setPlaceholderText("Enter private server link (required)")
        self.private_server_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(QLabel("Private Server Link:"))
        form_layout.addWidget(self.private_server_input)

        self.place_input = QLineEdit()
        self.place_input.setPlaceholderText("Enter place/game name (optional)")
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
            QMessageBox.warning(self, "Error", "Private server link cannot be empty!")
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
            "cookie": cookie
        }

        self.refresh_user_list()
        self.cancel_edit()
        QMessageBox.information(self, "Success", f"User {user_id} ({username}) updated successfully!")

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
            QMessageBox.warning(self, "Error", "Please enter a Private Server Link")
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
                "cookie": cookie
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

class RobloxManagerGUI(QMainWindow):

    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.process_data = {}
        self.config_manager = ConfigManager()
        self.setup_ui()
        self.setup_timers()

    def setup_ui(self):
        self.setWindowTitle("JARAM - Just Another Roblox Account Manager")
        self.setGeometry(100, 100, 1200, 800)

        icon_path = _get_icon_path()
        if icon_path and os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

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
        self.users_table.setColumnCount(9)
        self.users_table.setHorizontalHeaderLabels([
            "User ID", "Username", "Private Server", "Place", "Status", "PIDs", "Last Active", "Inactive Duration", "Actions"
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

        self.users_table.verticalHeader().setDefaultSectionSize(60)

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

        self.settings_offline_threshold_input = QSpinBox()
        self.settings_offline_threshold_input.setRange(15, 120)
        self.settings_offline_threshold_input.setSuffix(" seconds")
        self.settings_offline_threshold_input.setToolTip("How long to wait before restarting inactive users")
        timing_layout.addRow("Restart Inactive After:", self.settings_offline_threshold_input)

        self.settings_launch_delay_input = QSpinBox()
        self.settings_launch_delay_input.setRange(2, 15)
        self.settings_launch_delay_input.setSuffix(" seconds")
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

        buttons_layout.addStretch()

        content_layout.addLayout(buttons_layout)
        content_layout.addStretch()

        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)

        self.tab_widget.addTab(settings_widget, "Settings")

        self.load_settings_tab()

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

        total_users = len(self.user_data)
        active_users = sum(1 for data in self.user_data.values() if data.get('status') == 'Active')
        total_processes = sum(len(data.get('pids', [])) for data in self.user_data.values())
        pending_restarts = sum(1 for data in self.user_data.values() if data.get('needs_restart', False))

        self.total_users_label.setText(str(total_users))
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
                    min-width: 50px;
                    max-width: 60px;
                    min-height: 26px;
                    max-height: 28px;
                }}
                QPushButton:hover {{
                    background-color: {ModernStyle.PRIMARY_VARIANT};
                }}
            """)
            restart_btn.clicked.connect(lambda checked, uid=user_id: self.restart_user_session(uid))
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
                    background-color: 
                }}
            """)
            kill_btn.clicked.connect(lambda checked, uid=user_id: self.kill_user_processes(uid))
            actions_layout.addWidget(kill_btn)

            self.users_table.setCellWidget(row, 8, actions_widget)

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
        settings = self.config_manager.load_settings()

        self.settings_window_limit_input.setValue(settings.get("window_limit", 1))

        timeouts = settings.get("timeouts", {})
        self.settings_offline_threshold_input.setValue(timeouts.get("offline", 35))
        self.settings_launch_delay_input.setValue(timeouts.get("launch_delay", 4))

    def save_settings(self):
        settings = {
            "window_limit": self.settings_window_limit_input.value(),
            "timeouts": {
                "offline": self.settings_offline_threshold_input.value(),
                "launch_delay": self.settings_launch_delay_input.value()
            }
        }

        if self.config_manager.save_settings(settings):
            QMessageBox.information(self, "Success", "Settings saved successfully!")

        else:
            QMessageBox.critical(self, "Error", "Failed to save settings. Please check the logs for details.")

    def reset_settings(self):
        reply = QMessageBox.question(self, "Reset Settings",
                                   "Are you sure you want to reset all settings to defaults?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.settings_window_limit_input.setValue(1)
            self.settings_offline_threshold_input.setValue(35)
            self.settings_launch_delay_input.setValue(4)
            QMessageBox.information(self, "Reset Complete", "Settings have been reset to defaults. Click 'Save Settings' to apply.")

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
                         "JARAM (Just Another Roblox Account Manager) v1.0\n\n"
                         "Advanced multi-account Roblox session manager\n"
                         "with automated presence monitoring and process management.\n\n"
                         "Built with PyQt6 and modern design principles.\n\n"
                         f"Configuration stored in:\n{config_info['config_dir']}")

    def restart_all_sessions(self):
        if not self.worker_thread or not self.worker_thread.isRunning():
            QMessageBox.warning(self, "Manager Not Running", "Please start the manager first.")
            return

        reply = QMessageBox.question(self, "Confirm Restart",
                                   "Are you sure you want to restart all sessions?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for user_id in self.user_data.keys():
                self.worker_thread.restart_user_session(user_id)

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
    app.setApplicationVersion("1.0")
    app.setOrganizationName("cresqnt")

    icon_path = _get_icon_path()
    if icon_path and os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = RobloxManagerGUI()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()