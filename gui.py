import sys
import json
import time
import os
import shutil
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QGridLayout, QTabWidget, QTableWidget,
                            QTableWidgetItem, QPushButton, QLabel, QLineEdit,
                            QSpinBox, QTextEdit, QGroupBox, QStackedLayout,
                            QProgressBar, QComboBox, QCheckBox, QSplitter,
                            QHeaderView, QMessageBox, QDialog, QDialogButtonBox,
                            QFormLayout, QScrollArea, QFrame, QSizePolicy, QRadioButton)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt, QSize, QBuffer, QByteArray, QIODevice, QPointF, QPoint
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter, QMovie, QRegion, QPainterPath, QMouseEvent
from main import GameAccountOrchestrator, ApplicationProcessController, GameSessionInitiator, APP_VERSION, limit_strap_helpers
from cookie_extractor import CookieExtractor
from auto_updater import AutoUpdater
from RAM_export import transform
from log_utils import find_log_for_username, R_DISC_REASON, R_DISC_NOTIFY, R_DISC_SENDING, R_CONN_LOST

def _get_icon_path():
    # Try multiple locations for the icon file
    possible_paths = [
        "JARAM.ico",  # Current directory
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "JARAM.ico"),  # Script directory
    ]
    
    # If running as PyInstaller bundle, check the temp directory
    if hasattr(sys, '_MEIPASS'):
        possible_paths.insert(0, os.path.join(sys._MEIPASS, "JARAM.ico"))
    
    for icon_path in possible_paths:
        if os.path.exists(icon_path):
            print(f"Found icon at: {icon_path}")  # Debug print
            return icon_path
    
    print("Icon not found in any location")  # Debug print
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
                "offline": 25,
                "launch_delay": 10,
                "initial_delay": 10,
                "kill_timeout": 1740,
                "poll_interval": 10,
                "webhook_url": "",
                "ping_message": "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"
            },
            "timeout_monitor": {
                "kill_timeout": 1740,
                "kill_timeout_disabled": False,
                "poll_interval": 10,
                "webhook_url": "",
                "ping_message": "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"
            },
            "process_management": {
                "limit_strap_processes": True
            }
        }

        self.default_user_structure = {
            "username": "",
            "cookie": "",
            "private_server_link": "",
            "place": ""
        }

    def _deep_update(self, base, update):
        """Recursively update base dict with update dict."""
        for k, v in update.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k] = self._deep_update(base[k], v)
            else:
                base[k] = v
        return base

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
                # Legacy format - just cookie string
                new_data[user_id] = {
                    "username": f"User_{user_id}",
                    "cookie": user_info,
                    "server_type": "private",  # Default to private for backward compatibility
                    "private_server_link": "",
                    "place_id": "",
                    "disabled": False  # Default to enabled for backward compatibility
                }
            elif isinstance(user_info, dict):
                # Ensure all required fields exist with backward compatibility
                new_data[user_id] = {
                    "username": user_info.get("username", f"User_{user_id}"),
                    "cookie": user_info.get("cookie", ""),
                    "server_type": user_info.get("server_type", "private"),  # Default to private
                    "private_server_link": user_info.get("private_server_link", ""),
                    "place_id": user_info.get("place_id", ""),
                    "disabled": user_info.get("disabled", False)  # Default to enabled for backward compatibility
                }
            else:
                # Invalid format
                new_data[user_id] = {
                    "username": f"User_{user_id}",
                    "cookie": "",
                    "server_type": "private",
                    "private_server_link": "",
                    "place_id": ""
                }
        return new_data

    def get_users_for_manager(self):
        users = self.load_users()
        manager_format = {}
        for user_id, user_info in users.items():
            if isinstance(user_info, dict):
                # Ensure all required fields exist with backward compatibility
                manager_format[user_id] = {
                    "username": user_info.get("username", f"User_{user_id}"),
                    "cookie": user_info.get("cookie", ""),
                    "server_type": user_info.get("server_type", "private"),
                    "private_server_link": user_info.get("private_server_link", ""),
                    "place_id": user_info.get("place_id", ""),
                    "disabled": user_info.get("disabled", False)
                }
            else:
                # Legacy format - just cookie string
                manager_format[user_id] = {
                    "username": f"User_{user_id}",
                    "cookie": user_info,
                    "server_type": "private",
                    "private_server_link": "",
                    "place_id": "",
                    "disabled": False  # Default to enabled for legacy accounts
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

    # Cache for frequently used styles
    _style_cache = {}

    @classmethod
    def get_cached_style(cls, style_key, style_func):
        """Get cached style or generate and cache it"""
        if style_key not in cls._style_cache:
            cls._style_cache[style_key] = style_func()
        return cls._style_cache[style_key]

    @staticmethod
    def get_stylesheet():
        return f"""
        QMainWindow {{
            background-color: {ModernStyle.BACKGROUND};
            color: {ModernStyle.TEXT_PRIMARY};
            border: 1px solid {ModernStyle.BORDER};
            border-radius: 8px;
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
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 500;
            min-width: 60px;
            min-height: 20px;
            max-height: 24px;
            font-size: 12px;
        }}

        QPushButton:hover {{
            background-color: {ModernStyle.PRIMARY_VARIANT};
        }}

        QPushButton:pressed {{
            background-color: #3730a3;
        }}

        QPushButton:disabled {{
            background-color: {ModernStyle.SURFACE_VARIANT};
            color: {ModernStyle.TEXT_SECONDARY};
        }}

        QPushButton.success {{
            background-color: {ModernStyle.SECONDARY};
        }}

        QPushButton.success:hover {{
            background-color: #059669;
        }}

        QPushButton.danger {{
            background-color: {ModernStyle.ERROR};
        }}

        QPushButton.danger:hover {{
            background-color: #dc2626;
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

class CustomTitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setFixedHeight(32)  # Slightly taller for better proportions
        self.setStyleSheet(f"""
            CustomTitleBar {{
                background-color: {ModernStyle.SURFACE_VARIANT};
                border-bottom: 1px solid {ModernStyle.BORDER};
            }}
        """)
        
        # Track mouse position for window dragging
        self.drag_position = QPoint()
        
        self.setup_ui()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 0, 0)  # Slightly more padding
        layout.setSpacing(0)
        
        # App icon and title
        icon_label = QLabel()
        icon_path = _get_icon_path()
        if icon_path:
            pixmap = QPixmap(icon_path)
            icon_label.setPixmap(pixmap.scaled(18, 18, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        icon_label.setFixedSize(18, 18)
        
        title_label = QLabel("JARAM")
        title_label.setStyleSheet(f"""
            QLabel {{
                color: {ModernStyle.TEXT_PRIMARY};
                font-weight: 500;
                font-size: 13px;
                margin-left: 8px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
        """)
        
        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addStretch()
        
        # Create button container for proper alignment
        button_container = QWidget()
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(0)
        
        # Window control buttons - minimize and close
        self.minimize_btn = self.create_minimize_button()
        self.close_btn = self.create_close_button()
        
        button_layout.addWidget(self.minimize_btn)
        button_layout.addWidget(self.close_btn)
        
        layout.addWidget(button_container)
        
    def create_minimize_button(self):
        btn = QPushButton()
        btn.setFixedSize(36, 28)  # Same size as close button
        btn.setText("−")
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {ModernStyle.TEXT_SECONDARY};
                border: none;
                border-radius: 4px;
                font-size: 12px;
                font-weight: normal;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
            QPushButton:hover {{
                background-color: rgba(255, 255, 255, 0.1);
                color: {ModernStyle.TEXT_PRIMARY};
            }}
            QPushButton:pressed {{
                background-color: rgba(255, 255, 255, 0.2);
            }}
        """)
        btn.clicked.connect(self.minimize_window)
        return btn
        
    def create_close_button(self):
        btn = QPushButton()
        btn.setFixedSize(36, 28)  # Smaller close button
        btn.setText("×")
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {ModernStyle.TEXT_SECONDARY};
                border: none;
                border-radius: 4px;
                font-size: 12px;
                font-weight: normal;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
            QPushButton:hover {{
                background-color: #e81123;
                color: white;
            }}
            QPushButton:pressed {{
                background-color: #c50e1f;
                color: white;
            }}
        """)
        btn.clicked.connect(self.close_window)
        return btn
        
    def minimize_window(self):
        if self.parent:
            self.parent.showMinimized()
            
    def close_window(self):
        if self.parent:
            self.parent.close()
            
    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_position = event.globalPosition().toPoint() - self.parent.frameGeometry().topLeft()
            event.accept()
            
    def mouseMoveEvent(self, event: QMouseEvent):
        if event.buttons() == Qt.MouseButton.LeftButton and self.parent:
            if not self.parent.isMaximized():
                self.parent.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()
            
    def mouseDoubleClickEvent(self, event: QMouseEvent):
        # Double-click functionality removed since maximize is disabled
        pass

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
        # Cache for previous status to avoid unnecessary updates
        self._previous_status = {}
        self._previous_process_data = {}

    def initialize_manager(self):
        try:
            self.manager = GameAccountOrchestrator()
            self.process_mgr = ApplicationProcessController(self.manager.protected_process_id)
            self.launcher = GameSessionInitiator(
                self.manager.game_place_id,
                self.process_mgr,
                self.manager.security_manager,
                self.manager.process_monitor
            )

            # Start the timeout monitor
            self.manager.timeout_monitor.start()

            self.user_states = {user_id: {
                "last_active": 0,
                "inactive_since": None,
                "user_info": user_info,
                "requires_restart": False,
                "status": "Initializing",
                "last_check": 0
            } for user_id, user_info in self.manager.user_configurations.items()
            if not (isinstance(user_info, dict) and user_info.get("disabled", False))}

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

            for pid in self.manager.process_monitor.account_process_mapping.get(user_id, []):
                if self.process_mgr.confirm_process_running(pid):
                    self.process_mgr.eliminate_process(pid, self.manager.process_monitor)

            cookie = state["user_info"].get("cookie", "") if isinstance(state["user_info"], dict) else state["user_info"]
            try:
                if self.launcher.initiate_gaming_session(user_id, cookie, state["user_info"]):
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
            for pid in self.manager.process_monitor.account_process_mapping.get(user_id, []).copy():
                if self.process_mgr.confirm_process_running(pid):
                    if self.process_mgr.eliminate_process(pid, self.manager.process_monitor):
                        killed_count += 1

            return True
        except Exception as e:
            return False

    def kill_all_processes(self):
        if not self.process_mgr:
            return False

        try:
            killed = self.process_mgr.eliminate_process(None, self.manager.process_monitor)
            return killed
        except Exception as e:
            return False

    def cleanup_dead_processes(self):
        if not self.process_mgr:
            return False

        try:
            self.process_mgr.purge_terminated_processes(self.manager.process_monitor)
            return True
        except Exception as e:
            return False

    def run(self):
        if not self.initialize_manager():
            return

        self.running = True

        try:
            self.launcher.bootstrap_all_gaming_sessions(self.manager.user_configurations)
        except Exception as e:
            pass

        while self.running:
            current_timestamp = time.time()

            try:

                if current_timestamp - self.timing_trackers['cleanup'] >= self.manager.monitoring_intervals['maintenance']:
                    self.process_mgr.purge_terminated_processes(self.manager.process_monitor)
                    self.timing_trackers['cleanup'] = current_timestamp

                if current_timestamp - self.timing_trackers['orphan_check'] >= (self.manager.monitoring_intervals['maintenance'] * 2):
                    self.process_mgr.remove_unmanaged_processes(
                        self.manager.process_monitor,
                        set(self.manager.user_configurations.keys())
                    )

                    # Limit strap processes if enabled
                    if self.manager.limit_strap_processes:
                        self.process_mgr.limit_strap_processes()

                    self.timing_trackers['orphan_check'] = current_timestamp

                if current_timestamp - self.timing_trackers['window_check'] >= self.manager.monitoring_intervals['window_check']:
                    window_counts = self.process_mgr.enumerate_window_instances()

                    process_data = {}
                    for pid, user_id in self.manager.process_monitor.process_ownership.items():
                        if self.process_mgr.confirm_process_running(pid):
                            create_time = self.manager.process_monitor.process_birth_times.get(pid, 0)
                            window_count = window_counts.get(pid, 0)
                            process_data[pid] = {
                                'user_id': user_id,
                                'created': datetime.fromtimestamp(create_time).strftime("%H:%M:%S") if create_time else "Unknown",
                                'windows': window_count
                            }

                    # Only emit if process data has changed
                    if process_data != self._previous_process_data:
                        self.process_signal.emit(process_data)
                        self._previous_process_data = process_data.copy()

                    for pid, count in window_counts.items():
                        if count > self.manager.maximum_windows and pid != self.manager.protected_process_id:
                            self.process_mgr.eliminate_process(pid, self.manager.process_monitor)

                    self.timing_trackers['window_check'] = current_timestamp

                # Only update status every 5 seconds to reduce UI overhead
                status_update_interval = 5
                should_update_status = current_timestamp - self.timing_trackers.get('status_update', 0) >= status_update_interval

                status_data = {}
                for user_id, state in self.user_states.items():
                    # Skip frequent checks for the same user
                    if current_timestamp - state.get("last_check", 0) < 5:
                        # Use cached status data
                        status_data[user_id] = {
                            'status': state.get('status', 'Unknown'),
                            'pids': self.manager.process_monitor.account_process_mapping.get(user_id, []),
                            'needs_restart': state.get("requires_restart", False),
                            'last_active': state.get("last_active", 0),
                            'inactive_since': state.get("inactive_since")
                        }
                        continue

                    cookie = state["user_info"].get("cookie", "") if isinstance(state["user_info"], dict) else state["user_info"]
                    activity_status = self.manager.activity_tracker.verify_user_online_status(
                        user_id, cookie, self.manager.security_manager
                    )

                    state["last_check"] = current_timestamp

                    if activity_status is None:

                        status_data[user_id] = {
                            'status': state.get('status', 'API Error'),
                            'pids': self.manager.process_monitor.account_process_mapping.get(user_id, []),
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
                        if inactive_duration >= self.manager.timeout_configuration['inactivity_limit']:
                            if not self.user_states[user_id]["requires_restart"]:
                                self.user_states[user_id]["requires_restart"] = True

                        status = f"Inactive ({int(inactive_duration)}s)"
                        self.user_states[user_id]["status"] = status

                    pids = self.manager.process_monitor.account_process_mapping.get(user_id, [])

                    status_data[user_id] = {
                        'status': status,
                        'pids': pids,
                        'needs_restart': self.user_states[user_id]["requires_restart"],
                        'last_active': self.user_states[user_id]["last_active"],
                        'inactive_since': self.user_states[user_id]["inactive_since"]
                    }

                # Only emit status signal if there are changes or it's time for an update
                if should_update_status or status_data != self._previous_status:
                    self.status_signal.emit(status_data)
                    self.timing_trackers['status_update'] = current_timestamp
                    self._previous_status = status_data.copy()

                restart_candidates = [user_id for user_id, state in self.user_states.items()
                                    if state["requires_restart"]]

                if restart_candidates and (current_timestamp - self.timing_trackers['relaunch']) >= self.manager.timeout_configuration['startup_delay']:
                    target_user = restart_candidates[0]
                    target_state = self.user_states[target_user]

                    running_pids = []
                    for pid in self.manager.process_monitor.account_process_mapping.get(target_user, []):
                        if self.process_mgr.confirm_process_running(pid):
                            running_pids.append(pid)

                    if running_pids:
                        for pid in running_pids:
                            self.process_mgr.eliminate_process(pid, self.manager.process_monitor)

                    target_cookie = target_state["user_info"].get("cookie", "") if isinstance(target_state["user_info"], dict) else target_state["user_info"]
                    try:
                        if self.launcher.initiate_gaming_session(target_user, target_cookie, target_state["user_info"]):
                            self.user_states[target_user]["inactive_since"] = None
                            self.user_states[target_user]["requires_restart"] = False
                            self.user_states[target_user]["status"] = "Restarting"
                            self.timing_trackers['relaunch'] = current_timestamp
                    except Exception as e:
                        pass

            except Exception as error:
                pass

            time.sleep(self.manager.monitoring_intervals['activity_check'])

    def stop(self):
        self.running = False
        # Clean up resources to prevent memory leaks
        if hasattr(self, 'manager') and self.manager:
            if hasattr(self.manager, 'activity_tracker'):
                # Clean up session pool
                for session_data in self.manager.activity_tracker._connection_pool.values():
                    session_data['session'].close()
                self.manager.activity_tracker._connection_pool.clear()

        # Clear caches
        self._previous_status.clear()
        self._previous_process_data.clear()

class UserManagementDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("User Account Management")
        self.setModal(True)

        self.resize(1600, 950)
        self.setMinimumSize(1400, 800)
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

        # Server Type Selection
        form_layout.addWidget(QLabel("Server Type:"))
        server_type_layout = QHBoxLayout()

        self.private_server_radio = QRadioButton("Private Server")
        self.public_server_radio = QRadioButton("Public Server")
        self.private_server_radio.setChecked(True)  # Default to private server

        self.private_server_radio.toggled.connect(self._on_server_type_changed)
        self.public_server_radio.toggled.connect(self._on_server_type_changed)

        server_type_layout.addWidget(self.private_server_radio)
        server_type_layout.addWidget(self.public_server_radio)
        server_type_layout.addStretch()
        form_layout.addLayout(server_type_layout)

        # Private Server Link (shown when Private Server is selected)
        self.private_server_label = QLabel("Private Server Link:")
        self.private_server_input = QLineEdit()
        self.private_server_input.setPlaceholderText("Enter private server link")
        self.private_server_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(self.private_server_label)
        form_layout.addWidget(self.private_server_input)

        # Place ID (shown when Public Server is selected)
        self.place_id_label = QLabel("Place ID:")
        self.place_id_input = QLineEdit()
        self.place_id_input.setPlaceholderText("Enter place ID (e.g., 15532962292)")
        self.place_id_input.setStyleSheet(self._get_input_style())
        form_layout.addWidget(self.place_id_label)
        form_layout.addWidget(self.place_id_input)

        # Initially hide place ID fields since private server is default
        self.place_id_label.hide()
        self.place_id_input.hide()

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

        # Add some spacing before account status
        form_layout.addWidget(QLabel(""))  # Empty label for spacing

        # Account Status - make it more prominent
        status_group = QGroupBox("Account Status")
        status_layout = QVBoxLayout(status_group)

        self.disabled_checkbox = QCheckBox("🚫 Disable this account (prevent automatic launching)")
        self.disabled_checkbox.setToolTip("When checked, this account will not be launched automatically and will be excluded from the manager")
        self.disabled_checkbox.setStyleSheet(f"""
            QCheckBox {{
                color: {ModernStyle.TEXT_PRIMARY};
                font-size: 12px;
                font-weight: bold;
                padding: 8px;
                spacing: 12px;
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
                border: 2px solid {ModernStyle.BORDER};
                border-radius: 4px;
                background-color: {ModernStyle.SURFACE};
            }}
            QCheckBox::indicator:checked {{
                background-color: #AA4444;
                border-color: #AA4444;
            }}
            QCheckBox::indicator:checked:hover {{
                background-color: #BB5555;
                border-color: #BB5555;
            }}
        """)

        status_layout.addWidget(self.disabled_checkbox)

        # Add warning label
        warning_label = QLabel("⚠️ Disabled accounts will not launch and will appear grayed out in the main interface")
        warning_label.setStyleSheet(f"""
            QLabel {{
                color: #FFAA44;
                font-size: 10px;
                font-style: italic;
                padding: 4px;
            }}
        """)
        status_layout.addWidget(warning_label)

        form_layout.addWidget(status_group)

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

    def _on_server_type_changed(self):
        """Handle server type radio button changes"""
        if self.private_server_radio.isChecked():
            # Show private server fields, hide place ID fields
            self.private_server_label.show()
            self.private_server_input.show()
            self.place_id_label.hide()
            self.place_id_input.hide()
        else:
            # Show place ID fields, hide private server fields
            self.private_server_label.hide()
            self.private_server_input.hide()
            self.place_id_label.show()
            self.place_id_input.show()

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
                padding: 6px 10px;
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
                padding: 6px 14px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
                min-height: 24px;
                max-height: 28px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {ModernStyle.PRIMARY_VARIANT};
            }}
            QPushButton:pressed {{
                background-color: #3730a3;
            }}
        """

    def _get_secondary_button_style(self):
        return f"""
            QPushButton {{
                background-color: {ModernStyle.SURFACE_VARIANT};
                color: {ModernStyle.TEXT_PRIMARY};
                border: 1px solid {ModernStyle.BORDER};
                padding: 6px 16px;
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
                min-width: 60px;
                max-width: 70px;
                min-height: 24px;
                max-height: 26px;
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
            server_type = user_info.get("server_type", "private")
            private_server_link = user_info.get("private_server_link", "")
            place_id = user_info.get("place_id", "")
            cookie = user_info.get("cookie", "")
        else:
            username = f"User_{user_id}"
            server_type = "private"  # Legacy format defaults to private
            private_server_link = ""
            place_id = ""
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

        # Server Type indicator
        server_type_label = QLabel(f"Type: {'Private Server' if server_type == 'private' else 'Public Server'}")
        server_type_label.setStyleSheet(f"""
            QLabel {{
                color: {ModernStyle.PRIMARY if server_type == 'private' else ModernStyle.SECONDARY};
                font-size: 11px;
                font-weight: bold;
                margin: 0px;
                padding: 0px;
            }}
        """)
        info_layout.addWidget(server_type_label)

        # Show connection info based on server type
        if server_type == "private" and private_server_link:
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
        elif server_type == "public" and place_id:
            place_id_label = QLabel(f"Place ID: {place_id}")
            place_id_label.setStyleSheet(f"""
                QLabel {{
                    color: {ModernStyle.TEXT_SECONDARY};
                    font-size: 11px;
                    margin: 0px;
                    padding: 0px;
                }}
            """)
            place_id_label.setWordWrap(True)
            info_layout.addWidget(place_id_label)

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
            self.place_id_input.setText(user_info.get("place_id", ""))
            self.cookie_input.setText(user_info.get("cookie", ""))

            # Set server type radio buttons
            server_type = user_info.get("server_type", "private")  # Default to private for backward compatibility
            if server_type == "public":
                self.public_server_radio.setChecked(True)
            else:
                self.private_server_radio.setChecked(True)
            self._on_server_type_changed()  # Update field visibility

            # Set disabled status
            self.disabled_checkbox.setChecked(user_info.get("disabled", False))
        else:
            # Legacy format - treat as private server
            self.user_id_input.setText(user_id)
            self.user_id_input.setEnabled(False)
            self.username_input.setText(f"User_{user_id}")
            self.private_server_input.setText("")
            self.place_id_input.setText("")
            self.cookie_input.setText(user_info)
            self.private_server_radio.setChecked(True)
            self._on_server_type_changed()

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
        self.place_id_input.clear()
        self.cookie_input.clear()
        self.private_server_radio.setChecked(True)  # Reset to default
        self.disabled_checkbox.setChecked(False)  # Reset to enabled
        self._on_server_type_changed()  # Update field visibility

        self.add_btn.show()
        self.update_btn.hide()
        self.cancel_edit_btn.hide()

    def update_user(self):
        if not self.selected_user_id:
            return

        user_id = self.selected_user_id
        username = self.username_input.text().strip()
        private_server_link = self.private_server_input.text().strip()
        place_id = self.place_id_input.text().strip()
        cookie = self.cookie_input.text().strip()

        # Determine server type
        server_type = "private" if self.private_server_radio.isChecked() else "public"

        if not username:
            username = f"User_{user_id}"

        # Validate based on server type
        if server_type == "private":
            if not private_server_link:
                QMessageBox.warning(self, "Error", "Private server link cannot be empty!")
                self.private_server_input.setFocus()
                return
        else:  # public server
            if not place_id:
                QMessageBox.warning(self, "Error", "Place ID cannot be empty for public server!")
                self.place_id_input.setFocus()
                return

            if not place_id.isdigit():
                QMessageBox.warning(self, "Error", "Place ID should be numeric (e.g., 15532962292)")
                self.place_id_input.setFocus()
                return

        if not cookie:
            QMessageBox.warning(self, "Error", "Cookie cannot be empty!")
            self.cookie_input.setFocus()
            return

        self.original_config[user_id] = {
            "username": username,
            "server_type": server_type,
            "private_server_link": private_server_link if server_type == "private" else "",
            "place_id": place_id if server_type == "public" else "",
            "cookie": cookie,
            "disabled": self.disabled_checkbox.isChecked()
        }

        self.refresh_user_list()
        self.cancel_edit()
        QMessageBox.information(self, "Success", f"User {user_id} ({username}) updated successfully!")

    def add_user(self):
        user_id = self.user_id_input.text().strip()
        username = self.username_input.text().strip()
        private_server_link = self.private_server_input.text().strip()
        place_id = self.place_id_input.text().strip()
        cookie = self.cookie_input.text().strip()

        # Determine server type
        server_type = "private" if self.private_server_radio.isChecked() else "public"

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

        # Validate based on server type
        if server_type == "private":
            if not private_server_link:
                QMessageBox.warning(self, "Error", "Please enter a Private Server Link")
                self.private_server_input.setFocus()
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
                                           "Continue anyway?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.No:
                    self.private_server_input.setFocus()
                    return
        else:  # public server
            if not place_id:
                QMessageBox.warning(self, "Error", "Please enter a Place ID for public server")
                self.place_id_input.setFocus()
                return

            if not place_id.isdigit():
                QMessageBox.warning(self, "Error", "Place ID should be numeric (e.g., 15532962292)")
                self.place_id_input.setFocus()
                return

        if not cookie:
            QMessageBox.warning(self, "Error", "Please enter a Cookie")
            self.cookie_input.setFocus()
            return

        if not username:
            username = f"User_{user_id}"

        if not cookie.startswith('_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_'):
            reply = QMessageBox.question(self, "Cookie Warning",
                                       "The cookie doesn't appear to be in the expected ROBLOSECURITY format. Continue anyway?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                self.cookie_input.setFocus()
                return

        try:
            # Create account data with new structure
            self.original_config[user_id] = {
                "username": username,
                "server_type": server_type,
                "private_server_link": private_server_link if server_type == "private" else "",
                "place_id": place_id if server_type == "public" else "",
                "cookie": cookie,
                "disabled": self.disabled_checkbox.isChecked()
            }

            self.user_id_input.clear()
            self.username_input.clear()
            self.private_server_input.clear()
            self.place_id_input.clear()
            self.cookie_input.clear()
            self.private_server_radio.setChecked(True)  # Reset to default
            self.disabled_checkbox.setChecked(False)  # Reset to enabled

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
        # Cache for previous data to avoid unnecessary table updates
        self._previous_user_data = {}
        self._previous_process_data = {}
        
        # Window resizing variables
        self.resize_margin = 5
        self.resizing = False
        self.resize_direction = None
        
        self.setup_ui()
        self.setup_timers()

    def setup_ui(self):
        self.setWindowTitle("Just Another Roblox Account Manager 1.1.1")
        self.setGeometry(100, 100, 1200, 800)
        
        # Remove default window frame and title bar
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        
        # Add drop shadow effect
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        
        icon_path = _get_icon_path()
        if icon_path and os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Add custom title bar
        self.title_bar = CustomTitleBar(self)
        main_layout.addWidget(self.title_bar)
        
        # Content area with margins
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.addWidget(content_widget)

        header_layout = QHBoxLayout()

        title_label = QLabel("JARAM - Just Another Roblox Account Manager 1.1.1")
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

        content_layout.addLayout(header_layout)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Stopped")
        self.status_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY}; font-weight: bold;")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.uptime_label = QLabel("Uptime: 00:00:00")
        status_layout.addWidget(self.uptime_label)

        content_layout.addLayout(status_layout)

        self.tab_widget = QTabWidget()
        content_layout.addWidget(self.tab_widget)

        self.setup_dashboard_tab()
        self.setup_users_tab()
        self.setup_accounts_tab()
        self.setup_processes_tab()
        self.setup_logs_tab()
        self.setup_settings_tab()
        self.setup_RAMEXPORT_tab()
        self.setup_donation_tab()
        self.setup_credits_tab()

        self.setStyleSheet(ModernStyle.get_stylesheet())

        self.start_time = None
        self.user_data = {}

        self.auto_updater = AutoUpdater()
        self.pending_update = None

        QTimer.singleShot(2000, self.check_for_updates_on_startup)



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
        self.users_table.setColumnCount(8)
        self.users_table.setHorizontalHeaderLabels([
            "User ID", "Username", "Server Type", "Connection", "Status", "PIDs", "Last Active", "Actions"
        ])

        header = self.users_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # User ID
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Username
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Server Type
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Connection
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Status
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # PIDs
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Last Active
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)  # Actions

        self.users_table.setColumnWidth(3, 200)  # Connection
        self.users_table.setColumnWidth(6, 100)  # Last Active
        self.users_table.setColumnWidth(7, 130)  # Actions - smaller to fit buttons

        self.users_table.verticalHeader().setDefaultSectionSize(50)  # Normal height

        # Enable context menu for right-click actions
        self.users_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.users_table.customContextMenuRequested.connect(self.show_user_context_menu)

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

    def setup_accounts_tab(self):
        """Setup the account management tab"""
        accounts_widget = QWidget()
        layout = QVBoxLayout(accounts_widget)

        # Header
        header_label = QLabel("Account Management")
        header_label.setStyleSheet(f"""
            QLabel {{
                font-size: 18px;
                font-weight: bold;
                color: {ModernStyle.TEXT_PRIMARY};
                padding: 10px 0;
            }}
        """)
        layout.addWidget(header_label)

        # Create a horizontal layout for the form and account list
        main_layout = QHBoxLayout()

        # Left side - Add/Edit form
        form_widget = QWidget()
        form_widget.setMaximumWidth(400)
        form_layout = QVBoxLayout(form_widget)

        form_title = QLabel("Add New Account")
        form_title.setStyleSheet(f"""
            QLabel {{
                font-size: 14px;
                font-weight: bold;
                color: {ModernStyle.TEXT_PRIMARY};
                padding: 5px 0;
            }}
        """)
        form_layout.addWidget(form_title)

        # Form fields
        self.account_user_id = QLineEdit()
        self.account_user_id.setPlaceholderText("User ID (e.g., 123456789)")
        form_layout.addWidget(QLabel("User ID:"))
        form_layout.addWidget(self.account_user_id)

        self.account_username = QLineEdit()
        self.account_username.setPlaceholderText("Username (e.g., PlayerName)")
        form_layout.addWidget(QLabel("Username:"))
        form_layout.addWidget(self.account_username)

        # Server type
        form_layout.addWidget(QLabel("Server Type:"))
        server_layout = QHBoxLayout()
        self.account_private_radio = QRadioButton("Private Server")
        self.account_public_radio = QRadioButton("Public Server")
        self.account_private_radio.setChecked(True)
        server_layout.addWidget(self.account_private_radio)
        server_layout.addWidget(self.account_public_radio)
        form_layout.addLayout(server_layout)

        # Private server link
        self.account_private_link = QLineEdit()
        self.account_private_link.setPlaceholderText("Private server link")
        form_layout.addWidget(QLabel("Private Server Link:"))
        form_layout.addWidget(self.account_private_link)

        # Place ID (for public servers)
        self.account_place_id = QLineEdit()
        self.account_place_id.setPlaceholderText("Place ID")
        self.account_place_id_label = QLabel("Place ID:")
        form_layout.addWidget(self.account_place_id_label)
        form_layout.addWidget(self.account_place_id)

        # Initially hide place ID fields
        self.account_place_id_label.hide()
        self.account_place_id.hide()

        # Cookie
        self.account_cookie = QLineEdit()
        self.account_cookie.setPlaceholderText("ROBLOSECURITY cookie")
        form_layout.addWidget(QLabel("Cookie:"))
        form_layout.addWidget(self.account_cookie)

        # Disabled checkbox
        self.account_disabled = QCheckBox("Disable this account")
        form_layout.addWidget(self.account_disabled)

        # Buttons
        button_layout = QHBoxLayout()
        self.add_account_btn = QPushButton("Add Account")
        self.add_account_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ModernStyle.PRIMARY};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: {ModernStyle.PRIMARY_VARIANT}; }}
        """)
        self.add_account_btn.clicked.connect(self.add_account)
        button_layout.addWidget(self.add_account_btn)

        self.clear_form_btn = QPushButton("Clear")
        self.clear_form_btn.clicked.connect(self.clear_account_form)
        button_layout.addWidget(self.clear_form_btn)

        form_layout.addLayout(button_layout)
        form_layout.addStretch()

        # Connect radio buttons to show/hide fields
        self.account_private_radio.toggled.connect(self.on_account_server_type_changed)

        main_layout.addWidget(form_widget)

        # Right side - Account list
        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)

        list_title = QLabel("Existing Accounts")
        list_title.setStyleSheet(f"""
            QLabel {{
                font-size: 14px;
                font-weight: bold;
                color: {ModernStyle.TEXT_PRIMARY};
                padding: 5px 0;
            }}
        """)
        list_layout.addWidget(list_title)

        # Account list table
        self.accounts_list = QTableWidget()
        self.accounts_list.setColumnCount(6)
        self.accounts_list.setHorizontalHeaderLabels([
            "User ID", "Username", "Server Type", "Status", "Actions", "Delete"
        ])

        # Set column widths
        header = self.accounts_list.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)  # Fixed width for username
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Status - stretch to fill remaining space
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)

        self.accounts_list.setColumnWidth(1, 120)  # Username - smaller (about 1/3 less)
        self.accounts_list.setColumnWidth(4, 90)   # Actions - more space for button
        self.accounts_list.setColumnWidth(5, 80)   # Delete - more space for button

        # Set bigger row height to accommodate buttons properly
        self.accounts_list.verticalHeader().setDefaultSectionSize(35)

        list_layout.addWidget(self.accounts_list)

        main_layout.addWidget(list_widget)
        layout.addLayout(main_layout)

        self.tab_widget.addTab(accounts_widget, "Accounts")

        # Load accounts into the list
        self.refresh_accounts_list()

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

        self.scan_trace_chk = QCheckBox("Show SCAN-TRACE messages")
        self.scan_trace_chk.setChecked(False)
        controls_layout.addWidget(self.scan_trace_chk)

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

        # Shutdown Settings
        timeout_group = QGroupBox("Shutdown Settings")
        timeout_layout = QFormLayout(timeout_group)

        self.settings_strap_threshold_input = QSpinBox()
        self.settings_strap_threshold_input.setRange(1, 200)
        self.settings_strap_threshold_input.setToolTip("Max number of strap.exe helpers before trimming")
        timeout_layout.addRow("Strap Limit:", self.settings_strap_threshold_input)

        # Kill timeout with disable checkbox
        kill_timeout_container = QWidget()
        kill_timeout_layout = QHBoxLayout(kill_timeout_container)
        kill_timeout_layout.setContentsMargins(0, 0, 0, 0)
        
        self.kill_timeout_input = QSpinBox()
        self.kill_timeout_input.setRange(60, 7200)
        self.kill_timeout_input.setSuffix(" s")
        self.kill_timeout_input.setToolTip("Time until window auto-closes (≤ 1,740s recommended)")
        
        self.disable_kill_timeout_checkbox = QCheckBox("Disable")
        self.disable_kill_timeout_checkbox.setToolTip("Disable automatic process termination")
        self.disable_kill_timeout_checkbox.toggled.connect(self.on_disable_kill_timeout_toggled)
        
        kill_timeout_layout.addWidget(self.kill_timeout_input)
        kill_timeout_layout.addWidget(self.disable_kill_timeout_checkbox)
        kill_timeout_layout.addStretch()
        
        timeout_layout.addRow("Kill After:", kill_timeout_container)

        self.poll_interval_input = QSpinBox()
        self.poll_interval_input.setRange(1, 120)
        self.poll_interval_input.setSuffix(" s")
        self.poll_interval_input.setToolTip("How often to check for timeouts")
        timeout_layout.addRow("Poll Interval:", self.poll_interval_input)

        self.webhook_input = QLineEdit()
        self.webhook_input.setPlaceholderText("Discord webhook URL")
        self.webhook_input.setToolTip("Keep empty to disable")
        timeout_layout.addRow("Webhook URL:", self.webhook_input)

        self.ping_msg_input = QLineEdit()
        self.ping_msg_input.setPlaceholderText("Ping message (optional)")
        timeout_layout.addRow("Ping Message:", self.ping_msg_input)

        content_layout.addWidget(timeout_group)

        timing_group = QGroupBox("Timing Settings")
        timing_layout = QFormLayout(timing_group)

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

        # Process Management Settings
        process_group = QGroupBox("Process Management")
        process_layout = QFormLayout(process_group)

        self.settings_limit_strap_checkbox = QCheckBox()
        self.settings_limit_strap_checkbox.setToolTip(
            "Automatically limit strap.exe processes to only the oldest one. "
            "This helps prevent multiple strap processes from running simultaneously."
        )
        process_layout.addRow("Limit Strap Processes:", self.settings_limit_strap_checkbox)

        content_layout.addWidget(process_group)

        updater_group = QGroupBox("Auto Updater")
        updater_layout = QVBoxLayout(updater_group)

        version_info_layout = QHBoxLayout()
        version_label = QLabel(f"Current Version: {APP_VERSION}")
        version_label.setStyleSheet(f"font-weight: bold; color: {ModernStyle.PRIMARY};")
        version_info_layout.addWidget(version_label)
        version_info_layout.addStretch()

        self.update_status_label = QLabel("Click 'Check for Updates' to check for new versions")
        self.update_status_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY};")
        version_info_layout.addWidget(self.update_status_label)
        updater_layout.addLayout(version_info_layout)

        update_buttons_layout = QHBoxLayout()

        self.check_updates_btn = QPushButton("Check for Updates")
        self.check_updates_btn.clicked.connect(self.check_for_updates)
        update_buttons_layout.addWidget(self.check_updates_btn)

        self.download_update_btn = QPushButton("Download Update")
        self.download_update_btn.setProperty("class", "success")
        self.download_update_btn.clicked.connect(self.download_update)
        self.download_update_btn.setVisible(False)
        update_buttons_layout.addWidget(self.download_update_btn)

        update_buttons_layout.addStretch()
        updater_layout.addLayout(update_buttons_layout)

        self.update_progress = QProgressBar()
        self.update_progress.setVisible(False)
        updater_layout.addWidget(self.update_progress)

        self.update_info_display = QTextEdit()
        self.update_info_display.setMaximumHeight(100)
        self.update_info_display.setReadOnly(True)
        self.update_info_display.setVisible(False)
        updater_layout.addWidget(self.update_info_display)

        content_layout.addWidget(updater_group)

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

        self.replace_ps_chk = QCheckBox("Replace private server links (otherwise keep existing)")
        self.replace_ps_chk.setChecked(False)
        layout.addWidget(self.replace_ps_chk)

        # ── run button ─────────────────────────────────────────────
        run_btn = QPushButton("Fetch && Apply Accounts")
        run_btn.setProperty("class", "success")
        run_btn.clicked.connect(self.execute_ram_import)
        layout.addWidget(run_btn)

        layout.addStretch()
        self.tab_widget.addTab(tab, "RAM Export")

    def setup_donation_tab(self):
        donation_widget = QWidget()
        layout = QVBoxLayout(donation_widget)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(20)

        title_label = QLabel("Support JARAM Development")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"color: {ModernStyle.PRIMARY}; margin: 20px 0;")
        content_layout.addWidget(title_label)

        description_group = QGroupBox("Help Keep JARAM Free & Open Source")
        description_layout = QVBoxLayout(description_group)

        description_text = QLabel("""
        JARAM is a free and open-source project developed by cresqnt.

        All donations are voluntary and greatly appreciated! ❤️
        """)
        description_text.setWordWrap(True)
        description_text.setStyleSheet(f"color: {ModernStyle.TEXT_PRIMARY}; font-size: 14px; padding: 10px;")
        description_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_layout.addWidget(description_text)

        content_layout.addWidget(description_group)

        robux_group = QGroupBox("Donate Robux")
        robux_layout = QVBoxLayout(robux_group)

        robux_info = QLabel("Choose an amount to donate via Robux:")
        robux_info.setStyleSheet(f"color: {ModernStyle.TEXT_PRIMARY}; font-weight: bold; margin-bottom: 15px;")
        robux_layout.addWidget(robux_info)

        grid_layout = QGridLayout()
        grid_layout.setSpacing(10)

        robux_amounts = [1, 2, 5, 10, 15, 20, 50, 100, 200, 300, 400, 500, 600, 750, 1000, 2000, 3000, 4000, 5000, 10000]

        for i, amount in enumerate(robux_amounts):
            row = i // 4
            col = i % 4

            donate_btn = QPushButton(f"{amount:,} R$")
            donate_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.SECONDARY};
                    color: {ModernStyle.TEXT_PRIMARY};
                    border: none;
                    padding: 8px 12px;
                    border-radius: 8px;
                    font-weight: bold;
                    font-size: 13px;
                    min-width: 100px;
                    min-height: 32px;
                }}
                QPushButton:hover {{
                    background-color: 
                }}
                QPushButton:pressed {{
                    background-color: 
                }}
            """)
            donate_btn.clicked.connect(lambda checked, amt=amount: self.open_robux_donation(amt))
            grid_layout.addWidget(donate_btn, row, col)

        robux_layout.addLayout(grid_layout)
        content_layout.addWidget(robux_group)

        content_layout.addStretch()

        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)

        self.tab_widget.addTab(donation_widget, "Donate")

    def open_robux_donation(self, amount):
        """Open donation link for specified Robux amount"""

        donation_urls = {
            1: "https://www.roblox.com/game-pass/215081264/1-Robux",
            2: "https://www.roblox.com/game-pass/215081387/2-Robux",
            5: "https://www.roblox.com/game-pass/215081486/5-Robux",
            10: "https://www.roblox.com/game-pass/215081540/10-Robux",
            15: "https://www.roblox.com/game-pass/215081604/15-Robux",
            20: "https://www.roblox.com/game-pass/215081699/20-Robux",
            50: "https://www.roblox.com/game-pass/215081770/50-Robux",
            100: "https://www.roblox.com/game-pass/215081864/100-Robux",
            200: "https://www.roblox.com/game-pass/215081954/200-ROBUX",
            300: "https://www.roblox.com/game-pass/215082141/300-ROBUX",
            400: "https://www.roblox.com/game-pass/215082255/400-ROBUX",
            500: "https://www.roblox.com/game-pass/215082386/500-ROBUX",
            600: "https://www.roblox.com/game-pass/215082490/600-ROBUX",
            750: "https://www.roblox.com/game-pass/215082588/750-ROBUX",
            1000: "https://www.roblox.com/game-pass/215082721/1K-ROBUX",
            2000: "https://www.roblox.com/game-pass/215082950/2K-ROBUX",
            3000: "https://www.roblox.com/game-pass/215575837/3K-ROBUX",
            4000: "https://www.roblox.com/game-pass/215575912/4K-ROBUX",
            5000: "https://www.roblox.com/game-pass/215576007/5K-ROBUX",
            10000: "https://www.roblox.com/game-pass/215576532/10K-ROBUX"
        }

        donation_url = donation_urls.get(amount)

        if not donation_url:
            QMessageBox.warning(self, "Error", f"No donation gamepass available for {amount:,} Robux.")
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Robux Donation")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(f"Donate {amount:,} Robux")
        msg.setInformativeText(
            f"This will open the {amount:,} Robux gamepass in your browser.\n\n"
            "Thank you for supporting JARAM development! ❤️"
        )

        open_button = msg.addButton("Open Gamepass", QMessageBox.ButtonRole.ActionRole)
        msg.addButton(QMessageBox.StandardButton.Cancel)

        result = msg.exec()

        if msg.clickedButton() == open_button:
            try:
                import webbrowser
                webbrowser.open(donation_url)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to open gamepass: {e}")

    @staticmethod
    def _make_dev_card(name: str,
                    movie_bytes: bytes,
                    fallback: str = "GIF\nError") -> QWidget:
        card   = QWidget()
        layout = QVBoxLayout(card)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)
        layout.setContentsMargins(5, 5, 5, 5)

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

        team_group = QGroupBox("Development Team")
        team_group.setStyleSheet("QGroupBox { margin: 5px; padding-top: 10px; }")
        team_layout = QHBoxLayout(team_group)
        team_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        team_layout.setSpacing(40)
        team_layout.setContentsMargins(10, 5, 10, 10)

        # — cresqnt (Developer) —
        try:
            bytes_c = Path(__file__).with_name("cresqnt.gif").read_bytes()
        except FileNotFoundError:
            bytes_c = urlopen("https://media1.tenor.com/m/CNBGgG2DU10AAAAd/nyan-cat-poptart.gif").read()

        cresqnt_card = self._make_dev_card("cresqnt", bytes_c)
        # Add a subtle label to indicate role
        cresqnt_wrapper = QWidget()
        cresqnt_wrapper_layout = QVBoxLayout(cresqnt_wrapper)
        cresqnt_wrapper_layout.setSpacing(2)
        cresqnt_wrapper_layout.setContentsMargins(0, 0, 0, 0)
        cresqnt_wrapper_layout.addWidget(cresqnt_card)
        role_label = QLabel("Developer")
        role_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        role_label.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY}; font-size: 11px; font-style: italic;")
        cresqnt_wrapper_layout.addWidget(role_label)

        team_layout.addWidget(cresqnt_wrapper)

        # — Jirach1 (Contributor) —
        try:
            bytes_j = Path(__file__).with_name("jirachi.gif").read_bytes()
        except FileNotFoundError:
            bytes_j = urlopen("https://kyl.neocities.org/jirachi.gif").read()

        jirach_card = self._make_dev_card("Jirach1", bytes_j)
        # Add a subtle label to indicate role
        jirach_wrapper = QWidget()
        jirach_wrapper_layout = QVBoxLayout(jirach_wrapper)
        jirach_wrapper_layout.setSpacing(2)
        jirach_wrapper_layout.setContentsMargins(0, 0, 0, 0)
        jirach_wrapper_layout.addWidget(jirach_card)
        role_label2 = QLabel("Contributor")
        role_label2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        role_label2.setStyleSheet(f"color: {ModernStyle.TEXT_SECONDARY}; font-size: 11px; font-style: italic;")
        jirach_wrapper_layout.addWidget(role_label2)

        team_layout.addWidget(jirach_wrapper)

        content_layout.addWidget(team_group)

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
                padding: 8px 16px;
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
            import requests
            r = requests.get(f"{base_url}/GetAccountsJson", params=params, timeout=15)
            if r.status_code == 200:
                accounts_raw = r.json()
            elif r.status_code == 400:
                raise RuntimeError("400 Bad Request – 'Allow external connections' is OFF in Roblox Account Manager.")
            elif r.status_code == 401:
                raise RuntimeError("401 Unauthorized – Wrong Password")
            elif r.status_code == 404:
                raise RuntimeError("404 Not Found – RAM endpoint missing on this port.")
            elif r.status_code == 500:
                raise RuntimeError("500 Server Error – RAM threw an internal error.")
            else:
                raise RuntimeError(f"{r.status_code} {r.reason} – RAM API request failed.")

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
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

        if self.merge_chk.isChecked():
            existing = self.config_manager.load_users()
            merged = existing.copy()
            for uid, data in new_users.items():
                if uid in merged and not self.replace_ps_chk.isChecked():
                    # keep existing private server link
                    data["private_server_link"] = merged[uid].get("private_server_link", "")
                merged[uid] = data
        else:
            merged = new_users

        if self.config_manager.save_users(merged):
            QMessageBox.information(self, "Success",
                f"Imported {len(new_users)} accounts.\n"
                f"Total users.json entries: {len(merged)}")
            # Refresh the accounts list if we're on the accounts tab
            if hasattr(self, 'refresh_accounts_list'):
                self.refresh_accounts_list()
        else:
            QMessageBox.critical(self, "Save Error", "Failed to write users.json!")

    def open_url(self, url):
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open URL: {e}")

    def setup_timers(self):
        # Reduced timer frequency to improve performance
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(2000)  # Update every 2 seconds instead of 1

        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self.update_uptime)
        self.uptime_timer.start(1000)  # Keep uptime at 1 second for accuracy

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.resize_direction = self.get_resize_direction(event.position().toPoint())
            if self.resize_direction:
                self.resizing = True
                self.resize_start_pos = event.globalPosition().toPoint()
                self.resize_start_geometry = self.geometry()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not self.resizing:
            # Update cursor based on position
            direction = self.get_resize_direction(event.position().toPoint())
            if direction:
                if direction in ['top', 'bottom']:
                    self.setCursor(Qt.CursorShape.SizeVerCursor)
                elif direction in ['left', 'right']:
                    self.setCursor(Qt.CursorShape.SizeHorCursor)
                elif direction in ['top-left', 'bottom-right']:
                    self.setCursor(Qt.CursorShape.SizeFDiagCursor)
                elif direction in ['top-right', 'bottom-left']:
                    self.setCursor(Qt.CursorShape.SizeBDiagCursor)
            else:
                self.setCursor(Qt.CursorShape.ArrowCursor)
        else:
            # Perform resize
            self.perform_resize(event.globalPosition().toPoint())
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.resizing = False
            self.resize_direction = None
            self.setCursor(Qt.CursorShape.ArrowCursor)
        super().mouseReleaseEvent(event)

    def get_resize_direction(self, pos):
        margin = self.resize_margin
        rect = self.rect()
        
        left = pos.x() <= margin
        right = pos.x() >= rect.width() - margin
        top = pos.y() <= margin
        bottom = pos.y() >= rect.height() - margin
        
        if top and left:
            return 'top-left'
        elif top and right:
            return 'top-right'
        elif bottom and left:
            return 'bottom-left'
        elif bottom and right:
            return 'bottom-right'
        elif top:
            return 'top'
        elif bottom:
            return 'bottom'
        elif left:
            return 'left'
        elif right:
            return 'right'
        return None

    def perform_resize(self, global_pos):
        if not self.resize_direction:
            return
            
        delta = global_pos - self.resize_start_pos
        new_geometry = self.resize_start_geometry
        
        if 'left' in self.resize_direction:
            new_geometry.setLeft(new_geometry.left() + delta.x())
        if 'right' in self.resize_direction:
            new_geometry.setRight(new_geometry.right() + delta.x())
        if 'top' in self.resize_direction:
            new_geometry.setTop(new_geometry.top() + delta.y())
        if 'bottom' in self.resize_direction:
            new_geometry.setBottom(new_geometry.bottom() + delta.y())
            
        # Enforce minimum size
        min_width, min_height = 800, 600
        if new_geometry.width() < min_width:
            if 'left' in self.resize_direction:
                new_geometry.setLeft(new_geometry.right() - min_width)
            else:
                new_geometry.setRight(new_geometry.left() + min_width)
        if new_geometry.height() < min_height:
            if 'top' in self.resize_direction:
                new_geometry.setTop(new_geometry.bottom() - min_height)
            else:
                new_geometry.setBottom(new_geometry.top() + min_height)
                
        self.setGeometry(new_geometry)

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
        # Only refresh if data has actually changed
        if status_data != self._previous_user_data:
            self.user_data = status_data
            self.refresh_users()
            self._previous_user_data = status_data.copy()

    def update_process_data(self, process_data):
        # Only refresh if data has actually changed
        if process_data != self._previous_process_data:
            self.process_data = process_data
            self.refresh_processes()
            self._previous_process_data = process_data.copy()

    def refresh_users(self):
        self.users_table.setRowCount(len(self.user_data))

        users_config = self.config_manager.load_users()

        for row, (user_id, data) in enumerate(self.user_data.items()):
            # Check if account is disabled
            user_info = users_config.get(user_id, {})
            is_disabled = user_info.get("disabled", False) if isinstance(user_info, dict) else False

            # User ID column
            self.users_table.setItem(row, 0, QTableWidgetItem(user_id))

            if isinstance(user_info, dict):
                username = user_info.get("username", f"User_{user_id}")
                server_type = user_info.get("server_type", "private")
                private_server_link = user_info.get("private_server_link", "")
                place_id = user_info.get("place_id", "")
            else:
                username = f"User_{user_id}"
                server_type = "private"  # Legacy format defaults to private
                private_server_link = ""
                place_id = ""

            # Username column
            self.users_table.setItem(row, 1, QTableWidgetItem(username))

            # Server Type column
            server_type_display = "Private" if server_type == "private" else "Public"
            self.users_table.setItem(row, 2, QTableWidgetItem(server_type_display))

            # Connection column - show appropriate connection info based on server type
            if server_type == "private" and private_server_link:
                if "roblox.com/share" in private_server_link:
                    connection_display = "Share: " + private_server_link.split("?")[1][:20] + "..."
                else:
                    connection_display = private_server_link[:25] + "..." if len(private_server_link) > 25 else private_server_link
            elif server_type == "public" and place_id:
                connection_display = f"Place ID: {place_id}"
            else:
                connection_display = "Not configured"
            self.users_table.setItem(row, 3, QTableWidgetItem(connection_display))

            # Status column - show "Disabled" for disabled accounts or actual status
            if is_disabled:
                status_item = QTableWidgetItem("Disabled")
                status_item.setForeground(QColor("#FF6666"))  # Light red
            else:
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

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(2, 2, 2, 2)
            actions_layout.setSpacing(2)

            # Simple toggle button
            if is_disabled:
                toggle_btn = QPushButton("Enable")
                toggle_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        padding: 2px 4px;
                        border-radius: 2px;
                        font-size: 8px;
                        max-width: 40px;
                        max-height: 18px;
                    }}
                    QPushButton:hover {{ background-color: #45a049; }}
                """)
            else:
                toggle_btn = QPushButton("Disable")
                toggle_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #f44336;
                        color: white;
                        border: none;
                        padding: 2px 4px;
                        border-radius: 2px;
                        font-size: 8px;
                        max-width: 40px;
                        max-height: 18px;
                    }}
                    QPushButton:hover {{ background-color: #da190b; }}
                """)
            toggle_btn.clicked.connect(lambda checked, uid=user_id: self.toggle_user_enabled(uid))
            actions_layout.addWidget(toggle_btn)

            restart_btn = QPushButton("Restart")
            restart_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.PRIMARY};
                    color: white;
                    border: none;
                    padding: 2px 4px;
                    border-radius: 2px;
                    font-size: 8px;
                    max-width: 35px;
                    max-height: 18px;
                }}
                QPushButton:hover {{ background-color: {ModernStyle.PRIMARY_VARIANT}; }}
            """)
            restart_btn.clicked.connect(lambda checked, uid=user_id: self.restart_user_session(uid))
            actions_layout.addWidget(restart_btn)

            kill_btn = QPushButton("Kill")
            kill_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.ERROR};
                    color: white;
                    border: none;
                    padding: 2px 4px;
                    border-radius: 2px;
                    font-size: 8px;
                    max-width: 30px;
                    max-height: 18px;
                }}
                QPushButton:hover {{ background-color: #c62828; }}
            """)
            kill_btn.clicked.connect(lambda checked, uid=user_id: self.kill_user_processes(uid))
            actions_layout.addWidget(kill_btn)

            self.users_table.setCellWidget(row, 7, actions_widget)  # Updated column index

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
                    min-height: 22px;
                    max-height: 24px;
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

        timeouts = cfg.get("timeouts", {})
        self.settings_initial_delay_input.setValue(timeouts.get("initial_delay", 10))
        self.settings_offline_threshold_input.setValue(timeouts.get("offline", 25))
        self.settings_launch_delay_input.setValue(timeouts.get("launch_delay", 10))
        self.settings_strap_threshold_input.setValue(timeouts.get("strap_threshold", 10))

        tm = cfg.get("timeout_monitor", {})
        self.kill_timeout_input.setValue(tm.get("kill_timeout", 1740))
        self.disable_kill_timeout_checkbox.setChecked(tm.get("kill_timeout_disabled", False))
        self.on_disable_kill_timeout_toggled(tm.get("kill_timeout_disabled", False))
        self.poll_interval_input.setValue(tm.get("poll_interval", 10))
        self.webhook_input.setText(tm.get("webhook_url", ""))
        self.ping_msg_input.setText(tm.get("ping_message", "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"))

        process_management = cfg.get("process_management", {})
        self.settings_limit_strap_checkbox.setChecked(process_management.get("limit_strap_processes", True))

    def save_settings(self):
        settings = {
            "window_limit": self.settings_window_limit_input.value(),
            "timeouts": {
                "initial_delay": self.settings_initial_delay_input.value(),
                "offline": self.settings_offline_threshold_input.value(),
                "launch_delay": self.settings_launch_delay_input.value(),
                "strap_threshold": self.settings_strap_threshold_input.value(),
                "kill_timeout": self.kill_timeout_input.value(),
                "poll_interval": self.poll_interval_input.value(),
                "webhook_url": self.webhook_input.text().strip(),
                "ping_message": self.ping_msg_input.text().strip() or "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"
            },
            "timeout_monitor": {
                "kill_timeout": self.kill_timeout_input.value(),
                "kill_timeout_disabled": self.disable_kill_timeout_checkbox.isChecked(),
                "poll_interval": self.poll_interval_input.value(),
                "webhook_url": self.webhook_input.text().strip(),
                "ping_message": self.ping_msg_input.text().strip() or "<@YourPing> This message is sent whenever your active processes drop to 1 or 0, for debugging, leave webhook empty if not interested"
            },
            "process_management": {
                "limit_strap_processes": self.settings_limit_strap_checkbox.isChecked()
            }
        }

        if self.config_manager.save_settings(settings):
            if hasattr(self, 'worker_thread') and self.worker_thread and self.worker_thread.isRunning():
                if hasattr(self.worker_thread, 'apply_new_settings'):
                    self.worker_thread.apply_new_settings(settings)
            QMessageBox.information(self, "Success", "Settings saved and applied!")
        else:
            QMessageBox.critical(self, "Error", "Failed to save settings.")

    def reset_settings(self):
        """Load the hard-coded defaults from ConfigManager into the UI."""
        defaults = self.config_manager.default_settings
        t = defaults["timeouts"]

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
        self.disable_kill_timeout_checkbox.setChecked(t.get("kill_timeout_disabled", False))
        self.on_disable_kill_timeout_toggled(t.get("kill_timeout_disabled", False))
        self.poll_interval_input.setValue(t["poll_interval"])
        self.webhook_input.setText(t["webhook_url"])
        self.ping_msg_input.setText(t["ping_message"])

        QMessageBox.information(
            self,
            "Reset Complete",
            "All settings have been restored to their default values.\n"
            "Click 'Save Settings' to confirm them."
        )

    def _clear_bad_flags(self):
        users = self.config_manager.load_users()
        for info in users.values():
            if isinstance(info, dict):
                info["bad"] = False
        self.config_manager.save_users(users)
        QMessageBox.information(self, "Done", "All bad-cookie marks cleared.")
        if hasattr(self, 'refresh_users'):
            self.refresh_users()
        self.load_settings_tab()

    def check_for_updates(self):
        """Check for updates from GitHub."""
        try:
            self.check_updates_btn.setEnabled(False)
            self.check_updates_btn.setText("Checking...")
            self.update_status_label.setText("Checking for updates...")

            updater = AutoUpdater()

            from PyQt6.QtCore import QThread, pyqtSignal

            class UpdateChecker(QThread):
                update_checked = pyqtSignal(dict)

                def __init__(self, updater):
                    super().__init__()
                    self.updater = updater

                def run(self):
                    result = self.updater.check_for_updates()
                    self.update_checked.emit(result or {})

            self.update_checker = UpdateChecker(updater)
            self.update_checker.update_checked.connect(self.on_update_checked)
            self.update_checker.start()

        except Exception as e:
            self.check_updates_btn.setEnabled(True)
            self.check_updates_btn.setText("Check for Updates")
            self.update_status_label.setText(f"Error checking for updates: {str(e)}")

    def on_update_checked(self, result):
        """Handle the result of update check."""
        try:
            self.check_updates_btn.setEnabled(True)
            self.check_updates_btn.setText("Check for Updates")

            if not result:
                self.update_status_label.setText("Failed to check for updates")
                return

            if result.get('available', False):
                latest_version = result.get('latest_version', 'Unknown')
                self.update_status_label.setText(f"Update available: v{latest_version}")
                self.download_update_btn.setVisible(True)

                release_notes = result.get('release_notes', '')
                if release_notes:
                    self.update_info_display.setPlainText(f"Release Notes for v{latest_version}:\n\n{release_notes}")
                    self.update_info_display.setVisible(True)

                self.pending_update = result

            else:
                latest_version = result.get('latest_version', 'Unknown')
                self.update_status_label.setText(f"You have the latest version (v{latest_version})")
                self.download_update_btn.setVisible(False)
                self.update_info_display.setVisible(False)

        except Exception as e:
            self.update_status_label.setText(f"Error processing update check: {str(e)}")

    def download_update(self):
        """Download the available update."""
        try:
            if not hasattr(self, 'pending_update') or not self.pending_update:
                QMessageBox.warning(self, "Error", "No update information available")
                return

            download_url = self.pending_update.get('download_url')
            if not download_url:
                QMessageBox.warning(self, "Error", "No download URL available")
                return

            latest_version = self.pending_update.get('latest_version', 'Unknown')
            reply = QMessageBox.question(
                self,
                "Download Update",
                f"Download and install update to version {latest_version}?\n\n"
                "The application will need to restart to apply the update.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply != QMessageBox.StandardButton.Yes:
                return

            self.download_update_btn.setEnabled(False)
            self.download_update_btn.setText("Downloading...")
            self.update_progress.setVisible(True)
            self.update_progress.setValue(0)

            from PyQt6.QtCore import QThread, pyqtSignal

            class UpdateDownloader(QThread):
                progress_updated = pyqtSignal(int)
                download_completed = pyqtSignal(str)
                download_failed = pyqtSignal(str)

                def __init__(self, updater, download_url):
                    super().__init__()
                    self.updater = updater
                    self.download_url = download_url

                def run(self):
                    try:
                        def progress_callback(progress):
                            self.progress_updated.emit(int(progress))

                        file_path = self.updater.download_update(self.download_url, progress_callback)
                        if file_path:
                            self.download_completed.emit(file_path)
                        else:
                            self.download_failed.emit("Download failed")
                    except Exception as e:
                        self.download_failed.emit(str(e))

            self.update_downloader = UpdateDownloader(AutoUpdater(), download_url)
            self.update_downloader.progress_updated.connect(self.update_progress.setValue)
            self.update_downloader.download_completed.connect(self.on_download_completed)
            self.update_downloader.download_failed.connect(self.on_download_failed)
            self.update_downloader.start()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start download: {str(e)}")
            self.download_update_btn.setEnabled(True)
            self.download_update_btn.setText("Download Update")
            self.update_progress.setVisible(False)

    def on_download_completed(self, file_path):
        """Handle successful download completion."""
        try:
            self.update_progress.setVisible(False)
            self.download_update_btn.setEnabled(True)
            self.download_update_btn.setText("Download Update")

            reply = QMessageBox.question(
                self,
                "Update Downloaded",
                "Update downloaded successfully!\n\n"
                "Would you like to apply the update now?\n"
                "The application will close and restart.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.apply_update(file_path)
            else:
                QMessageBox.information(
                    self,
                    "Update Ready",
                    f"Update has been downloaded to:\n{file_path}\n\n"
                    "You can apply it later by restarting the application."
                )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error handling download completion: {str(e)}")

    def on_download_failed(self, error_message):
        """Handle download failure."""
        self.update_progress.setVisible(False)
        self.download_update_btn.setEnabled(True)
        self.download_update_btn.setText("Download Update")
        QMessageBox.critical(self, "Download Failed", f"Failed to download update:\n{error_message}")

    def apply_update(self, update_file):
        """Apply the downloaded update."""
        try:
            updater = AutoUpdater()

            if self.worker_thread and self.worker_thread.isRunning():
                self.stop_manager()
                time.sleep(2)  

            if updater.apply_update(update_file):
                QMessageBox.information(
                    self,
                    "Update Applied",
                    "Update has been applied successfully!\n"
                    "The application will now restart."
                )

                import subprocess
                import sys
                subprocess.Popen([sys.executable] + sys.argv)
                self.close()
            else:
                QMessageBox.critical(
                    self,
                    "Update Failed",
                    "Failed to apply the update. Please try again or update manually."
                )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error applying update: {str(e)}")

    def check_for_updates_on_startup(self):
        """Check for updates automatically on startup."""
        try:

            from PyQt6.QtCore import QThread, pyqtSignal

            class StartupUpdateChecker(QThread):
                update_found = pyqtSignal(dict)

                def __init__(self, updater):
                    super().__init__()
                    self.updater = updater

                def run(self):
                    try:
                        result = self.updater.check_for_updates(timeout=5)
                        if result and result.get('available', False):
                            self.update_found.emit(result)
                    except Exception:
                        pass  

            self.startup_checker = StartupUpdateChecker(self.auto_updater)
            self.startup_checker.update_found.connect(self.on_startup_update_found)
            self.startup_checker.start()

        except Exception:
            pass  

    def on_startup_update_found(self, update_info):
        """Handle when an update is found on startup."""
        try:
            latest_version = update_info.get('latest_version', 'Unknown')
            current_version = update_info.get('current_version', APP_VERSION)

            reply = QMessageBox.question(
                self,
                "Update Available",
                f"A new version of JARAM is available!\n\n"
                f"Current Version: {current_version}\n"
                f"Latest Version: {latest_version}\n\n"
                f"Would you like to go to the Settings tab to download it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:

                self.tab_widget.setCurrentIndex(4)  
                self.pending_update = update_info
                self.update_status_label.setText(f"Update available: v{latest_version}")
                self.download_update_btn.setVisible(True)

                release_notes = update_info.get('release_notes', '')
                if release_notes:
                    self.update_info_display.setPlainText(f"Release Notes for v{latest_version}:\n\n{release_notes}")
                    self.update_info_display.setVisible(True)

        except Exception as e:
            pass  

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
                         f"JARAM(Just Another Roblox Account Manager) v{APP_VERSION}\n\n"
                         "Advanced multi-account Roblox session manager\n"
                         "with automated presence monitoring and process management.\n\n"
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

    def show_user_context_menu(self, position):
        """Show context menu for user table right-click"""
        item = self.users_table.itemAt(position)
        if item is None:
            return

        row = item.row()
        if row >= len(list(self.user_data.keys())):
            return

        user_id = list(self.user_data.keys())[row]
        users_config = self.config_manager.load_users()
        user_info = users_config.get(user_id, {})
        is_disabled = user_info.get("disabled", False) if isinstance(user_info, dict) else False

        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)

        # Toggle enable/disable action
        if is_disabled:
            enable_action = menu.addAction("🔓 Enable Account")
            enable_action.triggered.connect(lambda: self.toggle_user_enabled(user_id))
        else:
            disable_action = menu.addAction("🔒 Disable Account")
            disable_action.triggered.connect(lambda: self.toggle_user_enabled(user_id))

        menu.addSeparator()

        # Other actions
        restart_action = menu.addAction("🔄 Restart Session")
        restart_action.triggered.connect(lambda: self.restart_user_session(user_id))

        kill_action = menu.addAction("💀 Kill Processes")
        kill_action.triggered.connect(lambda: self.kill_user_processes(user_id))

        # Show menu at cursor position
        menu.exec(self.users_table.mapToGlobal(position))

    def on_account_server_type_changed(self):
        """Handle server type radio button changes"""
        if self.account_private_radio.isChecked():
            self.account_place_id_label.hide()
            self.account_place_id.hide()
        else:
            self.account_place_id_label.show()
            self.account_place_id.show()

    def on_disable_kill_timeout_toggled(self, checked):
        """Handle disable kill timeout checkbox toggle"""
        self.kill_timeout_input.setEnabled(not checked)
        if checked:
            self.kill_timeout_input.setToolTip("Kill timeout is disabled")
        else:
            self.kill_timeout_input.setToolTip("Time until window auto-closes (≤ 1,740s recommended)")

    def clear_account_form(self):
        """Clear all form fields"""
        self.account_user_id.clear()
        self.account_username.clear()
        self.account_private_link.clear()
        self.account_place_id.clear()
        self.account_cookie.clear()
        self.account_disabled.setChecked(False)
        self.account_private_radio.setChecked(True)
        self.on_account_server_type_changed()

    def add_account(self):
        """Add a new account"""
        user_id = self.account_user_id.text().strip()
        username = self.account_username.text().strip()
        private_link = self.account_private_link.text().strip()
        place_id = self.account_place_id.text().strip()
        cookie = self.account_cookie.text().strip()
        disabled = self.account_disabled.isChecked()

        server_type = "private" if self.account_private_radio.isChecked() else "public"

        # Validation
        if not user_id:
            QMessageBox.warning(self, "Error", "User ID is required!")
            return

        if not username:
            username = f"User_{user_id}"

        if not cookie:
            QMessageBox.warning(self, "Error", "Cookie is required!")
            return

        if server_type == "private" and not private_link:
            QMessageBox.warning(self, "Error", "Private server link is required for private servers!")
            return

        if server_type == "public" and not place_id:
            QMessageBox.warning(self, "Error", "Place ID is required for public servers!")
            return

        # Check if user already exists
        users_config = self.config_manager.load_users()
        if user_id in users_config:
            QMessageBox.warning(self, "Error", f"User {user_id} already exists!")
            return

        # Create account data
        account_data = {
            "username": username,
            "server_type": server_type,
            "private_server_link": private_link if server_type == "private" else "",
            "place_id": place_id if server_type == "public" else "",
            "cookie": cookie,
            "disabled": disabled
        }

        # Save account
        users_config[user_id] = account_data
        if self.config_manager.save_users(users_config):
            QMessageBox.information(self, "Success", f"Account {user_id} ({username}) added successfully!")
            self.clear_account_form()
            self.refresh_accounts_list()
            self.refresh_users()  # Refresh the users tab too
        else:
            QMessageBox.critical(self, "Error", "Failed to save account!")

    def refresh_accounts_list(self):
        """Refresh the accounts list table"""
        users_config = self.config_manager.load_users()
        self.accounts_list.setRowCount(len(users_config))

        for row, (user_id, user_info) in enumerate(users_config.items()):
            if isinstance(user_info, dict):
                username = user_info.get("username", f"User_{user_id}")
                server_type = user_info.get("server_type", "private")
                disabled = user_info.get("disabled", False)
            else:
                username = f"User_{user_id}"
                server_type = "private"
                disabled = False

            # User ID
            self.accounts_list.setItem(row, 0, QTableWidgetItem(user_id))

            # Username
            self.accounts_list.setItem(row, 1, QTableWidgetItem(username))

            # Server Type
            self.accounts_list.setItem(row, 2, QTableWidgetItem(server_type.title()))

            # Status
            status = "Disabled" if disabled else "Enabled"
            status_item = QTableWidgetItem(status)
            if disabled:
                status_item.setForeground(QColor("#FF6666"))
            else:
                status_item.setForeground(QColor("#66FF66"))
            self.accounts_list.setItem(row, 3, status_item)

            # Edit button - simplified approach without wrapper widget
            edit_btn = QPushButton("Edit")
            edit_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ModernStyle.PRIMARY};
                    color: white;
                    border: none;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-size: 8px;
                    font-weight: bold;
                    min-width: 50px;
                    max-width: 80px;
                    min-height: 18px;
                    max-height: 22px;
                }}
                QPushButton:hover {{ background-color: {ModernStyle.PRIMARY_VARIANT}; }}
            """)
            edit_btn.clicked.connect(lambda checked, uid=user_id: self.edit_account(uid))
            self.accounts_list.setCellWidget(row, 4, edit_btn)

            # Delete button - simplified approach without wrapper widget
            delete_btn = QPushButton("Del")
            delete_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #f44336;
                    color: white;
                    border: none;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-size: 8px;
                    font-weight: bold;
                    min-width: 40px;
                    max-width: 70px;
                    min-height: 18px;
                    max-height: 22px;
                }}
                QPushButton:hover {{ background-color: #da190b; }}
            """)
            delete_btn.clicked.connect(lambda checked, uid=user_id: self.delete_account(uid))
            self.accounts_list.setCellWidget(row, 5, delete_btn)

    def edit_account(self, user_id):
        """Edit an existing account"""
        users_config = self.config_manager.load_users()
        user_info = users_config.get(user_id, {})

        if isinstance(user_info, dict):
            # Fill form with existing data
            self.account_user_id.setText(user_id)
            self.account_user_id.setEnabled(False)  # Don't allow changing user ID
            self.account_username.setText(user_info.get("username", f"User_{user_id}"))
            self.account_private_link.setText(user_info.get("private_server_link", ""))
            self.account_place_id.setText(user_info.get("place_id", ""))
            self.account_cookie.setText(user_info.get("cookie", ""))
            self.account_disabled.setChecked(user_info.get("disabled", False))

            server_type = user_info.get("server_type", "private")
            if server_type == "public":
                self.account_public_radio.setChecked(True)
            else:
                self.account_private_radio.setChecked(True)
            self.on_account_server_type_changed()

            # Change button text
            self.add_account_btn.setText("Update Account")
            self.add_account_btn.clicked.disconnect()
            self.add_account_btn.clicked.connect(lambda: self.update_account(user_id))

    def update_account(self, user_id):
        """Update an existing account"""
        username = self.account_username.text().strip()
        private_link = self.account_private_link.text().strip()
        place_id = self.account_place_id.text().strip()
        cookie = self.account_cookie.text().strip()
        disabled = self.account_disabled.isChecked()

        server_type = "private" if self.account_private_radio.isChecked() else "public"

        # Validation
        if not username:
            username = f"User_{user_id}"

        if not cookie:
            QMessageBox.warning(self, "Error", "Cookie is required!")
            return

        if server_type == "private" and not private_link:
            QMessageBox.warning(self, "Error", "Private server link is required for private servers!")
            return

        if server_type == "public" and not place_id:
            QMessageBox.warning(self, "Error", "Place ID is required for public servers!")
            return

        # Update account data
        users_config = self.config_manager.load_users()
        users_config[user_id] = {
            "username": username,
            "server_type": server_type,
            "private_server_link": private_link if server_type == "private" else "",
            "place_id": place_id if server_type == "public" else "",
            "cookie": cookie,
            "disabled": disabled
        }

        # Save account
        if self.config_manager.save_users(users_config):
            QMessageBox.information(self, "Success", f"Account {user_id} ({username}) updated successfully!")
            self.clear_account_form()
            self.account_user_id.setEnabled(True)
            self.add_account_btn.setText("Add Account")
            self.add_account_btn.clicked.disconnect()
            self.add_account_btn.clicked.connect(self.add_account)
            self.refresh_accounts_list()
            self.refresh_users()  # Refresh the users tab too
        else:
            QMessageBox.critical(self, "Error", "Failed to update account!")

    def delete_account(self, user_id):
        """Delete an account"""
        reply = QMessageBox.question(self, "Confirm Delete",
                                   f"Are you sure you want to delete account {user_id}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            users_config = self.config_manager.load_users()
            if user_id in users_config:
                del users_config[user_id]
                if self.config_manager.save_users(users_config):
                    QMessageBox.information(self, "Success", f"Account {user_id} deleted successfully!")
                    self.refresh_accounts_list()
                    self.refresh_users()  # Refresh the users tab too
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete account!")

    def toggle_user_enabled(self, user_id):
        """Toggle the enabled/disabled status of a user account"""
        try:
            users_config = self.config_manager.load_users()
            if user_id in users_config:
                user_info = users_config[user_id]
                if isinstance(user_info, dict):
                    # Toggle the disabled status
                    current_disabled = user_info.get("disabled", False)
                    user_info["disabled"] = not current_disabled

                    # Save the updated configuration
                    if self.config_manager.save_users(users_config):
                        # If we're disabling the account, kill its processes
                        if user_info["disabled"]:
                            if self.worker_thread and self.worker_thread.isRunning():
                                self.worker_thread.kill_user_processes(user_id)

                        # Refresh the display
                        self.refresh_users()

                        status = "disabled" if user_info["disabled"] else "enabled"
                        QMessageBox.information(self, "Account Status Changed",
                                              f"Account {user_id} has been {status}.")
                        return True
                    else:
                        QMessageBox.critical(self, "Error", "Failed to save account configuration.")
                        return False
                else:
                    QMessageBox.warning(self, "Error", "Cannot modify legacy account format. Please update account configuration.")
                    return False
            else:
                QMessageBox.warning(self, "Error", f"Account {user_id} not found.")
                return False
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to toggle account status: {e}")
            return False

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
                self.worker_thread.process_mgr.eliminate_process(
                    int(pid), self.worker_thread.manager.process_monitor
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
                self._cleanup_resources()
                event.accept()
            else:
                event.ignore()
        else:
            self._cleanup_resources()
            event.accept()

    def _cleanup_resources(self):
        """Clean up resources to prevent memory leaks"""
        # Stop timers
        if hasattr(self, 'ui_timer'):
            self.ui_timer.stop()
        if hasattr(self, 'uptime_timer'):
            self.uptime_timer.stop()

        # Clear caches
        self._previous_user_data.clear()
        self._previous_process_data.clear()

        # Clear style cache
        ModernStyle._style_cache.clear()

def main():
    app = QApplication(sys.argv)

    app.setApplicationName("JARAM")
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("cresqnt")

    # Set application icon
    icon_path = _get_icon_path()
    if icon_path and os.path.exists(icon_path):
        icon = QIcon(icon_path)
        app.setWindowIcon(icon)
        print(f"Set application icon from: {icon_path}")
    else:
        print("Could not set application icon - file not found")

    window = RobloxManagerGUI()
    
    # Also set the window icon specifically
    if icon_path and os.path.exists(icon_path):
        window.setWindowIcon(QIcon(icon_path))
        print(f"Set window icon from: {icon_path}")
    
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()