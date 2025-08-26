import requests
import json
import time
import os
import sys
import subprocess
import shutil
import zipfile
import tempfile
from pathlib import Path
from packaging import version as pkg_version
from typing import Optional, Dict, Any, Tuple
import logging

from main import APP_VERSION as CURRENT_VERSION

class AutoUpdater:
    """
    Auto updater that checks for new releases on GitHub and handles updates.
    """

    def __init__(self, repo_url: str = "https://github.com/cresqnt-sys/JARAM"):
        self.repo_url = repo_url.rstrip('/')
        self.api_url = f"https://api.github.com/repos/cresqnt-sys/JARAM"
        self.current_version = CURRENT_VERSION
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Set up logging for the auto updater."""
        logger = logging.getLogger('auto_updater')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def check_for_updates(self, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """
        Check for updates by comparing current version with latest GitHub release.

        Args:
            timeout: Request timeout in seconds

        Returns:
            Dictionary with update information if available, None otherwise
        """
        try:
            self.logger.info(f"Checking for updates... Current version: {self.current_version}")

            response = requests.get(
                f"{self.api_url}/releases/latest",
                timeout=timeout,
                headers={
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': f'JARAM-AutoUpdater/{self.current_version}'
                }
            )

            if response.status_code == 404:
                self.logger.warning("No releases found on GitHub")
                return None

            response.raise_for_status()
            release_data = response.json()

            latest_version = release_data.get('tag_name', '').lstrip('v')

            if not latest_version:
                self.logger.warning("Could not determine latest version from release data")
                return None

            if self._is_newer_version(latest_version, self.current_version):
                self.logger.info(f"New version available: {latest_version}")

                return {
                    'available': True,
                    'latest_version': latest_version,
                    'current_version': self.current_version,
                    'release_url': release_data.get('html_url'),
                    'download_url': self._get_download_url(release_data),
                    'release_notes': release_data.get('body', ''),
                    'published_at': release_data.get('published_at'),
                    'prerelease': release_data.get('prerelease', False)
                }
            else:
                self.logger.info("No updates available")
                return {
                    'available': False,
                    'latest_version': latest_version,
                    'current_version': self.current_version
                }

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error while checking for updates: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error checking for updates: {e}")
            return None

    def _is_newer_version(self, latest: str, current: str) -> bool:
        """
        Compare version strings to determine if latest is newer than current.

        Args:
            latest: Latest version string
            current: Current version string

        Returns:
            True if latest version is newer
        """
        try:
            return pkg_version.parse(latest) > pkg_version.parse(current)
        except Exception as e:
            self.logger.error(f"Error comparing versions: {e}")

            return latest != current

    def _get_download_url(self, release_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract download URL from release data.

        Args:
            release_data: GitHub release API response data

        Returns:
            Download URL for the release asset
        """
        assets = release_data.get('assets', [])

        for asset in assets:
            name = asset.get('name', '').lower()
            if name.endswith('.exe') or name.endswith('.zip'):
                return asset.get('browser_download_url')

        return release_data.get('zipball_url')

    def download_update(self, download_url: str, progress_callback=None) -> Optional[str]:
        """
        Download the update file.

        Args:
            download_url: URL to download the update from
            progress_callback: Optional callback function for progress updates

        Returns:
            Path to downloaded file, None if failed
        """
        try:
            self.logger.info(f"Downloading update from: {download_url}")

            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()

            temp_dir = tempfile.mkdtemp()
            filename = download_url.split('/')[-1]
            if not filename or '.' not in filename:
                filename = 'update.zip'

            file_path = os.path.join(temp_dir, filename)

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            progress_callback(progress)

            self.logger.info(f"Update downloaded to: {file_path}")
            return file_path

        except Exception as e:
            self.logger.error(f"Error downloading update: {e}")
            return None

    def apply_update(self, update_file: str) -> bool:
        """
        Apply the downloaded update.

        Args:
            update_file: Path to the downloaded update file

        Returns:
            True if update was applied successfully
        """
        try:
            self.logger.info(f"Applying update from: {update_file}")

            backup_dir = self._create_backup()
            if not backup_dir:
                self.logger.error("Failed to create backup")
                return False

            if update_file.endswith('.zip'):
                return self._apply_zip_update(update_file, backup_dir)
            elif update_file.endswith('.exe'):
                return self._apply_exe_update(update_file)
            else:
                self.logger.error(f"Unsupported update file format: {update_file}")
                return False

        except Exception as e:
            self.logger.error(f"Error applying update: {e}")
            return False

    def _create_backup(self) -> Optional[str]:
        """Create a backup of the current installation."""
        try:
            current_dir = Path(__file__).parent
            backup_dir = current_dir / f"backup_{int(time.time())}"
            backup_dir.mkdir(exist_ok=True)

            important_files = ['main.py', 'gui.py', 'version.py', 'auto_updater.py']
            for file in important_files:
                src = current_dir / file
                if src.exists():
                    shutil.copy2(src, backup_dir / file)

            self.logger.info(f"Backup created at: {backup_dir}")
            return str(backup_dir)

        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return None

    def _apply_zip_update(self, zip_file: str, backup_dir: str) -> bool:
        """Apply update from zip file."""
        try:
            current_dir = Path(__file__).parent

            with zipfile.ZipFile(zip_file, 'r') as zip_ref:

                temp_extract_dir = tempfile.mkdtemp()
                zip_ref.extractall(temp_extract_dir)

                extract_path = Path(temp_extract_dir)
                content_dirs = list(extract_path.iterdir())

                if len(content_dirs) == 1 and content_dirs[0].is_dir():
                    source_dir = content_dirs[0]
                else:
                    source_dir = extract_path

                for item in source_dir.rglob('*'):
                    if item.is_file():
                        rel_path = item.relative_to(source_dir)
                        dest_path = current_dir / rel_path
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item, dest_path)

                shutil.rmtree(temp_extract_dir)

            self.logger.info("Update applied successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error applying zip update: {e}")
            return False

    def _apply_exe_update(self, exe_file: str) -> bool:
        """Apply update from executable file."""
        try:

            current_exe = sys.executable
            backup_exe = f"{current_exe}.backup"

            shutil.copy2(current_exe, backup_exe)

            shutil.copy2(exe_file, current_exe)

            self.logger.info("Executable update applied successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error applying exe update: {e}")
            return False

    def get_update_info(self) -> Dict[str, Any]:
        """Get information about available updates."""
        return self.check_for_updates() or {
            'available': False,
            'current_version': self.current_version,
            'error': 'Could not check for updates'
        }
