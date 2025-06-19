import time
import threading
from typing import Optional, Callable
from PyQt6.QtCore import QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import QMessageBox, QProgressDialog, QApplication
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

class CookieExtractionThread(QThread):

    cookie_extracted = pyqtSignal(str)
    extraction_failed = pyqtSignal(str)
    status_update = pyqtSignal(str)
    browser_ready = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.driver = None
        self.should_stop = False
        self.extraction_timeout = 300
        self.extraction_completed = False

    def run(self):
        try:
            self.status_update.emit("Initializing browser...")
            self._setup_browser()

            if self.should_stop:
                return

            self.status_update.emit("Navigating to Roblox login page...")
            self._navigate_to_login()

            if self.should_stop:
                return

            self.status_update.emit("Browser ready - Please complete login manually")
            self.browser_ready.emit()

            self._wait_for_login_completion()

        except Exception as e:
            self.extraction_failed.emit(f"Unexpected error: {str(e)}")
        finally:
            self._cleanup_browser()

    def _setup_browser(self):
        try:

            options = uc.ChromeOptions()

            options.add_argument("--no-first-run")
            options.add_argument("--no-default-browser-check")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-plugins-discovery")
            options.add_argument("--disable-dev-shm-usage")

            options.add_argument("--window-size=1200,800")

            self.driver = uc.Chrome(options=options, version_main=None)

            self.driver.implicitly_wait(10)
            self.driver.set_page_load_timeout(30)

        except Exception as e:
            raise Exception(f"Failed to initialize browser: {str(e)}")

    def _navigate_to_login(self):
        try:
            self.driver.get("https://www.roblox.com/login")

            WebDriverWait(self.driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            if "login" not in self.driver.current_url.lower():
                raise Exception("Failed to navigate to login page")

        except TimeoutException:
            raise Exception("Login page failed to load within timeout period")
        except Exception as e:
            raise Exception(f"Navigation error: {str(e)}")

    def _wait_for_login_completion(self):
        start_time = time.time()
        check_interval = 2
        last_url = ""
        consecutive_same_url_count = 0

        while not self.should_stop and (time.time() - start_time) < self.extraction_timeout and not self.extraction_completed:
            try:

                try:
                    current_window = self.driver.current_window_handle
                    current_url = self.driver.current_url.lower()
                except:
                    if not self.extraction_completed:
                        self.extraction_completed = True
                        self.extraction_failed.emit("Browser window was closed by user")
                    return

                if current_url == last_url:
                    consecutive_same_url_count += 1
                else:
                    consecutive_same_url_count = 0
                    last_url = current_url

                login_success_indicators = [
                    "roblox.com/home",
                    "roblox.com/discover",
                    "roblox.com/games",
                    "roblox.com/catalog",
                    "roblox.com/avatar"
                ]

                is_logged_in = ("login" not in current_url and
                               "roblox.com" in current_url and
                               any(indicator in current_url for indicator in login_success_indicators))

                if not is_logged_in and current_url == "https://www.roblox.com/":
                    is_logged_in = True

                if is_logged_in:
                    self.status_update.emit("Login detected! Verifying authentication...")

                    time.sleep(2)

                    if self._verify_login_status():
                        self.status_update.emit("Authentication verified! Extracting cookie...")

                        cookie = self._extract_roblosecurity_cookie()
                        if cookie and not self.extraction_completed:
                            self.extraction_completed = True
                            self.cookie_extracted.emit(cookie)
                            return
                    elif consecutive_same_url_count >= 2:
                        self.status_update.emit("Waiting for page to fully load...")

                        time.sleep(3)
                        if self._verify_login_status():
                            self.status_update.emit("Authentication verified! Extracting cookie...")
                            cookie = self._extract_roblosecurity_cookie()
                            if cookie and not self.extraction_completed:
                                self.extraction_completed = True
                                self.cookie_extracted.emit(cookie)
                                return

                time.sleep(check_interval)

            except WebDriverException as e:

                if not self.extraction_completed:
                    self.extraction_completed = True
                    self.extraction_failed.emit("Browser connection lost")
                return
            except Exception as e:
                if not self.extraction_completed:
                    self.extraction_completed = True
                    self.extraction_failed.emit(f"Error during login monitoring: {str(e)}")
                return

        if not self.should_stop and not self.extraction_completed:
            self.extraction_completed = True
            self.extraction_failed.emit("Login timeout - please try again")

    def _verify_login_status(self) -> bool:
        try:

            login_indicators = [
                "//a[contains(@href, '/users/')]",
                "//span[contains(@class, 'avatar')]",
                "//*[contains(@class, 'navbar-right')]//a[contains(@href, '/my/')]",
                "//*[contains(text(), 'Robux')]",
                "//a[contains(@href, '/my/account')]"
            ]

            for indicator in login_indicators:
                try:
                    elements = self.driver.find_elements(By.XPATH, indicator)
                    if elements:
                        return True
                except:
                    continue

            return False
        except Exception:
            return False

    def _extract_roblosecurity_cookie(self) -> Optional[str]:
        try:

            time.sleep(1)

            cookies = self.driver.get_cookies()

            for cookie in cookies:
                if cookie['name'] == '.ROBLOSECURITY':
                    cookie_value = cookie['value']

                    if (cookie_value and
                        len(cookie_value) > 100 and
                        cookie_value.startswith('_|WARNING:-DO-NOT-SHARE-THIS')):
                        return cookie_value

            self.driver.refresh()
            time.sleep(2)

            cookies = self.driver.get_cookies()
            for cookie in cookies:
                if cookie['name'] == '.ROBLOSECURITY':
                    cookie_value = cookie['value']
                    if (cookie_value and
                        len(cookie_value) > 100 and
                        cookie_value.startswith('_|WARNING:-DO-NOT-SHARE-THIS')):
                        return cookie_value

            return None

        except Exception as e:
            return None

    def _cleanup_browser(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            finally:
                self.driver = None

    def stop_extraction(self):
        self.should_stop = True
        if not self.extraction_completed:
            self.extraction_completed = True
        self._cleanup_browser()

class CookieExtractor(QObject):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.extraction_thread = None
        self.progress_dialog = None
        self.callback = None
        self.callback_called = False

    def extract_cookie_async(self, callback: Callable[[str], None], parent_widget=None):
        if self.extraction_thread and self.extraction_thread.isRunning():
            QMessageBox.warning(parent_widget, "Extraction in Progress",
                              "Cookie extraction is already in progress. Please wait.")
            return

        self.callback = callback
        self.callback_called = False

        self.extraction_thread = CookieExtractionThread()
        self.extraction_thread.cookie_extracted.connect(self._on_cookie_extracted)
        self.extraction_thread.extraction_failed.connect(self._on_extraction_failed)
        self.extraction_thread.status_update.connect(self._on_status_update)
        self.extraction_thread.browser_ready.connect(self._on_browser_ready)
        self.extraction_thread.finished.connect(self._on_thread_finished)

        self._create_progress_dialog(parent_widget)

        self.extraction_thread.start()

    def _create_progress_dialog(self, parent_widget):
        self.progress_dialog = QProgressDialog(parent_widget)
        self.progress_dialog.setWindowTitle("Cookie Extraction")
        self.progress_dialog.setLabelText("Initializing browser...")
        self.progress_dialog.setRange(0, 0)
        self.progress_dialog.setCancelButtonText("Cancel")
        self.progress_dialog.setModal(True)
        self.progress_dialog.canceled.connect(self._cancel_extraction)
        self.progress_dialog.show()

    def _on_cookie_extracted(self, cookie: str):
        if self.callback_called:
            return

        self.callback_called = True

        if self.progress_dialog:
            self.progress_dialog.close()

        if self.callback:
            self.callback(cookie)

    def _on_extraction_failed(self, error_message: str):
        if self.callback_called:
            return

        self.callback_called = True

        if self.progress_dialog:
            self.progress_dialog.close()

        QMessageBox.critical(None, "Cookie Extraction Failed",
                           f"Failed to extract cookie:\n\n{error_message}")

        if self.callback:
            self.callback(None)

    def _on_status_update(self, status: str):
        if self.progress_dialog:
            self.progress_dialog.setLabelText(status)

    def _on_browser_ready(self):
        if self.progress_dialog:
            self.progress_dialog.setLabelText(
                "Browser is ready!\n\n"
                "Please complete the Roblox login process in the browser window:\n"
                "1. Enter your username/email and password\n"
                "2. Complete any 2FA verification if required\n"
                "3. Wait for redirect to Roblox homepage\n\n"
                "The cookie will be extracted automatically once login is detected.\n"
                "This dialog will close when extraction is complete."
            )

    def _on_thread_finished(self):
        if self.progress_dialog:
            self.progress_dialog.close()

        self.extraction_thread = None

    def _cancel_extraction(self):
        if self.callback_called:
            return

        self.callback_called = True

        if self.extraction_thread:
            self.extraction_thread.stop_extraction()
            self.extraction_thread.wait(5000)

        if self.callback:
            self.callback(None)