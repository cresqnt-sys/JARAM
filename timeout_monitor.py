# timeout_monitor.py
import psutil, time, threading, queue, requests, sys, traceback

TARGET_NAME = "RobloxPlayerBeta.exe"

class TimeoutMonitor:
    """Background thread that kills stale / inactive Roblox clients."""
    def __init__(self,
                 kill_timeout: int,
                 poll_interval: int,
                 webhook_url: str,
                 ping_message: str):
        self.kill_timeout        = kill_timeout
        self.poll_interval       = poll_interval
        self.webhook_url         = webhook_url
        self.ping_message        = ping_message

        self.proc_state = {}     # pid -> last_active ts
        self.thread   = None
        self.stop_evt = threading.Event()

        # outbound messages for GUI / logs
        self.msg_q: "queue.Queue[str]" = queue.Queue()

    # ── public api ──────────────────────────────────────────────────────
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_evt.clear()
        self.thread = threading.Thread(target=self._run, name="TimeoutMon", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=4)

    # ── internal helpers ────────────────────────────────────────────────
    def _seconds_running(self, p: psutil.Process) -> float:
        try:  return time.time() - p.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied): return 0.0

    def _kill(self, p: psutil.Process, reason: str):
        try:
            p.kill()
            self.msg_q.put(f"Killed {p.pid} ({reason})")
        except Exception:
            pass

    def _send_webhook(self):
        if not self.webhook_url: return
        try:
            requests.post(self.webhook_url,
                          json={"content": self.ping_message},
                          timeout=8)
        except Exception:
            pass

    def _run(self):
        last_count = None
        while not self.stop_evt.is_set():
            try:
                procs = [p for p in psutil.process_iter(["pid","name","create_time"])
                        if p.info["name"] == TARGET_NAME]

                # age-based kill
                for p in procs:
                    if time.time() - p.create_time() >= self.kill_timeout:
                        self._kill(p, "age-limit")

                # webhook when count drops to ≤ 1
                count = len(procs)
                if last_count and last_count > 1 and count <= 1:
                    self._send_webhook()
                last_count = count

                self.msg_q.put(f"TimeoutMon: {count} procs")

            except Exception:
                traceback.print_exc(file=sys.stderr)

            for _ in range(int(self.poll_interval*2)):
                if self.stop_evt.is_set(): break
                time.sleep(0.5)
