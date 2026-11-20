"""Background jobs for long operations (feature C).

Each job runs in its own thread with its own SQLite connection, so the web UI stays responsive
(SQLite WAL lets the UI read the last committed state). Jobs on the same case are serialized by a
per-case lock; a second analysis request for a busy case is refused rather than queued silently.
Progress and cancellation are persisted in the `jobs` table; jobs left running by a killed process
are marked `interrupted` at the next start (Store.recover_interrupted_jobs). Because analysis
results are committed in one transaction, a cancelled/failed/interrupted job never replaces the
last successful run.
"""
from __future__ import annotations

import json
import threading
import time

from argos.config import Settings
from argos.normalize.timeutil import now_iso
from argos.store import Store


class CaseBusy(Exception):
    pass


class QueueFull(Exception):
    pass


class DataDirBusy(Exception):
    pass


class DataDirLock:
    """Exclusive, OS-level lock on a data directory held by the running web server (R08).

    Job admission is process-local, so the supported deployment is ONE server process per data directory.
    The lock makes that assumption enforceable: a second server, or a mutating CLI command, refuses to run
    while a server holds it. The lock is released automatically if the process dies."""

    def __init__(self, home):
        from pathlib import Path
        self.path = Path(home) / ".argos-server.lock"
        self.fd = None

    def acquire(self):
        import os
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise DataDirBusy(f"another ARGOS server is using {self.path.parent}") from exc
        self.fd = fd
        return self

    def release(self):
        import os
        if self.fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self.fd, 0, 0)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None

    @classmethod
    def held_by_other(cls, home) -> bool:
        lk = cls(home)
        try:
            lk.acquire()
        except DataDirBusy:
            return True
        lk.release()
        return False


class JobRunner:
    """Admission control for long operations (R08): at most `settings.max_concurrent_jobs` analyses run at
    once across ALL cases (default 1, because analysis memory grows with case size); up to
    `settings.max_queued_jobs` further jobs wait in status `queued`; beyond that a submission is rejected
    with QueueFull. Jobs on the same case are serialized (CaseBusy). A queued job can be cancelled before it
    starts. Admission is per process: see DataDirLock."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._max_running = max(1, int(getattr(settings, "max_concurrent_jobs", 1)))
        self._running = 0
        self._fifo: list[str] = []  # queued job ids in submission order (fair, first-in first-out)
        self._cond = threading.Condition(self._guard)
        self._admitted = 0  # running + queued jobs of this process

    def _case_lock(self, case_id: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(case_id, threading.Lock())

    def busy(self, case_id: str) -> bool:
        return self._case_lock(case_id).locked()

    def submit_analysis(self, store: Store, case_id: str) -> str:
        lock = self._case_lock(case_id)
        if not lock.acquire(blocking=False):
            raise CaseBusy("another operation is running or queued on this case; wait for it or cancel it")
        with self._guard:
            running = max(1, int(getattr(self.settings, "max_concurrent_jobs", 1)))
            limit = running + max(0, int(getattr(self.settings, "max_queued_jobs", 8)))
            if self._admitted >= limit:
                lock.release()
                raise QueueFull(f"analysis queue is full ({self._admitted} admitted: up to {running} running and "
                                f"{limit - running} queued); try again later")
            self._admitted += 1
        try:
            jid = store.create_job(case_id, "analyze")
            with self._guard:
                self._fifo.append(jid)
        except Exception:
            with self._guard:
                self._admitted -= 1
            lock.release()
            raise
        t = threading.Thread(target=self._run_analysis, args=(jid, case_id, lock), name=f"argos-{jid}", daemon=True)
        self._threads[jid] = t
        t.start()
        return jid

    def _run_analysis(self, jid: str, case_id: str, lock: threading.Lock):
        from argos.analysis import AnalysisCancelled, run_analysis
        st = Store(self.settings.db_path)
        last = [0.0]
        have_slot = False
        try:
            st.update_job(jid, message="queued: waiting for an analysis slot")
            while True:
                with self._cond:
                    if self._fifo and self._fifo[0] == jid and self._running < self._max_running:
                        self._fifo.pop(0)
                        self._running += 1
                        have_slot = True
                        self._cond.notify_all()
                        break
                    self._cond.wait(0.2)
                j = st.get_job(jid)
                if j and j.get("cancel_requested"):
                    with self._cond:
                        if jid in self._fifo:
                            self._fifo.remove(jid)
                        self._cond.notify_all()
                    break
            if not have_slot:
                st.update_job(jid, status="cancelled", message="cancelled before it started", finished_at=now_iso())
                return
            if (st.get_job(jid) or {}).get("cancel_requested"):
                st.update_job(jid, status="cancelled", message="cancelled before it started", finished_at=now_iso())
                return
            st.update_job(jid, status="running", started_at=now_iso(), progress=0.0, message="starting")

            def progress(frac, msg):
                now = time.monotonic()
                if now - last[0] >= 0.25 or frac >= 1.0:
                    last[0] = now
                    st.update_job(jid, progress=round(float(frac), 3), message=str(msg)[:200])

            def cancel():
                j = st.get_job(jid)
                return bool(j and j.get("cancel_requested"))

            res = run_analysis(st, self.settings, case_id, progress=progress, cancel=cancel)
            st.update_job(jid, status="succeeded", progress=1.0, message="done", finished_at=now_iso(),
                          result=json.dumps({"run_id": res["run_id"], "stats": res.get("stats")}))
        except AnalysisCancelled as exc:
            st.update_job(jid, status="cancelled", message=str(exc), finished_at=now_iso())
        except Exception as exc:  # noqa: BLE001 - recorded for the analyst
            st.update_job(jid, status="failed", error=f"{type(exc).__name__}: {exc}"[:2000], finished_at=now_iso())
        finally:
            with self._cond:
                if have_slot:
                    self._running -= 1
                self._admitted -= 1
                self._cond.notify_all()
            st.close()
            lock.release()
            self._threads.pop(jid, None)

    def wait(self, jid: str, timeout: float | None = None) -> bool:
        t = self._threads.get(jid)
        if t is None:
            return True
        t.join(timeout)
        return not t.is_alive()

    @staticmethod
    def cancel(store: Store, jid: str) -> bool:
        j = store.get_job(jid)
        if not j or j["status"] not in ("queued", "running"):
            return False
        store.update_job(jid, cancel_requested=1)
        return True
