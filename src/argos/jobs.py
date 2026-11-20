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


class JobRunner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}

    def _case_lock(self, case_id: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(case_id, threading.Lock())

    def busy(self, case_id: str) -> bool:
        return self._case_lock(case_id).locked()

    def submit_analysis(self, store: Store, case_id: str) -> str:
        lock = self._case_lock(case_id)
        if not lock.acquire(blocking=False):
            raise CaseBusy("another operation is running on this case; wait for it or cancel it")
        try:
            jid = store.create_job(case_id, "analyze")
        except Exception:
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
        try:
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
