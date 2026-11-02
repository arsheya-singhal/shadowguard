"""ShadowGuard v2 engine: explainable behavioral ransomware-like activity detector.

Source of evidence (all user-level, no driver):
  * file-system change notifications (watchdog -> ReadDirectoryChangesW on Windows)
  * Shannon entropy of the first 4 KB of recently changed files (content jumps from readable to random-looking)
  * per-process I/O write counters (psutil) for best-effort process attribution
Educational prototype: it alerts, it never blocks or deletes anything."""
import collections, json, math, os, queue, threading, time, traceback
from pathlib import Path
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WINDOW, TICK, WATCH_AT, ALERT_AT, GRACE = 5.0, 0.5, 30, 60, 10.0
SAMPLE_BYTES, ENT_MIN, ENT_JUMP = 4096, 7.0, 2.0
# processes that react to file changes (indexing, antivirus); their I/O is de-prioritised for attribution
BACKGROUND = {"searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe", "msmpeng.exe",
              "system", "svchost.exe", "onedrive.exe", "explorer.exe", "backgroundtaskhost.exe"}
# key, label, saturation value (indicator is full at this value)
IND = [("mod", "Existing files rewritten", 30), ("ren", "Files renamed", 20), ("dirs", "Directories touched", 5),
       ("ext", "File-type diversity", 4), ("burst", "Burst vs baseline", 15), ("ent", "Entropy jumps", 15)]
WEIGHTS = {True: {"mod": 20, "ren": 20, "dirs": 10, "ext": 10, "burst": 10, "ent": 30},
           False: {"mod": 30, "ren": 25, "dirs": 15, "ext": 15, "burst": 15, "ent": 0}}  # False = original 5-indicator model
REASON = {"mod": "{v:.0f} existing files were rewritten within 5 s",
          "ren": "{v:.0f} files were renamed within 5 s",
          "dirs": "activity spread across {v:.0f} directories",
          "ext": "{v:.0f} different file types were touched",
          "burst": "event rate is {v:.1f}x the learned normal rate",
          "ent": "{v:.0f} files changed from readable to random-looking content"}


def level(n):
    return "HIGH" if n >= .67 else "MEDIUM" if n >= .34 else "LOW"


def entropy(path):
    """Shannon entropy (bits/byte, 0..8) of the first 4 KB; None if unreadable or tiny."""
    try:
        with open(path, "rb") as f:
            b = f.read(SAMPLE_BYTES)
    except OSError:
        return None
    if len(b) < 64:
        return None
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


class _Handler(FileSystemEventHandler):
    def __init__(self, m):
        self.m = m

    def on_any_event(self, e):
        if not e.is_directory and e.event_type in ("created", "modified", "moved"):
            self.m._on_event(e)


class Monitor:
    def __init__(self, root, use_entropy=True, report_dir=None, sample_procs=True):
        self.root, self.use_entropy = Path(root), use_entropy
        self.report_dir = Path(report_dir) if report_dir else self.root.parent / "reports"
        self.lock, self.stop_ev, self.obs, self.error = threading.RLock(), threading.Event(), None, ""
        self.me, self.io, self.idle = os.getpid(), {}, {}
        self.sample_procs, self.pcache, self.names, self.denied = sample_procs, {}, {}, set()
        self.last_sample, self.seq, self.tick_ms = 0.0, 0, 0.0
        self.active, self.io_passes, self.io_ready = False, 0, threading.Event()
        self.entq = queue.Queue(maxsize=2000)
        self.events_total, self.error_tb = 0, ""
        self.iolog = collections.deque(maxlen=20000)
        self.ent_map = {}
        self.reset()

    # ---------- lifecycle ----------
    def reset(self):
        with self.lock:
            self.q = collections.deque(maxlen=60000)
            self.feed = collections.deque(maxlen=200)
            self.hist, self.rate_hist, self.base_hist = (collections.deque([0] * 180, maxlen=180) for _ in range(3))
            self.jumps, self.checked, self.procs = {}, {}, []
            self.alert = self.t0 = None
            self.base, self.peak, self.last_tick = 0.5, 0, time.time()
            self.score, self.values, self.norms, self.points = 0, {}, {}, {}

    def rescan(self):
        """Learn the entropy of every existing file (the 'before' picture)."""
        m = {}
        for p in self.root.rglob("*"):
            if p.is_file():
                e = entropy(p)
                if e is not None:
                    m[str(p)] = e
        with self.lock:
            self.ent_map = m

    def rescan_async(self):
        threading.Thread(target=self.rescan, daemon=True).start()

    def restart_watch(self):
        """(Re)attach the folder watcher. Needed if the watched folder was deleted and recreated."""
        if self.obs:
            try:
                self.obs.stop()
                self.obs.join(timeout=2)
            except Exception:
                pass
        self.root.mkdir(parents=True, exist_ok=True)
        self.obs = Observer()
        self.obs.schedule(_Handler(self), str(self.root), recursive=True)
        self.obs.daemon = True
        self.obs.start()

    def refresh_async(self):
        """After Setup: reattach the watcher, relearn file entropy, clear state (in the background)."""
        def work():
            self.restart_watch()
            self.rescan()
            self.reset()
        threading.Thread(target=work, daemon=True).start()

    def start(self, wait=False):
        (self.rescan if wait else self.rescan_async)()
        self.restart_watch()
        threading.Thread(target=self._loop, daemon=True).start()
        threading.Thread(target=self._ent_loop, daemon=True).start()  # disk reads never block detection
        threading.Thread(target=self._io_loop, daemon=True).start()  # slow process sampling never blocks detection

    def stop(self):
        self.stop_ev.set()
        if self.obs:
            self.obs.stop()
            self.obs.join(timeout=2)

    def rearm(self):
        """Clear the latched alert and peak so the next scenario is judged on its own (history is kept)."""
        with self.lock:
            self.alert, self.t0, self.peak, self.jumps = None, None, 0, {}

    def set_entropy(self, on):
        self.use_entropy = bool(on)
        self.reset()

    # ---------- events ----------
    def _on_event(self, e):
        t, dest = time.time(), getattr(e, "dest_path", "")
        self.events_total += 1
        with self.lock:
            self.q.append((t, e.event_type, e.src_path, dest))
            self.feed.append((t, e.event_type, os.path.basename(dest or e.src_path)))
            if e.event_type == "moved" and e.src_path in self.ent_map:
                self.ent_map[dest] = self.ent_map.pop(e.src_path)

    def _check_entropy(self, p, now):
        try:
            st = os.stat(p)
        except OSError:
            return
        key = (st.st_mtime_ns, st.st_size)
        with self.lock:
            if self.checked.get(p) == key:
                return
            self.checked[p] = key
        new = entropy(p)
        if new is None:
            return
        with self.lock:
            old = self.ent_map.get(p)
            if old is not None and new >= ENT_MIN and new - old >= ENT_JUMP:
                self.jumps[p] = now
            self.ent_map[p] = new

    def _sample_io(self, now, active):
        """Per-process write deltas, kept cheap: Process objects are cached, unreadable processes are skipped for good,
        and while the sandbox is quiet we sample only every 2 s (learning each process's normal write rate)."""
        if not self.sample_procs:
            self.io_ready.set()
            return
        dt = now - self.last_sample
        if not active and self.last_sample and dt < 2.0:
            return
        first, self.last_sample = not self.io, now
        k = max(dt / TICK, 1.0)  # how many ticks this sample covers
        live = set(psutil.pids())
        for pid in [x for x in self.pcache if x not in live]:
            for d in (self.pcache, self.io, self.idle, self.names):
                d.pop(pid, None)
        for pid in live:
            if pid == self.me or pid in self.denied:
                continue
            p = self.pcache.get(pid)
            try:
                if p is None:
                    p = self.pcache[pid] = psutil.Process(pid)
                io = p.io_counters()
            except Exception:
                self.denied.add(pid)
                continue
            w, b = io.write_count, io.write_bytes
            old = self.io.get(pid)
            self.io[pid] = (w, b)
            if not old or first:
                continue
            dw, db = max(w - old[0], 0), max(b - old[1], 0)
            if active:
                if dw or db:
                    nm = self.names.get(pid)
                    if nm is None:
                        try:
                            nm = self.names[pid] = p.name()
                        except Exception:
                            nm = "?"
                    self.iolog.append((now, pid, nm, dw, db, k))
            else:
                i = self.idle.setdefault(pid, [0.0, 0.0])
                i[0] += 0.4 * (dw / k - i[0])
                i[1] += 0.4 * (db / k - i[1])
        self.io_passes += 1
        if self.io_passes >= 2:
            self.io_ready.set()

    def _top_procs(self, now, n=5):
        tot = {}
        for t, pid, name, dw, db, k in list(self.iolog):
            if now - t <= WINDOW:
                i = self.idle.get(pid, (0.0, 0.0))
                a = tot.setdefault(pid, [name, 0.0, 0.0])
                a[1] += max(dw - i[0] * k, 0)
                a[2] += max(db - i[1] * k, 0)
        rows = []
        for pid, (name, ew, eb) in tot.items():
            bg = name.lower() in BACKGROUND
            rank = (eb + 64 * ew) * (0.25 if bg else 1.0)
            if rank > 0:
                rows.append({"pid": pid, "name": name, "writes": int(ew), "bytes": int(eb), "background": bg, "rank": rank})
        return sorted(rows, key=lambda r: -r["rank"])[:n]

    # ---------- analysis ----------
    def _loop(self):
        nxt = time.time()
        while not self.stop_ev.is_set():
            t0 = time.time()
            try:
                self.tick()
            except Exception as ex:  # keep monitoring even if one tick fails
                self.error, self.error_tb = repr(ex), traceback.format_exc()
            self.tick_ms = 0.8 * self.tick_ms + 0.2 * (time.time() - t0) * 1000
            nxt += TICK
            self.stop_ev.wait(max(0.0, nxt - time.time()))

    def _ent_loop(self):
        while not self.stop_ev.is_set():
            try:
                p = self.entq.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._check_entropy(p, time.time())
            except Exception as ex:
                self.error = repr(ex)

    def _io_loop(self):
        while not self.stop_ev.is_set():
            try:
                self._sample_io(time.time(), self.active)
            except Exception as ex:
                self.error = repr(ex)
            self.stop_ev.wait(TICK)

    def tick(self):
        now = time.time()
        with self.lock:
            allev, last = list(self.q), self.last_tick
            self.last_tick = now
        self.active = any(e[0] > now - 1.0 for e in allev)
        ev = [e for e in allev if now - e[0] <= WINDOW]
        created = {e[2] for e in allev if e[1] == "created" and now - e[0] <= GRACE}
        mods = {e[2] for e in ev if e[1] == "modified" and e[2] not in created}
        mv = [e for e in ev if e[1] == "moved"]
        touched = mods | {e[3] for e in mv}
        if self.use_entropy:  # only look inside files whose events arrived since the last tick
            fresh = {e[2] for e in allev if e[0] > last and e[1] == "modified" and e[2] not in created}
            fresh |= {e[3] for e in allev if e[0] > last and e[1] == "moved"}
            for p in list(fresh)[:60]:
                try:
                    self.entq.put_nowait(p)
                except queue.Full:
                    break
        with self.lock:
            self.jumps = {p: t for p, t in self.jumps.items() if now - t <= WINDOW}
            njumps = len(self.jumps)
        rate = sum(1 for e in ev if now - e[0] <= 1.0)
        gate = min(len(touched) / 10.0, 1.0)  # diversity only matters when many files are involved
        v = {"mod": len(mods), "ren": len(mv), "dirs": len({os.path.dirname(x) for x in touched | {e[2] for e in mv}}),
             "ext": len({os.path.splitext(x)[1].lower() for x in touched | {e[2] for e in mv}}),
             "burst": rate / (self.base + 1.0), "ent": njumps}
        w = WEIGHTS[self.use_entropy]
        n = {k: min(v[k] / sat, 1.0) for k, _, sat in IND}
        n["dirs"] *= gate
        n["ext"] *= gate
        pts = {k: w[k] * n[k] for k in n}
        score = int(round(sum(pts.values())))
        if score >= 5 and self.t0 is None:
            self.t0 = min((e[0] for e in ev), default=now)  # activity began at its first event
        if score < 5 and not self.alert:
            self.t0 = None
        if score < WATCH_AT and not self.alert:  # learn the baseline from calm periods, with a cap on jumps
            self.base = 0.95 * self.base + 0.05 * min(rate, 3 * self.base + 2)
        procs = self._top_procs(now)
        with self.lock:
            self.values, self.norms, self.points, self.score, self.procs = v, n, pts, score, procs
            self.peak = max(self.peak, score)
            self.hist.append(score)
            self.rate_hist.append(rate)
            self.base_hist.append(self.base)
            self.seq += 1
            a = self.alert
            if a and now - a["time"] <= 3.0 and procs:  # attribution firms up as more I/O is observed
                a["process"], a["candidates"] = procs[0], procs
                a["reasons"] = [REASON[k].format(v=v[k]) for k, _, _ in IND if w[k] and n[k] >= .67]  # evidence firms up too
                a["indicators"] = {k: round(v[k], 2) for k in v}
            elif a and not a.get("saved"):
                a["saved"] = True
                self._save("incident")
            if score >= ALERT_AT and not self.alert:
                top = procs[0] if procs else None
                self.alert = {"time": now, "clock": time.strftime("%H:%M:%S"), "score": score,
                              "latency_s": round(now - (self.t0 or now), 2), "process": top, "candidates": procs,
                              "entropy_mode": self.use_entropy, "indicators": {k: round(v[k], 2) for k in v},
                              "reasons": [REASON[k].format(v=v[k]) for k, _, _ in IND if w[k] and n[k] >= .67]}
                self._save("incident")

    # ---------- output ----------
    def _save(self, prefix):
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            p = self.report_dir / time.strftime(f"{prefix}_%Y%m%d_%H%M%S.json")
            p.write_text(json.dumps({"alert": self.alert, "peak_score": self.peak, "score_history": list(self.hist)},
                                    indent=2, default=str))
            return str(p)
        except OSError as ex:
            self.error = repr(ex)

    def save_report(self):
        with self.lock:
            return self._save("report")

    def snapshot(self):
        with self.lock:
            s = self.score
            state = "SUSPICIOUS" if self.alert else "WATCH" if s >= WATCH_AT else "NORMAL"
            return {"score": s, "state": state, "values": dict(self.values), "norms": dict(self.norms),
                    "points": dict(self.points), "weights": WEIGHTS[self.use_entropy], "hist": list(self.hist),
                    "rate": list(self.rate_hist), "base": list(self.base_hist), "feed": list(self.feed)[-16:],
                    "procs": list(self.procs), "alert": self.alert, "peak": self.peak,
                    "entropy": self.use_entropy, "error": self.error, "seq": self.seq,
                    "tick_ms": self.tick_ms, "sampling": self.sample_procs, "events": self.events_total}
