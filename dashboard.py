"""ShadowGuard v2 dashboard: live gauge, indicator meters, score and event-rate timelines, event feed,
process candidates and a plain-English evidence panel. Scenario buttons run demo_tools.py safely in the sandbox.
Run:  python dashboard.py"""
import math, subprocess, sys, threading, time, tkinter as tk
from pathlib import Path
from engine import Monitor, IND, level, TICK

HERE = Path(__file__).resolve().parent
SB = Path.home() / "ShadowGuardDemo" / "sandbox"
BG, PANEL, PANEL2, FG, MUTED = "#0b0e12", "#151a21", "#1f2630", "#e6e9ed", "#8b96a3"
ACC, WARN, AMBER = "#38bdf8", "#f97316", "#fbbf24"
LV = {"LOW": ACC, "MEDIUM": AMBER, "HIGH": WARN}
ST = {"NORMAL": ACC, "WATCH": AMBER, "SUSPICIOUS": WARN}
UI, MONO, LINE_C = "Segoe UI", "Consolas", "#2a323b"


class App:
    def __init__(self):
        SB.mkdir(parents=True, exist_ok=True)
        self.lite = "--lite" in sys.argv
        self.mon = Monitor(SB, sample_procs=not self.lite)
        self.mon.start()
        self.seen, self.last = -1, {}
        self.proc, self.msg, self.done, self.tog, self.sig = None, "Ready. Click 'Setup sandbox' first.", [], 0, None
        self.build()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(500, self.update)

    # ---------- layout ----------
    def build(self):
        r = self.root = tk.Tk()
        r.title("ShadowGuard v2 - behavioral file-activity monitor")
        r.configure(bg=BG)
        r.geometry("1320x840")
        r.minsize(1150, 720)
        head = tk.Frame(r, bg=BG)
        head.pack(fill="x", padx=18, pady=(12, 4))
        tk.Label(head, text="ShadowGuard", font=(UI, 22, "bold"), bg=BG, fg=FG).pack(side="left")
        tk.Label(head, text=f"   watching {SB}   |   educational prototype, sandbox only", font=(MONO, 10),
                 bg=BG, fg=MUTED).pack(side="left", pady=(10, 0))
        self.pill = tk.Label(head, text="NORMAL", font=(UI, 14, "bold"), bg=ACC, fg=BG, padx=22, pady=5)
        self.pill.pack(side="right")
        bar = tk.Frame(r, bg=BG)
        bar.pack(fill="x", padx=18, pady=4)
        for text, cmd, col in [("1  Setup sandbox", lambda: self.run("setup"), PANEL2),
                               ("Normal edits", lambda: self.run("normal"), PANEL2),
                               ("Bulk copy", lambda: self.run("bulk"), PANEL2),
                               ("Bulk edit", lambda: self.run("bulkedit"), PANEL2),
                               ("Archive (zip)", lambda: self.run("archive"), PANEL2),
                               ("Ransomware-like", lambda: self.run("simulate"), "#5a2a10"),
                               ("Reset", self.reset, PANEL2), ("Save report", self.save, PANEL2)]:
            tk.Button(bar, text=text, command=cmd, bg=col, fg=FG, activebackground=ACC, activeforeground=BG,
                      relief="flat", font=(UI, 10, "bold"), padx=12, pady=6, bd=0).pack(side="left", padx=(0, 6))
        self.ent = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="Entropy analysis", variable=self.ent, command=self.toggle,
                       bg=BG, fg=FG, selectcolor=PANEL2, activebackground=BG, activeforeground=FG,
                       font=(UI, 10)).pack(side="right")
        self.names = tk.BooleanVar(value=not self.lite)
        tk.Checkbutton(bar, text="Names", variable=self.names, command=self.toggle_names, bg=BG, fg=FG,
                       selectcolor=PANEL2, activebackground=BG, activeforeground=FG, font=(UI, 10)).pack(side="right", padx=10)
        body = tk.Frame(r, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=6)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)
        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.gauge = tk.Canvas(left, bg=PANEL, width=380, height=270, highlightthickness=0)
        self.gauge.pack(pady=(0, 8))
        self.meters = tk.Canvas(left, bg=PANEL, width=380, height=340, highlightthickness=0)
        self.meters.pack(fill="y", expand=True)
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure((0, 1, 2), weight=1, uniform="c")
        right.rowconfigure(0, weight=3)
        right.rowconfigure(1, weight=2)
        right.rowconfigure(2, weight=4)
        self.line = tk.Canvas(right, bg=PANEL, highlightthickness=0, height=200)
        self.line.grid(row=0, column=0, columnspan=3, sticky="nsew", pady=(0, 8))
        self.rate = tk.Canvas(right, bg=PANEL, highlightthickness=0, height=120)
        self.rate.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(0, 8))
        self.feed = self.panel(right, 0, "LIVE FILE EVENTS")
        self.procs = self.panel(right, 1, "PROCESS CANDIDATES (best effort)")
        self.evid = self.panel(right, 2, "EVIDENCE")
        for t, c in [("created", "#7dd3fc"), ("modified", FG), ("moved", WARN), ("hi", WARN), ("dim", MUTED), ("b", ACC)]:
            for w in (self.feed, self.procs, self.evid):
                w.tag_config(t, foreground=c)
        self.status = tk.Label(r, text="", font=(MONO, 10), bg=BG, fg=MUTED, anchor="w")
        self.status.pack(fill="x", padx=18, pady=(0, 8))

    def panel(self, parent, col, title):
        f = tk.Frame(parent, bg=PANEL)
        f.grid(row=2, column=col, sticky="nsew", padx=(0 if col == 0 else 4, 0 if col == 2 else 4))
        tk.Label(f, text=title, font=(UI, 9, "bold"), bg=PANEL, fg=MUTED, anchor="w").pack(fill="x", padx=10, pady=(8, 0))
        t = tk.Text(f, bg=PANEL, fg=FG, font=(MONO, 9), relief="flat", height=8, width=10, wrap="word",
                    highlightthickness=0, state="disabled")
        t.pack(fill="both", expand=True, padx=8, pady=6)
        return t

    # ---------- actions ----------
    def run(self, name):
        if self.proc and self.proc.poll() is None:
            self.msg = "A scenario is still running..."
            return
        if name != "setup":
            self.mon.rearm()
        self.proc = subprocess.Popen([sys.executable, str(HERE / "demo_tools.py"), name], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True,
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        threading.Thread(target=self.pump, args=(self.proc, name), daemon=True).start()

    def pump(self, p, name):
        for line in p.stdout:
            self.msg = line.strip() or self.msg
        p.wait()
        self.done.append(name)

    def reset(self):
        self.mon.reset()
        self.msg = "Reset."

    def save(self):
        self.msg = f"Report saved: {self.mon.save_report()}"

    def toggle(self):
        self.mon.set_entropy(self.ent.get())
        self.msg = "Entropy analysis " + ("ON (6 indicators)" if self.ent.get() else "OFF (original 5-indicator model)")

    def toggle_names(self):
        self.mon.sample_procs = self.names.get()
        self.msg = "Process names " + ("ON" if self.names.get() else "OFF (lighter)")

    def close(self):
        self.mon.stop()
        self.root.destroy()

    # ---------- refresh ----------
    def update(self):
        try:
            self._update_once()
        except Exception as ex:  # never let one bad redraw stop the refresh loop
            import traceback
            traceback.print_exc()
            self.status.config(text=f"UI error: {ex!r}", fg=WARN)
        self.root.after(500, self.update)

    def _update_once(self):
        while self.done:
            n = self.done.pop(0)
            if n == "setup":
                self.mon.refresh_async()
            if n == "simulate":
                self.msg = "Simulation finished. Run 'Setup sandbox' before repeating it."
        s = self.mon.snapshot()
        self.tog += 1
        col = ST[s["state"]]
        flash = s["state"] == "SUSPICIOUS" and (self.tog // 2) % 2 == 0
        self.pill.config(text=s["state"], bg=BG if flash else col, fg=col if flash else BG)
        if s["seq"] != self.seen:  # redraw the heavy parts only when the engine produced new data
            self.seen = s["seq"]
            self.draw_gauge(s, col)
            self.draw_meters(s)
            self.draw_line(s)
            self.draw_rate(s)
            self.fill_panels(s)
        self.status.config(fg=MUTED, text=self.msg + f"   [events seen {s['events']} | ticks {s['seq']} | {s['tick_ms']:.0f} ms/tick]"
                           + (f"   [engine error: {s['error']}]" if s["error"] else ""))

    def draw_gauge(self, s, col):
        c = self.gauge
        c.delete("all")
        w, h = int(c["width"]), int(c["height"])
        cx, cy = w / 2, h - 78
        r = min(w / 2 - 34, cy - 36)
        for a, b, zc in [(0, 30, ACC), (30, 60, AMBER), (60, 100, WARN)]:
            c.create_arc(cx - r, cy - r, cx + r, cy + r, start=180 - b * 1.8, extent=(b - a) * 1.8, style="arc",
                         width=16, outline=zc)
        for v in (0, 30, 60, 100):
            ang = math.radians(180 - v * 1.8)
            c.create_text(cx + (r + 22) * math.cos(ang), cy - (r + 22) * math.sin(ang), text=str(v), fill=MUTED,
                          font=(UI, 9))
        ang = math.radians(180 - s["score"] * 1.8)
        c.create_line(cx, cy, cx + (r - 22) * math.cos(ang), cy - (r - 22) * math.sin(ang), fill=col, width=4,
                      capstyle="round")
        c.create_oval(cx - 8, cy - 8, cx + 8, cy + 8, fill=col, outline="")
        c.create_text(cx, cy + 30, text=str(s["score"]), font=(MONO, 32, "bold"), fill=col)
        c.create_text(cx, cy + 62, text=f"RISK SCORE   peak {s['peak']}", font=(UI, 9, "bold"), fill=MUTED)

    def draw_meters(self, s):
        c = self.meters
        c.delete("all")
        w = int(c["width"])
        c.create_text(16, 16, text="BEHAVIORAL INDICATORS (last 5 s)", anchor="w", fill=MUTED, font=(UI, 9, "bold"))
        for i, (k, label, sat) in enumerate(IND):
            y, wt = 40 + i * 49, s["weights"][k]
            n, v = s["norms"].get(k, 0), s["values"].get(k, 0)
            off = wt == 0
            lv = level(n)
            c.create_text(16, y, text=label + ("  (off)" if off else ""), anchor="w", fill=MUTED if off else FG, font=(UI, 10))
            val = f"{v:.1f}x" if k == "burst" else f"{v:.0f}"
            txt = "off" if off else f"{val} {lv}   {s['points'].get(k, 0):.0f}/{wt} pts"
            c.create_text(w - 16, y, text=txt, anchor="e", fill=MUTED if off else LV[lv], font=(MONO, 9, "bold"))
            c.create_rectangle(16, y + 14, w - 16, y + 26, fill=PANEL2, outline="")
            if not off and n > 0:
                c.create_rectangle(16, y + 14, 16 + (w - 32) * n, y + 26, fill=LV[lv], outline="")

    def chart(self, c, title, hi):
        c.delete("all")
        W, H = max(c.winfo_width(), 200), max(c.winfo_height(), 80)
        l, rr, t, b = 44, 14, 26, 20
        c.create_text(l, 12, text=title, anchor="w", fill=MUTED, font=(UI, 9, "bold"))
        c.create_text(l, H - 8, text="-90 s", anchor="w", fill=MUTED, font=(UI, 8))
        c.create_text(W - rr, H - 8, text="now", anchor="e", fill=MUTED, font=(UI, 8))
        y = lambda v: t + (H - t - b) * (1 - min(v / hi, 1))
        return W, H, l, rr, y

    def draw_line(self, s):
        c = self.line
        W, H, l, rr, y = self.chart(c, "RISK SCORE OVER TIME", 100)
        c.create_rectangle(l, y(100), W - rr, y(60), fill="#26150c", outline="")
        c.create_rectangle(l, y(60), W - rr, y(30), fill="#231f0d", outline="")
        for v, col, lab in [(0, LINE_C, "0"), (30, AMBER, "WATCH 30"), (60, WARN, "ALERT 60")]:
            c.create_line(l, y(v), W - rr, y(v), fill=col, dash=(4, 4) if v else ())
            c.create_text(l - 6, y(v), text=lab.split()[-1], anchor="e", fill=MUTED, font=(UI, 8))
        hist = s["hist"]
        dx = (W - rr - l) / (len(hist) - 1)
        pts = [(l + i * dx, y(v)) for i, v in enumerate(hist) if i % 2 == 0 or i == len(hist) - 1]
        c.create_polygon([(l, y(0))] + pts + [(W - rr, y(0))], fill="#10304a", outline="")
        c.create_line(*[q for p in pts for q in p], fill=ACC, width=2)
        a, t, b = s["alert"], 26, 20
        if a:
            x = W - rr - (time.time() - a["time"]) / TICK * dx
            if x >= l:
                c.create_line(x, t, x, H - b, fill=WARN, width=2)
                c.create_text(x + 4, t + 8, text="ALERT", anchor="w", fill=WARN, font=(UI, 9, "bold"))

    def draw_rate(self, s):
        c = self.rate
        rates = s["rate"]
        W, H, l, rr, y = self.chart(c, "FILE EVENTS PER SECOND   (dashed = learned normal rate)", max(10, max(rates) * 1.15))
        dx = (W - rr - l) / (len(rates) - 1)
        pts = [(l + i * dx, y(v)) for i, v in enumerate(rates) if i % 2 == 0 or i == len(rates) - 1]
        c.create_polygon([(l, y(0))] + pts + [(W - rr, y(0))], fill="#16324a", outline="")
        c.create_line(*[q for p in pts for q in p], fill=ACC, width=2)
        c.create_line(*[q for i, v in enumerate(s["base"]) if i % 6 == 0 for q in (l + i * dx, y(v))], fill=AMBER, dash=(3, 3))
        c.create_text(l - 6, y(0), text="0", anchor="e", fill=MUTED, font=(UI, 8))
        c.create_text(l - 6, y(max(10, max(rates) * 1.15)), text=f"{max(10, max(rates) * 1.15):.0f}", anchor="e",
                      fill=MUTED, font=(UI, 8))

    def put(self, w, parts):
        if self.last.get(id(w)) == parts:
            return
        self.last[id(w)] = parts
        w.config(state="normal")
        w.delete("1.0", "end")
        for text, tag in parts:
            w.insert("end", text, tag)
        w.config(state="disabled")

    def fill_panels(self, s):
        sig = (len(s["feed"]), s["feed"][-1][0] if s["feed"] else 0)
        if sig != self.sig:
            self.sig = sig
            self.put(self.feed, [(f"{time.strftime('%H:%M:%S', time.localtime(t))}  {k:<8} {n}\n", k)
                                 for t, k, n in reversed(s["feed"])] or [("waiting for file activity...", "dim")])
        pr = [(f"{'>' if i == 0 else ' '} {p['name'][:20]:<20} pid {p['pid']:<6}\n    {p['writes']} extra writes, "
               f"{p['bytes'] // 1024} KB" + ("  (background service)" if p["background"] else "") + "\n",
               "hi" if i == 0 else "dim") for i, p in enumerate(s["procs"][:5])]
        self.put(self.procs, pr or [("no process I/O correlated with file events yet", "dim")])
        a = s["alert"]
        if a:
            p = a["process"]
            ev = [(f"ALERT at {a['clock']}\n", "hi"),
                  (f"score {a['score']}/100, detected {a['latency_s']} s after activity began\n", "b"),
                  (f"likely process: {p['name']} (pid {p['pid']})\n" if p else "process: unknown\n", "b"), ("\nWhy:\n", "dim")]
            ev += [(f" - {r}\n", "modified") for r in a["reasons"]]
        else:
            top = sorted(s["points"].items(), key=lambda kv: -kv[1])[:3]
            lab = {k: l for k, l, _ in IND}
            ev = [("No alert.\n", "b"), (f"peak score so far: {s['peak']}\n\n", "dim"), ("Biggest contributors now:\n", "dim")]
            ev += [(f" - {lab[k]}: {v:.0f} pts\n", "modified") for k, v in top if v > 0.5] or [(" none\n", "dim")]
        self.put(self.evid, ev)


if __name__ == "__main__":
    App().root.mainloop()
