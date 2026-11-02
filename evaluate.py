"""Automated evaluation: runs every scenario N times against a fresh monitor and measures
peak score, alert, detection latency, process-attribution accuracy (ground truth = the PID of the
scenario process we started) and monitor CPU use. Writes results.csv and results.md.

  python evaluate.py --runs 3            # entropy-aware model
  python evaluate.py --runs 3 --compare  # also run the original 5-indicator model (ablation)"""
import argparse, csv, os, statistics as st, subprocess, sys, time
from pathlib import Path
import psutil
from engine import Monitor

HERE = Path(__file__).resolve().parent
SB = Path.home() / "ShadowGuardDemo" / "sandbox"
SCEN = [("normal", False), ("bulk", False), ("bulkedit", False), ("archive", False), ("simulate", True)]  # (name, is_attack)


def tool(*a):
    return subprocess.Popen([sys.executable, str(HERE / "demo_tools.py"), *a], stdout=subprocess.DEVNULL)


def run_once(scn, entropy):
    tool("setup").wait()
    m = Monitor(SB, use_entropy=entropy, report_dir=HERE / "reports_eval")
    m.start(wait=True)
    time.sleep(2.0)
    me, c0, t0 = psutil.Process(), sum(psutil.Process().cpu_times()[:2]), time.time()
    p = tool(scn)
    p.wait()
    time.sleep(4.5)  # let the last window drain and attribution settle
    cpu = (sum(me.cpu_times()[:2]) - c0) / (time.time() - t0) * 100 / (psutil.cpu_count() or 1)
    s = m.snapshot()
    m.stop()
    a = s["alert"]
    return {"peak": s["peak"], "alert": bool(a), "latency": a["latency_s"] if a else None, "cpu": cpu,
            "right_proc": bool(a and a["process"] and a["process"]["pid"] == p.pid),
            "top3": bool(a and any(c["pid"] == p.pid for c in a["candidates"][:3])),
            "proc": a["process"]["name"] if a and a["process"] else ""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--compare", action="store_true")
    n = ap.parse_args().runs
    modes = [(True, "entropy-aware")] + ([(False, "basic-5-indicator")] if ap.parse_args().compare else [])
    rows, md = [], []
    for entropy, mname in modes:
        res = {}
        for scn, attack in SCEN:
            res[scn] = [run_once(scn, entropy) for _ in range(n)]
            for i, r in enumerate(res[scn], 1):
                rows.append({"model": mname, "scenario": scn, "run": i, **r})
                print(f"[{mname}] {scn} run {i}: peak {r['peak']} alert {r['alert']} latency {r['latency']} cpu {r['cpu']:.1f}%")
        md += [f"### Model: {mname} ({n} runs per scenario)", "",
               "| Scenario | Avg peak score | Alerts | Avg latency (s) | Process top-1 / top-3 | Monitor CPU % |", "|---|---|---|---|---|---|"]
        for scn, attack in SCEN:
            r = res[scn]
            al = [x for x in r if x["alert"]]
            lat = f"{st.mean(x['latency'] for x in al):.1f}" if al else "n/a"
            md.append(f"| {scn} | {st.mean(x['peak'] for x in r):.0f} | {len(al)}/{n} | {lat} | "
                      f"{sum(x['right_proc'] for x in r)} / {sum(x['top3'] for x in r)} of {len(al)} | {st.mean(x['cpu'] for x in r):.1f} |")
        atk = [x for s, a in SCEN if a for x in res[s]]
        ben = [x for s, a in SCEN if not a for x in res[s]]
        md += ["", f"Detection rate: {sum(x['alert'] for x in atk)}/{len(atk)}   "
               f"False-positive rate: {sum(x['alert'] for x in ben)}/{len(ben)}", ""]
    with open(HERE / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (HERE / "results.md").write_text("\n".join(md))
    print("\n" + "\n".join(md))


if __name__ == "__main__":
    main()
