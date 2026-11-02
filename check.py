"""Quick engine self-test WITHOUT the dashboard. Prints what the engine sees once per second.
Run:  py check.py        (close the dashboard first)"""
import subprocess, sys, time
from pathlib import Path
from engine import Monitor

SB = Path.home() / "ShadowGuardDemo" / "sandbox"
subprocess.run([sys.executable, str(Path(__file__).with_name("demo_tools.py")), "setup"])
m = Monitor(SB)
m.start(wait=True)
print("warming up (up to 20 s)...")
m.io_ready.wait(20)
time.sleep(1)
print("starting simulation; watch the numbers:\n")
p = subprocess.Popen([sys.executable, str(Path(__file__).with_name("demo_tools.py")), "simulate"], stdout=subprocess.DEVNULL)
for i in range(12):
    time.sleep(1)
    s = m.snapshot()
    print(f"t={i + 1:2d}s  events seen={s['events']:4d}  ticks={s['seq']:3d}  score={s['score']:3d}  peak={s['peak']:3d}  "
          f"{s['tick_ms']:.0f} ms/tick  state={s['state']}  error={s['error'] or '-'}")
p.wait()
print("\nalert:", (m.alert or {}).get("reasons", "none"))
if m.error_tb:
    print("\nLAST ENGINE ERROR:\n" + m.error_tb)
m.stop()
