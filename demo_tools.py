"""Safe activity generator for ShadowGuard. Works ONLY inside ~/ShadowGuardDemo/sandbox.
Every command except `setup` refuses to run unless the sandbox marker file exists.

  setup     create 160 dummy files in 8 folders        (benign scenarios:)
  normal    12 slow edits                              bulk     300 new files, like a copy/extract
  bulkedit  80 fast legitimate edits (find/replace)    archive  zip every file into one new archive
                                                       (attack-like:)
  simulate  overwrite with random bytes + rename to .locked (ransomware-LIKE, dummy files only)"""
import os, random, shutil, sys, time, zipfile
from pathlib import Path

ROOT = Path.home() / "ShadowGuardDemo"
SB = ROOT / "sandbox"
MARK = SB / ".shadowguard_sandbox"
EXTS = [".txt", ".csv", ".jpg", ".pdf", ".docx"]


def guard():
    if not MARK.exists() or SB.resolve().parent.name != "ShadowGuardDemo":
        sys.exit("Refusing to run: sandbox not found. Run `python demo_tools.py setup` first.")


def files():
    guard()
    base = SB.resolve()
    return [p for p in SB.rglob("*") if p.is_file() and not p.is_symlink() and p.name != MARK.name
            and p.suffix not in (".zip",) and "bulk_copy" not in p.parts and base in p.resolve().parents]


def setup():
    # Empty the sandbox but keep the folder itself, so a running monitor keeps watching it.
    if MARK.exists():
        for c in SB.iterdir():
            if c.is_dir() and not c.is_symlink():
                shutil.rmtree(c)
            else:
                c.unlink()
    elif SB.exists() and any(SB.iterdir()):
        sys.exit("Folder exists and is not a ShadowGuard sandbox; refusing to touch it.")
    SB.mkdir(parents=True, exist_ok=True)
    for d in range(8):
        (SB / f"folder_{d}").mkdir()
    for i in range(160):
        p = SB / f"folder_{i % 8}" / f"file_{i:03d}{EXTS[i % len(EXTS)]}"
        p.write_text(f"dummy demo content {i} quarterly report notes\n" * random.randint(100, 400))
    MARK.write_text("ShadowGuard demo sandbox - safe to delete\n")
    print("Sandbox ready: 160 dummy files in 8 folders.")


def normal():
    print("Normal: 12 slow edits...")
    for p in random.sample(files(), 12):
        with open(p, "a") as f:
            f.write("an ordinary edit\n")
        time.sleep(1.5)


def bulk():
    guard()
    d = SB / "bulk_copy"
    d.mkdir(exist_ok=True)
    print("Bulk copy: 300 new files...")
    for i in range(300):
        (d / f"item_{i:03d}{EXTS[i % len(EXTS)]}").write_text("copied data\n" * 50)


def bulkedit():
    print("Bulk edit: appending a line to 80 existing files quickly (legitimate find/replace style)...")
    for p in random.sample(files(), 80):
        with open(p, "a") as f:
            f.write("updated header line\n")
        time.sleep(0.02)


def archive():
    print("Archive: compressing every file into one new .zip (reads only, high-entropy NEW file)...")
    out = SB / f"backup_{int(time.time())}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files():
            z.write(p, p.name)
            time.sleep(0.01)


def simulate():
    fs = files()
    random.shuffle(fs)
    print(f"Ransomware-LIKE simulation on {len(fs)} dummy files (sandbox only)...")
    for p in fs:
        size = p.stat().st_size
        with open(p, "r+b") as f:  # rewrite in place with random-looking bytes, then rename
            f.write(os.urandom(size))
        p.rename(p.with_name(p.name + ".locked"))
        time.sleep(0.03)


CMDS = {"setup": setup, "normal": normal, "bulk": bulk, "bulkedit": bulkedit, "archive": archive, "simulate": simulate}

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c not in CMDS:
        sys.exit(__doc__)
    print(f"[pid {os.getpid()}] {c} started")
    CMDS[c]()
    print(f"{c} finished")
