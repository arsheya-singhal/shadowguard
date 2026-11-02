# ShadowGuard v2 (educational prototype)

Setup (once):   pip install -r requirements.txt
Live demo:      python dashboard.py        (click "1 Setup sandbox", then the scenario buttons)
Evaluation:     python evaluate.py --runs 3 --compare   -> results.csv, results.md

Files: engine.py (detection), dashboard.py (GUI), demo_tools.py (safe scenarios, sandbox only), evaluate.py (automated tests).
Everything runs inside ~/ShadowGuardDemo/sandbox. The tool only alerts; it never blocks or deletes anything.
