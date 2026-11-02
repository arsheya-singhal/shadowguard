### Model: entropy-aware (3 runs per scenario)

| Scenario | Avg peak score | Alerts | Avg latency (s) | Process top-1 / top-3 | Monitor CPU % |
|---|---|---|---|---|---|
| normal | 8 | 0/3 | n/a | 0 / 0 of 0 | 6.0 |
| bulk | 0 | 0/3 | n/a | 0 / 0 of 0 | 6.0 |
| bulkedit | 0 | 0/3 | n/a | 0 / 0 of 0 | 5.9 |
| archive | 0 | 0/3 | n/a | 0 / 0 of 0 | 6.1 |
| simulate | 33 | 1/3 | 2.5 | 0 / 0 of 1 | 6.0 |

Detection rate: 1/3   False-positive rate: 0/12

### Model: basic-5-indicator (3 runs per scenario)

| Scenario | Avg peak score | Alerts | Avg latency (s) | Process top-1 / top-3 | Monitor CPU % |
|---|---|---|---|---|---|
| normal | 11 | 0/3 | n/a | 0 / 0 of 0 | 6.0 |
| bulk | 0 | 0/3 | n/a | 0 / 0 of 0 | 6.1 |
| bulkedit | 0 | 0/3 | n/a | 0 / 0 of 0 | 6.1 |
| archive | 0 | 0/3 | n/a | 0 / 0 of 0 | 6.2 |
| simulate | 98 | 3/3 | 3.1 | 0 / 0 of 3 | 6.1 |

Detection rate: 3/3   False-positive rate: 0/12
