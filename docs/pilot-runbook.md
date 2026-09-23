# Two-week pilot runbook

This runbook is the evidence contract for the remaining pilot gate. It does
not generate or invent production labels. An analyst must review at least 20
real submissions during two weeks and export one JSONL record per submission:

```json
{"id":"pilot-001","predicted":"phishing","actual":"clean","signals":{"content.sms_code_request":0.8}}
```

Allowed labels are `phishing`, `suspicious`, `clean`, and `needs_review`.
Keep the source-system export, anonymisation decision, review timestamp, and
organization approval outside the repository. Do not commit message bodies.

Generate the auditable report and calibration input:

```powershell
python scripts/pilot_report.py pilot-decisions.jsonl `
  --report pilot-report.md `
  --weights-labels pilot-labels.jsonl
```

After review, an operator may produce candidate weights without replacing the
active file:

```powershell
./bin/phishlens admin weights tune `
  --labels pilot-labels.jsonl `
  --out weights.pilot.yaml
```

The pilot owner must record the before/after weights, approve the change, and
rerun the synthetic F1 gate plus the three demo smoke checks. Attach the
resulting `pilot-report.md`, approval, command output, and exact image digest
to the release evidence. Until this evidence exists, the pilot checkbox stays
open.
