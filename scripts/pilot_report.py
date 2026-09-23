"""Build an auditable FP/FN report from reviewed pilot decisions.

Input JSONL contract per line:
{"id":"...", "predicted":"phishing", "actual":"clean",
 "signals":{"content.sms_code_request":0.8}}
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

LABELS = {"phishing", "suspicious", "clean", "needs_review"}


def load_records(path: Path) -> list[dict]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"line {number}: invalid JSON: {error}") from error
        if not isinstance(record, dict) or not record.get("id"):
            raise ValueError(f"line {number}: id is required")
        for field in ("predicted", "actual"):
            value = str(record.get(field, "")).strip().lower()
            if value not in LABELS:
                raise ValueError(f"line {number}: {field} must be one of {sorted(LABELS)}")
            record[field] = value
        signals = record.get("signals", {})
        if not isinstance(signals, dict):
            raise ValueError(f"line {number}: signals must be an object")
        record["signals"] = signals
        records.append(record)
    if not records:
        raise ValueError("no pilot records found")
    return records


def binary_metrics(records: list[dict]) -> tuple[int, int, int, int, float, float, float]:
    tp = sum(r["actual"] == "phishing" and r["predicted"] == "phishing" for r in records)
    fp = sum(r["actual"] != "phishing" and r["predicted"] == "phishing" for r in records)
    fn = sum(r["actual"] == "phishing" and r["predicted"] != "phishing" for r in records)
    tn = len(records) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return tp, fp, fn, tn, precision, recall, f1


def render(records: list[dict]) -> str:
    tp, fp, fn, tn, precision, recall, f1 = binary_metrics(records)
    counts = Counter(r["actual"] for r in records)
    predicted = Counter(r["predicted"] for r in records)
    lines = [
        "# Pilot review report",
        "",
        f"- Reviewed submissions: **{len(records)}**",
        f"- Actual labels: `{dict(sorted(counts.items()))}`",
        f"- Predicted labels: `{dict(sorted(predicted.items()))}`",
        "",
        "## Phishing-vs-non-phishing metrics",
        "",
        "| TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {tp} | {fp} | {fn} | {tn} | {precision:.3f} | {recall:.3f} | {f1:.3f} |",
        "",
        "FP means a non-phishing analyst label predicted as phishing; FN means a",
        "phishing analyst label predicted as another class. Weight changes require",
        "analyst approval before replacing the active weights file.",
        "",
    ]
    return "\n".join(lines)


def write_tune_labels(records: list[dict], path: Path) -> int:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for record in records:
            output.write(json.dumps({"label": record["actual"], "signals": record["signals"]}, ensure_ascii=False) + "\n")
    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="reviewed pilot JSONL")
    parser.add_argument("--report", type=Path, default=Path("pilot-report.md"))
    parser.add_argument("--weights-labels", type=Path, help="write labels.jsonl for admin weights tune")
    args = parser.parse_args()
    records = load_records(args.input)
    args.report.write_text(render(records), encoding="utf-8", newline="\n")
    if args.weights_labels:
        write_tune_labels(records, args.weights_labels)
    print(f"reported {len(records)} reviewed submissions to {args.report}")


if __name__ == "__main__":
    main()
