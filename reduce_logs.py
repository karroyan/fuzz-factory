#!/usr/bin/env python3
"""从 out/logs/*.log 重建结果与成功率汇总(即使主进程崩了也能救数据)。
用法: python3 reduce_logs.py <OUT_DIR>
"""
import json, re, sys
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else "./out")
recs = []
for lg in sorted((out / "logs").glob("*.log")):
    txt = lg.read_text(errors="ignore")
    m = re.search(r"START lang=(\S+)", txt)
    lang = m.group(1) if m else "?"
    status, valid = "incomplete", False
    md = re.findall(r"DONE status=(\S+) valid_poc=(\w+)", txt)
    mf = re.findall(r"FAIL (\w+)", txt)
    if md:
        status = md[-1][0]; valid = md[-1][1] == "True"
    elif mf:
        status = mf[-1]
    recs.append({"name": lg.stem, "lang": lang, "status": status, "valid_poc": valid})

def rate(sub):
    n = len(sub); ok = sum(r["valid_poc"] for r in sub)
    cr = sum(r["status"] in ("crash_not_differential", "valid_poc") for r in sub)
    return n, cr, ok, (ok / n if n else 0)

langs = sorted({r["lang"] for r in recs})
done = [r for r in recs if r["status"] != "incomplete"]
print(f"\n已完成 {len(done)} / 落地 log {len(recs)} 个")
print("=" * 60)
print(f"{'group':<12}{'tasks':>7}{'crashed':>9}{'valid_poc':>11}{'poc_rate':>10}")
print("-" * 60)
for l in langs:
    n, cr, ok, pr = rate([r for r in done if r["lang"] == l])
    print(f"{l:<12}{n:>7}{cr:>9}{ok:>11}{pr:>9.1%}")
print("-" * 60)
n, cr, ok, pr = rate(done)
print(f"{'OVERALL':<12}{n:>7}{cr:>9}{ok:>11}{pr:>9.1%}")
print("=" * 60)
from collections import Counter
print("状态分布:", dict(Counter(r["status"] for r in done)))
(out / "reduced_summary.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in recs))
print(f"\n[out] {out}/reduced_summary.jsonl")
