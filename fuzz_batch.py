#!/usr/bin/env python3
"""
fuzz_batch.py — 批量对 ossfuzz-harbor bundle 跑 libFuzzer,产“有效 PoC”并记录成功/失败详情。

支持两阶段续跑:
  - 每个 task 有独立的持久化 corpus 目录,跑越久 / 分多轮越累积。
  - 已经拿到有效 PoC 的 task 记入 success_ledger,后续轮次自动跳过(--skip-succeeded)。

有效 PoC 定义(= factory 的 poc-differential-vul-crash-fix-clean):
  vul 镜像触发 sanitizer 崩溃  且  fix 镜像干净退出(exit==0)。
  仅 OOM / 超时 / 两边都崩 → 不算,状态记为 crash_not_differential。

用法见文件末尾 or `python3 fuzz_batch.py -h`。
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# bundle 路径为本地私有,放 gitignore 的 local_config.py;公开代码只留占位符。
try:
    import local_config as _CFG
except Exception:
    _CFG = None
DEFAULT_BUNDLE = ((getattr(_CFG, "BUNDLE", "") if _CFG else "")
                  or os.environ.get("FUZZ_BUNDLE", "")
                  or "/path/to/ossfuzz-harbor-bundles/<your-bundle>")
SANITIZER_SIGNS = (
    "ERROR: AddressSanitizer", "AddressSanitizer:", "ERROR: libFuzzer: deadly signal",
    "SEGV on unknown address", "heap-buffer-overflow", "heap-use-after-free",
    "stack-buffer-overflow", "global-buffer-overflow", "UndefinedBehaviorSanitizer",
    "runtime error:", "SUMMARY: UBSan", "SUMMARY: AddressSanitizer", "LeakSanitizer",
    "Uncaught Python exception",  # atheris (python)
)
OOM_SIGN = "out-of-memory"
_C_KEYWORDS = set("if else for while switch case break return static void const struct union "
                  "enum typedef sizeof unsigned signed char short int long float double goto "
                  "continue default extern register volatile inline do sizeof NULL true false "
                  "assert memcpy memset malloc free size_t uint32_t uint8_t u32 u8 u64 int32_t".split())


def _dict_line(tok: str) -> str:
    out = []
    for ch in tok:
        o = ord(ch)
        if ch == "\\": out.append("\\\\")
        elif ch == '"': out.append('\\"')
        elif 32 <= o < 127: out.append(ch)
        else: out.append("\\x%02x" % o)
    return '"' + "".join(out) + '"'


def build_diff_hints(task) -> dict:
    """从 fix.diff 抽 libFuzzer 字典 + focus_function 候选(纯脚本、无 agent)。"""
    p = Path(task["task_dir"]) / "environment" / "workspace" / "fix.diff"
    if not p.exists():
        return {"dict": [], "focus": []}
    change, ctx, focus = [], [], []
    func_re = re.compile(r"\b([A-Za-z_]\w{2,})\s*\(")
    for ln in p.read_text(errors="ignore").splitlines():
        if ln.startswith("@@"):
            for m in func_re.finditer(ln.split("@@")[-1]):
                focus.append(m.group(1))
            continue
        if ln.startswith(("#", "index", "diff", "---", "+++", "##")):
            continue
        (change if ln[:1] in "+-" else ctx).append(ln[1:] if ln[:1] in "+-" else ln)
    body = "\n".join(change)
    toks = [m.group(1) for m in re.finditer(r'"((?:[^"\\]|\\.){2,64})"', body)]
    toks += re.findall(r"0x[0-9a-fA-F]{2,}", body)
    ids = {}
    for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_]{3,40}", body):
        w = m.group(0)
        if w not in _C_KEYWORDS:
            ids[w] = ids.get(w, 0) + 1
    dict_entries = list(dict.fromkeys(toks + sorted(ids, key=lambda k: -ids[k])[:40]))[:64]
    # focus 候选:上下文里像函数定义的行 + 改动行里调用的函数
    for s in ("\n".join(change + ctx)).splitlines():
        s = s.strip()
        m = re.match(r"^[A-Za-z_][\w\s\*]*\b([A-Za-z_]\w{2,})\s*\([^;{]*\)?\s*\{?\s*$", s)
        if m and "(" in s and not s.endswith(";"):
            focus.append(m.group(1))
    for m in func_re.finditer(body):
        focus.append(m.group(1))
    # focus 宁缺毋滥:丢掉泛词(size/list/self…),只留够特异的项目函数名
    focus = [f for f in dict.fromkeys(focus)
             if f not in _C_KEYWORDS and len(f) >= 6
             and ("_" in f or any(c.isupper() for c in f[1:]))][:12]
    return {"dict": dict_entries, "focus": focus}

# 状态含义(写进 log,便于汇报):
#   valid_poc        —— 成功:vul 崩 + fix 干净
#   no_artifact      —— 失败:fuzz 到点没撞出任何 crash(可加时间/换引擎)
#   crash_not_differential —— 失败:撞到了但不是该洞(OOM/两边都崩/fix 也崩)
#   no_fuzz_target / missing_image / engine_timeout / error —— 环境/异常类失败
_LOCK = threading.Lock()


def sh(cmd, timeout=None):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, text=True)
    return p.returncode, p.stdout


def load_tasks(bundle: Path, langs, limit):
    tasks = []
    for meta_path in sorted(bundle.glob("task-core/*/tests/task_metadata.json")):
        meta = json.loads(meta_path.read_text())
        lang = meta.get("language_adapter", "")
        if langs and lang not in langs:
            continue
        tasks.append({
            "name": meta_path.parents[1].name,
            "task_dir": str(meta_path.parents[1]),
            "task_id": meta.get("task_id", ""),
            "lang": lang,
            "vul_img": meta.get("vulnerable_runner_image", ""),
            "fix_img": meta.get("fixed_runner_image", ""),
        })
    if limit:
        tasks = tasks[:limit]
    return tasks


# ---------- fuzz:持久化 corpus,libFuzzer 会把新覆盖样本写回该目录(累积) ----------
def run_libfuzzer(task, secs, art_host: Path, corpus_host: Path, dict_host: Path | None, focus, fork=0):
    art_host.mkdir(parents=True, exist_ok=True); os.chmod(art_host, 0o777)
    corpus_host.mkdir(parents=True, exist_ok=True); os.chmod(corpus_host, 0o777)
    corpus_before = sum(1 for _ in corpus_host.iterdir())
    mounts = ["-v", f"{art_host}:/artifacts", "-v", f"{corpus_host}:/corpus"]
    if dict_host:
        dict_host.mkdir(parents=True, exist_ok=True); os.chmod(dict_host, 0o777)
        mounts += ["-v", f"{dict_host}:/dict:ro"]
    focus_env = ["-e", "FOCUS_CANDIDATES=" + " ".join(focus or [])]
    script = f"""
set +e
T="${{FUZZ_TARGET}}"
[ -z "$T" ] && {{ echo NO_FUZZ_TARGET > /artifacts/_reason; exit 3; }}
# 每轮都合并官方种子(-o 覆盖同名),与 agent 种子/已累积 corpus 共存
Z="/out/${{T}}_seed_corpus.zip"
[ -f "$Z" ] && unzip -o -q "$Z" -d /corpus 2>/dev/null
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1
DICT=""; [ -s /dict/task.dict ] && DICT="-dict=/dict/task.dict"
# focus:仅当候选函数名真存在于目标二进制符号里才用(避免硬失败)
FOCUS=""
for c in ${{FOCUS_CANDIDATES:-}}; do
  if grep -aqw "$c" "/out/$T" 2>/dev/null; then FOCUS="-focus_function=$c"; echo "$c" > /artifacts/_focus; break; fi
done
# fork 模式:多进程并行 + 崩溃/OOM/超时隔离不中断,一轮持续收集多个 crash
FORKFLAGS="{'-fork=%d -ignore_crashes=1 -ignore_ooms=1 -ignore_timeouts=1' % fork if fork else ''}"
run() {{ timeout {secs+120} /out/"$T" /corpus -max_total_time={secs} \
    -artifact_prefix=/artifacts/ -rss_limit_mb=2048 -print_final_stats=1 $FORKFLAGS "$@"; }}
run $DICT $FOCUS > /artifacts/_fuzz.log 2>&1
echo "FUZZ_RC=$?" > /artifacts/_rc
# 兜底:focus 若被 libFuzzer 拒绝,去掉 focus 重跑
if grep -q "Failed to set focus function" /artifacts/_fuzz.log; then
  echo "fallback-no-focus" >> /artifacts/_focus
  run $DICT > /artifacts/_fuzz.log 2>&1
  echo "FUZZ_RC=$?" > /artifacts/_rc
fi
"""
    rc, _ = sh(["sudo", "docker", "run", "--rm", *mounts, *focus_env,
                "--entrypoint", "bash", task["vul_img"], "-c", script],
               timeout=secs + 300)
    arts = {"crash": [], "oom": [], "leak": [], "timeout": []}
    for f in sorted(art_host.iterdir()):
        for pfx in arts:
            if f.name.startswith(pfx + "-"):
                arts[pfx].append(str(f))
    stats = {}
    fl = art_host / "_fuzz.log"
    if fl.exists():
        txt = fl.read_text(errors="ignore")
        m = re.search(r"stat::number_of_executed_units:\s*(\d+)", txt)
        if m: stats["execs"] = int(m.group(1))
        m = re.search(r"stat::average_exec_per_sec:\s*(\d+)", txt)
        if m: stats["exec_per_sec"] = int(m.group(1))
    corpus_after = sum(1 for _ in corpus_host.iterdir())
    focus_used = ""
    fp = art_host / "_focus"
    if fp.exists():
        focus_used = fp.read_text().splitlines()[0].strip()
    return {"engine_rc": rc, "artifacts": arts, "stats": stats,
            "corpus_before": corpus_before, "corpus_after": corpus_after,
            "focus_used": focus_used}


# ---------- 差分验证 ----------
def replay(image, poc):
    try:
        rc, out = sh(["sudo", "docker", "run", "--rm", "-v", f"{poc}:/tmp/poc:ro",
                      image, "/tmp/poc"], timeout=240)
    except subprocess.TimeoutExpired:
        return {"exit": -1, "sanitizer": False, "oom": False, "tail": "replay-timeout"}
    low = out.lower()
    return {"exit": rc,
            "sanitizer": any(s.lower() in low for s in SANITIZER_SIGNS),
            "oom": OOM_SIGN in low,
            "tail": "\n".join(out.splitlines()[-40:])}


def differential(task, poc):
    v = replay(task["vul_img"], poc)
    f = replay(task["fix_img"], poc)
    return {"vul": v, "fix": f,
            "valid": v["sanitizer"] and (not v["oom"]) and f["exit"] == 0}


def process(task, args, out_dir: Path):
    # 顶层兜底:任何异常都转成 error 记录,绝不向 fut.result() 抛(否则主循环会挂)
    try:
        return _process(task, args, out_dir)
    except Exception as e:
        return {"name": task["name"], "task_id": task.get("task_id", ""),
                "lang": task.get("lang", "?"), "phase": args.phase, "secs": args.secs,
                "status": "error", "valid_poc": False,
                "reason": f"{type(e).__name__}: {e}"}


def _process(task, args, out_dir: Path):
    t0 = time.time()
    rec = {"name": task["name"], "task_id": task["task_id"], "lang": task["lang"],
           "phase": args.phase, "secs": args.secs, "status": "", "valid_poc": False,
           "reason": ""}
    log_path = out_dir / "logs" / f"{task['name']}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(msg):
        with open(log_path, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}][{args.phase}] {msg}\n")

    log(f"START lang={task['lang']} vul={task['vul_img']}")
    if not task["vul_img"] or not task["fix_img"]:
        rec["status"] = "missing_image"; log("FAIL missing_image"); return rec

    art_host = out_dir / "artifacts" / task["name"]
    corpus_host = out_dir / "corpus" / task["name"]
    dict_host = None
    focus = []
    dict_tokens = []
    if args.use_diff:
        hints = build_diff_hints(task)
        focus = hints["focus"]
        dict_tokens += hints["dict"]
        rec["diff"] = {"dict_size": len(hints["dict"]), "focus_candidates": len(focus)}
        log(f"diff hints: dict={len(hints['dict'])} focus_cands={focus[:6]}")
    if args.agent_assist:
        import agent_assist
        a = agent_assist.generate(task, cache_dir=out_dir / "agent_cache")  # 优先读预生成缓存
        corpus_host.mkdir(parents=True, exist_ok=True); os.chmod(corpus_host, 0o777)
        for i, b in enumerate(a["seeds"]):        # agent 种子写进 corpus,fuzz 在其上变异发现 PoC
            (corpus_host / f"agentseed_{i:04d}").write_bytes(b)
        dict_tokens += a.get("dict", [])
        rec["agent"] = {"backend": a["backend"], "seeds": len(a["seeds"]),
                        "dict": len(a.get("dict", [])), "error": a.get("error", "")}
        log(f"agent-assist backend={a['backend']} seeds={len(a['seeds'])} "
            f"dict+={len(a.get('dict', []))} err={a.get('error', '')}")
    if dict_tokens:
        seen = set(); uniq = [t for t in dict_tokens if not (t in seen or seen.add(t))]
        dict_host = out_dir / "dict" / task["name"]
        dict_host.mkdir(parents=True, exist_ok=True)
        (dict_host / "task.dict").write_text("\n".join(_dict_line(t) for t in uniq[:128]))
    try:
        fz = run_libfuzzer(task, args.secs, art_host, corpus_host, dict_host, focus, args.fork)
    except subprocess.TimeoutExpired:
        rec["status"] = "engine_timeout"; rec["reason"] = "fuzz wall-timeout"
        rec["elapsed"] = round(time.time() - t0, 1); log("FAIL engine_timeout"); return rec

    rec["artifacts"] = {k: len(v) for k, v in fz["artifacts"].items()}
    rec["stats"] = fz["stats"]
    rec["corpus"] = {"before": fz["corpus_before"], "after": fz["corpus_after"]}
    if args.use_diff:
        rec["focus_used"] = fz.get("focus_used", "")
    log(f"fuzz done execs={fz['stats'].get('execs','?')} "
        f"exec/s={fz['stats'].get('exec_per_sec','?')} focus_used={fz.get('focus_used','')} "
        f"artifacts={rec['artifacts']} corpus {fz['corpus_before']}->{fz['corpus_after']}")

    if art_host.joinpath("_reason").exists():
        rec["status"] = "no_fuzz_target"; rec["reason"] = "image has no FUZZ_TARGET"
        log("FAIL no_fuzz_target"); rec["elapsed"] = round(time.time() - t0, 1); return rec

    order = (fz["artifacts"]["crash"] + fz["artifacts"]["leak"]
             + fz["artifacts"]["oom"] + fz["artifacts"]["timeout"])
    # fork 模式可能产很多 crash:按内容去重 + 截断,避免差分复现爆炸
    seen, uniq = set(), []
    for p in order:
        try:
            h = hashlib.sha256(Path(p).read_bytes()).hexdigest()
        except Exception:
            h = p
        if h not in seen:
            seen.add(h); uniq.append(p)
    order = uniq[:args.max_pocs]
    if not order:
        rec["status"] = "no_artifact"; rec["reason"] = "fuzz 到点未撞出 crash"
        log("FAIL no_artifact (未撞出崩溃)"); rec["elapsed"] = round(time.time() - t0, 1); return rec

    rec["crash_candidates"] = len(seen)
    log(f"crash candidates: {len(seen)} unique, differential-testing {len(order)}")
    rec["status"] = "crash_not_differential"
    rejects = 0
    for poc in order:
        d = differential(task, poc)
        log(f"differential poc={Path(poc).name} vul_exit={d['vul']['exit']} "
            f"vul_san={d['vul']['sanitizer']} vul_oom={d['vul']['oom']} fix_exit={d['fix']['exit']} "
            f"=> {'VALID' if d['valid'] else 'reject'}")
        if d["valid"]:
            rec.update(valid_poc=True, status="valid_poc", poc=poc,
                       vul_exit=d["vul"]["exit"], fix_exit=d["fix"]["exit"],
                       error_txt=d["vul"]["tail"], reason="vul 崩 + fix 干净")
            # 保存 PoC:成功绝不因写盘失败而丢(harvest 到可写 out 目录,再尽力写回 bundle)
            try:
                harvest_poc(task, poc, d["vul"]["tail"], out_dir, args.write_back)
                rec["written_back"] = True
                log("saved poc + error.txt (harvest + bundle best-effort)")
            except Exception as e:
                rec["writeback_error"] = f"{type(e).__name__}: {e}"
                log(f"WARN save poc failed(不影响成功计数): {e}")
            break
        rejects += 1
        if rejects >= args.early_stop:   # 早停:连续 reject 到阈值就停,避免磨完同一个共享 bug
            rec["reason"] = f"撞到崩溃但前 {rejects} 个差分均不通过(早停,多为共享 bug)"
            log(f"early-stop after {rejects} rejects")
            break
    else:
        rec["reason"] = "撞到崩溃但差分不通过(非该洞/两边都崩)"
    log(f"DONE status={rec['status']} valid_poc={rec['valid_poc']}")
    rec["elapsed"] = round(time.time() - t0, 1)
    return rec


def harvest_poc(task, poc, crash_tail, out_dir: Path, write_bundle: bool):
    """先把 PoC 存到可写的 out/pocs/<task>/(绝不失败);再尽力 sudo 写回 bundle(只读也不报错)。"""
    hv = out_dir / "pocs" / task["name"]
    hv.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(poc, hv / "poc")
    (hv / "error.txt").write_text(crash_tail.strip() + "\n", encoding="utf-8")
    if not write_bundle:
        return
    ws = Path(task["task_dir"]) / "environment" / "workspace"
    pocs = Path(task["task_dir"]) / "environment" / "cybergym_server_data" / "pocs"
    # bundle 目录 root 所有,用 sudo 尽力写(失败忽略,harvest 已经保住结果)
    try:
        sh(["sudo", "cp", str(hv / "poc"), str(ws / "poc")], timeout=30)
        sh(["sudo", "cp", str(hv / "error.txt"), str(ws / "error.txt")], timeout=30)
        sh(["sudo", "mkdir", "-p", str(pocs)], timeout=30)
        sh(["sudo", "cp", str(hv / "poc"), str(pocs / "poc")], timeout=30)
    except Exception:
        pass


def load_ledger(out_dir: Path):
    p = out_dir / "success_ledger.txt"
    return set(p.read_text().split()) if p.exists() else set()


def append_ledger(out_dir: Path, name: str):
    with _LOCK, open(out_dir / "success_ledger.txt", "a") as f:
        f.write(name + "\n")


def write_progress(out_dir: Path, phase, total, done, counts, succeeded):
    prog = {"phase": phase, "total": total, "done": done, "running": total - done,
            "valid_poc_this_phase": counts.get("valid_poc", 0),
            "status_breakdown": counts, "succeeded_cumulative": succeeded,
            "updated": time.strftime("%Y-%m-%d %H:%M:%S")}
    with _LOCK:
        (out_dir / "progress.json").write_text(json.dumps(prog, ensure_ascii=False, indent=2))


def print_status(out_dir: Path):
    prog = out_dir / "progress.json"
    if not prog.exists():
        print("(尚无 progress.json,任务可能还没开始)"); return
    p = json.loads(prog.read_text())
    print(f"阶段: {p['phase']}   进度: {p['done']}/{p['total']} "
          f"(running {p['running']})   更新于 {p['updated']}")
    print(f"本阶段有效PoC: {p['valid_poc_this_phase']}   累计成功(去重): {p['succeeded_cumulative']}")
    print("状态分布:", json.dumps(p["status_breakdown"], ensure_ascii=False))


def summarize(records):
    def rate(sub):
        n = len(sub); ok = sum(r.get("valid_poc") for r in sub)
        cr = sum(r.get("status") in ("crash_not_differential", "valid_poc") for r in sub)
        return {"tasks": n, "crashed": cr, "valid_poc": ok,
                "poc_rate": round(ok / n, 3) if n else 0}
    langs = sorted({r["lang"] for r in records})
    return {"overall": rate(records),
            "by_lang": {l: rate([r for r in records if r["lang"] == l]) for l in langs}}


def print_table(summary, phase, secs):
    o = summary["overall"]
    print("\n" + "=" * 64)
    print(f"PHASE={phase}  ENGINE=libfuzzer  budget={secs}s")
    print("=" * 64)
    print(f"{'group':<12}{'tasks':>7}{'crashed':>9}{'valid_poc':>11}{'poc_rate':>10}")
    print("-" * 64)
    for lang, s in summary["by_lang"].items():
        print(f"{lang:<12}{s['tasks']:>7}{s['crashed']:>9}{s['valid_poc']:>11}{s['poc_rate']:>9.1%}")
    print("-" * 64)
    print(f"{'OVERALL':<12}{o['tasks']:>7}{o['crashed']:>9}{o['valid_poc']:>11}{o['poc_rate']:>9.1%}")
    print("=" * 64 + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", type=Path, default=Path(DEFAULT_BUNDLE))
    ap.add_argument("--out", type=Path, default=Path("./out"))
    ap.add_argument("--phase", default="p1")
    ap.add_argument("--secs", type=int, default=600)
    ap.add_argument("--langs", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--write-back", action="store_true")
    ap.add_argument("--use-diff", action="store_true",
                    help="用 fix.diff 定向:抽字典(-dict)+ focus_function(纯脚本,无 agent)")
    ap.add_argument("--agent-assist", action="store_true",
                    help="agent 脚手架:读 description+diff 产种子/字典喂 fuzz(需 OPENAI_BASE_URL+key,否则 stub)")
    ap.add_argument("--fork", type=int, default=0,
                    help="libFuzzer fork 模式子进程数(>0 开启:多进程+崩溃隔离+持续收集多 crash)")
    ap.add_argument("--max-pocs", type=int, default=15,
                    help="每个 task 最多差分验证多少个去重后的 crash 候选")
    ap.add_argument("--early-stop", type=int, default=3,
                    help="连续 reject 到该数就停止差分(避免磨完同一个共享 bug,提速)")
    ap.add_argument("--skip-succeeded", action="store_true",
                    help="跳过 success_ledger 里已成功的 task(第二阶段用)")
    ap.add_argument("--resume", action="store_true",
                    help="续跑:跳过本阶段已完成的 task(但重跑 error 的),结果追加不覆盖")
    ap.add_argument("--status", action="store_true", help="只打印当前进度快照后退出")
    args = ap.parse_args()

    args.out = args.out.resolve()          # docker -v 必须绝对路径
    args.bundle = args.bundle.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.status:
        print_status(args.out); return

    langs = set(x for x in args.langs.split(",") if x) or None
    tasks = load_tasks(args.bundle, langs, args.limit)
    ledger = load_ledger(args.out) if args.skip_succeeded else set()
    if ledger:
        before = len(tasks)
        tasks = [t for t in tasks if t["name"] not in ledger]
        print(f"[info] 跳过已成功 {before - len(tasks)} 个,剩 {len(tasks)} 个待跑")

    # 续跑:读本阶段已有结果,跳过已完成(status != error)的,error 的重跑
    prior_records = []
    res_path = args.out / f"results_{args.phase}.jsonl"
    if args.resume and res_path.exists():
        done_ok = set()
        for line in res_path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("status") != "error":
                done_ok.add(r["name"]); prior_records.append(r)
        before = len(tasks)
        tasks = [t for t in tasks if t["name"] not in done_ok]
        print(f"[info] 续跑:跳过已完成 {before - len(tasks)} 个(error 的会重跑),剩 {len(tasks)} 个")

    total = len(tasks)
    print(f"[info] PHASE={args.phase} tasks={total} secs={args.secs} jobs={args.jobs} "
          f"langs={args.langs or 'all'} use_diff={args.use_diff} agent_assist={args.agent_assist} "
          f"fork={args.fork} write_back={args.write_back}")
    # 续跑时把已完成结果并入统计,结果文件用追加模式(不覆盖)
    records = list(prior_records)
    counts = {}
    for r in prior_records:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    done = 0
    total_all = total + len(prior_records)
    run_log = open(args.out / "run.log", "a")
    run_log.write(f"\n===== PHASE {args.phase} start {time.strftime('%F %T')} "
                  f"total={total}{' (resume, done '+str(len(prior_records))+')' if args.resume else ''} =====\n")
    res_f = open(args.out / f"results_{args.phase}.jsonl", "a" if args.resume else "w")
    write_progress(args.out, args.phase, total, 0, counts, len(load_ledger(args.out)))

    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(process, t, args, args.out): t for t in tasks}
        for fut in as_completed(futs):
            try:
                rec = fut.result()
            except Exception as e:               # 防御:绝不让异常中断主循环
                t = futs[fut]
                rec = {"name": t["name"], "lang": t.get("lang", "?"), "phase": args.phase,
                       "secs": args.secs, "status": "error", "valid_poc": False,
                       "reason": f"{type(e).__name__}: {e}"}
            records.append(rec); done += 1
            counts[rec["status"]] = counts.get(rec["status"], 0) + 1
            if rec.get("valid_poc"):
                append_ledger(args.out, rec["name"])
            res_f.write(json.dumps(rec, ensure_ascii=False) + "\n"); res_f.flush()
            mark = "✓POC" if rec.get("valid_poc") else rec["status"]
            line = (f"[{done}/{total}] {rec['name']:<46} {mark:<22} "
                    f"({rec.get('elapsed','?')}s) {rec.get('reason','')}")
            print(line, flush=True); run_log.write(line + "\n"); run_log.flush()
            write_progress(args.out, args.phase, total, done, counts, len(load_ledger(args.out)))

    res_f.close(); run_log.close()
    summary = summarize(records)
    (args.out / f"summary_{args.phase}.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print_table(summary, args.phase, args.secs)
    print(f"[out] {args.out}/results_{args.phase}.jsonl  |  logs/  |  progress.json  |  run.log")


if __name__ == "__main__":
    main()
