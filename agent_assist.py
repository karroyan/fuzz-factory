#!/usr/bin/env python3
"""
agent_assist.py — 出题 agent 的“脚手架”步:读 description+diff,产 **种子 + 字典**,
喂给 fuzz(fuzz 负责真正发现 PoC)。agent 绝不直接给最终崩溃字节。

两种后端:
  - real:OpenAI 兼容 /chat/completions(GLM-5.2 等)。需要 env:
        OPENAI_BASE_URL   (如 https://.../v1)
        MODEL_API_KEY 或 OPENAI_API_KEY 或 GLM_API_KEY
        AGENT_MODEL       (默认 glm-5.2)
  - stub:不依赖 API,从 fix.diff 合成种子(仅用于验证管线连通)。
        触发:env AGENT_ASSIST_STUB=1,或未配置 key 时自动回退。
"""
from __future__ import annotations
import base64, json, os, re, time, urllib.request, urllib.error
from pathlib import Path

MAX_SEEDS = 3
MAX_SEED_BYTES = 256


def _read(task, name):
    p = Path(task["task_dir"]) / "environment" / "workspace" / name
    return p.read_text(errors="ignore") if p.exists() else ""


# 端点/密钥文件等敏感配置放在 gitignore 的 local_config.py(不上传公开仓库);
# 公开代码只保留占位符,实际值由 local_config.py 或环境变量提供。
try:
    import local_config as _CFG
except Exception:
    _CFG = None


def _cfg(name, default=""):
    return (getattr(_CFG, name, "") or default) if _CFG else default


DEFAULT_BASE_URL = _cfg("BASE_URL") or "https://your-openai-compatible-endpoint/v1"
DEFAULT_MODEL = _cfg("MODEL") or "glm-5.2"
_KEY_FILE_CANDS = [
    os.environ.get("MODEL_KEY_FILE", ""),
    os.environ.get("CYBERGYM_ROOT", "") + "/test_intern.py" if os.environ.get("CYBERGYM_ROOT") else "",
    _cfg("KEY_FILE"),
]
DEFAULT_KEY_FILE = next((p for p in _KEY_FILE_CANDS if p and Path(p).exists()),
                        _cfg("KEY_FILE"))


def _read_key():
    # 与 datawheel read_model_key 一致:先 env 四个名,再从 key 文件正则抓 api_key='...'
    for name in ("LLM_API_KEY", "OPENAI_API_KEY", "MODEL_API_KEY", "GLM_API_KEY"):
        if os.environ.get(name):
            return os.environ[name]
    p = Path(DEFAULT_KEY_FILE)
    if p.exists():
        m = re.search(r"api_key\s*=\s*['\"]([^'\"]+)['\"]", p.read_text(errors="replace"))
        if m:
            return m.group(1)
    return None


def _llm_config():
    base = (os.environ.get("OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    model = os.environ.get("AGENT_MODEL", DEFAULT_MODEL)
    return base, _read_key(), model


SYS_PROMPT = (
    "You are a security fuzzing assistant helping CONSTRUCT benchmark test cases, not solve them. "
    "Given a vulnerability description and the vulnerable-vs-fixed source diff, produce raw-byte SEED "
    "inputs that steer a coverage-guided fuzzer TOWARD the vulnerable code path, plus dictionary tokens. "
    "Do NOT try to output the exact crashing input; produce structurally-plausible seeds the fuzzer will "
    "mutate. The fuzz target consumes a single raw byte buffer. "
    'Reply STRICT JSON only, no prose: {"seeds_b64":[...],"dict":[...]}. '
    "PRIORITIZE the dict: give up to 30 dictionary tokens (keywords, magic bytes, format markers "
    "from the vulnerable code). Seeds are optional and must be tiny: at most "
    f"{MAX_SEEDS} seeds, each <= {MAX_SEED_BYTES} bytes (base64). Keep the whole answer short."
)


_RETRY_CODES = {429, 500, 502, 503, 504}


def _post(base, key, payload, retries=3):
    body = json.dumps(payload).encode()
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(base + "/chat/completions", data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {key}"})
        try:
            with urllib.request.urlopen(req, timeout=400) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:      # 503/429 等过载:退避后重试
            last = e
            if e.code not in _RETRY_CODES:
                raise
        except urllib.error.URLError as e:       # 网络抖动:也重试
            last = e
        if attempt < retries - 1:
            time.sleep(2 * (attempt + 1))        # 2s, 4s 退避
    raise last


def _chat(base, key, model, description, diff, project):
    # prompt 砍小(输入越短→推理越短→越不容易被 length 截断):描述+diff 各截 ~800 字
    user = f"PROJECT: {project}\n\nDESCRIPTION:\n{description[:800]}\n\nDIFF (vulnerable->fixed):\n{diff[:800]}"
    # GLM-5.2 / Intern-S2 都是推理模型,且此端点不认 reasoning_effort/thinking:disabled
    # (实测照样重推理)。reasoning 先吃 token,预算不够就 finish_reason=length、content
    # 恒为 null → unparseable。唯一有效解:给足 max_tokens 让它把推理写完,写完才会在
    # content 里吐 JSON。实测 16000 下 finish=stop、正常出 JSON(单次约 60~90s)。
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYS_PROMPT},
                     {"role": "user", "content": user}],
        "temperature": 0.2,   # 低温:推理更收敛、更短,减少被 length 截断的概率
        "max_tokens": 16000,
    }
    data = _post(base, key, payload)
    msg = data["choices"][0]["message"]
    # 正文优先取 content;为空则回退 reasoning 字段(推理模型偶尔只填这里)
    return msg.get("content") or msg.get("reasoning_content") or msg.get("reasoning") or ""


def _parse(content):
    if not content or not content.strip():
        raise ValueError("empty content")
    t = content.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)      # 去 markdown 围栏
    t = re.sub(r"\s*```$", "", t)
    m = re.search(r"\{.*\}", t, re.S)            # 取最外层大括号块
    raw = m.group(0) if m else t
    obj = None
    for cand in (raw, re.sub(r",(\s*[}\]])", r"\1", raw)):   # 原样 / 去尾逗号
        try:
            obj = json.loads(cand); break
        except Exception:
            continue
    if obj is None:
        raise ValueError("unparseable JSON")
    seeds = []
    for s in (obj.get("seeds_b64") or [])[:MAX_SEEDS]:
        try:
            b = base64.b64decode(s)
            if 0 < len(b) <= MAX_SEED_BYTES:
                seeds.append(b)
        except Exception:
            continue
    dic = [str(t) for t in (obj.get("dict") or []) if t][:64]
    return seeds, dic


def _stub(task):
    """无 API 时:从 diff 抽 token 合成几个结构化种子(仅验证管线)。"""
    import fuzz_batch as F
    h = F.build_diff_hints(task)
    toks = [t for t in h["dict"] if t][:12]
    seeds = []
    # 每个字符串 token 单独成种子 + 一个把它们拼起来的种子
    for t in toks[:6]:
        try:
            seeds.append(t.encode("latin-1", "ignore")[:MAX_SEED_BYTES] or b"A")
        except Exception:
            pass
    if toks:
        seeds.append((" ".join(toks)).encode("latin-1", "ignore")[:MAX_SEED_BYTES])
    return [s for s in seeds if s], h["dict"]


def _cache_path(cache_dir, task):
    return Path(cache_dir) / f"{Path(task['task_dir']).name}.json"


def _cache_load(cache_dir, task):
    if not cache_dir:
        return None
    p = _cache_path(cache_dir, task)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
        d["seeds"] = [base64.b64decode(s) for s in d.get("seeds_b64", [])]
        return d
    except Exception:
        return None


def _cache_save(cache_dir, task, res):
    if not cache_dir:
        return
    p = _cache_path(cache_dir, task)
    p.parent.mkdir(parents=True, exist_ok=True)
    d = {"seeds_b64": [base64.b64encode(s).decode() for s in res["seeds"]],
         "dict": res["dict"], "backend": res["backend"], "error": res["error"]}
    p.write_text(json.dumps(d))


def _compute(task) -> dict:
    description = _read(task, "description.txt")
    diff = _read(task, "fix.diff")
    project = task.get("task_id", "")
    base, key, model = _llm_config()
    if os.environ.get("AGENT_ASSIST_STUB") == "1" or not (base and key):
        seeds, dic = _stub(task)
        return {"seeds": seeds, "dict": dic, "backend": "stub", "error": ""}
    try:
        content = _chat(base, key, model, description, diff, project)
        seeds, dic = _parse(content)
        if not seeds and not dic:
            raise ValueError("empty response")
        return {"seeds": seeds, "dict": dic, "backend": f"real:{model}", "error": ""}
    except Exception as e:
        seeds, dic = _stub(task)
        return {"seeds": seeds, "dict": dic, "backend": "stub-fallback",
                "error": f"{type(e).__name__}: {e}"}


def generate(task, cache_dir=None) -> dict:
    """返回 {"seeds":[bytes...], "dict":[str...], "backend":..., "error":...}。
    有缓存先用缓存(fuzz 阶段零等待);否则现算并写缓存。"""
    cached = _cache_load(cache_dir, task)
    if cached is not None:
        cached["backend"] = "cache:" + cached.get("backend", "?")
        return cached
    res = _compute(task)
    _cache_save(cache_dir, task, res)
    return res


def precompute(out_dir, langs=None, jobs=10):
    """并行预生成所有 task 的种子缓存(GLM 调用是 I/O bound,可高并发)。"""
    import sys, time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import fuzz_batch as F
    cache_dir = Path(out_dir).resolve() / "agent_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    lset = set(x for x in (langs or "").split(",") if x) or None
    tasks = F.load_tasks(F.Path(F.DEFAULT_BUNDLE).resolve(), lset, 0)
    todo = [t for t in tasks if not _cache_path(cache_dir, t).exists()]
    print(f"[precompute] total={len(tasks)} 待生成={len(todo)} jobs={jobs} cache={cache_dir}")
    done = {"n": 0}
    def work(t):
        r = generate(t, cache_dir=cache_dir)  # 无缓存则算并落盘
        return t["name"], r
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(work, t): t for t in todo}
        for fut in as_completed(futs):
            name, r = fut.result()
            done["n"] += 1
            print(f"[{done['n']}/{len(todo)}] {name:<46} backend={r['backend']} "
                  f"seeds={len(r['seeds'])} dict={len(r['dict'])} {r.get('error','')}", flush=True)
    real = sum(1 for t in tasks if (lambda d: d and d.get("backend","").startswith("real"))(_cache_load(cache_dir, t)))
    print(f"[precompute] done. real-agent 命中 {real}/{len(tasks)} (其余 stub/回退)")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--precompute", action="store_true", help="并行预生成所有 task 的种子缓存")
    ap.add_argument("--out", default="./out_agent")
    ap.add_argument("--langs", default="")
    ap.add_argument("--jobs", type=int, default=10)
    ap.add_argument("--selftest", action="store_true", help="单 task 自检(验证 endpoint+key)")
    args = ap.parse_args()
    base, key, model = _llm_config()
    print(f"base_url={base}  model={model}  key={'<found>' if key else '<MISSING>'}  key_file={DEFAULT_KEY_FILE}")
    if args.precompute:
        precompute(args.out, args.langs, args.jobs)
    else:  # 自检:取 bundle 里第一个 task 验证 endpoint+key
        import fuzz_batch as _F
        td = next(Path(_F.DEFAULT_BUNDLE).glob("task-core/*"))
        r = generate({"task_dir": str(td), "task_id": td.name})
        print(f"backend={r['backend']}  seeds={len(r['seeds'])}  dict={len(r['dict'])}  error={r['error']}")
