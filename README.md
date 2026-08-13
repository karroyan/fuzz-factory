# fuzz-factory · 批量 PoC 生产流水线

对 `ossfuzz-harbor` 漏洞 bundle 批量跑 libFuzzer,自动产出并**差分验证**"有效 PoC",记录成功/失败明细。支持四种递进的增强模式:**纯 fuzz → +diff 定向 → +fork 并行 → +agent 种子**。

---

## 1. 目标与"有效 PoC"的定义

每个 task 是一个 OSS-Fuzz 漏洞,带**漏洞版镜像**(vul)和**修复版镜像**(fix)两个 docker 镜像。流水线对每个 task 跑 fuzz,拿到崩溃输入后做**差分验证**:

> **有效 PoC = 同一个输入在 vul 镜像触发 sanitizer 崩溃,且在 fix 镜像干净退出(exit==0)。**

只有满足差分才算成功。以下情况**不算**:
- OOM / 超时;
- vul、fix 两边都崩(说明是共享 bug,不是被修复的那个洞);
- fix 也非零退出。

判定逻辑见 `fuzz_batch.py` 的 `differential()`。

---

## 2. bundle 规模

整个 bundle 共 **106 个漏洞 task**:

| 语言 | 数量 |
|------|------|
| c_cpp | 60 |
| python | 35 |
| go | 11 |
| **合计** | **106** |

`--langs` 可只跑某一种语言(如只跑 c_cpp 做实验)。

---

## 3. 代码结构

| 文件 | 作用 |
|------|------|
| `fuzz_batch.py` | **主引擎**。加载 task → docker 跑 libFuzzer → 收集 crash → 去重 → 差分验证 → 记录 + 写回 PoC |
| `agent_assist.py` | **agent 脚手架**。读 `description.txt`+`fix.diff`,调 LLM(glm-5.2)产出**种子 + 字典**喂给 fuzzer;带缓存与预生成 |
| `run_two_phase.sh` | **编排器**。Phase1 全量短预算建 corpus → 自动接 Phase2 只对没出 PoC 的续跑长预算 |
| `reduce_logs.py` | 日志精简小工具 |

### 两阶段策略
- **Phase1**:全部 task × 短预算(默认 300s),先把好撞的收掉、给每个 task 建持久化 corpus。
- **Phase2**:只对 Phase1 没出 PoC 的 task,续跑长预算(复用 Phase1 累积的 corpus,越跑越肥)。
- 每个 task 有独立持久化 corpus 目录,libFuzzer 把新覆盖样本写回,跨轮累积。
- 已成功的 task 记入 `success_ledger.txt`,后续轮次 `--skip-succeeded` 自动跳过。

---

## 4. 四种模式

四种模式通过环境变量 / 开关叠加,一个比一个强。统一入口都是 `run_two_phase.sh`:

```
用法: [ENV...] ./run_two_phase.sh [OUT_DIR] [P1_SECS] [P2_SECS] [JOBS] [LANGS] [LIMIT]
环境变量开关: USE_DIFF=1(默认开) FORK=N(默认2) AGENT=0/1 RESUME=0/1
```

### 模式 A · 纯 fuzz(基线)
最朴素的 libFuzzer:只喂官方 seed_corpus,不做任何定向。
```bash
USE_DIFF=0 FORK=0 ./run_two_phase.sh out_pure 300 1800 4
```
> **示例结果**(`out_0807/`,该轮跑到 17/106 中断):基本撞不出差分 PoC,`no_artifact` 为主。作为对照基线。

### 模式 B · +diff 定向
从 `fix.diff` 纯脚本抽取 **libFuzzer 字典(-dict)** 和 **focus_function 候选**,把 fuzz 引向被修改的代码路径(无 LLM)。对应 `build_diff_hints()`。
```bash
USE_DIFF=1 FORK=0 ./run_two_phase.sh out_diff 300 1800 4
```
> **示例结果**(`out_diff_0807/summary_p1.json`,106 task):
> ```json
> {"overall": {"tasks": 106, "crashed": 24, "valid_poc": 0, "poc_rate": 0.0}}
> ```
> 崩溃数比纯 fuzz 多(字典帮助命中代码路径),但单进程下差分 PoC 仍难产。

### 模式 C · +fork 并行
在模式 B 基础上开 libFuzzer **fork 模式**:多子进程并行 + 崩溃/OOM/超时隔离不中断,一轮能持续收集**多个不同 crash**,大幅提高撞到"那个洞"的概率。对应 `run_libfuzzer()` 的 `-fork/-ignore_crashes` 分支。
```bash
USE_DIFF=1 FORK=6 ./run_two_phase.sh out_fork 300 1800 1
```
> **示例结果**(`out_j1f6_0807/`,106 task,FORK=6):**首次跑出 2 个有效 PoC** —— `go-yaml`(go)、`gpac-cve-2023-0358`(c_cpp)。
> ```json
> {"overall": {"tasks": 106, "crashed": 25, "valid_poc": 2, "poc_rate": 0.019}}
> ```
> 一个成功记录的 crash 栈(go-yaml,`gopkg.in/yaml.v3` 递归解析 deadly signal),存于 `out_j1f6_0807/pocs/<task>/error.txt`。

### 模式 D · +agent 种子
在模式 C 基础上开 **agent 脚手架**:LLM 读漏洞描述 + diff,产出**结构化种子写进 corpus + 字典 token**,让 fuzzer 在更靠近漏洞的起点上变异。**agent 绝不直接给崩溃字节**,只提供引导。
```bash
# 建议先并行预生成种子缓存(fuzz 阶段零等待)
python3 agent_assist.py --precompute --out out_agent --langs c_cpp --jobs 6
# 再开 AGENT=1 跑
AGENT=1 USE_DIFF=1 FORK=2 ./run_two_phase.sh out_agent 300 600 4 c_cpp
```
> **示例结果**(`out_ab_agent/`,60 个 c_cpp,Phase1 已完成、Phase2 进行中):
> ```json
> {"overall": {"tasks": 60, "crashed": 18, "valid_poc": 2, "poc_rate": 0.033}}
> ```
> 两个成功:`gpac-cve-2023-0358`(与模式 C 重复)、**`mruby-cve-2022-0717`(新增)**。
> - `mruby-cve-2022-0717` 用的是 **real:glm-5.2** 缓存(3 seed / 30 dict)—— **真正由 agent 种子促成的新 PoC**。
> - `gpac-cve-2023-0358` 那条 agent 缓存其实是 **stub-fallback**,说明该 task 主要还是 fork+diff 的功劳。

---

## 5. agent 内部机制

```
description.txt + fix.diff
        │  (截断到各 ~800 字,压缩 prompt)
        ▼
   glm-5.2 (OpenAI 兼容 /chat/completions)
        │  严格 JSON: {"seeds_b64":[...], "dict":[...]}
        ▼
   种子写进 task 的 corpus/  +  字典写进 dict/task.dict
        ▼
   libFuzzer 在种子上变异 → 真正发现 PoC
```

- **端点**:内部 OpenAI 兼容 `/chat/completions`,模型 `glm-5.2`。端点地址与密钥文件路径放在**未纳入 git 的 `local_config.py`**(见下文「配置」),公开代码只有占位符。
- **缓存**:结果落 `OUT/agent_cache/<task>.json`,precompute 高并发预生成;`--precompute` 只跳过已存在的缓存文件。
- **回退**:没配 key / API 报错 / JSON 解析失败 → 自动 `stub`,从 diff 抽 token 合成种子(保证管线不断)。

### 关键坑与修复(已解决)
glm-5.2 是**推理模型**,先把内容写进 `reasoning` 字段再吐 `content`。最初 `max_tokens=3000` 时推理还没写完就被 `length` 截断,`content` 恒为 null → 满屏 `unparseable JSON` → 全退回 stub(命中率仅 ~25%)。

排查确认端点**不认** `reasoning_effort:minimal` / `thinking:disabled`,唯一有效解是**给足 token 让推理写完**。当前 `agent_assist.py` 的配置:
- `max_tokens=16000`(实测 finish=stop、正常出 JSON,单次约 60~90s);
- `temperature=0.2`(推理更收敛、更短);
- 输入 desc/diff 各截 **800 字**(输入越短推理越短);
- **503/429 自动退避重试**(端点过载时救回)。

修复后 c_cpp real 命中率 **27/60 → 38/60(63%)**;剩余 stub 多为推理超 16000 token 的硬骨头,stub 种子仍照常喂 fuzz,不影响管线。

---

## 6. 怎么看结果

每个 `OUT/` 目录:

| 路径 | 内容 |
|------|------|
| `success_ledger.txt` | **成功清单**,每行一个 task 名,`wc -l` 即成功数 |
| `progress.json` | 实时进度 + 状态分布快照 |
| `summary_p1/p2.json` | 分语言 tasks/crashed/valid_poc/poc_rate |
| `results_p1/p2.jsonl` | **逐条明细**,每 task 一行 JSON(状态、crash 数、差分结果、PoC 路径、崩溃栈) |
| `pocs/<task>/poc` + `error.txt` | 实际 PoC 字节 + 崩溃摘要 |
| `run.log` / `logs/<task>.log` | 实时流水 / 每 task 详细日志 |
| `corpus/<task>/` | 该 task 的持久化 corpus(跨轮累积) |
| `agent_cache/<task>.json` | agent 预生成的种子/字典缓存 |

常用命令:
```bash
# 成功数
wc -l < OUT/success_ledger.txt
# 进度快照
python3 fuzz_batch.py --out OUT --status
# 实时流水
tail -f OUT/run.log
# 是否还在跑
pgrep -af fuzz_batch.py
# agent 缓存 real/stub 命中分布
python3 - <<'EOF'
import json,glob,collections
c=collections.Counter(json.load(open(f))["backend"].split(":")[0] for f in glob.glob("OUT/agent_cache/*.json"))
print(dict(c))
EOF
```

### 状态含义
| status | 含义 |
|--------|------|
| `valid_poc` | ✅ 成功:vul 崩 + fix 干净 |
| `no_artifact` | fuzz 到点没撞出任何 crash(可加时间/换模式) |
| `crash_not_differential` | 撞到了但差分不过(OOM/两边都崩/共享 bug) |
| `no_fuzz_target` / `missing_image` / `engine_timeout` / `error` | 环境/异常类失败 |

---

## 7. 各模式结果汇总

> **说明**:下表与前文各「示例结果」均取自本机跑过的 `out_*/` 目录。**这些输出目录不纳入 git**(见 `.gitignore`),此处数字仅作为**在 106 个漏洞数据集上成功率的示例**,用于展示各模式的相对效果;克隆本仓库后需自行运行才能复现。

| 模式 | 目录(本地) | 关键开关 | 范围 | crashed | valid_poc | 备注 |
|------|------|----------|------|---------|-----------|------|
| A 纯fuzz | `out_0807` | 无 | 106(17中断) | — | 0 | 基线 |
| B +diff | `out_diff_0807` | `USE_DIFF=1` | 106 | 24 | 0 | 崩溃变多,差分仍难产 |
| C +fork | `out_j1f6_0807` | `USE_DIFF=1 FORK=6` | 106 | 25→34 | **2** | 首次出 PoC(go-yaml, gpac-0358) |
| D +agent | `out_ab_agent` | `AGENT=1 FORK=2` | 60(c_cpp) | 18 | **2** | 含 1 个新洞 mruby-0717(P2进行中) |

**趋势**:每叠加一层增强,撞到"目标洞"的能力上升。fork 模式带来第一批 PoC;agent 种子在 fork 基础上进一步拿下了 fork 也没出的 `mruby-cve-2022-0717`。

---

## 8. 配置(首次使用)

端点、密钥文件、bundle 路径均为本地私有,**不纳入 git**。首次使用请任选其一:

**方式一 · `local_config.py`(推荐)**
```bash
cp local_config.example.py local_config.py   # local_config.py 已在 .gitignore
# 编辑填入你的 BASE_URL / MODEL / KEY_FILE / BUNDLE
```
**方式二 · 环境变量**
```bash
export OPENAI_BASE_URL="https://your-endpoint/v1"
export LLM_API_KEY="..."          # 或 MODEL_KEY_FILE 指向含 api_key 的文件
export FUZZ_BUNDLE="/path/to/ossfuzz-harbor-bundles/<bundle>"
```
验证:`python3 agent_assist.py --selftest`,看到 `key=<found>` 且 `backend=real:glm-5.2` 即通。

---

## 9. 复现某一模式的最小命令

```bash
cd /path/to/fuzz-factory

# 只跑前 10 个 c_cpp、快速验证管线
USE_DIFF=1 FORK=2 ./run_two_phase.sh out_smoke 120 300 4 c_cpp 10

# 完整 agent 模式(推荐先 precompute)
python3 agent_assist.py --precompute --out out_run --langs c_cpp --jobs 6
AGENT=1 ./run_two_phase.sh out_run 300 600 4 c_cpp 0

# 断点续跑(跳过已完成,error 的重跑)
RESUME=1 AGENT=1 ./run_two_phase.sh out_run 300 600 4 c_cpp 0
```

---

## 附:文件与 git 说明

**纳入 git(会上传)**:`fuzz_batch.py`、`agent_assist.py`、`run_two_phase.sh`、`reduce_logs.py`、`README.md`、`local_config.example.py`、`.gitignore`。

**不纳入 git(见 `.gitignore`,仅本地)**:
- `local_config.py` —— 端点/密钥文件/bundle 路径等**私有配置**,绝不上传。
- `out_*/` —— 所有 fuzz 输出、语料、PoC、缓存、日志。
- `_probe.py` —— 单 task 打端点、dump 响应的调试探针(内含端点访问逻辑)。
- `_raw*.txt` / `_agent_latency.txt` / `*.nohup` / `*.log` / `precompute*.log` / `__pycache__/` —— 调试临时产物。
