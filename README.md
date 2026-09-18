# MCPScope

MCP 资产发现、风险识别与受控安全验证平台。

MCPScope 是一个本地优先、证据导向的 MCP 安全工具，覆盖公开资产发现、协议指纹、能力风险分析、审计历史和经人工批准的受控验证。

工具把流程拆分为两个安全边界：公开索引查询只生成候选地址，不连接候选 MCP；主动指纹扫描必须确认目标处于书面授权范围。后续审计默认只读取 MCP 元数据、筛选高风险候选并生成测试计划，只有再次显式批准后才执行一次 `tools/call`。

## 环境要求

- macOS 或 Linux
- Python 3.11+
- Node.js 20+ 与 npm

不需要 Docker。首次运行 `mcpscope` 会自动创建 `.venv`、安装 Python 依赖，并在缺少 Node 依赖时执行 `npm ci`。

## 快速开始

```bash
cp .env.example .env
./mcpscope --help
./mcpscope --version
```

## 完整流程

```text
公开索引
   ↓  targets-discover（被动，不连接候选 MCP）
候选 URL 清单
   ↓  targets-scan（主动，要求授权确认）
MCP 指纹、工具清单和风险排序
   ↓  audit（单目标，只生成计划）
确定性安全校验
   ↓  execute（再次审批，只调用一次）
原始证据、规则分析和人工复核
```

### 1. 被动发现候选目标

默认查询 crt.sh、HuggingFace、GitHub、npm、PyPI、Smithery、Glama、PulseMCP、Censys、FOFA 和 Shodan。需要凭据的来源在未配置时会给出警告并跳过：

```bash
./mcpscope targets-discover \
  --limit-per-source 100 \
  --output data/targets/candidates.json
```

也可以只选择部分来源：

```bash
./mcpscope targets-discover \
  --source huggingface \
  --source github \
  --output data/targets/candidates.json
```

该命令不会连接候选 MCP 服务，也不会调用任何 MCP 工具。可使用 `--source` 重复选择来源，使用 `--since` 排除旧结果中已有的地址。

### 2. 对授权目标执行 MCP 指纹扫描

主动扫描会执行 MCP 初始化和 `tools/list`，因此必须先人工核对候选清单，只保留书面授权范围内的地址：

```bash
./mcpscope targets-scan \
  --input data/targets/authorized-targets.json \
  --max-targets 25 \
  --concurrency 4 \
  --authorization-ack I_HAVE_AUTHORIZATION \
  --output data/targets/fingerprint-results.json
```

输入支持以下格式：

- `targets-discover` 生成的 JSON；
- JSON 数组；
- JSONL；
- 每行一个 URL 的文本文件。

扫描结果包括实际 MCP 端点、传输方式、协议版本、服务信息、服务指令、工具、资源、提示、重定向、Cloudflare 指纹、高风险候选、认证推断和优先级分数。该阶段仍不会执行 `tools/call`。每次扫描会写入 `data/history.sqlite3`，`--resume` 可以跳过旧扫描中已有的 URL。

生成离线 Markdown 汇总：

```bash
./mcpscope targets-report \
  --input data/targets/fingerprint-results.json \
  --output data/targets/fingerprint-report.md
```

比较两次指纹扫描，识别新增、消失、风险变化和工具变化：

```bash
./mcpscope targets-diff \
  --old data/targets/fingerprint-old.json \
  --new data/targets/fingerprint-new.json \
  --output data/targets/fingerprint-diff.json
```

生成 SARIF、HTML、Markdown 和 CSV：

```bash
./mcpscope report --input data/targets/fingerprint-results.json \
  --format sarif --format html --format markdown --format csv
```

查询历史、趋势和单目标纵向记录：

```bash
./mcpscope history
./mcpscope trend critical_count
./mcpscope longitudinal https://authorized.example/mcp
./mcpscope decay
```

持续复扫最近一次扫描中的严重执行类目标仍属于主动操作，因此需要授权确认：

```bash
./mcpscope watch --max-rounds 1 --authorization-ack I_HAVE_AUTHORIZATION
```

### 3. 为单个授权目标生成测试计划

```bash
./mcpscope audit \
  --url https://authorized.example/mcp \
  --plan-top 5
```

运行目录写入 `data/runs/<run-id>/`。不配置大模型时使用本地安全模板；使用兼容接口生成计划时增加 `--llm`：

```bash
./mcpscope audit \
  --url https://authorized.example/mcp \
  --llm \
  --plan-top 5
```

大模型读取 `.env` 中的 `LLM_API_URL`、`LLM_MODEL` 和 `LLM_API_KEY`。大模型输出必须通过本地确定性安全校验，不能直接执行。

### 4. 人工批准后执行一次调用

```bash
./mcpscope execute \
  --run-dir data/runs/20260810-120000-ab12cd34 \
  --candidate-id 1 \
  --approve \
  --authorization-ack I_HAVE_AUTHORIZATION
```

已有原始结果时，工具拒绝重复执行。批准记录包含测试计划的 SHA-256 摘要。

### 5. 一键运行单目标流程

如果希望从一个 URL 自动完成探测、风险筛选和测试计划生成，可以使用 `one-click`：

```bash
./mcpscope one-click \
  --url https://authorized.example/mcp \
  --plan-top 5
```

默认流程会在生成计划后停止，并输出运行目录。确认计划和授权范围后，可以显式允许执行一个候选的一次调用：

```bash
./mcpscope one-click \
  --url https://authorized.example/mcp \
  --plan-top 5 \
  --execute \
  --candidate-id 1 \
  --approve \
  --authorization-ack I_HAVE_AUTHORIZATION
```

`one-click` 不会批量调用所有高风险工具；每次最多执行一个候选，且仍要求人工批准。执行后可以追加 `--review-decision` 和 `--review-notes` 记录人工结论。

### 6. 记录人工结论

```bash
./mcpscope review \
  --run-dir data/runs/20260810-120000-ab12cd34 \
  --candidate-id 1 \
  --decision needs_more_evidence \
  --notes "需要服务所有者提供授权范围和业务测试账号"
```

## 其他命令

只读取一个已知 MCP 的工具列表：

```bash
./mcpscope discover --url https://authorized.example/mcp
```

扫描结果还可以通过 `feed-corvus`、`feed-condor`、`feed-shrike` 和 `feed-ibis` 转换给下游系统。`feed-ibis` 默认只预览，实际提交同时要求 `--apply --approve`。向 CobaltoHQ 发出事件使用 `emit-cobalto --approve`，不会随扫描自动发送。

运行离线测试：

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
npm --prefix node test
```

## 数据目录

```text
data/targets/             目标发现和指纹扫描结果
data/history.sqlite3      扫描运行、目标快照和纵向历史
data/runs/<run-id>/
  manifest.json           运行状态和目标
  discovery.json          MCP tools/list 原始结果
  candidates.json         高风险工具候选
  plans/                  测试计划和确定性校验结果
  approvals/              计划哈希和人工批准记录
  raw/                    单次调用原始结果
  results/                规则分析结果
  reviews/                人工最终判定
```

## 安全边界

- 公开索引发现与主动 MCP 探测是两个独立命令。
- 主动批量探测必须提供授权确认，并默认限制为 25 个目标、4 个并发。
- 消失原因主动分类和持续复扫同样要求授权确认。
- 不默认调用任何 MCP 工具。
- 不关闭 TLS 校验，不绕过 OAuth、Bearer 或 API Key 认证。
- 命令、SQL、文件路径、URL、收件人和金额由确定性校验器检查。
- 所有目标 URL 都会移除查询参数和嵌入式凭证，避免将令牌写入结果。
- 原始响应、分析结果和人工结论分开保存。

本工具识别的是高风险能力和需要复核的证据，不会仅凭一次响应自动确认漏洞。

## 研究网站

`site/` 包含 MCPScope 的静态研究网站，展示脱敏后的方法、数据分布、证据等级和案例。网站不会发布原始目标、凭据、响应内容或测试路径。

从仓库上级目录中的研究 CSV 重新生成公开汇总：

```bash
python3 scripts/build_public_site_data.py
```

本地预览：

```bash
python3 -m http.server 4173 --directory site
```

访问 `http://localhost:4173/`。推送到 `main` 后，GitHub Pages 工作流会部署 `site/`。

网站数据与结构检查：

```bash
node --test site/tests/site.test.mjs
```
