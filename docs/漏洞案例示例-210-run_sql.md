# 漏洞案例测试示例：run_sql

## 案例来源

本示例来自：

    测试/210_有漏洞/001_有漏洞/

历史记录中的目标和工具：

    目标：https://mcp.gab.sale/sse
    传输：SSE
    服务：sellfox-api
    工具：run_sql
    风险类别：任意 SQL 或数据库操作
    历史结论：确认匿名 SQL 执行

历史测试参数：

    {"sql":"SELECT 12345 AS audit_safe_probe","max_rows":1}

该查询只返回一个常量，不读取业务表，也不修改数据。

> 注意：该 URL 是历史测试目标，当前状态可能已经改变。只有获得目标所有者书面授权后，才可以重新连接或调用。本文不表示目标当前仍然存在漏洞。

## 1. 只读发现工具列表

先确认 MCP 服务和 run_sql 工具是否仍然存在：

    ./run.sh discover --url https://mcp.gab.sale/sse --transport sse --output data/run_sql-discovery.json

该命令只执行 MCP 初始化和 tools/list，不会调用 run_sql。

查看工具信息：

    jq '.tools[] | {name, description, inputSchema}' data/run_sql-discovery.json

如果连接失败、工具不存在或服务要求认证，应停止后续步骤。

## 2. 生成安全测试计划

仅对已经授权的目标运行 audit：

    ./run.sh audit --url https://mcp.gab.sale/sse --transport sse --plan-top 5

命令会输出运行目录，例如：

    Run directory: data/runs/20260810-190000-ab12cd34

查看候选工具和计划：

    jq '.[] | {candidate_id, risk_level, risk_categories, tool: .tool.name}' data/runs/20260810-190000-ab12cd34/candidates.json
    less data/runs/20260810-190000-ab12cd34/plans/candidate-1.json

如果只有 run_sql 命中规则，通常会生成 candidate_id 1。最终以实际 candidates.json 和计划文件为准。

## 3. 人工批准后执行一次调用

确认目标、工具、参数和授权范围后，再执行：

    ./run.sh execute --run-dir data/runs/20260810-190000-ab12cd34 --candidate-id 1 --transport sse --approve --authorization-ack I_HAVE_AUTHORIZATION

计划必须是只读常量查询，例如：

    {"arguments":{"sql":"SELECT 12345 AS audit_safe_probe","max_rows":1}}

工具会再次执行确定性安全校验，并拒绝同一候选的重复调用。结果保存到：

    data/runs/<run-id>/raw/candidate-1.json
    data/runs/<run-id>/results/candidate-1.json

## 4. 如何判断结果

如果响应返回 audit_safe_probe: 12345，说明请求已经到达 SQL 工具处理逻辑，可支持“调用可达”的判断。建议按三个层次记录：

    U1：无认证即可 initialize + tools/list
    U2：无认证 tools/call 到达 run_sql 处理逻辑
    U3：造成非公开数据泄露或敏感状态变化

历史案例支持匿名 SQL 调用到达工具并返回常量结果；新的研究结论必须以本次复测的原始响应为准。

## 5. 记录人工结论

例如当前只确认调用可达、还需要补充业务证据：

    ./run.sh review --run-dir data/runs/20260810-190000-ab12cd34 --candidate-id 1 --decision needs_more_evidence --notes "常量 SQL 返回成功；需服务所有者确认匿名权限边界和数据库范围"

可选结论为 confirmed、not_confirmed 和 needs_more_evidence。

## 6. 常见错误

如果 audit 输出 candidate_count: 0 和 generated_plan_count: 0，说明当前工具清单没有命中本地高风险规则，plans/ 中不会有测试计划，此时不能直接执行 candidate_id 1。

## 7. 本地无公网演示

只想验证命令和测试框架时，可运行仓库自带测试：

    PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
    npm --prefix node test

本地测试不会连接上述历史公网目标。

 ./run.sh one-click \
    --url https://mcp.gab.sale/sse \
    --plan-top 5