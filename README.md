# Mango + IDA 固件候选路径审查 Agent

代码、配置、日志与结果位于 `D:\chatgpt\mango-agent`。复用 C 盘已安装 Mango 的 Python 3.11 环境；本项目只使用 Python 标准库，不需要安装额外依赖。

本项目是借鉴 ClearAgent 迭代工具调用、LATTE 二进制语义分析和 IRIS 告警审查思路的工程原型，不是这些论文的完整复现。

## 首次使用

1. 在 IDA Pro 8.3 中打开原 AC20 `httpd.idb`，等待分析完成。反编译该 MIPS 二进制需要可用的对应 Hex-Rays 反编译器。
2. 按 `Ctrl+Alt+M` 启动之前安装的 MCP 插件。本项目适配现有插件的 `http://127.0.0.1:13337/mcp` JSON-RPC 接口，而非任意新版 MCP 服务。
3. 双击 `start.cmd`，先选择 1 检查环境，然后选择 2 查看已有四条候选路径。
4. 自动模式需要配置 API；只有 ChatGPT 产品名称或网页版登录不能配置这个独立程序。

## 两种运行方式

### API 自动模式：完整 Agent 循环

编辑本机 `config.json`，填入提供方的 API Base URL（通常到 `/v1`，不要填到 `/chat/completions`）和模型名。接口需要支持 Chat Completions 协议。程序使用普通 JSON 决策协议，不依赖服务商的 function calling。

双击 `configure.cmd`（或启动菜单 6）打开本地配置窗口。DeepSeek 官方接口已填入 `https://api.deepseek.com`，默认模型为当前官方文档列出的 `deepseek-flash`。API Key 在窗口中隐藏输入，保存时使用当前 Windows 用户的 DPAPI 加密，密文存放在项目 `secrets/api-key.dpapi`；不会写入 JSON 配置和报告。不要把密钥发送到聊天或提交代码仓库。程序也支持优先从 `MANGO_AGENT_API_KEY` 环境变量读取密钥。

“保存并测试连接”只发送一个简单 JSON 连通性提示，测试结果写入 `runs/model-connection.json`。真实审查需要随后从菜单 4 启动。

本次使用的 IDA 数据库副本在 `D:\chatgpt\mango-agent\ida-workspace\httpd.idb`，可以在 IDA 中打开副本后按 Ctrl+Alt+M。原目录里有上次未正常关闭留下的未打包文件，因此本次没有执行恢复覆盖原分析的操作。

自动模式会向你配置的模型服务发送选中的 Mango 候选结果及相关 IDA 伪代码。配置提供方后再使用此模式。

PowerShell 示例：

```powershell
Set-Location D:\chatgpt\mango-agent
$agentPython = 'C:\Users\hp\Documents\Codex\2026-11-03\new-chat\work\mango-pyenv\Scripts\python.exe'
& $agentPython agent.py doctor
& $agentPython agent.py list
& $agentPython agent.py review --candidate 0 --mode api
```

Agent 首先获取危险调用所在函数，再由模型选择查询调用者、被调用者、字符串引用等。默认最多 6 轮模型决策、16 次只读工具请求。代码文本被视为不可信数据；只允许白名单查询，不执行模型返回的代码或命令。

### 文件交接模式：无 API 时分步运行

```powershell
& $agentPython agent.py review --candidate 0 --mode handoff
```

程序连接 IDA 获取初始代码，创建 `runs/<时间-编号>/next_request.json`。把文件中的任务、证据交给你使用的模型，把模型返回的 JSON 保存为本地 `response.json`，然后运行：

```powershell
& $agentPython agent.py resume 'D:\chatgpt\mango-agent\runs\实际运行编号' --response 'D:\chatgpt\mango-agent\response.json'
```

模型要求补充函数时，resume 实际调用 IDA，保存证据并刷新 next_request.json；收到结束结论时生成最终报告。这个模式包含人工传递步骤，不等同于已经完成独立自动模型连接。

模型决策格式（示意）：

```json
{"action":"tools","requests":[{"tool":"function_at","args":{"address":"0x498890"},"reason":"确定汇点调用所属函数"}]}
```

结束格式：

```json
{"action":"finish","status":"insufficient_evidence","summary":"尚未确认输入设置入口。","evidence":[{"id":"E0001","claim":"请填写该实际证据支持的具体观察"}],"missing_evidence":["输入写入入口及过滤逻辑"],"next_steps":["继续核对相关引用"]}
```

证据编号必须对应实际成功的工具返回。程序验证编号存在，语义是否成立仍需人工审查。

## 分析新 ELF

```powershell
& $agentPython agent.py analyze 'D:\ac20.extracted\httpd' --category cmdi --timeout 600
```

输出写入 D 盘 runs/mango-*。成功后使用 `review --results '实际目录\cmdi_results.json'`。overflow 模式改为 `--category overflow` 和 `overflow_results.json`。先在 IDA 打开同一二进制；程序强制核对 SHA256，不一致会停止。

## 输出文件

- `mango-original.json`：本次输入的原始 Mango 结果副本。
- `state.json`：候选、IDA 元数据、所有观察、模型决策与当前状态。
- `evidence/E*.json`：独立保存的完整只读工具响应，提示词中的代码可能被截断，原始证据保留。
- `model-round-*.json`：API 模式的模型决策。
- `next_request.json`：下一轮模型请求，用于文件交接及审计。
- `events.jsonl`：运行事件记录。
- `report.json`、`report.md`：审查报告。

结论状态：supported（静态证据支持风险）、contradicted（存在反证）、insufficient_evidence（证据不足）。不自动称为已确认漏洞，不声称执行过动态验证；Mango 原始排名不变，不解释为概率。

## 验证

`test_agent.py` 使用本地模拟 IDA 与模型端点验证真实 HTTP 协议、主动补充证据和报告输出；模拟测试不代表 AC20 已完成实际模型审查。

```powershell
& $agentPython -m unittest -v test_agent.py
```

## 当前边界

第一版聚焦一个 ELF 的一条候选路径；不自动解包固件，不训练模型，不实现跨程序 NVRAM、动态库汇点自动生成或动态测试。Mango 分析和审查分别留痕。工具失败、模型失败和未完成任务都不会变成“没有漏洞”的结论。
