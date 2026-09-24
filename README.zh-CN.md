<div align="center">

# 🛡️ agent-scan（简体中文）

**AI Agent 生态的 `npm audit`。**

面向 **MCP Server · Agent Skills · AGENTS.md / 规则文件 · Agent 工具代码** 的静态安全扫描器 + 在线 MCP 投毒探测（probe）。
检测提示词注入、隐藏指令、数据外泄、工具投毒与供应链风险。

**零依赖 · 完全离线 · 结果确定 · 原生 SARIF 输出**

</div>

> 完整文档以英文 [README.md](README.md) 为准，本文为同步摘要。

---

你的编程助手会自动安装 MCP Server、从市场下载 Skill、并逐字执行陌生人写的 `SKILL.md` / `AGENTS.md` 里的指令。**没有任何工具检查过这些文件到底让你的 Agent 做了什么。**

攻击真实且在重复发生：技能市场里用 base64 和零宽 Unicode 走私指令、Agent 会照做的 `curl | bash` "初始化步骤"、不带版本锁的 `npx` 启动、离你的 SSH 私钥只有一次 `execSync` 距离的命令注入。`agent-scan` 给 Agent 生态补上缺失的审计环节。

## 安装

```bash
npx @yoshine2007/agent-scan path/to/repo       # 无需安装
npm install -g @yoshine2007/agent-scan         # 或全局安装
```

仅需 Node ≥ 20。不需要 API Key，不发起任何网络请求，模型也不参与扫描——扫描是磁盘文件的纯函数。

## 快速开始

```bash
agent-scan .                    # 扫描当前仓库
agent-scan ~/.claude            # 审查你的 Agent「能看到」的一切
agent-scan SKILL.md --format md # 单文件，Markdown 报告
agent-scan --sarif -o out.sarif # 接入 GitHub code scanning
agent-scan --fail-on high       # CI 门禁：high 及以上直接失败
agent-scan --rules              # 查看全部 30 条规则
agent-scan probe npx -y some-mcp-server  # ⚡ 在线工具投毒探测
```

### ⚡ 动态探测：审计不存在于任何文件里的东西

投毒的工具描述往往只在运行时下发，仓库里根本没有。`agent-scan probe <命令>` 会在本地拉起这个 MCP Server，完成握手并抓取全部 `tools/list` / `prompts/list` / `resources/list` 元数据，用 7 条 **AS-T** 规则检测（隐藏 Unicode、指令覆盖话术、隐瞒指令、外泄语句、投毒 schema 默认值）。**它绝不执行任何 tool**——只抓元数据，硬超时，探测结束立刻杀进程。agent-scan 自己的参数要写在 server 命令之前（如 `probe --format json node server.js`）。

## 检测什么

| 组 | 覆盖面 | 代表规则 |
|---|---|---|
| **P — 提示词注入** | `SKILL.md`、`AGENTS.md`、`.cursorrules`、提示词文档 | 指令覆盖（含中文"忽略以上指令"）、零宽/双向 Unicode 走私、"不要告诉用户"类隐瞒指令、系统提示词探测、**解码后为指令的 base64 载荷**、越狱框架话术 |
| **M — MCP 配置** | `.mcp.json`、`claude_desktop_config.json` 等 | 不锁版本的 `npx` 启动、配置内嵌 `bash -c` 一行流、明文 `http://` 端点、`env`/`headers` 里的真实密钥、全局 `autoApprove` |
| **S — 工具源码** | MCP Server 与 Agent 工具的 JS/TS/Python/Go/Shell | `exec(\`…${input}…\`)` 命令注入、`eval`/`new Function`、文件工具路径穿越、模型控制 URL 的 SSRF、**300 字符内"读密钥+发网络"组合**、代码混淆 |
| **N — npm 供应链** | `package.json` | `postinstall` 钩子、`github:user/repo#branch` 依赖、`"*"` 版本范围、脚本里的 `curl … \| bash` |
| **T — 工具投毒** ⚡ | `agent-scan probe` 抓取的在线 MCP 元数据 | 工具名/标题里的隐藏 Unicode、运行时下发的指令覆盖与"不要告诉用户"话术、描述里的凭据外泄语句、危险引导命令、带载荷默认值的投毒 schema |

全部规则的说明与修复建议见 **[docs/rules.md](docs/rules.md)**。

## 为什么可信

- **默认纯静态**：不执行被扫代码、不联网、不依赖大模型，规则全部可审阅。唯一的例外是显式发起的 `probe`：它只拉起你指定的 server、只做元数据握手（`initialize` + `*/list`），从不调用 tool，结束即杀进程。
- **零依赖**：扫描器自己不会成为你的供应链风险（`npm ls --all` 为空，可验证）。
- **确定性**：同样的输入字节永远得到同样的结果，适合 CI。
- **自用自扫**：`npm run scan:self` 扫描本仓库；`examples/` 提供三个仿真攻击样本。

## 局限（明说）

- 模式匹配存在误报与漏报：`CRITICAL` 是"立刻看这一行"，不是定罪；干净扫描不是认证。
- 文件扫描只覆盖**文件**；运行时元数据用 `agent-scan probe`（本地 stdio server）。远程/SSE server 与"调用工具之后"的行为仍不在范围内——跨次探测的 rug-pull 对比在 Roadmap 上。

## 许可证

[MIT](LICENSE)
