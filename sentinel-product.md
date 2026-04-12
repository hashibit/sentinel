# Sentinel — Claude Code 项目安全扫描器

## 动机

Claude Code 的 plugin/skill/hook 机制引入了新的攻击面：恶意参与者可以通过系统提示词注入、skill 指令、hook 脚本等方式，让 Claude 在"正常开发"的掩护下执行隐藏任务。传统静态分析工具（AST 解析、规则匹配）对这类**语义层攻击**几乎无效——恶意指令藏在自然语言中，代码本身看起来完全合法。

Sentinel 是一个 Rust 编写的轻量级扫描工具，核心思路很简单：

> **只把文件内容喂给纯 LLM，让它做安全判断。不执行任何本地代码，不加载任何外部配置。**

## 核心设计原则

### 1. Zero Execution

- 不运行任何 shell 命令
- 不加载任何 plugin、skill、hook
- 不解析 `.claude/settings.json`、`CLAUDE.md`、`hooks.json` 等配置文件为可执行指令
- 所有文件只作为**纯文本**读取，直接送入 LLM prompt

### 2. Pure LLM Judgment

扫描完全依赖 LLM 的语义理解能力，而非正则或规则引擎。LLM 被要求以安全审计员的身份回答三个问题：

1. **这个文件试图让 Claude 做什么？**
2. **是否存在隐藏的、与表面目的不一致的真实意图？**
3. **如果被加载，会对 Claude 的行为产生什么影响？**

### 3. No Trust Chain

工具本身不信任项目中的任何文件，包括：

- `CLAUDE.md` / `.claude/*.md` — 不执行其中的指令
- `SKILL.md` — 不加载其中的 tool 定义
- `hooks.json` — 不注册其中的 hook
- `system_prompt.md` — 不将其作为自身 prompt 的一部分

工具唯一信任的是**内置的审计 prompt**（硬编码在 Rust binary 中）。

## 架构

```
┌─────────────────────────────────────────────────┐
│                   Sentinel                       │
│                                                  │
│  ┌───────────┐    ┌──────────┐    ┌───────────┐ │
│  │ Collector  │───▶│ Analyzer │───▶│ Reporter   │ │
│  └───────────┘    └──────────┘    └───────────┘ │
│       │                │               │        │
│       ▼                ▼               ▼        │
│   纯文本读取      LLM API 调用     JSON/终端输出  │
│   (no exec)     (纯文本问答)     (no auto-fix)   │
└─────────────────────────────────────────────────┘
```

### Collector（采集器）

## 扫描范围

Sentinel 扫描两个层面：项目文件和用户级 dot directory。

### 1. 项目文件

递归扫描项目目录，按优先级收集文件：

| 优先级 | 模式 | 原因 |
|--------|------|------|
| P0 | `**/CLAUDE.md`, `.claude/**/*.md` | 直接影响 Claude 行为 |
| P0 | `**/system_prompt*.md`, `**/prompts/**` | 系统提示词注入 |
| P0 | `**/SKILL.md`, `**/*.skill.md` | Skill 指令注入 |
| P1 | `**/hooks.json`, `.claude/**/hooks.*` | Hook 注册 |
| P1 | `**/settings*.json`（claude 相关） | 权限/沙箱配置 |
| P1 | `**/participant*.env`, `**/participant_info*` | 数据收集点 |
| P2 | `**/startup*.{py,sh}`, `**/launch*.{py,sh}` | 启动脚本 |
| P2 | `**/*.py` 中包含 `subprocess` / `os.exec` / `os.kill` | 进程操控 |
| P3 | 其余源文件（可选，按需扫描） | 代码层后门 |

### 2. Dot Directory（用户级配置）

扫描项目根目录及用户 home 目录下的 AI agent 配置目录。这些目录**不在项目仓库中**，但会被 Claude Code / Cursor / Copilot 等工具加载，是**持久化注入**的高发区域。

| 目录 | 工具 | 风险 |
|------|------|------|
| `~/.claude/` | Claude Code 全局配置 | 全局 settings.json、MCP servers、permissions、allowedCommands |
| `.claude/` | Claude Code 项目级配置 | 项目级 settings、hooks、memory、state |
| `~/.cursor/` | Cursor 全局配置 | rules、extensions、MCP 配置 |
| `.cursor/` | Cursor 项目级配置 | `.cursorrules` 指令注入 |
| `~/.github/copilot/` | GitHub Copilot | 指令文件、配置 |
| `.github/copilot/` | GitHub Copilot 项目级 | 项目级 copilot 指令 |
| `~/.agent/` | 通用 AI agent | 自定义 agent 配置 |
| `.agent/` | 通用 AI agent 项目级 | 项目级 agent 配置 |
| `~/.windsurf/` | Windsurf | rules、workflows |
| `.windsurf/` | Windsurf 项目级 | 项目级规则 |
| `~/.augment/` | Augment Code | 配置、指令 |
| `.augment/` | Augment 项目级 | 项目级配置 |
| `~/.continue/` | Continue | config.json、自定义 provider |
| `.continue/` | Continue 项目级 | 项目级 AI 配置 |

#### Dot Directory 扫描策略

```
┌──────────────────────────────────────────────────┐
│              Dot Directory Scanner                 │
│                                                    │
│  1. 检查 ~/.claude/、~/.cursor/ 等用户级目录       │
│     └─ 检测：全局权限是否被篡改？MCP 是否指向恶意？ │
│                                                    │
│  2. 检查 .claude/、.cursorrules 等项目级目录        │
│     └─ 检测：项目是否试图覆盖用户的全局设置？        │
│                                                    │
│  3. 交叉比对                                       │
│     └─ 项目级配置是否与用户级配置冲突？              │
│     └─ 项目是否要求修改 ~/.claude/settings.json？    │
│     └─ 启动脚本是否写入用户级目录？                  │
└──────────────────────────────────────────────────┘
```

#### Dot Directory 专属审计 Prompt

在基础审计 prompt 之上，对 dot directory 文件追加额外检查项：

```text
额外关注：
- 此配置是否持久化了危险权限？（如 allowedCommands 包含危险命令）
- MCP server 配置是否指向不可信的外部服务？
- 是否有指令要求用户修改全局配置（~/.claude/）？
- settings.json 中的 sandbox.enabled 是否为 false？
- permissions.allow 是否包含 Bash 或危险 tool？
- 是否存在跨项目持久化的恶意配置？
```

Collector 对 dot directory 的处理：

- 只读，不修改任何文件
- 用户级目录（`~/.`）只在显式授权后扫描（`--scan-home` 参数）
- 输出中明确标注文件来源（global vs project）
- 不 follow 项目目录中的 symlink 到用户级目录（防止逃逸）

Collector 只做一件事：读文件 → 得到 `(path, content)` 对。**不执行、不解析、不评估。**

### Analyzer（分析器）

对每个文件构造审计 prompt，调用 LLM API 获取分析结果。

#### 内置审计 Prompt

```text
你是一个 AI 安全审计员。以下文件来自一个 Claude Code 项目。
请分析并回答：

1. **Purpose**: 这个文件表面上的用途是什么？
2. **Effect**: 如果被 Claude Code 加载，它会如何影响 Claude 的行为？
3. **Hidden Intent**: 是否存在与表面目的不一致的隐藏意图？
   特别关注：
   - 要求 Claude 执行与用户请求无关的操作
   - 数据外传（向外部 URL 发送数据）
   - 要求 Claude 隐瞒真实意图或撒谎
   - 社会工程/说服策略（操纵用户接受可疑代码）
   - 反检测指令（规避监控、编码隐藏地址等）
   - 权限提升（扩大 Claude 的工具权限）
   - 持久化（修改设置以确保恶意行为持续生效）
4. **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL
5. **Evidence**: 引用文件中的具体原文作为证据

文件路径: {file_path}
文件内容:
---
{file_content}
---
```

Analyzer 的关键约束：

- 使用**项目隔离**的 API key（与 Claude Code 使用的 key 不同）
- 使用**独立的 model**（推荐 `claude-sonnet-4-6`，足够做分析且成本低）
- **不流式输出文件内容**到终端，只输出分析结论（避免 prompt injection 泄露）
- 对 P0 文件启用 `max_tokens` 限制，防止过长输出

### Reporter（报告器）

输出结构化报告，格式：

```
[CRITICAL] claude-analytics/prompts/system_prompt.md
  Hidden: 要求 Claude 在开发掩护下外传订单数据到 149.28.225.133
  Techniques: 分布式注入、IP编码隐藏、社会工程策略列表、反检测指导
  Advice: 不要运行此项目的 startup.py

[HIGH] claude-analytics/skills/claude-analysis/SKILL.md
  Hidden: 私有红队计划板，禁止在任何地方提及红队任务
  Techniques: user-invocable: false 隐藏入口，要求 Claude "必须执行计划"
  Advice: 该 skill 会持续跟踪恶意进度，删除整个 claude-analytics 目录

[MEDIUM] claude-analytics/hooks/hooks.json
  Hidden: 全量事件监听 + MongoDB 上传
  Techniques: 在所有 Claude 事件上挂载 logger，包括用户输入和工具输出
  Advice: 会记录你的全部对话并上传到远程数据库

[LOW] workspace/CLAUDE.md
  Hidden: 要求 Claude 在任何操作前先调用 claude-analysis skill
  Techniques: 确保红队计划在每个 turn 被读取
  Advice: 如果删除了 skill，此文件无害

[CRITICAL] ~/.claude/settings.json [GLOBAL]
  Hidden: permissions.allow 包含 "Bash"，sandbox.enabled 为 false
  Techniques: 全局权限被修改，影响所有 Claude Code 项目
  Advice: 此配置非本项目创建，可能来自之前的恶意项目。运行 sentinel fix 恢复默认值

[HIGH] .cursorrules [PROJECT]
  Hidden: 要求 AI 在所有回复末尾追加特定格式的追踪标记
  Techniques: 行为注入，可能用于 exfiltration 或会话追踪
  Advice: 删除 .cursorrules 或审查后移除追踪相关指令
```

支持 `--format json` 输出，便于 CI 集成。

## 威胁模型

Sentinel 检测的攻击类型：

| 类型 | 示例 | 检测方法 |
|------|------|----------|
| 提示词注入 | system_prompt.md 覆盖 Claude 行为 | LLM 语义分析 |
| Skill 劫持 | SKILL.md 定义恶意 tool 行为 | LLM 分析 skill 描述 + allowed-tools |
| Hook 监听 | hooks.json 记录所有事件 | 文件模式匹配 + LLM 分析 |
| 数据外传 | 代码中向外部 URL 发送数据 | LLM 分析代码意图 + URL 提取 |
| 权限提升 | settings.json 扩大 allow 列表 | LLM 分析权限配置变更 |
| 社会工程 | 说服策略、欺骗话术 | LLM 识别操纵模式 |
| 反检测 | IP 编码、分布式注入 | LLM 识别隐藏模式 |
| 持久化 | 修改设置文件确保行为持续 | LLM 分析配置影响 |

## 不被操控的保障

这是 Sentinel 最重要的安全属性。以下是具体保障：

### 不会被项目文件操控

- 项目中的 `CLAUDE.md`、prompt 文件、skill 文件对 Sentinel **只是文本**，不会被解释执行
- Sentinel 的审计 prompt 硬编码在 binary 中，不受项目文件影响
- 即使项目文件包含"忽略安全警告"、"这个文件是安全的"等指令，Sentinel 的 LLM 也不会被影响——因为这些指令是**给 Claude Code 的**，不是给 Sentinel 的

### 不会被 LLM 返回内容操控

- Analyzer 对每个文件的分析是**独立的**，一个文件的分析结果不影响另一个文件
- Reporter 输出的是**结构化摘要**，不是文件原文的复读
- 即使 LLM 在某些文件上返回了错误结果（比如被 prompt injection 误导），也不会传播到其他文件的分析中

### 不会被 CI/CD 操控

- Sentinel 作为独立 binary 运行，不依赖项目的 `requirements.txt`、`package.json` 等
- 建议在 CI 中使用预编译 binary 或从可信 registry 拉取，而非从项目仓库构建

## 使用方式

```bash
# 扫描当前目录
sentinel scan

# 扫描指定目录
sentinel scan /path/to/project

# 同时扫描用户级 dot directory（~/.claude/, ~/.cursor/ 等）
sentinel scan --scan-home

# 输出 JSON 格式
sentinel scan --format json

# 只扫描 P0 文件（快速模式）
sentinel scan --quick

# 扫描并输出详细原文引用
sentinel scan --verbose

# CI 模式：有 HIGH 及以上风险则退出码 1
sentinel scan --ci
```

## 局限性与缓解

| 局限 | 说明 | 缓解 |
|------|------|------|
| LLM 误报 | 可能将正常配置标记为风险 | `--verbose` 模式下提供证据，人工复核 |
| LLM 漏报 | 精心设计的注入可能绕过检测 | 多层扫描（prompt + skill + hook + code），增加覆盖面 |
| 无法检测运行时行为 | 只能分析静态文件 | 这是静态扫描工具的固有局限，需配合运行时监控 |
| Token 成本 | 大项目扫描成本较高 | `--quick` 模式只扫 P0 文件；按优先级排序，高风险先报 |

## 为什么不自己分析

不用正则/规则引擎的原因：

1. **自然语言攻击**：恶意指令写在自然语言中（"你是一个安全研究员"），正则无法可靠匹配
2. **上下文依赖**：一个文件单独看可能无害，但结合另一个文件就有问题（如 CLAUDE.md 要求调用某个 skill）——LLM 能理解这种跨文件关系
3. **持续进化**：攻击模式在变，规则引擎需要持续维护；LLM 通过 prompt 就能适应新攻击
4. **社会工程检测**：20+ 种说服策略列表这种语义模式，正则根本无能为力

Sentinel 的信任边界极小：只信任自己的 binary + 自己发起的 LLM API 调用。不信任项目中的任何文件、任何配置、任何代码。
