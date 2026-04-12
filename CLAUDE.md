# Sentinel — Claude Code 安全扫描器

## 项目概述

Rust 编写的轻量级扫描工具。将 Claude Code 项目中的文件发送给 LLM，检测安全威胁（prompt injection、数据外传、权限提升等）。

**核心原则**：Zero Execution（不执行任何代码）、Pure LLM Judgment（仅靠 LLM 判断）、No Trust Chain（不信任项目中任何文件）。

详见 `sentinel-product.md`。

## 技术栈

- **语言**: Rust
- **构建**: `cargo`
- **LLM API**: `anthropic` crate（直接调用 Claude API）
- **目标平台**: macOS / Linux CLI

## 开发规则

- `cargo build` / `cargo test` 必须通过
- 错误用 `thiserror` 定义，`anyhow` 仅限 main/binary 层
- LLM API 调用放在独立模块中
- Sentinel 自身不执行/解释项目中的配置文件（`.claude/`、`CLAUDE.md` 等）——零信任
- 提交前必须通过 `cargo clippy -- -D warnings`

## 命令

```bash
cargo build              # 构建
cargo test               # 测试
cargo run -- scan        # 扫描当前目录
cargo run -- scan --ci   # CI 模式（HIGH 及以上风险 exit 1）
cargo clippy -- -D warnings  # 代码检查
```
