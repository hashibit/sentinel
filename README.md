# CCCheck

A lightweight security scanner for Claude Code (and similar AI coding agent) projects. Sends your project's configuration files to an LLM and asks it to detect security threats — prompt injection, data exfiltration, privilege escalation, and more.

## Why

AI coding agents read project-local config files (`CLAUDE.md`, `.claude/`, hooks, skills, etc.) and follow their instructions. A malicious project can embed hidden instructions that trick the agent into:

- **Data exfiltration** — silently sending your code or env vars to an external server
- **Prompt injection** — overriding safety guidelines or concealing true intent
- **Privilege escalation** — expanding tool permissions or disabling sandboxes
- **Persistence** — modifying global config so the behavior carries across projects

You can't read every config file carefully. CCCheck can.

## Core Principles

- **Zero Execution** — CCCheck never executes any code from the scanned project. It only reads text files and sends them to the LLM.
- **Pure LLM Judgment** — Security analysis is done entirely by the LLM. CCCheck itself contains no heuristic rules about what's "safe" or "dangerous".
- **No Trust Chain** — CCCheck does not trust, execute, or interpret any file in the scanned project. All audit prompts are hardcoded in CCCheck's own source.

## Architecture

CCCheck runs three phases:

```
Collect -> Analyze -> Report
```

### 1. Collect

Gathers files that AI agents are most likely to read and obey:

| Priority | Files |
|----------|-------|
| P0 | `CLAUDE.md`, `.claude/**/*.md`, `SKILL.md`, prompts |
| P1 | `hooks.json`, `settings*.json`, participant info |
| P2 | startup/launch scripts |

Also scans global dot directories (`~/.claude/`, `~/.cursor/`, etc.) with `--scan-home`. Binary files and files >100KB are skipped.

### 2. Analyze

Each collected file is sent to the LLM in parallel with a hardcoded audit prompt that asks:

1. **Purpose** — What does this file do?
2. **Effect** — How would it change agent behavior?
3. **Hidden Intent** — Is there anything inconsistent with the apparent purpose?
4. **Risk Level** — `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
5. **Evidence** — Direct quotes from the file

Global config files (`--scan-home`) get additional checks for dangerous permissions, MCP server endpoints, and cross-project persistence.

### 3. Report

Findings are sorted by risk (highest first) and displayed with:
- Risk level, file path, and source tag (`[GLOBAL]` for user-level configs)
- Detected techniques and hidden intent
- Actionable advice
- Evidence quotes (`--verbose`)

Or output as JSON with `--format json`.

## Installation

```bash
git clone https://github.com/nickelchen/cccheck
cd cccheck
cargo build --release
```

The binary will be at `target/release/cccheck`.

## Usage

```bash
# Basic scan of current directory
cargo run -- scan

# Or use the compiled binary
cccheck scan

# Scan a specific directory
cargo run -- scan /path/to/project

# Quick mode — only P0 files
cargo run -- scan --quick

# Include global dot directories
cargo run -- scan --scan-home

# Verbose output with evidence quotes
cargo run -- scan --verbose

# CI mode — exit code 1 if HIGH+ risk found
cargo run -- scan --ci

# JSON output
cargo run -- scan --format json

# Custom max tokens for LLM responses
cargo run -- scan --max-tokens 4096

# Combine flags
cargo run -- scan --quick --scan-home --ci
```

## Configuration

CCCheck supports two authentication methods, selected by the environment variable name:

```bash
# Method 1: Anthropic native auth (x-api-key header)
export ANTHROPIC_API_KEY=sk-xxxxx

# Method 2: Bearer token auth (Authorization: Bearer header) — for API proxies
export ANTHROPIC_AUTH_TOKEN=sk-sp-0xxx
```

You can also customize the base URL and model:

```bash
# Optional — custom API base URL (for proxies)
export ANTHROPIC_BASE_URL=https://your-proxy.example.com

# Optional — custom model
export ANTHROPIC_MODEL=claude-sonnet-4-6
```

### Example: DashScope (百炼) proxy

```bash
export ANTHROPIC_BASE_URL=https://coding.dashscope.aliyuncs.com/apps/anthropic
export ANTHROPIC_MODEL=kimi-k2.5
export ANTHROPIC_AUTH_TOKEN=sk-sp-0xxx
```

### Example: Official Anthropic API

```bash
export ANTHROPIC_API_KEY=sk-ant-xxxxx
```

## CI Integration

Add to your CI pipeline to block builds with security findings:

```yaml
- name: Security scan
  run: cargo run -- scan --ci
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Exit code 1 when any finding is `HIGH` or `CRITICAL`.

## Threat Categories

CCCheck's audit prompt checks for:

- **Prompt injection** — Instructions that override or bypass safety guidelines
- **Data exfiltration** — Sending code, credentials, or environment variables to external URLs
- **Social engineering** — Persuasive language designed to make the user accept suspicious changes
- **Anti-detection** — Encoding, obfuscation, or instructions to evade detection
- **Privilege escalation** — Expanding tool permissions, disabling sandboxes
- **Persistence** — Modifying global settings to ensure behavior continues across sessions

## License

MIT
