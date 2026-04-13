use crate::error::SentinelError;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Directory to scan
    pub target_dir: PathBuf,
    /// Also scan user-level dot directories (~/.claude/, ~/.cursor/, etc.)
    pub scan_home: bool,
    /// Output as JSON
    pub format_json: bool,
    /// Quick mode: only P0 files
    pub quick: bool,
    /// Verbose output with evidence quotes
    pub verbose: bool,
    /// CI mode: exit code 1 if HIGH+ risk found
    pub ci_mode: bool,
    /// Maximum tokens for LLM responses
    pub max_tokens: u32,
    /// Max concurrent LLM API requests (default 8)
    pub concurrency: usize,
}

/// LLM provider / API format
#[derive(Debug, Clone)]
pub enum LlmProvider {
    /// Anthropic Messages API with `x-api-key` header
    AnthropicNative { api_key: String },
    /// Anthropic Messages API with `Authorization: Bearer` header (for proxies)
    AnthropicBearer { api_key: String },
    /// OpenAI-compatible Chat Completions API
    OpenAi { api_key: String },
}

impl ScanConfig {
    /// Detect the LLM provider from environment variables.
    ///
    /// Priority: OPENAI_API_KEY > ANTHROPIC_AUTH_TOKEN > ANTHROPIC_API_KEY
    pub fn provider() -> Result<LlmProvider, SentinelError> {
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            return Ok(LlmProvider::OpenAi { api_key: key });
        }
        if let Ok(key) = std::env::var("ANTHROPIC_AUTH_TOKEN") {
            return Ok(LlmProvider::AnthropicBearer { api_key: key });
        }
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            return Ok(LlmProvider::AnthropicNative { api_key: key });
        }
        Err(SentinelError::MissingApiKey)
    }

    pub fn base_url(provider: &LlmProvider) -> String {
        match provider {
            LlmProvider::OpenAi { .. } => std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
            _ => std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".to_string()),
        }
    }

    pub fn model(provider: &LlmProvider) -> String {
        match provider {
            LlmProvider::OpenAi { .. } => {
                std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string())
            }
            _ => {
                std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-sonnet-4-6".to_string())
            }
        }
    }

    pub fn concurrency() -> usize {
        std::env::var("SENTINEL_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8)
    }
}
