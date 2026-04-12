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

/// Authentication method for the API
#[derive(Debug, Clone)]
pub enum AuthType {
    /// Anthropic native: `x-api-key` header + `anthropic-version`
    XApiKey,
    /// OpenAI style: `Authorization: Bearer <key>`
    Bearer,
}

impl ScanConfig {
    /// Returns (api_key, auth_type) together
    pub fn api_key() -> Result<(String, AuthType), SentinelError> {
        if let Ok(key) = std::env::var("ANTHROPIC_AUTH_TOKEN") {
            return Ok((key, AuthType::Bearer));
        }
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            return Ok((key, AuthType::XApiKey));
        }
        Err(SentinelError::MissingApiKey)
    }

    pub fn base_url() -> String {
        std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string())
    }

    pub fn model() -> String {
        std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| "claude-sonnet-4-6".to_string())
    }

    pub fn concurrency() -> usize {
        std::env::var("SENTINEL_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8)
    }
}
