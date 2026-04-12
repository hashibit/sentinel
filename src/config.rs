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
}

impl ScanConfig {
    pub fn api_key() -> Result<String, SentinelError> {
        std::env::var("ANTHROPIC_API_KEY").map_err(|_| SentinelError::MissingApiKey)
    }

    pub fn model() -> &'static str {
        "claude-sonnet-4-6"
    }

    pub fn max_tokens() -> u32 {
        1024
    }
}
