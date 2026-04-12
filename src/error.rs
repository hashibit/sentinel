use thiserror::Error;

#[derive(Error, Debug)]
pub enum SentinelError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("LLM API error: {0}")]
    LlmApi(String),

    #[error("Failed to parse LLM response: {0}")]
    ParseError(String),

    #[error("No API key found. Set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN environment variable.")]
    MissingApiKey,

    #[error("Glob pattern error: {0}")]
    Glob(#[from] glob::GlobError),

    #[error("Pattern error: {0}")]
    Pattern(#[from] glob::PatternError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}
