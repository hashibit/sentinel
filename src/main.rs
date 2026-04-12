mod analyzer;
mod collector;
mod config;
mod error;
mod reporter;
mod threat;

use clap::{Parser, Subcommand};
use config::ScanConfig;
use std::path::PathBuf;
use threat::RiskLevel;

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(about = "Claude Code project security scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project directory for security threats
    Scan {
        /// Directory to scan (default: current directory)
        path: Option<PathBuf>,

        /// Also scan user-level dot directories (~/.claude/, ~/.cursor/, etc.)
        #[arg(long)]
        scan_home: bool,

        /// Output in JSON format
        #[arg(long)]
        format: Option<String>,

        /// Quick mode: only scan P0 files (CLAUDE.md, SKILL.md, prompts)
        #[arg(short, long)]
        quick: bool,

        /// Verbose output with evidence quotes
        #[arg(short, long)]
        verbose: bool,

        /// CI mode: exit code 1 if HIGH or higher risk found
        #[arg(long)]
        ci: bool,

        /// Maximum tokens for LLM responses
        #[arg(long, default_value_t = 2048)]
        max_tokens: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            scan_home,
            format,
            quick,
            verbose,
            ci,
            max_tokens,
        } => {
            let config = ScanConfig {
                target_dir: path.unwrap_or_else(|| PathBuf::from(".")),
                scan_home,
                format_json: format.as_deref() == Some("json"),
                quick,
                verbose,
                ci_mode: ci,
                max_tokens,
            };

            // Verify API key early
            if ScanConfig::api_key().is_err() {
                eprintln!("Error: ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN environment variable is not set.");
                std::process::exit(1);
            }

            let result = scanner::run_scan(&config).await?;

            if config.ci_mode && result.max_risk_level() >= RiskLevel::High {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

mod scanner {
    use crate::collector::CollectedFile;
    use crate::config::ScanConfig;
    use crate::error::SentinelError;
    use crate::threat::ScanResult;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    pub async fn run_scan(config: &ScanConfig) -> Result<ScanResult, SentinelError> {
        let start = Instant::now();

        // Create HTTP client once for reuse
        // Note: some API gateways (e.g. Alibaba Cloud WAF) block the default reqwest UA
        let http_client = reqwest::Client::builder()
            .user_agent("sentinel/0.1.0")
            .build()
            .map_err(|e| SentinelError::LlmApi(format!("Failed to build HTTP client: {e}")))?;

        // Phase 1: Collect
        let project_files = crate::collector::collect_project(&config.target_dir, config.quick)?;
        let dot_files = crate::collector::collect_dot_dirs(config.scan_home)?;

        let all_files: Vec<CollectedFile> = project_files
            .into_iter()
            .chain(dot_files.into_iter())
            .collect();

        let total = all_files.len();
        if total == 0 {
            eprintln!("No files found to scan.");
            return Ok(ScanResult {
                findings: vec![],
                files_scanned: 0,
                scan_duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Show progress only in text mode
        let show_progress = !config.format_json;
        let done = Arc::new(AtomicUsize::new(0));

        eprintln!("\n  Analyzing {total} file(s)...\n");

        // Phase 2: Analyze in parallel with progress
        let mut handles = Vec::new();
        for file in all_files {
            let config = config.clone();
            let client = http_client.clone();
            let progress = Arc::clone(&done);
            let handle = tokio::spawn(async move {
                let path_display = file.path.display().to_string();
                let result = crate::analyzer::analyze_file(&client, &file, &config).await;
                let current = progress.fetch_add(1, Ordering::Relaxed) + 1;
                if show_progress {
                    match &result {
                        Ok(finding) => {
                            eprint!(
                                "\r  [{:>3}/{total}] {:10} {}",
                                current,
                                finding.risk_level.as_str(),
                                truncate_path(&path_display, 50)
                            );
                        }
                        Err(e) => {
                            eprint!(
                                "\r  [{:>3}/{total}] {:<10} {}",
                                current,
                                "ERROR",
                                truncate_path(&path_display, 50)
                            );
                            // Print full error on a new line so it isn't overwritten
                            eprintln!("\n    → {e}");
                        }
                    }
                }
                result.ok()
            });
            handles.push(handle);
        }

        let mut findings = Vec::new();
        for handle in handles {
            if let Ok(Some(finding)) = handle.await {
                findings.push(finding);
            }
        }

        if show_progress {
            eprintln!(); // newline after last progress line
        }

        // Sort by risk level (highest first)
        findings.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

        let duration = start.elapsed().as_millis() as u64;

        let result = ScanResult {
            findings,
            files_scanned: total,
            scan_duration_ms: duration,
        };

        // Phase 3: Report
        if config.format_json {
            println!("{}", crate::reporter::report_json(&result).unwrap_or_default());
        } else {
            crate::reporter::report_text(&result, config.verbose);
        }

        Ok(result)
    }

    fn truncate_path(path: &str, max: usize) -> String {
        if path.len() <= max {
            path.to_string()
        } else {
            format!("...{}", &path[path.len() - max + 3..])
        }
    }
}
