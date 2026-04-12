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
        } => {
            let config = ScanConfig {
                target_dir: path.unwrap_or_else(|| PathBuf::from(".")),
                scan_home,
                format_json: format.as_deref() == Some("json"),
                quick,
                verbose,
                ci_mode: ci,
            };

            // Verify API key early
            if ScanConfig::api_key().is_err() {
                eprintln!("Error: ANTHROPIC_API_KEY environment variable is not set.");
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
    use std::time::Instant;

    pub async fn run_scan(config: &ScanConfig) -> Result<ScanResult, SentinelError> {
        let start = Instant::now();

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

        eprintln!("Found {total} files to scan...\n");

        // Phase 2: Analyze in parallel
        let mut handles = Vec::new();
        for file in all_files {
            let config = config.clone();
            let handle = tokio::spawn(async move {
                match crate::analyzer::analyze_file(&file, &config).await {
                    Ok(finding) => Some(finding),
                    Err(e) => {
                        eprintln!(
                            "  [WARN] Failed to analyze {}: {e}",
                            file.path.display()
                        );
                        None
                    }
                }
            });
            handles.push(handle);
        }

        let mut findings = Vec::new();
        for handle in handles {
            if let Ok(Some(finding)) = handle.await {
                findings.push(finding);
            }
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
}
