use crate::error::SentinelError;
use crate::threat::{RiskLevel, ScanResult};

// ── ANSI color codes ──────────────────────────────────────────────

const R: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";

fn color_for_level(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical | RiskLevel::High => RED,
        RiskLevel::Medium => YELLOW,
        RiskLevel::Low => GREEN,
    }
}

fn risk_badge(level: &RiskLevel) -> String {
    let c = color_for_level(level);
    let label = level.as_str();
    format!("{c}{BOLD}[{label:^8}]{R}")
}

// ── Text report ───────────────────────────────────────────────────

pub fn report_text(result: &ScanResult, verbose: bool) {
    print_header(result);

    if result.findings.is_empty() {
        println!();
        println!("  {GREEN}{BOLD}All Clear{R}  {DIM}— all scanned files appear safe.{R}");
        println!();
    } else {
        println!();
        for (i, finding) in result.findings.iter().enumerate() {
            if i > 0 {
                println!("  {DIM}{:─<72}{R}", "");
            }
            print_finding(finding, verbose);
            println!();
        }
    }

    print_summary(result);
}

fn print_header(result: &ScanResult) {
    let w = 72;
    println!("{}", "═".repeat(w));
    println!("  {CYAN}{BOLD}Sentinel Security Scan Report{R}");
    println!(
        "  {DIM}{} files scanned  ·  {:.1}s elapsed{R}",
        result.files_scanned,
        result.scan_duration_ms as f64 / 1000.0
    );
    println!("{}", "═".repeat(w));
}

fn print_finding(finding: &crate::threat::Finding, verbose: bool) {
    let badge = risk_badge(&finding.risk_level);
    let source_tag = match &finding.source {
        crate::threat::FileSource::Global => format!("  {MAGENTA}[GLOBAL]{R}"),
        crate::threat::FileSource::Project => String::new(),
    };

    println!(
        "  {badge} {BOLD}{}{R}{source}",
        finding.file_path,
        source = source_tag
    );

    println!("  {DIM}Purpose:{R}    {}", finding.purpose);
    println!("  {DIM}Effect:{R}     {}", finding.effect);
    println!("  {DIM}Hidden:{R}     {}", finding.hidden_intent);

    if !finding.techniques.is_empty() {
        let techs = finding
            .techniques
            .iter()
            .map(|t| format!("{CYAN}{t}{R}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {DIM}Techniques:{R} {techs}");
    }

    println!("  {DIM}Advice:{R}     {}", finding.advice);

    if verbose && !finding.evidence.is_empty() {
        println!("  {DIM}Evidence:{R}");
        for ev in &finding.evidence {
            println!("    {YELLOW}•{R} {DIM}\"{}\"{R}", ev);
        }
    }
}

// ── Summary ───────────────────────────────────────────────────────

fn print_summary(result: &ScanResult) {
    let w = 72;
    println!("{}", "─".repeat(w));

    let counts = result.count_by_level();
    let total_findings: usize = counts.iter().map(|(_, c)| c).sum();

    if total_findings > 0 {
        println!("  {BOLD}Risk Distribution:{R}");
        for (level, count) in &counts {
            if *count > 0 {
                let c = color_for_level(level);
                let bar: String = "█".repeat(*count);
                println!("    {c}{level:>8}{R}  {bar} {count}");
            }
        }
        println!();
    }

    let max = result.max_risk_level();
    match max {
        RiskLevel::Critical => {
            println!("  {RED}{BOLD}Verdict: CRITICAL — immediate action required{R}");
        }
        RiskLevel::High => {
            println!("  {RED}{BOLD}Verdict: HIGH — review before proceeding{R}");
        }
        RiskLevel::Medium => {
            println!("  {YELLOW}{BOLD}Verdict: MEDIUM — findings should be reviewed{R}");
        }
        RiskLevel::Low => {
            println!("  {GREEN}{BOLD}Verdict: LOW — no significant threats detected{R}");
        }
    }

    println!("{}", "─".repeat(w));
}

// ── JSON report ───────────────────────────────────────────────────

pub fn report_json(result: &ScanResult) -> Result<String, SentinelError> {
    serde_json::to_string_pretty(result).map_err(|e| SentinelError::ParseError(e.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{FileSource, Finding};

    fn make_finding(risk: RiskLevel) -> Finding {
        Finding {
            file_path: "test.md".to_string(),
            source: FileSource::Project,
            risk_level: risk,
            purpose: "Test".to_string(),
            effect: "None".to_string(),
            hidden_intent: "None detected".to_string(),
            techniques: vec![],
            advice: "OK".to_string(),
            evidence: vec![],
        }
    }

    #[test]
    fn test_report_json_roundtrip() {
        let result = ScanResult {
            findings: vec![make_finding(RiskLevel::Low)],
            files_scanned: 1,
            scan_duration_ms: 100,
        };
        let json = report_json(&result).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.findings.len(), 1);
    }
}
