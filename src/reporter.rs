use crate::error::SentinelError;
use crate::threat::ScanResult;

pub fn report_text(result: &ScanResult, verbose: bool) {
    if result.findings.is_empty() {
        println!("No findings. All scanned files appear safe.");
        print_summary(result);
        return;
    }

    for finding in &result.findings {
        let source_tag = match &finding.source {
            crate::threat::FileSource::Global => " [GLOBAL]",
            crate::threat::FileSource::Project => "",
        };

        println!("[{}] {}{}", finding.risk_level, finding.file_path, source_tag);
        println!("  Hidden: {}", finding.hidden_intent);

        if !finding.techniques.is_empty() {
            println!("  Techniques: {}", finding.techniques.join(", "));
        }

        println!("  Advice: {}", finding.advice);

        if verbose && !finding.evidence.is_empty() {
            println!("  Evidence:");
            for ev in &finding.evidence {
                println!("    - \"{ev}\"");
            }
        }

        println!();
    }

    print_summary(result);
}

fn print_summary(result: &ScanResult) {
    println!("---");
    println!(
        "Scanned {} files in {:.1}s",
        result.files_scanned,
        result.scan_duration_ms as f64 / 1000.0
    );

    let counts = result.count_by_level();
    for (level, count) in &counts {
        if *count > 0 {
            println!("  {}: {}", level, count);
        }
    }
}

pub fn report_json(result: &ScanResult) -> Result<String, SentinelError> {
    serde_json::to_string_pretty(result).map_err(|e| SentinelError::ParseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{FileSource, Finding, RiskLevel};

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
