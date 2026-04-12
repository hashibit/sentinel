use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "CRITICAL")]
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    pub fn numeric(&self) -> u8 {
        match self {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        }
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.numeric().cmp(&other.numeric())
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileSource {
    #[serde(rename = "project")]
    Project,
    #[serde(rename = "global")]
    Global,
}

impl std::fmt::Display for FileSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileSource::Project => write!(f, "PROJECT"),
            FileSource::Global => write!(f, "GLOBAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file_path: String,
    pub source: FileSource,
    pub risk_level: RiskLevel,
    pub purpose: String,
    pub effect: String,
    pub hidden_intent: String,
    pub techniques: Vec<String>,
    pub advice: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub scan_duration_ms: u64,
}

impl ScanResult {
    pub fn max_risk_level(&self) -> RiskLevel {
        self.findings
            .iter()
            .map(|f| f.risk_level)
            .max()
            .unwrap_or(RiskLevel::Low)
    }

    pub fn count_by_level(&self) -> Vec<(RiskLevel, usize)> {
        let mut counts = vec![
            (RiskLevel::Critical, 0),
            (RiskLevel::High, 0),
            (RiskLevel::Medium, 0),
            (RiskLevel::Low, 0),
        ];
        for f in &self.findings {
            for (level, count) in &mut counts {
                if f.risk_level == *level {
                    *count += 1;
                    break;
                }
            }
        }
        counts
    }
}

/// LLM response structure — we ask the model to return JSON in this shape
#[derive(Debug, Deserialize)]
pub struct LlmAnalysis {
    pub purpose: String,
    pub effect: String,
    pub hidden_intent: String,
    pub risk_level: String,
    pub techniques: Vec<String>,
    pub advice: String,
    pub evidence: Vec<String>,
}
