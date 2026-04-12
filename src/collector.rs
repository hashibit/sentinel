use crate::error::SentinelError;
use crate::threat::FileSource;
use std::path::{Path, PathBuf};

/// Maximum file size to read (100KB)
const MAX_FILE_SIZE: u64 = 100 * 1024;

/// A collected file with its content
pub struct CollectedFile {
    pub path: PathBuf,
    pub content: String,
    pub source: FileSource,
}

/// Dot directories to scan when --scan-home is set
const HOME_DOT_DIRS: &[(&str, &str)] = &[
    (".claude", "Claude Code global config"),
    (".cursor", "Cursor global config"),
    (".github/copilot", "GitHub Copilot global config"),
    (".agent", "Generic AI agent config"),
    (".windsurf", "Windsurf global config"),
    (".augment", "Augment Code global config"),
    (".continue", "Continue global config"),
];

/// Project-level dot directories (always scanned)
const PROJECT_PATTERNS: &[(&str, &[&str])] = &[
    ("P0", &["**/CLAUDE.md"]),
    ("P0", &[".claude/**/*.md"]),
    ("P0", &["**/system_prompt*.md", "**/prompts/**/*.md"]),
    ("P0", &["**/SKILL.md", "**/*.skill.md"]),
    ("P1", &["**/hooks.json", ".claude/**/hooks.*"]),
    ("P1", &["**/settings*.json"]),
    ("P1", &["**/participant*.env", "**/participant_info*"]),
    ("P2", &["**/startup*.{py,sh}", "**/launch*.{py,sh}"]),
];

/// Dot directory project-level patterns
const PROJECT_DOT_DIR_PATTERNS: &[&str] = &[
    ".claude",
    ".cursor",
    ".cursorrules",
    ".github/copilot",
    ".agent",
    ".windsurf",
    ".augment",
    ".continue",
];

fn should_scan_file(path: &Path) -> bool {
    if let Ok(metadata) = path.metadata() {
        if !metadata.is_file() {
            return false;
        }
        if metadata.len() > MAX_FILE_SIZE {
            return false;
        }
    } else {
        return false;
    }

    // Skip binary files by checking extension
    let is_binary_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            matches!(
                e.to_lowercase().as_str(),
                "png" | "jpg"
                    | "jpeg"
                    | "gif"
                    | "ico"
                    | "svg"
                    | "woff"
                    | "woff2"
                    | "ttf"
                    | "otf"
                    | "eot"
                    | "wasm"
                    | "zip"
                    | "tar"
                    | "gz"
                    | "exe"
                    | "dll"
                    | "so"
                    | "dylib"
                    | "pdf"
                    | "doc"
                    | "docx"
            )
        })
        .unwrap_or(false);

    if is_binary_ext {
        return false;
    }

    true
}

fn read_file_safe(path: &Path) -> Result<String, SentinelError> {
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

/// Collect project files from a directory
pub fn collect_project(dir: &Path, quick_mode: bool) -> Result<Vec<CollectedFile>, SentinelError> {
    let mut files = Vec::new();
    let patterns_to_scan = if quick_mode {
        // Only P0 patterns
        vec![
            "**/CLAUDE.md",
            ".claude/**/*.md",
            "**/system_prompt*.md",
            "**/prompts/**/*.md",
            "**/SKILL.md",
            "**/*.skill.md",
        ]
    } else {
        PROJECT_PATTERNS
            .iter()
            .flat_map(|(_, pats)| pats.iter().copied())
            .collect()
    };

    for pattern in &patterns_to_scan {
        let full_pattern = dir.join(pattern).to_string_lossy().to_string();
        let glob_results = glob::glob(&full_pattern)?;

        for entry in glob_results {
            let path = entry?;
            if should_scan_file(&path) {
                if let Ok(content) = read_file_safe(&path) {
                    files.push(CollectedFile {
                        path,
                        content,
                        source: FileSource::Project,
                    });
                }
            }
        }
    }

    // Also scan project-level dot directories
    for dot_dir in PROJECT_DOT_DIR_PATTERNS {
        let dot_path = dir.join(dot_dir);
        if dot_path.exists() {
            collect_dot_dir_recursive(&dot_path, &mut files, FileSource::Project)?;
        }
    }

    // Deduplicate by path
    files.sort_by_key(|f| f.path.clone());
    files.dedup_by_key(|f| f.path.clone());

    Ok(files)
}

/// Collect dot directories from home
pub fn collect_dot_dirs(
    scan_home: bool,
) -> Result<Vec<CollectedFile>, SentinelError> {
    if !scan_home {
        return Ok(Vec::new());
    }

    let home = dirs_home()?;
    let mut files = Vec::new();

    for (dir_name, _description) in HOME_DOT_DIRS {
        let dir_path = home.join(dir_name.trim_start_matches('.'));
        if dir_path.exists() {
            collect_dot_dir_recursive(&dir_path, &mut files, FileSource::Global)?;
        }
    }

    Ok(files)
}

/// Recursively collect files from a dot directory
fn collect_dot_dir_recursive(
    dir: &Path,
    files: &mut Vec<CollectedFile>,
    source: FileSource,
) -> Result<(), SentinelError> {
    if !dir.is_dir() {
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();

        // Don't follow symlinks to directories outside the scanned tree
        if path.is_symlink() {
            continue;
        }

        if path.is_file() && should_scan_file(&path) {
            if let Ok(content) = read_file_safe(&path) {
                files.push(CollectedFile {
                    path,
                    content,
                    source: source.clone(),
                });
            }
        } else if path.is_dir() {
            collect_dot_dir_recursive(&path, files, source.clone())?;
        }
    }

    Ok(())
}

fn dirs_home() -> Result<PathBuf, SentinelError> {
    dirs::home_dir().ok_or_else(|| SentinelError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Could not determine home directory",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_project() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create a CLAUDE.md
        fs::write(dir.path().join("CLAUDE.md"), "# Test Project").unwrap();

        // Create .claude/settings.json
        let claude_dir = dir.path().join(".claude");
        fs::create_dir(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("settings.json"),
            r#"{"sandbox": true}"#,
        )
        .unwrap();

        dir
    }

    #[test]
    fn test_collect_project_basic() {
        let dir = setup_test_project();
        let files = collect_project(dir.path(), true).unwrap();

        // Should find CLAUDE.md and .claude/settings.json
        assert!(files.iter().any(|f| f
            .path
            .file_name()
            .map(|n| n == "CLAUDE.md")
            .unwrap_or(false)));
        assert!(files.iter().any(|f| f
            .path
            .file_name()
            .map(|n| n == "settings.json")
            .unwrap_or(false)));
    }

    #[test]
    fn test_should_skip_large_file() {
        let dir = TempDir::new().unwrap();
        let big_file = dir.path().join("big.md");
        let content = "x".repeat((MAX_FILE_SIZE + 1) as usize);
        fs::write(&big_file, &content).unwrap();

        assert!(!should_scan_file(&big_file));
    }
}
