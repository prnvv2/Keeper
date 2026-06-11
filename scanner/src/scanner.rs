// Rust scanner engine — applies a list of regex rules to input text
// and returns all matches sorted by severity (highest first).
// Used by Python via PyO3 or as a standalone subprocess.

use crate::patterns::Rule;

// A single match found by a rule
#[derive(Debug, serde::Serialize)]
pub struct Match {
    pub rule_id: String,   // Which rule triggered
    pub start: usize,      // Byte offset of match start
    pub end: usize,        // Byte offset of match end
    pub matched: String,   // The matched text substring
    pub severity: f64,     // Severity of the matched rule
}

// Complete scan result for one input text
#[derive(Debug, serde::Serialize)]
pub struct ScanResult {
    pub matches: Vec<Match>,   // All matches, sorted by severity desc
    pub max_severity: f64,     // Highest severity found
    pub total_matches: usize,  // Total number of matches
}

// Scan input text against all provided rules.
// Returns matches sorted by severity (highest first).
pub fn scan_text(text: &str, rules: &[Rule]) -> ScanResult {
    let mut matches = Vec::new();

    for rule in rules {
        for m in rule.pattern.find_iter(text) {
            matches.push(Match {
                rule_id: rule.id.clone(),
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
                severity: rule.severity,
            });
        }
    }

    // Sort by severity descending (most dangerous matches first)
    matches.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

    let max_severity = matches.first().map(|m| m.severity).unwrap_or(0.0);
    let total_matches = matches.len();

    ScanResult {
        matches,
        max_severity,
        total_matches,
    }
}
