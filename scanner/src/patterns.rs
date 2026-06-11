// Rust pattern definitions for the AANF scanner.
// Each Rule has a regex pattern and a severity score (0-1).
// These are compiled once at startup for maximum throughput.

use regex::Regex;

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,          // Unique rule identifier (e.g., "jailbreak-dan")
    pub pattern: Regex,      // Compiled regex pattern
    pub severity: f64,       // Severity 0.0-1.0 (used for risk scoring)
}

impl Rule {
    // Constructor that compiles the regex at creation time.
    pub fn new(id: &str, pattern: &str, severity: f64) -> Self {
        Self {
            id: id.to_string(),
            pattern: Regex::new(pattern).expect("invalid regex"),
            severity,
        }
    }
}

// Default set of rules covering common LLM attack patterns.
pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule::new("jailbreak-dan", r"(?i)(dan|developer.?mode|ignore.*instructions)", 0.9),
        Rule::new("sql-injection", r"(?i)(\bSELECT\b.*\bFROM\b|\bDROP\b|\bUNION\b.*\bSELECT\b)", 0.8),
        Rule::new("xss-script", r"(?i)<script[^>]*>", 0.85),
        Rule::new("escape-seq", r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", 0.7),
        Rule::new("pii-email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", 0.5),
        Rule::new("pii-phone", r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", 0.5),
    ]
}
