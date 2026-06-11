// Rust standalone binary — reads text from stdin, scans it,
// and outputs JSON results to stdout.
// Usage: cat prompt.txt | cargo run --release

mod patterns;
mod scanner;

use std::io::{self, Read};

fn main() {
    // Load default rule set (compiled regexes)
    let rules = patterns::default_rules();

    // Read all of stdin into a string
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("read stdin");

    // Scan and output JSON
    let result = scanner::scan_text(&input, &rules);
    let json = serde_json::to_string_pretty(&result).expect("serialize");
    println!("{json}");
}
