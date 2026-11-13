use crate::types::LogSlice;
use std::fs;

const TAIL_LINES: usize = 500;

pub fn collect() -> Vec<LogSlice> {
    let sources = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
    ];

    sources
        .iter()
        .filter_map(|path| {
            let content = fs::read_to_string(path).ok()?;
            let lines: Vec<String> = content
                .lines()
                .rev()
                .take(TAIL_LINES)
                .map(str::to_string)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();

            if lines.is_empty() {
                return None;
            }

            Some(LogSlice {
                source: path.to_string(),
                lines,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_vec() {
        let slices = collect();
        for slice in &slices {
            assert!(!slice.source.is_empty());
            assert!(!slice.lines.is_empty());
        }
    }
}
