use crate::types::HostInfo;
use chrono::Utc;
use std::fs;

pub fn collect() -> HostInfo {
    HostInfo {
        hostname: read_hostname(),
        os: read_os(),
        kernel: read_kernel(),
        uptime_seconds: read_uptime(),
        collected_at: Utc::now(),
    }
}

fn read_hostname() -> String {
    for path in &["/etc/hostname", "/proc/sys/kernel/hostname"] {
        let v = fs::read_to_string(path).unwrap_or_default();
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    "unknown".to_string()
}

fn read_os() -> String {
    if let Ok(contents) = fs::read_to_string("/etc/os-release") {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    "unknown".to_string()
}

fn read_kernel() -> String {
    fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map(|f| f as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_non_empty_hostname() {
        let info = collect();
        assert!(!info.hostname.is_empty());
    }

    #[test]
    fn collect_returns_uptime_greater_than_zero() {
        let info = collect();
        assert!(info.uptime_seconds > 0);
    }
}
