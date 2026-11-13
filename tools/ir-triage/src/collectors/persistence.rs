use crate::types::{CronEntry, PersistenceSnapshot, ServiceEntry};
use std::fs;
use std::path::Path;

pub fn collect() -> PersistenceSnapshot {
    PersistenceSnapshot {
        systemd_services: collect_services(),
        cron_entries: collect_cron(),
    }
}

fn collect_services() -> Vec<ServiceEntry> {
    let mut entries = Vec::new();
    let dirs = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ];

    let mut seen = std::collections::HashSet::new();

    for dir in &dirs {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".service") {
                continue;
            }
            if !seen.insert(name.clone()) {
                continue;
            }
            let description = read_unit_description(&entry.path());
            entries.push(ServiceEntry {
                name,
                state: "unknown".to_string(),
                enabled: "unknown".to_string(),
                description,
            });
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn read_unit_description(path: &Path) -> String {
    let content = fs::read_to_string(path).unwrap_or_default();
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("Description=") {
            return val.trim().to_string();
        }
    }
    String::new()
}

fn collect_cron() -> Vec<CronEntry> {
    let mut entries = Vec::new();

    let system_crontab = "/etc/crontab";
    if let Ok(content) = fs::read_to_string(system_crontab) {
        for line in content.lines() {
            if let Some(entry) = parse_system_cron_line(line, system_crontab) {
                entries.push(entry);
            }
        }
    }

    let cron_dirs = ["/etc/cron.d", "/var/spool/cron/crontabs"];
    for dir in &cron_dirs {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for file in rd.flatten() {
            let path = file.path();
            let user = file.file_name().to_string_lossy().to_string();
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            for line in content.lines() {
                if let Some(entry) = parse_user_cron_line(line, &user, &path.to_string_lossy()) {
                    entries.push(entry);
                }
            }
        }
    }

    entries
}

fn parse_system_cron_line(line: &str, source: &str) -> Option<CronEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(7, ' ').collect();
    if parts.len() < 7 {
        return None;
    }
    let schedule = parts[..5].join(" ");
    let user = parts[5].to_string();
    let command = parts[6].to_string();

    Some(CronEntry {
        user,
        schedule,
        command,
        source: source.to_string(),
    })
}

fn parse_user_cron_line(line: &str, user: &str, source: &str) -> Option<CronEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() < 6 {
        return None;
    }
    let schedule = parts[..5].join(" ");
    let command = parts[5].to_string();

    Some(CronEntry {
        user: user.to_string(),
        schedule,
        command,
        source: source.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_system_cron_valid_line() {
        let line = "17 * * * * root cd / && run-parts --report /etc/cron.hourly";
        let entry = parse_system_cron_line(line, "/etc/crontab").unwrap();
        assert_eq!(entry.user, "root");
        assert_eq!(entry.schedule, "17 * * * *");
        assert!(entry.command.contains("cron.hourly"));
    }

    #[test]
    fn parse_system_cron_skips_comment() {
        assert!(parse_system_cron_line("# this is a comment", "/etc/crontab").is_none());
    }

    #[test]
    fn parse_system_cron_skips_empty() {
        assert!(parse_system_cron_line("", "/etc/crontab").is_none());
    }

    #[test]
    fn parse_user_cron_valid_line() {
        let line = "0 2 * * * /usr/bin/backup.sh";
        let entry =
            parse_user_cron_line(line, "deploy", "/var/spool/cron/crontabs/deploy").unwrap();
        assert_eq!(entry.user, "deploy");
        assert_eq!(entry.schedule, "0 2 * * *");
        assert_eq!(entry.command, "/usr/bin/backup.sh");
    }

    #[test]
    fn collect_returns_persistence_snapshot() {
        let snap = collect();
        let _ = snap.systemd_services;
        let _ = snap.cron_entries;
    }
}
