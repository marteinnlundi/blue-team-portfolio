use crate::types::ProcessEntry;
use std::fs;

pub fn collect() -> Vec<ProcessEntry> {
    let mut entries = Vec::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return entries,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let base = format!("/proc/{}", pid);

        let command_line = fs::read_to_string(format!("{}/cmdline", base))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let comm = fs::read_to_string(format!("{}/comm", base))
            .unwrap_or_default()
            .trim()
            .to_string();

        if comm.is_empty() {
            continue;
        }

        let ppid = read_ppid(&base);
        let user = read_user(pid);

        entries.push(ProcessEntry {
            pid,
            ppid,
            name: comm,
            command_line: if command_line.is_empty() {
                format!("[{}]", pid)
            } else {
                command_line
            },
            user,
        });
    }

    entries.sort_by_key(|p| p.pid);
    entries
}

fn read_ppid(base: &str) -> u32 {
    let status = fs::read_to_string(format!("{}/status", base)).unwrap_or_default();
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("PPid:") {
            return val.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn read_user(pid: u32) -> String {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
    let mut uid: Option<u32> = None;
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("Uid:") {
            uid = val.split_whitespace().next().and_then(|v| v.parse().ok());
            break;
        }
    }
    let uid = match uid {
        Some(u) => u,
        None => return "unknown".to_string(),
    };
    resolve_uid(uid)
}

fn resolve_uid(uid: u32) -> String {
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(uid) {
            return parts[0].to_string();
        }
    }
    uid.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_finds_at_least_one_process() {
        let procs = collect();
        assert!(!procs.is_empty());
    }

    #[test]
    fn collect_includes_pid_1() {
        let procs = collect();
        let init = procs.iter().find(|p| p.pid == 1);
        assert!(init.is_some(), "expected pid 1 in process list");
    }

    #[test]
    fn all_entries_have_non_empty_name() {
        for p in collect() {
            assert!(!p.name.is_empty(), "pid {} has empty name", p.pid);
        }
    }
}
