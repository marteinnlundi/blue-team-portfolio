use crate::types::{AuthEvent, UserSession, UserSnapshot};
use std::fs;

pub fn collect() -> UserSnapshot {
    UserSnapshot {
        active_sessions: collect_sessions(),
        recent_auth_events: collect_auth_events(200),
    }
}

fn collect_sessions() -> Vec<UserSession> {
    let mut sessions = Vec::new();
    let utmp_path = "/var/run/utmp";
    if !std::path::Path::new(utmp_path).exists() {
        return sessions;
    }

    let data = match fs::read(utmp_path) {
        Ok(d) => d,
        Err(_) => return sessions,
    };

    let record_size = 384;
    for chunk in data.chunks_exact(record_size) {
        let ut_type = i16::from_le_bytes([chunk[0], chunk[1]]);
        if ut_type != 7 {
            continue;
        }

        let user = read_cstr(&chunk[8..40]);
        let tty = read_cstr(&chunk[40..52]);
        let host = read_cstr(&chunk[52..308]);

        if user.is_empty() {
            continue;
        }

        sessions.push(UserSession {
            user,
            tty,
            from: host,
            login_time: String::new(),
        });
    }

    sessions
}

fn read_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn collect_auth_events(limit: usize) -> Vec<AuthEvent> {
    let candidates = ["/var/log/auth.log", "/var/log/secure"];
    let content = candidates
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .unwrap_or_default();

    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(limit);

    lines[start..]
        .iter()
        .filter_map(|line| parse_auth_line(line))
        .collect()
}

fn parse_auth_line(line: &str) -> Option<AuthEvent> {
    let lower = line.to_lowercase();

    let (event_type, user, source) = if lower.contains("failed password for") {
        let user = extract_after(line, "for ")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown")
            .to_string();
        let source = extract_after(line, "from ")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        ("authentication_failure", user, source)
    } else if lower.contains("accepted password for") || lower.contains("accepted publickey for") {
        let user = extract_after(line, "for ")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown")
            .to_string();
        let source = extract_after(line, "from ")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        ("authentication_success", user, source)
    } else if lower.contains("session opened for user") {
        let user = extract_after(line, "for user ")
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown")
            .to_string();
        ("session_open", user, String::new())
    } else if lower.contains("sudo") && lower.contains("command") {
        let user = line
            .split_whitespace()
            .nth(4)
            .unwrap_or("unknown")
            .trim_end_matches(':')
            .to_string();
        ("privilege_escalation", user, String::new())
    } else {
        return None;
    };

    let time = line
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ");

    Some(AuthEvent {
        time,
        event_type: event_type.to_string(),
        user,
        source,
        details: line.to_string(),
    })
}

fn extract_after<'a>(s: &'a str, needle: &str) -> Option<&'a str> {
    s.find(needle).map(|i| &s[i + needle.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth_line_failure() {
        let line = "May 29 10:00:00 host sshd[123]: Failed password for root from 192.168.1.1 port 22 ssh2";
        let ev = parse_auth_line(line).unwrap();
        assert_eq!(ev.event_type, "authentication_failure");
        assert_eq!(ev.user, "root");
        assert_eq!(ev.source, "192.168.1.1");
    }

    #[test]
    fn parse_auth_line_success() {
        let line = "May 29 10:01:00 host sshd[124]: Accepted password for alice from 10.0.0.5 port 22 ssh2";
        let ev = parse_auth_line(line).unwrap();
        assert_eq!(ev.event_type, "authentication_success");
        assert_eq!(ev.user, "alice");
        assert_eq!(ev.source, "10.0.0.5");
    }

    #[test]
    fn parse_auth_line_returns_none_for_unrelated() {
        let line = "May 29 10:00:00 host systemd[1]: Started Daily Cleanup.";
        assert!(parse_auth_line(line).is_none());
    }

    #[test]
    fn collect_returns_snapshot() {
        let snap = collect();
        let _ = snap.active_sessions;
        let _ = snap.recent_auth_events;
    }
}
