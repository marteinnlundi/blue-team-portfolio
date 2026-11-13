use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: &'static str,
    pub collected_at: DateTime<Utc>,
    pub host: HostInfo,
    pub processes: Vec<ProcessEntry>,
    pub network: NetworkSnapshot,
    pub users: UserSnapshot,
    pub persistence: PersistenceSnapshot,
    pub log_slices: Vec<LogSlice>,
    pub manifest: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub uptime_seconds: u64,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: String,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub connections: Vec<NetworkConnection>,
    pub listening_ports: Vec<ListeningPort>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListeningPort {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub user: String,
    pub tty: String,
    pub from: String,
    pub login_time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthEvent {
    pub time: String,
    pub event_type: String,
    pub user: String,
    pub source: String,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSnapshot {
    pub active_sessions: Vec<UserSession>,
    pub recent_auth_events: Vec<AuthEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub state: String,
    pub enabled: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CronEntry {
    pub user: String,
    pub schedule: String,
    pub command: String,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistenceSnapshot {
    pub systemd_services: Vec<ServiceEntry>,
    pub cron_entries: Vec<CronEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogSlice {
    pub source: String,
    pub lines: Vec<String>,
}
